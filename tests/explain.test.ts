import { beforeEach, describe, expect, test } from "vitest";
import { stripDml } from "../src/core/output";
import { EXPLANATIONS } from "../src/explain/catalog";
import { apiLeafPaths, findExplanation } from "../src/explain/explain";
import { initializeScript } from "../src/index";

type Explained = Record<string, string> & { toString(): string };
type Api = Record<string, unknown>;

const logs: string[] = [];

function loadApi(): Api {
  (globalThis as unknown as { host: unknown }).host = {
    diagnostics: { debugLog: (line: string) => logs.push(line) },
    currentProcess: { Is64Bit: false, Modules: [] },
  };
  initializeScript();
  logs.length = 0;
  return (globalThis as unknown as { osed: Api }).osed;
}

function call(api: Api, path: string, ...args: unknown[]): unknown {
  const fn = path.split(".").reduce<unknown>((node, key) => (node as Record<string, unknown>)[key], api);
  return (fn as (...values: unknown[]) => unknown)(...args);
}

function explainOf(value: unknown): Explained {
  return (value as { explain: Explained }).explain;
}

const TEXT_FIELDS = ["what", "how", "when", "output", "report"] as const;

describe("explain catalog", () => {
  let api: Api;
  beforeEach(() => {
    api = loadApi();
  });

  test("every command reachable from @$osed() has an explanation", () => {
    const missing = apiLeafPaths(api).filter((path) => !findExplanation(path));
    expect(missing).toEqual([]);
  });

  test("every explanation names a command that exists", () => {
    const leaves = new Set(apiLeafPaths(api));
    const stale = EXPLANATIONS.flatMap((entry) => [entry.name, ...(entry.aliases ?? [])]).filter((path) => !leaves.has(path));
    expect(stale).toEqual([]);
  });

  test("each entry is complete and its placeholders name its own arguments or results", () => {
    for (const entry of EXPLANATIONS) {
      const names = new Set([...entry.args.map((arg) => arg.name), ...(entry.results ?? []).map((result) => result.name)]);
      for (const field of TEXT_FIELDS) {
        expect(entry[field].trim(), `${entry.name}.${field}`).not.toBe("");
        for (const [, placeholder] of entry[field].matchAll(/<([a-zA-Z][\w-]*)>/g)) {
          expect(names.has(placeholder), `${entry.name}.${field} uses undeclared <${placeholder}>`).toBe(true);
        }
      }
      expect(entry.summary.length, `${entry.name}.summary`).toBeLessThanOrEqual(60);
      const examplePath = /^dx @\$osed\(\)\.([\w.]+)\(/.exec(entry.example)?.[1];
      expect([entry.name, ...(entry.aliases ?? [])], `${entry.name}.example`).toContain(examplePath);
    }
  });

  test("explain() lists every command", () => {
    expect((call(api, "explain") as { success: boolean }).success).toBe(true);
    const text = stripDml(logs.join(""));
    for (const entry of EXPLANATIONS) expect(text).toContain(`  ${entry.name} `);
  });
});

describe(".explain on a command result", () => {
  let api: Api;
  beforeEach(() => {
    api = loadApi();
  });

  test("fills the arguments and the real result of the call", () => {
    const explained = explainOf(call(api, "sc.hash", "WinExec", "ROR13"));
    expect(String(explained)).toBe('=== explain: sc.hash("WinExec", "ROR13") ===');
    expect(explained.Report).toBe("Computed the ROR13 hash of WinExec as 0x0E8AFE98 with sc.hash, the value the shellcode's resolver compares.");
  });

  test("a command that returned a boolean now returns an object with success and .explain", () => {
    const result = call(api, "egghunter", "w00t", "ntaccess", true, "00 0A 0D", "win10") as { success: boolean };
    expect(result.success).toBe(true);
    const report = explainOf(result).Report;
    expect(report).toContain("49-byte ntaccess egghunter for the tag w00t");
    expect(report).toContain("syscall 0x29");
    expect(report).toContain("bad characters 00 0A 0D");
  });

  test("pattern_offset fills the offset it found", () => {
    expect(explainOf(call(api, "pattern_offset", 0x39654138)).Report).toContain("at offset 146 of the cyclic pattern");
  });

  test("sc.template lists each task with what it becomes", () => {
    const args = explainOf(call(api, "sc.template", "show=0", "winexec=calc.exe", "terminate", "bad=00 0A 0D 20")).Arguments;
    expect(args).toContain("show=0: sets the uCmdShow value");
    expect(args).toContain("winexec=calc.exe: builds the command line on the stack");
    expect(args).toContain("terminate: ends the process with TerminateProcess(-1, 0)");
    expect(args).toContain("bad=00 0A 0D 20: lists the bad characters");
  });

  test("explain stays out of the enumerable fields, so equality checks on results are unchanged", () => {
    const result = call(api, "math", 0x41) as Record<string, unknown>;
    expect(Object.keys(result)).not.toContain("explain");
    expect(explainOf(result).Report).toContain("0x41");
  });
});

describe("explain without running the command", () => {
  let api: Api;
  beforeEach(() => {
    api = loadApi();
  });

  test("explain(name) keeps the placeholders", () => {
    const explained = call(api, "explain", "sc.resolve") as Explained;
    expect(String(explained)).toBe("=== explain: sc.resolve ===");
    expect(explained.Report).toBe("Resolved <api> in <module> to <address> with sc.resolve by walking the module's export table in memory.");
  });

  test("explain(name) leaves an argument with a default as a placeholder", () => {
    const explained = call(api, "explain", "egghunter") as Explained;
    expect(explained.Report).toBe("Generated a <size>-byte <mode> egghunter for the tag <egg> with egghunter (syscall <syscallUsed>, bad characters <badchars>) and placed the tag twice in front of the second-stage payload.");
  });

  test("a call that left an argument out reports its default", () => {
    expect(explainOf(call(api, "egghunter")).Report).toContain("ntaccess egghunter for the tag W00T");
  });

  test("explain(name, args) fills the arguments, and a result when the module is not loaded stays a placeholder", () => {
    const explained = call(api, "explain", "sc.resolve", "kernel32", "WinExec") as Explained;
    expect(explained.Report).toBe("Resolved WinExec in kernel32 to <address> with sc.resolve by walking the module's export table in memory.");
  });

  test("explain(name, args) runs a read-only command silently and leaves last_result alone", () => {
    call(api, "math", 7);
    const before = call(api, "last_result");
    logs.length = 0;
    const explained = call(api, "explain", "sc.hash", "WinExec") as Explained;
    expect(explained.Report).toContain("as 0x0E8AFE98");
    expect(logs.join("")).toBe("");
    expect(call(api, "last_result")).toBe(before);
  });

  test("\"explain\" as the first argument matches explain(name, args)", () => {
    const direct = call(api, "sc.resolve", "explain", "kernel32", "WinExec") as Explained;
    const generic = call(api, "explain", "sc.resolve", "kernel32", "WinExec") as Explained;
    expect({ ...direct }).toEqual({ ...generic });
  });

  test("aliases share one explanation", () => {
    expect((call(api, "explain", "pattern_create") as Explained).Report).toBe((call(api, "explain", "pattern.create") as Explained).Report);
  });
});
