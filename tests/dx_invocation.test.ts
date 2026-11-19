import { beforeEach, describe, expect, test } from "vitest";
import { createFindMspCommand } from "../src/commands/findmsp";
import { stripDml } from "../src/core/output";
import { validateOptions } from "../src/core/validation";
import { initializeScript, normalizeInvocation } from "../src/index";

type Api = Record<string, unknown> & {
  egghunter: (...args: unknown[]) => boolean;
  findmsp: (...args: unknown[]) => boolean;
  last_result: () => { success: boolean; errors: string[]; warnings: string[]; findings: unknown[] } | undefined;
  exploit: Record<string, (...args: unknown[]) => unknown>;
};

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

function printed(): string {
  return stripDml(logs.join(""));
}

describe("egghunter from dx", () => {
  let api: Api;
  beforeEach(() => {
    api = loadApi();
  });

  test("os selects the NtAccessCheckAndAuditAlarm number for that build", () => {
    expect(api.egghunter("W00T", "ntaccess", false, "", "win10-2004")).toBe(true);
    expect(printed()).toContain("B8C8010000CD2E");
    expect(printed()).toContain("0x1C8 (Windows 10 2004)");
  });

  test("os accepts the build number shown by winver", () => {
    api.egghunter("W00T", "ntaccess", false, "", "18363");
    expect(printed()).toContain("B8C6010000CD2E");
  });

  test("syscall overrides os", () => {
    api.egghunter("W00T", "ntaccess", false, "", "win7", 0x1c2);
    expect(printed()).toContain("B8C2010000CD2E");
    expect(printed()).toContain("0x1C2 (explicit)");
  });

  test("wow64 uses the 64-bit number through the fs:[0xC0] gate", () => {
    api.egghunter("W00T", "ntaccess", true, "", "win10-2004");
    expect(printed()).toContain("B829000000" + "64FF13");
  });

  test("an unknown os warns and names the default", () => {
    api.egghunter("W00T", "ntaccess", false, "", "win95");
    expect(printed()).toContain('Unknown os "win95"');
    expect(printed()).toContain("0x1C9 (Windows 10 22H2)");
    expect(printed()).toContain("B8C9010000CD2E");
  });

  test("no os warns and names the default", () => {
    api.egghunter("W00T");
    expect(printed()).toContain("No os given");
    expect(printed()).toContain("0x1C9 (Windows 10 22H2)");
  });

  test("bad characters in the syscall immediate are reported", () => {
    expect(api.egghunter("W00T", "ntaccess", false, "C8", "win10-2004")).toBe(false);
    expect(printed()).toContain("byte 0xC8 at offset 8");
  });
});

describe("findmsp from dx", () => {
  test("positional arguments map to the documented options", () => {
    const options = normalizeInvocation("findmsp", [20000, 4096, 64]);
    const checked = validateOptions(options, createFindMspCommand().schema);
    expect(checked.errors).toEqual([]);
    expect(checked.value).toEqual({ patternLength: 20000, stackBytes: 4096, probeBytes: 64 });
  });

  test("omitted trailing arguments take the defaults", () => {
    const checked = validateOptions(normalizeInvocation("findmsp", [20000]), createFindMspCommand().schema);
    expect(checked.value).toEqual({ patternLength: 20000, stackBytes: 2048, probeBytes: 32 });
  });

  test("a call with arguments reaches the command", () => {
    const api = loadApi();
    api.findmsp(20000, 4096);
    const errors = api.last_result()?.errors ?? [];
    expect(errors.join(" ")).not.toContain("Unknown option key");
  });
});
