import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { buildTemplate, builderScript, callFrame, parseBadchars, parseTemplateArgs, pushString, Reg, renderAsm, renderKeystoneCode } from "../shellcode/writer";

const REGISTERS = ["eax", "ecx", "edx", "ebx", "ebp", "esi", "edi"];

const fail = (command: string, args: Record<string, unknown>, error: string): CommandResult =>
  ({ command, args, success: false, findings: [], warnings: [], errors: [error] });

const badList = (bytes: number[]): string => bytes.map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ");

/** Splits a trailing "bad=<list>" token off variadic arguments. */
export function splitBadToken(values: unknown[]): { rest: string[]; bad?: string } {
  const rest: string[] = [];
  let bad: string | undefined;
  for (const value of values) {
    const text = String(value);
    if (/^bad(chars)?=/i.test(text.trim())) bad = text.trim().replace(/^bad(chars)?=/i, "");
    else rest.push(text);
  }
  return { rest, bad };
}

export function createScPushStringCommand(): Command {
  return {
    name: "sc_push_string",
    description: "Print x86 instructions that build a NUL-terminated string on the stack without 00 or the given bad characters, leaving ESP (and an optional register) pointing at it.",
    usage: 'dx @$osed().sc.push_string(text, badchars?, register?)',
    examples: ['dx @$osed().sc.push_string("calc.exe")', 'dx @$osed().sc.push_string("cmd.exe /c whoami", "00 0A 0D 20", "ebx")'],
    compactExampleCount: 2,
    schema: { text: { type: "string", required: true }, badchars: { type: ["string", "array"] }, register: { type: "string" } },
    execute(options: Record<string, unknown>): CommandResult {
      const text = options.text as string;
      const badchars = parseBadchars(options.badchars);
      if (!badchars) return fail("sc_push_string", options, `Cannot read the bad characters "${String(options.badchars)}".`);
      const register = options.register === undefined || options.register === "" ? undefined : String(options.register).trim().toLowerCase();
      if (register !== undefined && !REGISTERS.includes(register)) return fail("sc_push_string", options, `Register must be one of ${REGISTERS.join(", ")}.`);
      const result = pushString(text, new Set(badchars), register as Reg | undefined);
      if (!result.ok) return fail("sc_push_string", options, result.error);

      const dwords = Math.floor(text.length / 4) + 1;
      out.section(`sc.push_string: ${text.length} chars + NUL in ${dwords} dwords, pushed last dword first`);
      out.info(`Avoids ${badList(badchars)}. Scratch register eax, ecx or edx may be clobbered.`);
      for (const line of renderAsm(result.lines)) out.print(line);
      out.print("");
      for (const line of renderKeystoneCode(result.lines)) out.print(line);
      return { command: "sc_push_string", args: { text, badchars, register }, success: true, findings: [{ text, dwords, lines: result.lines }], warnings: [], errors: [] };
    },
  };
}

export function createScCallFrameCommand(): Command {
  return {
    name: "sc_call_frame",
    description: "Print the push sequence for one stdcall API call through the sc.template resolver: arguments in reverse order, the ROR13 hash, the module base, and the two calls.",
    usage: 'dx @$osed().sc.call_frame(api, args..., "bad=<list>"?)',
    examples: ['dx @$osed().sc.call_frame("WinExec", "<ptr to cmd>", "1")', 'dx @$osed().sc.call_frame("TerminateProcess", "-1", "0", "bad=00 0A 0D")'],
    compactExampleCount: 2,
    schema: { api: { type: "string", required: true }, args: { type: "array" }, badchars: { type: ["string", "array"] } },
    execute(options: Record<string, unknown>): CommandResult {
      const badchars = parseBadchars(options.badchars);
      if (!badchars) return fail("sc_call_frame", options, `Cannot read the bad characters "${String(options.badchars)}".`);
      const args = ((options.args as unknown[] | undefined) ?? []).map(String);
      const result = callFrame(options.api as string, args, new Set(badchars));
      if (!result.ok) return fail("sc_call_frame", options, result.error);

      out.section(`sc.call_frame: ${result.title}`);
      out.info(`Avoids ${badList(badchars)}. Expects the sc.template frame: [ebp-0x04] resolver, [ebp-0x08] kernel32, [ebp-0x0c] last LoadLibraryA base.`);
      for (const warning of result.warnings) out.warn(warning);
      for (const line of renderAsm(result.lines)) out.print(line);
      out.print("");
      for (const line of renderKeystoneCode(result.lines)) out.print(line);
      return {
        command: "sc_call_frame",
        args: { api: result.api, args, badchars },
        success: true,
        findings: [{ api: result.api, module: result.module, hash: `0x${result.hash.toString(16).padStart(8, "0")}`, known: result.known, lines: result.lines }],
        warnings: result.warnings,
        errors: [],
      };
    },
  };
}

export function createScTemplateCommand(): Command {
  return {
    name: "sc_template",
    description: "Print a complete build_sc.py (Python 3 + Keystone) for null-free x86 shellcode: prologue, kernel32 lookup through the PEB, a ROR13 export resolver, one call frame per task, and the epilogue. The script reports every bad byte with its offset and line.",
    usage: 'dx @$osed().sc.template(task..., "bad=<list>"?)',
    examples: [
      'dx @$osed().sc.template("winexec=calc.exe", "exit")',
      'dx @$osed().sc.template("show=0", "winexec=cmd.exe /c whoami > C:\\\\out.txt", "terminate", "bad=00 0A 0D 20")',
      'dx @$osed().sc.template("loadlibrary=user32.dll", "getprocaddress=MessageBoxA")',
    ],
    compactExampleCount: 2,
    schema: { tasks: { type: "array" } },
    execute(options: Record<string, unknown>): CommandResult {
      const tokens = ((options.tasks as unknown[] | undefined) ?? []).map(String);
      const plan = parseTemplateArgs(tokens);
      if (!plan.ok) return fail("sc_template", options, plan.error);
      const invocation = `sc.template(${tokens.map((token) => JSON.stringify(token)).join(", ")})`;
      const result = buildTemplate(plan, invocation);
      if (!result.ok) return fail("sc_template", options, result.error);

      out.section(`sc.template: build_sc.py, ${plan.tasks.length} task(s), bad chars ${badList(plan.badchars)}`);
      out.info("Save everything below this line as build_sc.py and run: python build_sc.py");
      for (const line of result.script) out.print(line);
      return { command: "sc_template", args: { tasks: plan.tasks, badchars: plan.badchars }, success: true, findings: [{ tasks: plan.tasks, script: result.script.join("\n") }], warnings: [], errors: [] };
    },
  };
}

export function createScBuilderCommand(): Command {
  return {
    name: "sc_builder",
    description: "Print sc_builder.py, a config-driven Python 3 + Keystone builder: list the API calls at its top, run it, and get shellcode checked for bad bytes, size and forward calls, with an optional XOR decoder stub.",
    usage: 'dx @$osed().sc.builder(task..., "bad=<list>"?, "xor"?, "max=<bytes>"?)',
    examples: [
      "dx @$osed().sc.builder()",
      'dx @$osed().sc.builder("show=0", "winexec=cmd.exe /c whoami > C:\\\\out.txt", "terminate", "bad=00 0A 0D 20 2F")',
      'dx @$osed().sc.builder("winexec=calc.exe", "exit", "bad=00 0A 0D", "xor", "max=400")',
    ],
    compactExampleCount: 2,
    schema: { tasks: { type: "array" } },
    execute(options: Record<string, unknown>): CommandResult {
      const tokens = ((options.tasks as unknown[] | undefined) ?? []).map(String);
      const result = builderScript(tokens);
      if (!result.ok) return fail("sc_builder", options, result.error);

      const plan = result.plan;
      out.section(plan
        ? `sc.builder: sc_builder.py, ${plan.tasks.length} task(s), bad chars ${badList(plan.badchars)}${plan.xor ? ", XOR encoder on" : ""}`
        : "sc.builder: sc_builder.py with its default CONFIG (WinExec calc.exe, then TerminateProcess)");
      out.info("Save everything below this line as sc_builder.py and run: python sc_builder.py");
      for (const line of result.script.replace(/\n$/, "").split("\n")) out.print(line);
      return {
        command: "sc_builder",
        args: plan ? { tasks: plan.tasks, badchars: plan.badchars, xor: plan.xor, maxSize: plan.maxSize } : {},
        success: true,
        findings: [{ script: result.script }],
        warnings: [],
        errors: [],
      };
    },
  };
}
