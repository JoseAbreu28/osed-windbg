import { resolveTeb32Address, walkSehRecords } from "../analysis/seh";
import { executeDebuggerCommand, getPointerSize, tryReadMemory } from "../core/memory";
import { hex32 } from "./dep_plan";
import { findModuleByAddress } from "./modules";
import { readRegisters } from "./triage";

// The two facts about an SEH delivery only the live process can give: that the crash is one, and where
// ESP is when the dispatcher calls the handler.

export type SehCrash = { record: number; handler: number; eip: number; esp: number; teb: number; eipModule: string };

const dword = (address: number): number | undefined => {
  const bytes = tryReadMemory(BigInt(address >>> 0), 4);
  return bytes && bytes.length === 4 ? (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0 : undefined;
};

export const readByte = (address: number): number | undefined => tryReadMemory(BigInt(address >>> 0), 1)?.[0];

/** The crash is an SEH delivery when EIP is still in a module, so no saved EIP took the overwrite, and
 * the first SEH record's handler is in none, so the overflow wrote it. Undefined for anything else, and
 * the saved-EIP delivery stands. */
export function sehAtCrash(): SehCrash | undefined {
  if (getPointerSize() !== 4) return undefined;
  const regs = readRegisters(4);
  if (regs.ip === undefined || regs.sp === undefined) return undefined;
  const eip = Number(regs.ip) >>> 0;
  const eipModule = findModuleByAddress(BigInt(eip));
  if (!eipModule) return undefined;
  const teb = resolveTeb32Address(host.currentThread as Record<string, unknown>);
  if (!teb) return undefined;
  const first = walkSehRecords(teb, 1).records[0];
  if (!first || findModuleByAddress(first.handler)) return undefined;
  const file = eipModule.name.split(/[\\/]/).pop() ?? eipModule.name;
  return { record: Number(first.node) >>> 0, handler: Number(first.handler) >>> 0, eip, esp: Number(regs.sp) >>> 0, teb: Number(teb) >>> 0, eipModule: file };
}

const GPRS = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "efl"];
const BP_ID = 77;

/** Lets the exception through once with `handler` written over the record's handler and a breakpoint
 * on it, reads ESP when it hits, and puts back the handler, the SEH head and every register, so the
 * process is at the crash again and a second run measures the same thing. The dispatcher refuses a
 * handler in no image before it calls it, which is why the crash's own handler cannot be used. */
export function measureHandlerEsp(crash: SehCrash, handler: number): { esp?: number; how: string; reproduce?: string } {
  const slot = (crash.record + 4) >>> 0;
  const original = dword(slot);
  const head = dword(crash.teb);
  if (original === undefined || head === undefined) return { how: `the record at ${hex32(crash.record)} or the SEH head is unreadable` };
  const saved = readRegisters(4).all.filter((entry) => GPRS.indexOf(entry.name.toLowerCase()) >= 0);
  const run = (command: string): string[] => {
    try {
      return executeDebuggerCommand(command);
    } catch (_error) {
      return [];
    }
  };
  let esp: number | undefined;
  let stopped: number | undefined;
  try {
    run(`ed ${hex32(slot)} ${hex32(handler)}`);
    run(`bp${BP_ID} ${hex32(handler)}`);
    // From the crash's own exception event g hands the exception to the program. From a state this put
    // back, the faulting instruction runs again and the debugger stops on it first, so g once more.
    for (let tries = 0; tries < 2; tries += 1) {
      run("g");
      const after = readRegisters(4);
      stopped = after.ip === undefined ? undefined : Number(after.ip) >>> 0;
      if (stopped === handler && after.sp !== undefined) esp = Number(after.sp) >>> 0;
      if (stopped !== crash.eip) break;
    }
  } finally {
    run(`bc ${BP_ID}`);
    run(`ed ${hex32(slot)} ${hex32(original)}`);
    run(`ed ${hex32(crash.teb)} ${hex32(head)}`);
    for (const entry of saved) run(`r ${entry.name.toLowerCase()}=${hex32(Number(entry.value) >>> 0)}`);
  }
  if (esp === undefined) {
    return { how: `not measured: with ${hex32(handler)} as the handler, g stopped at ${stopped === undefined ? "nothing readable" : hex32(stopped)}, not on it` };
  }
  return { esp, how: `${hex32(handler)} written over the handler, bp on it, g; then the handler, the SEH head and the registers put back`,
    reproduce: `ed ${hex32(slot)} ${hex32(handler)} ; bp ${hex32(handler)} ; g ; ? ${hex32(crash.record)} - esp` };
}
