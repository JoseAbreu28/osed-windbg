import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readMemory, tryReadMemory } from "../core/memory";
import { normalizeAddress, normalizeByteArray } from "../core/validation";
import {
  BadcharBlock,
  FIRST_BLOCK_START,
  blockBytes,
  compareBadchars,
  expectedBytes,
  findReturnSlot,
  formatByteArray,
  locateExpectedArray,
  nextBadcharCommand,
  nextBlockStep,
  pythonBadcharHelper,
  pythonBadcharsLine,
  pythonBlockLine,
} from "../logic/badchars_logic";
import { findModuleByAddress } from "./modules";
import { readRegisters } from "./triage";

function result(command: string, args: Record<string, unknown>, findings: unknown[], warnings: string[] = []): CommandResult {
  return { command, args, success: true, findings, warnings, errors: [] };
}

function readLargestWindow(start: bigint, maxLength: number): Uint8Array | undefined {
  let low = 1;
  let high = maxLength;
  let best: Uint8Array | undefined;

  while (low <= high) {
    const mid = low + Math.floor((high - low) / 2);
    const chunk = tryReadMemory(start, mid);
    if (chunk) {
      best = chunk;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  return best;
}

const DEFAULT_WINDOW_BYTES = 2048;
const DEFAULT_MIN_RUN = 8;

function hexArg(value: number): string {
  return `0x${value.toString(16).toUpperCase().padStart(2, "0")}`;
}

function byteRange(bytes: number[]): string {
  return `${out.formatHexByte(bytes[0])}..${out.formatHexByte(bytes[bytes.length - 1])}`;
}

// Covers `ret N` cleanup between the popped return address and the stack pointer.
const RETURN_SLOT_REACH = 0x40;
const CONTENT_BACKTRACK = 8;

function readAfterReturnSlot(
  anchor: bigint,
  pointerSize: 4 | 8,
  length: number,
): { slot: bigint; landing: bigint; observed: Uint8Array } | undefined {
  const ip = readRegisters(pointerSize).ip;
  if (ip === undefined || findModuleByAddress(ip) !== undefined) return undefined;
  const reach = RETURN_SLOT_REACH + pointerSize;
  const start = anchor - BigInt(reach);
  const before = tryReadMemory(start, reach);
  if (!before) return undefined;
  const offset = findReturnSlot(before, ip, pointerSize);
  if (offset === undefined) return undefined;
  const slot = start + BigInt(offset);
  const landing = slot + BigInt(pointerSize);
  const observed = tryReadMemory(landing, length) ?? readLargestWindow(landing, length);
  return observed ? { slot, landing, observed } : undefined;
}

export function createBadcharsCommand(): Command {
  return {
    name: "badchars",
    description: "Identify bad characters from a memory byte sequence.",
    usage: "dx @$osed().badchars(address, exclude?)",
    examples: [
      "dx @$osed().badchars(0x00B8F900)",
      'dx @$osed().badchars("00B8F900", "00 0A 0D")',
    ],
    schema: {
      address: { type: ["number", "string"], required: true },
      exclude: { type: "array", elementType: "number", default: [] },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const address = normalizeAddress(options.address);
      const normalizedExclude = normalizeByteArray((options.exclude as number[]) ?? []);
      const expected = expectedBytes(normalizedExclude.values);
      const observed = readMemory(address, expected.length + 64);
      const compared = compareBadchars(observed, expected);
      const pointerSize = getPointerSize();

      out.section("Bad Character Analysis");
      out.info(`Start address: ${out.formatAddress(address, pointerSize)}`);
      if (normalizedExclude.values.length > 0) {
        out.info(`Known excludes: ${normalizedExclude.values.map((v) => out.formatHexByte(v)).join(" ")}`);
      }

      if (compared.badChars.length > 0) {
        out.warn(`Bad characters found: ${compared.badChars.map((v) => out.formatHexByte(v)).join(" ")}`);
      } else if (compared.expectedConsumed >= expected.length) {
        out.info("All expected bytes survived — no bad characters detected.");
      } else {
        out.info("No bad characters detected in the tested range.");
      }

      out.info(`Survivors: ${compared.survivorCount} of ${compared.expectedConsumed} tested bytes`);

      if (compared.expectedConsumed < expected.length) {
        const lastTested = expected[compared.expectedConsumed - 1];
        const firstUntested = expected[compared.expectedConsumed];
        out.warn(
          `Array truncated after ${out.formatHexByte(lastTested)}; bytes ${out.formatHexByte(firstUntested)}-0xFF not tested.`,
        );
        if (compared.truncatedAt !== undefined) {
          out.warn(`Likely terminator: ${out.formatHexByte(compared.truncatedAt)} (first byte that never arrived).`);
        }
      }

      const allExclude = [...new Set([...normalizedExclude.values, ...compared.badChars])].sort((a, b) => a - b);
      out.info(
        `Copy-ready exclude list: ${allExclude.map((v) => v.toString(16).toUpperCase().padStart(2, "0")).join(" ") || "(none)"}`,
      );
      const nextRun = compared.truncatedAt === undefined ? allExclude : [...allExclude, compared.truncatedAt].sort((a, b) => a - b);
      out.info(`Exploit line: ${pythonBadcharsLine(nextRun)}`);
      out.info(`Next command: ${nextBadcharCommand("badchars", out.formatAddress(address, pointerSize), nextRun)}`);
      out.whyItMatters("Accurate badchar profiling prevents payload corruption before shellcode staging.");

      const warnings = normalizedExclude.warning ? [normalizedExclude.warning] : [];
      return result(
        "badchars",
        {
          ...options,
          exclude: normalizedExclude.values,
        },
        [
          {
            badChars: compared.badChars,
            survivorCount: compared.survivorCount,
            expectedConsumed: compared.expectedConsumed,
            mismatches: compared.mismatches,
            truncatedAt: compared.truncatedAt,
            exclude: normalizedExclude.values,
            allExclude,
          },
        ],
        warnings,
      );
    },
  };
}

export function createBadcharArrayCommand(): Command {
  return {
    name: "badchar_array",
    description: "Generate a bad-character test byte array (0x00-0xFF minus excludes) in paste-ready forms.",
    usage: "dx @$osed().badchar_array(exclude?)",
    examples: ["dx @$osed().badchar_array()", 'dx @$osed().badchar_array("00 0A 0D")'],
    schema: {
      exclude: { type: "array", elementType: "number", default: [] },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const normalizedExclude = normalizeByteArray((options.exclude as number[]) ?? []);
      const expected = expectedBytes(normalizedExclude.values);
      const python = formatByteArray(expected, "python");
      const c = formatByteArray(expected, "c");
      const hex = formatByteArray(expected, "hex");

      out.section("Bad Character Test Array");
      out.info(`Bytes: ${expected.length} (excluded ${normalizedExclude.values.length})`);
      out.print(`Python: ${python}`);
      out.print(`C:      ${c}`);
      out.print(`Hex:    ${hex}`);
      out.whyItMatters("Send this array to the target, then use badchar_find to locate it in memory and see which bytes were mangled.");

      const warnings = normalizedExclude.warning ? [normalizedExclude.warning] : [];
      return result(
        "badchar_array",
        { ...options, exclude: normalizedExclude.values },
        [{ count: expected.length, exclude: normalizedExclude.values, bytes: expected, formats: { python, c, hex } }],
        warnings,
      );
    },
  };
}

export function createBadcharFunctionCommand(): Command {
  return {
    name: "badchar_function",
    description: "Print a Python BADCHARS list plus a badchar_array() helper for the exploit, so each run only grows the list.",
    usage: "dx @$osed().badchar_function(badchars?, space?)",
    examples: [
      'dx @$osed().badchar_function("00")',
      'dx @$osed().badchar_function("00 0A 0D")',
      'dx @$osed().badchar_function("00", 76)    // only 76 bytes fit after EIP: test in blocks',
    ],
    schema: {
      exclude: { type: "array", elementType: "number", default: [] },
      space: { type: "number", min: 0, max: 256, default: 0 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const normalizedExclude = normalizeByteArray((options.exclude as number[]) ?? []);
      const space = options.space as number;
      const lines = pythonBadcharHelper(normalizedExclude.values, space);

      out.section("Bad Character Python Helper");
      for (const line of lines) out.print(line);
      out.print("");
      if (space > 0) {
        const firstCommand = nextBadcharCommand("badchar_find", "@esp", normalizedExclude.values, [
          DEFAULT_WINDOW_BYTES,
          DEFAULT_MIN_RUN,
          hexArg(FIRST_BLOCK_START),
          space,
        ]);
        out.print(`${pythonBlockLine(FIRST_BLOCK_START)}  # first block, right after EIP`);
        out.print("");
        out.print(`First command: ${firstCommand}`);
        out.whyItMatters("Each badchar_find run prints the updated BADCHARS line, the next block, and the next command; paste them and send again.");
      } else {
        out.print("payload += badchar_array()  # where the test array goes");
        out.whyItMatters("Each badchar_find run prints the updated BADCHARS line; paste it over this one and send again.");
      }

      const warnings = normalizedExclude.warning ? [normalizedExclude.warning] : [];
      return result(
        "badchar_function",
        { ...options, exclude: normalizedExclude.values },
        [{ exclude: normalizedExclude.values, space, lines }],
        warnings,
      );
    },
  };
}

export function createBadcharFindCommand(): Command {
  return {
    name: "badchar_find",
    description: "Locate a sent bad-character array in memory (near an address or the stack pointer) and report the first corrupted byte.",
    usage: "dx @$osed().badchar_find(address?, exclude?, windowBytes?, minRun?, start?, size?)",
    examples: [
      "dx @$osed().badchar_find()",
      'dx @$osed().badchar_find("0012F800", "00 0A 0D")',
      'dx @$osed().badchar_find(@esp, "00", 2048, 8, 0x4E, 76)    // 76-byte block that starts at 0x4E',
    ],
    schema: {
      address: { type: ["number", "string"] },
      exclude: { type: "array", elementType: "number", default: [] },
      windowBytes: { type: "number", min: 256, max: 16384, default: DEFAULT_WINDOW_BYTES },
      minRun: { type: "number", min: 4, max: 64, default: DEFAULT_MIN_RUN },
      start: { type: "number", min: 0, max: 0xff },
      size: { type: "number", min: 0, max: 256 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const normalizedExclude = normalizeByteArray((options.exclude as number[]) ?? []);
      const size = (options.size as number | undefined) || undefined;
      const block: BadcharBlock | undefined =
        options.start !== undefined || size !== undefined
          ? { start: (options.start as number | undefined) ?? FIRST_BLOCK_START, size }
          : undefined;
      const expected = block ? blockBytes(normalizedExclude.values, block) : expectedBytes(normalizedExclude.values);
      const windowBytes = options.windowBytes as number;
      const minRun = options.minRun as number;

      let anchor: bigint | undefined;
      let anchorLabel = "n/a";
      if (options.address !== undefined) {
        anchor = normalizeAddress(options.address);
        anchorLabel = out.formatAddress(anchor, pointerSize);
      } else {
        const regs = readRegisters(pointerSize);
        anchor = regs.sp;
        anchorLabel = regs.sp !== undefined ? `${regs.spName ?? "sp"} ${out.formatAddress(regs.sp, pointerSize)}` : "n/a";
      }

      out.section("Bad Character Locate");
      if (anchor === undefined) {
        out.warn("No anchor address available (stack pointer unreadable). Provide an explicit address.");
        return result("badchar_find", options, [{ located: false }], ["No anchor address available."]);
      }
      out.info(`Anchor: ${anchorLabel}`);
      out.info(`Window: ${windowBytes} bytes, expecting a ${expected.length}-byte array.`);
      if (block) {
        if (expected.length === 0) {
          out.warn(`No bytes left to test from ${out.formatHexByte(block.start)} with this exclude list.`);
          return result("badchar_find", options, [{ located: false }], ["No bytes left to test."]);
        }
        out.info(`Block: ${byteRange(expected)}, ${expected.length} bytes.`);
      }

      let window = tryReadMemory(anchor, windowBytes);
      const warnings = normalizedExclude.warning ? [normalizedExclude.warning] : [];
      if (!window) {
        window = readLargestWindow(anchor, windowBytes);
        if (window) {
          warnings.push(`Anchor range was only partially readable; scanned ${window.length} byte(s).`);
        }
      }
      if (!window) {
        out.warn("Anchor memory was not readable.");
        return result("badchar_find", options, [{ located: false }], ["Anchor memory was not readable."]);
      }
      if (window.length < windowBytes) {
        out.warn(`Anchor range was only partially readable; scanned ${window.length} byte(s).`);
      }

      // A short last block can never reach the default run length.
      const located = locateExpectedArray(window, expected, Math.max(4, Math.min(minRun, expected.length)));
      let landing: bigint;
      let observed: Uint8Array;
      let locatedBy: "content" | "return-slot";
      let slack = 0;
      if (located) {
        // The run can start mid-array (after `ret N` the stack pointer sits past the first bytes),
        // so read back from where the array should begin and let the comparison skip the slack.
        const back = located.expectedStart + CONTENT_BACKTRACK;
        const runAddress = anchor + BigInt(located.offset);
        const backRead = tryReadMemory(runAddress - BigInt(back), back + expected.length + 64);
        landing = backRead ? runAddress - BigInt(back) : runAddress;
        observed = backRead ?? window.slice(located.offset);
        slack = backRead ? back : 0;
        locatedBy = "content";
        out.info(`Matched ${located.matchedRun} survivor bytes at anchor + 0x${located.offset.toString(16).toUpperCase()} (expected index ${located.expectedStart}).`);
      } else {
        const afterSlot = readAfterReturnSlot(anchor, pointerSize, expected.length + 64);
        if (!afterSlot) {
          out.warn(`Test array not found within ${windowBytes} bytes of the anchor (min run ${minRun}).`);
          out.warn("The overwritten return address was not found just before the anchor either. If the array sits before EIP, pass its address.");
          return result("badchar_find", options, [{ located: false }], warnings.length > 0 ? warnings : ["Test array not found near anchor."]);
        }
        landing = afterSlot.landing;
        observed = afterSlot.observed;
        locatedBy = "return-slot";
        out.info(
          `No survivor run near the anchor. Comparing from ${out.formatAddress(landing, pointerSize)}, right after the overwritten return address at ${out.formatAddress(afterSlot.slot, pointerSize)}.`,
        );
      }

      const compared = compareBadchars(observed, expected, slack);
      if (locatedBy === "content") {
        landing += BigInt(compared.startOffset);
        out.info(`Located at ${out.formatAddress(landing, pointerSize)}.`);
      }

      if (compared.badChars.length > 0) {
        out.warn(`Bad characters found: ${compared.badChars.map((v) => out.formatHexByte(v)).join(" ")}`);
      } else if (compared.expectedConsumed >= expected.length) {
        out.info("All expected bytes survived — no bad characters detected.");
      } else {
        out.info("No bad characters detected in the tested range.");
      }

      out.info(`Survivors: ${compared.survivorCount} of ${compared.expectedConsumed} tested bytes`);

      if (compared.expectedConsumed < expected.length) {
        const lastTested = expected[compared.expectedConsumed - 1];
        const firstUntested = expected[compared.expectedConsumed];
        const lastSent = block ? out.formatHexByte(expected[expected.length - 1]) : "0xFF";
        out.warn(
          `Array truncated after ${out.formatHexByte(lastTested)}; bytes ${out.formatHexByte(firstUntested)}-${lastSent} not tested.`,
        );
        if (compared.truncatedAt !== undefined) {
          out.warn(`Likely terminator: ${out.formatHexByte(compared.truncatedAt)} (first byte that never arrived).`);
        }
        if (compared.survivorCount === 0) {
          out.warn(
            "Nothing arrived after the return address. If the next run stops at the next byte again, the target caps the input length; move the array before EIP.",
          );
        }
      }

      const allExclude = [...new Set([...normalizedExclude.values, ...compared.badChars])].sort((a, b) => a - b);
      out.info(
        `Copy-ready exclude list: ${allExclude.map((v) => v.toString(16).toUpperCase().padStart(2, "0")).join(" ") || "(none)"}`,
      );
      const nextRun = compared.truncatedAt === undefined ? allExclude : [...allExclude, compared.truncatedAt].sort((a, b) => a - b);
      out.info(`Exploit line: ${pythonBadcharsLine(nextRun)}`);
      // Block runs pass the address to reach start and size; @esp keeps the command valid after a restart moves the stack.
      const anchorIsSp = options.address === undefined || (block !== undefined && anchor === readRegisters(pointerSize).sp);
      const addressArg = anchorIsSp ? "@esp" : out.formatAddress(anchor, pointerSize);
      const step = block ? nextBlockStep(block, expected, compared, nextRun) : undefined;
      if (!block || !step) {
        out.info(`Next command: ${nextBadcharCommand("badchar_find", addressArg, nextRun)}`);
      } else if (step.kind === "done") {
        out.info(`All bytes 0x01..0xFF tested; this was the last block. Final list: ${nextRun.map((v) => v.toString(16).toUpperCase().padStart(2, "0")).join(" ") || "(none)"}`);
      } else {
        if (step.kind === "next") {
          out.info(`Block clean: ${byteRange(expected)} arrived. Bytes past the block are outside the space, not bad chars.`);
          out.info(`Next block: ${byteRange(blockBytes(nextRun, { start: step.start, size: block.size }))}`);
        } else {
          out.info("Send the same block again with the grown list.");
        }
        const blockArgs = [windowBytes, minRun, hexArg(step.start), ...(block.size !== undefined ? [block.size] : [])];
        out.info(`Payload line: ${pythonBlockLine(step.start)}`);
        out.info(`Next command: ${nextBadcharCommand("badchar_find", addressArg, nextRun, blockArgs)}`);
      }

      return result(
        "badchar_find",
        { ...options, exclude: normalizedExclude.values },
        [
          {
            located: true,
            locatedBy,
            landingAddress: landing,
            anchorOffset: located?.offset,
            expectedStart: located?.expectedStart,
            matchedRun: located?.matchedRun,
            badChars: compared.badChars,
            survivorCount: compared.survivorCount,
            expectedConsumed: compared.expectedConsumed,
            mismatches: compared.mismatches,
            truncatedAt: compared.truncatedAt,
            allExclude,
            exclude: normalizedExclude.values,
            ...(block ? { block: { ...block, sent: expected.length, step } } : {}),
          },
        ],
        warnings,
      );
    },
  };
}
