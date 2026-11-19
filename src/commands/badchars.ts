import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";
import { getPointerSize, readMemory, tryReadMemory } from "../core/memory";
import { normalizeAddress, normalizeByteArray } from "../core/validation";
import { compareBadchars, expectedBytes, findReturnSlot, formatByteArray, locateExpectedArray, nextBadcharCommand, pythonBadcharHelper, pythonBadcharsLine } from "../logic/badchars_logic";
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
    usage: "dx @$osed().badchar_function(badchars?)",
    examples: ['dx @$osed().badchar_function("00")', 'dx @$osed().badchar_function("00 0A 0D")'],
    schema: {
      exclude: { type: "array", elementType: "number", default: [] },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const normalizedExclude = normalizeByteArray((options.exclude as number[]) ?? []);
      const lines = pythonBadcharHelper(normalizedExclude.values);

      out.section("Bad Character Python Helper");
      for (const line of lines) out.print(line);
      out.print("");
      out.print("payload += badchar_array()  # where the test array goes");
      out.whyItMatters("Each badchar_find run prints the updated BADCHARS line; paste it over this one and send again.");

      const warnings = normalizedExclude.warning ? [normalizedExclude.warning] : [];
      return result("badchar_function", { ...options, exclude: normalizedExclude.values }, [{ exclude: normalizedExclude.values, lines }], warnings);
    },
  };
}

export function createBadcharFindCommand(): Command {
  return {
    name: "badchar_find",
    description: "Locate a sent bad-character array in memory (near an address or the stack pointer) and report the first corrupted byte.",
    usage: "dx @$osed().badchar_find(address?, exclude?, windowBytes?, minRun?)",
    examples: ["dx @$osed().badchar_find()", 'dx @$osed().badchar_find("0012F800", "00 0A 0D")'],
    schema: {
      address: { type: ["number", "string"] },
      exclude: { type: "array", elementType: "number", default: [] },
      windowBytes: { type: "number", min: 256, max: 16384, default: 2048 },
      minRun: { type: "number", min: 4, max: 64, default: 8 },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const pointerSize = getPointerSize();
      const normalizedExclude = normalizeByteArray((options.exclude as number[]) ?? []);
      const expected = expectedBytes(normalizedExclude.values);
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

      const located = locateExpectedArray(window, expected, minRun);
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
        out.warn(
          `Array truncated after ${out.formatHexByte(lastTested)}; bytes ${out.formatHexByte(firstUntested)}-0xFF not tested.`,
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
      out.info(`Next command: ${nextBadcharCommand("badchar_find", options.address === undefined ? "@esp" : out.formatAddress(anchor, pointerSize), nextRun)}`);

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
          },
        ],
        warnings,
      );
    },
  };
}
