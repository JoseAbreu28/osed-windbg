import { getPointerSize } from "../core/memory";
import * as out from "../core/output";
import { scanPattern, type ScanOptions, type ScanResult } from "../core/scan_engine";
import { badcharAddressFilter } from "../logic/pointer_filter_logic";

export type BadcharScanResult = ScanResult & { dropped: number };

// Most low hits in a module hold a bad byte in their address, so a filtered scan
// reads far more candidates than it keeps. rop.scan_live uses the same depth.
export function badcharScanDepth(keep: number): number {
  return Math.min(Math.max(keep * 20, 1500), 4000);
}

// scanPattern that returns only addresses whose bytes avoid every bad char, with
// the same predicate rop.scan_live applies. dropped counts the rejected addresses
// met before the first maxResults clean ones.
export function scanPatternAvoiding(options: ScanOptions, pattern: Uint8Array, badchars: number[]): BadcharScanResult {
  if (badchars.length === 0) {
    return { ...scanPattern(options, pattern), dropped: 0 };
  }
  const scan = scanPattern({ ...options, maxResults: badcharScanDepth(options.maxResults) }, pattern);
  const filter = badcharAddressFilter(badchars, getPointerSize());
  const hits: bigint[] = [];
  let dropped = 0;
  for (const address of scan.hits) {
    if (hits.length >= options.maxResults) break;
    if (filter.predicate({ address })) {
      hits.push(address);
    } else {
      dropped += 1;
    }
  }
  return { ...scan, hits, stats: { ...scan.stats, results: hits.length }, dropped };
}

export function reportBadcharDrops(badchars: number[], dropped: number): void {
  if (badchars.length === 0) return;
  const list = badchars.map((byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ");
  out.info(`Bad chars ${list}: dropped ${dropped} candidate address(es) that contain one.`);
}

// Gadget commands take the bad chars in the slot after maxResults. A boolean there
// is executableOnly from the older order, so it moves one slot right.
export function badcharSlotArgs(args: unknown[], slot: number): unknown[] {
  if (typeof args[slot] !== "boolean") return args;
  return [...args.slice(0, slot), undefined, ...args.slice(slot)];
}
