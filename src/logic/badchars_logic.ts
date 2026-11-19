export type BadcharMismatch = {
  offset: number;
  expected: number;
  observed: number;
};

export type BadcharComparison = {
  badChars: number[];
  mismatches: BadcharMismatch[];
  survivorCount: number;
  expectedConsumed: number;
  startOffset: number;
  truncatedAt?: number;
};

export type ByteArrayFormat = "python" | "c" | "hex";

export type ArrayLocation = {
  offset: number;
  expectedStart: number;
  matchedRun: number;
};

export function expectedBytes(exclude: number[]): number[] {
  const excluded = new Set(exclude.map((value) => value & 0xff));
  const result: number[] = [];
  for (let i = 0; i <= 0xff; i += 1) {
    if (!excluded.has(i)) {
      result.push(i);
    }
  }
  return result;
}

function hexByte(value: number): string {
  return (value & 0xff).toString(16).padStart(2, "0");
}

// Render a test byte array in a paste-ready form for the sending harness.
export function formatByteArray(bytes: number[], format: ByteArrayFormat): string {
  switch (format) {
    case "python":
      return `b"${bytes.map((value) => `\\x${hexByte(value)}`).join("")}"`;
    case "c":
      return `"${bytes.map((value) => `\\x${hexByte(value)}`).join("")}"`;
    case "hex":
    default:
      return bytes.map(hexByte).join(" ");
  }
}

export function pythonBadcharsLine(badchars: number[]): string {
  const sorted = [...new Set(badchars.map((value) => value & 0xff))].sort((a, b) => a - b);
  return `BADCHARS = ${formatByteArray(sorted, "python")}`;
}

export function nextBadcharCommand(command: "badchars" | "badchar_find", addressArg: string, badchars: number[]): string {
  const sorted = [...new Set(badchars.map((value) => value & 0xff))].sort((a, b) => a - b);
  return `dx @$osed().${command}(${addressArg}, "${sorted.map((value) => hexByte(value).toUpperCase()).join(" ")}")`;
}

// One list to grow each run; the exploit derives the test array from it instead of pasting 255 bytes again.
export function pythonBadcharHelper(badchars: number[]): string[] {
  return [
    `${pythonBadcharsLine(badchars)}  # add each new bad char here`,
    "",
    "def badchar_array(bad=BADCHARS):",
    "    return bytes(b for b in range(256) if b not in bad)",
  ];
}

export function locateExpectedArray(window: Uint8Array, expected: number[], minRun = 8): ArrayLocation | undefined {
  const expectedIndex = new Map<number, number>();
  for (let i = 0; i < expected.length; i += 1) {
    expectedIndex.set(expected[i], i);
  }

  for (let start = 0; start < window.length; start += 1) {
    const ei = expectedIndex.get(window[start]);
    if (ei === undefined) continue;

    let run = 0;
    for (let i = 0; start + i < window.length && ei + i < expected.length; i += 1) {
      if (window[start + i] !== expected[ei + i]) break;
      run += 1;
    }
    if (run >= minRun) {
      return { offset: start, expectedStart: ei, matchedRun: run };
    }
  }

  for (let start = 0; start < window.length; start += 1) {
    const ei = expectedIndex.get(window[start]);
    if (ei === undefined) continue;

    let e = ei;
    let o = start;
    let matched = 0;
    while (e < expected.length && o < window.length) {
      if (window[o] === expected[e]) {
        matched += 1;
        e += 1;
        o += 1;
      } else if (expected[e] < window[o]) {
        e += 1;
      } else {
        break;
      }
    }
    if (matched >= minRun) {
      return { offset: start, expectedStart: ei, matchedRun: matched };
    }
  }

  return undefined;
}

// A cut in the first few array bytes leaves no survivor run to search for, but the
// overwritten return address that IP was popped from still sits just before the array.
export function findReturnSlot(before: Uint8Array, ip: bigint, pointerSize: 4 | 8): number | undefined {
  const needle: number[] = [];
  let rest = ip;
  for (let i = 0; i < pointerSize; i += 1) {
    needle.push(Number(rest & BigInt(0xff)));
    rest = rest >> BigInt(8);
  }
  for (let offset = before.length - pointerSize; offset >= 0; offset -= 1) {
    let match = true;
    for (let i = 0; i < pointerSize && match; i += 1) {
      match = before[offset + i] === needle[i];
    }
    if (match) return offset;
  }
  return undefined;
}

// Observed bytes past the array end that may still belong to it (expanded characters).
const EXPANSION_SLACK = 32;

type ByteFate = "kept" | "changed" | "dropped";

// Aligns the sent array with memory by edit distance, so one pass reports every byte that was
// replaced, dropped, or expanded. A trailing stretch with no paired survivors means the copy
// stopped; its first byte is reported as the likely terminator because later bytes never arrived.
// Up to `leadingSlack` leading observed bytes are free to skip, for callers that read from a little
// before where the array should start.
export function compareBadchars(observed: Uint8Array, expected: number[], leadingSlack = 0): BadcharComparison {
  const n = expected.length;
  const m = Math.min(observed.length, n + EXPANSION_SLACK);
  const width = m + 1;
  const cost = new Uint32Array((n + 1) * width);
  for (let j = 0; j <= m; j += 1) cost[j] = Math.max(0, j - leadingSlack);
  for (let i = 1; i <= n; i += 1) {
    cost[i * width] = i;
    for (let j = 1; j <= m; j += 1) {
      const pair = cost[(i - 1) * width + j - 1] + (expected[i - 1] === observed[j - 1] ? 0 : 1);
      const dropped = cost[(i - 1) * width + j] + 1;
      const extra = cost[i * width + j - 1] + 1;
      cost[i * width + j] = Math.min(pair, dropped, extra);
    }
  }

  let end = 0;
  for (let j = 1; j <= m; j += 1) {
    if (cost[n * width + j] < cost[n * width + end]) end = j;
  }

  const fate: ByteFate[] = new Array(n);
  const seen: number[] = new Array(n).fill(-1);
  const extras: Array<{ gap: number; value: number }> = [];
  let i = n;
  let j = end;
  while (i > 0 || j > leadingSlack) {
    const here = cost[i * width + j];
    if (i > 0 && j > 0 && expected[i - 1] === observed[j - 1] && here === cost[(i - 1) * width + j - 1]) {
      fate[i - 1] = "kept";
      seen[i - 1] = observed[j - 1];
      i -= 1;
      j -= 1;
    } else if (i > 0 && j > 0 && here === cost[(i - 1) * width + j - 1] + 1) {
      fate[i - 1] = "changed";
      seen[i - 1] = observed[j - 1];
      i -= 1;
      j -= 1;
    } else if (i > 0 && here === cost[(i - 1) * width + j] + 1) {
      fate[i - 1] = "dropped";
      i -= 1;
    } else {
      extras.push({ gap: i, value: observed[j - 1] });
      j -= 1;
    }
  }

  // Stack junk after a cut still matches a few array bytes by chance, so the copy is taken to
  // end where survivors most outnumber damaged bytes. Junk alone never gets ahead.
  let tested = 0;
  let score = 0;
  let best = 0;
  for (let k = 0; k < n; k += 1) {
    score += fate[k] === "kept" ? 1 : -1;
    if (fate[k] === "kept" && score > 0 && score >= best) {
      best = score;
      tested = k + 1;
    }
  }
  const truncated = n - tested >= 2;
  if (!truncated) tested = n;

  const expanded = new Map<number, number>();
  for (const { gap, value } of extras) {
    const before = gap - 1;
    const owner = before >= 0 && (fate[before] !== "kept" || gap >= n) ? before : gap;
    if (owner < tested && !expanded.has(owner)) expanded.set(owner, value);
  }

  const badChars: number[] = [];
  const mismatches: BadcharMismatch[] = [];
  let survivorCount = 0;
  for (let k = 0; k < tested; k += 1) {
    if (fate[k] === "kept" && !expanded.has(k)) {
      survivorCount += 1;
      continue;
    }
    badChars.push(expected[k]);
    const value = fate[k] === "dropped" ? -1 : fate[k] === "kept" ? expanded.get(k) ?? -1 : seen[k];
    mismatches.push({ offset: k, expected: expected[k], observed: value });
  }

  return {
    badChars,
    mismatches,
    survivorCount,
    expectedConsumed: tested,
    startOffset: j,
    ...(truncated ? { truncatedAt: expected[tested] } : {}),
  };
}
