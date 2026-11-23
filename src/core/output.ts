import { SCREEN } from "./screenshot_rule";

export type TableColumn = {
  key: string;
  header: string;
  width?: number;
};

let quietDepth = 0;
let held: string[] | undefined;

function write(line = ""): void {
  if (quietDepth > 0) return;
  if (held) held.push(line);
  else host.diagnostics.debugLog(`${line}\n`);
}

/** Runs fn with every output.ts line suppressed, for a lookup whose printout nobody asked for. */
export function quietly<T>(fn: () => T): T {
  quietDepth += 1;
  try {
    return fn();
  } finally {
    quietDepth -= 1;
  }
}

/** Runs fn with its lines held back instead of written, so the caller prints them where they belong.
 * dep_plan needs an answer before its first line that only a section further down produces. A nested
 * `quietly` still drops its lines rather than handing them over. */
export function capture<T>(fn: () => T): { value: T; lines: string[] } {
  const outer = held;
  const own: string[] = [];
  held = own;
  try {
    return { value: fn(), lines: own };
  } finally {
    held = outer;
  }
}

function pad(value: string, width: number): string {
  return value.length >= width ? value : `${value}${" ".repeat(width - value.length)}`;
}

export function stripDml(value: string): string {
  return value
    .replace(/<link\b[^>]*>(.*?)<\/link>/gi, "$1")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&amp;/gi, "&");
}

function visibleLength(value: string): number {
  return stripDml(value).length;
}

export function print(message: string): void {
  write(message);
}

export function section(title: string): void {
  write();
  write(`=== ${title} ===`);
}

/** A number dxCall writes in hex, as the user types an address or a flag value. */
export type Hex = { hex: number };

export function hex(value: number): Hex {
  return { hex: value };
}

function literal(value: unknown): string {
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "object" && value !== null && "hex" in value) return `0x${((value as Hex).hex >>> 0).toString(16).toUpperCase()}`;
  return String(value);
}

export function dxCall(path: string, args: unknown[]): string {
  return `dx @$osed().${path}(${args.map(literal).join(", ")})`;
}

export function echo(path: string, args: unknown[]): void {
  write(dxCall(path, args));
}

/** A dx call is one token. Breaking inside one leaves a command nobody can paste in one drag, so a call
 * that does not fit moves whole onto the next line instead. Its arguments never contain a `)`. */
const DX_CALL = /dx @\$osed\(\)\.[\w.]+\([^)]*\)/g;

/** The message split on spaces, with each dx call kept whole. */
function words(message: string): string[] {
  const found: string[] = [];
  let at = 0;
  DX_CALL.lastIndex = 0;
  for (let call = DX_CALL.exec(message); call !== null; call = DX_CALL.exec(message)) {
    found.push(...message.slice(at, call.index).split(" "), call[0]);
    at = call.index + call[0].length;
  }
  found.push(...message.slice(at).split(" "));
  return found.filter((word) => word !== "");
}

/** `message` under `prefix`, broken at spaces so no line passes the screen's width. The prefix repeats
 * on every line, because the screenshot rule reads it as evidence rather than as something to paste,
 * and the continuations are indented so a wrapped line reads as one. A word longer than the room left
 * overflows: cutting it would lose an address, and a guide's renderer would cut it anyway. */
export function wrapped(prefix: string, message: string, width = SCREEN.columns): string[] {
  const indent = /^\s*/.exec(message)?.[0] ?? "";
  const rest = `${prefix}${indent}    `;
  const lines: string[] = [];
  let line: string | undefined;
  for (const word of words(message)) {
    if (line === undefined) line = `${prefix}${indent}${word}`;
    else if (`${line} ${word}`.length <= width) line = `${line} ${word}`;
    else {
      lines.push(line);
      line = `${rest}${word}`;
    }
  }
  return line === undefined ? [`${prefix}${indent}`] : lines.concat(line);
}

/** A continuation `wrapped` made: the same tag, then the four spaces it indents by on top of whatever
 * the message itself was indented. No message in a dep_plan section starts that far in, so this marks a
 * continuation and nothing else there. The one ASCII table drawn with `out.info` does, so do not run
 * `unwrap` over a transcript that holds one. */
const CONTINUATION = /^(\[[+!-]\]) {5,}(\S.*)$/;

/** A transcript with the lines `wrapped` broke rejoined. A reader sees sentences, so a check on what a
 * section says reads this instead of pinning where a break happened to fall. */
export function unwrap(transcript: string): string {
  const lines: string[] = [];
  for (const line of transcript.split("\n")) {
    const more = CONTINUATION.exec(line);
    const previous = lines[lines.length - 1];
    if (more && previous !== undefined && previous.indexOf(more[1]) === 0) lines[lines.length - 1] = `${previous} ${more[2]}`;
    else lines.push(line);
  }
  return lines.join("\n");
}

function tagged(tag: string, message: string): void {
  for (const line of wrapped(tag, message)) write(line);
}

export function info(message: string): void {
  tagged("[+] ", message);
}

export function warn(message: string): void {
  tagged("[!] ", message);
}

export function error(message: string): void {
  tagged("[-] ", message);
}

export function whyItMatters(line: string): void {
  write(`Why this matters for exploitation: ${line}`);
}

export function formatAddress(address: bigint, pointerSize: 4 | 8): string {
  const width = pointerSize === 8 ? 16 : 8;
  return `0x${address.toString(16).toUpperCase().padStart(width, "0")}`;
}

export function formatHexByte(byte: number): string {
  return `0x${(byte & 0xff).toString(16).toUpperCase().padStart(2, "0")}`;
}

export function table(columns: TableColumn[], rows: Array<Record<string, string>>): void {
  const hasVisibleValues = rows.some((row) =>
    columns.some((column) => {
      const value = row[column.key];
      return value !== undefined && value !== "";
    }),
  );

  if (rows.length === 0 || !hasVisibleValues) {
    return;
  }

  const widths = columns.map((column) => {
    const maxValueWidth = rows.reduce((max, row) => {
      const value = row[column.key] ?? "";
      return Math.max(max, visibleLength(value));
    }, 0);

    return Math.max(column.width ?? 0, column.header.length, maxValueWidth);
  });

  const render = (values: string[]) => values.map((value, i) => pad(stripDml(value), widths[i])).join("  ");

  write(render(columns.map((column) => column.header)));
  write(render(widths.map((width) => "-".repeat(width))));

  for (const row of rows) {
    write(render(columns.map((column) => row[column.key] ?? "")));
  }
}
