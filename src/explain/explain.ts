import * as out from "../core/output";
import { stripDml } from "../core/output";
import { DxResult } from "../core/dx_result";
import { categoryForName } from "../commands/help";
import { EXPLANATIONS, type ExplainArg, type ExplainEntry, type ExplainResult } from "./catalog";

type LastResult = { success: boolean; findings: unknown[] };
type Leaf = (...args: unknown[]) => unknown;

export type ExplainState = {
  getLast: () => LastResult | undefined;
  setLast: (result: LastResult | undefined) => void;
};

type ExplainCall = {
  args: unknown[];
  /** True when the command ran, so an argument left out took its default. */
  ran: boolean;
  value?: unknown;
  last?: LastResult;
};

const VALUE_COLUMN = 23;
const WRAP_WIDTH = 78;
const INDENT = " ".repeat(VALUE_COLUMN);

const entriesByPath = new Map<string, ExplainEntry>();
for (const entry of EXPLANATIONS) {
  for (const path of [entry.name, ...(entry.aliases ?? [])]) entriesByPath.set(path, entry);
}

export function findExplanation(path: string): ExplainEntry | undefined {
  return entriesByPath.get(path) ?? entriesByPath.get(path.toLowerCase());
}

/**
 * dx shows every key of the object it displays, so each section is a key. dx hides keys that
 * start with two underscores, which keeps the title out of the listing.
 */
export class Explanation {
  public constructor(title: string, sections: Array<[string, string]>) {
    Object.defineProperty(this, "__title", { value: title, enumerable: false });
    for (const [label, text] of sections) (this as unknown as Record<string, string>)[label] = text;
  }

  public toString(): string {
    return `=== explain: ${(this as unknown as { __title: string }).__title} ===`;
  }
}

/** A primitive result cannot carry .explain, so it travels in this object instead. */
export class CommandOutcome {
  public constructor(value: unknown, success: boolean | undefined, explain: () => Explanation, field: "success" | "value" = "success") {
    const self = this as unknown as Record<string, unknown>;
    if (typeof value === "boolean" && field === "success") self.success = value;
    else {
      if (success !== undefined) self.success = success;
      if (value !== undefined) self.value = value;
    }
    Object.defineProperty(this, "explain", { get: explain, enumerable: false, configurable: true });
  }

  public toString(): string {
    const self = this as unknown as Record<string, unknown>;
    return "value" in self ? String(self.value) : String(self.success);
  }
}

function hex(value: number): string {
  return value < 0 ? `-0x${(-value).toString(16).toUpperCase()}` : `0x${value.toString(16).toUpperCase()}`;
}

function toPlainNumber(value: unknown): unknown {
  const int64 = value as { asNumber?: () => number } | null;
  return typeof value === "object" && value !== null && typeof int64?.asNumber === "function" ? int64.asNumber() : value;
}

function formatValue(raw: unknown, kind: ExplainArg["kind"]): string | undefined {
  const value = toPlainNumber(raw);
  if (value === undefined || value === null) return undefined;
  if (typeof value === "number") {
    if (kind === "number") return String(value);
    return kind === "address" || Math.abs(value) > 0xffff ? hex(value) : String(value);
  }
  if (typeof value === "bigint") return hex(Number(value));
  if (typeof value === "string") return value === "" ? "none" : stripDml(value);
  if (Array.isArray(value)) {
    const bytes = value.every((item) => typeof item === "number" && item >= 0 && item <= 0xff);
    if (bytes) return value.length === 0 ? "none" : value.map((item) => (item as number).toString(16).toUpperCase().padStart(2, "0")).join(" ");
    return value.map((item) => formatValue(item, kind) ?? "").join(", ");
  }
  return String(value);
}

function formatCallArg(raw: unknown): string {
  const value = toPlainNumber(raw);
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return Math.abs(value) > 0xffff ? hex(value) : String(value);
  return String(value);
}

function readPath(source: unknown, path: string): unknown {
  let current = source;
  for (const key of path.split(".")) {
    if (current === null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

function firstRows(value: unknown): Array<Record<string, string>> {
  if (!(value instanceof DxResult)) return [];
  const rows: Array<Record<string, string>> = [];
  for (let index = 0; index < value.length; index += 1) rows.push(value.rows[index] as unknown as Record<string, string>);
  return rows.filter((row) => !("Error" in row));
}

/**
 * A result field is read from the first row of a dx table, or from the first finding of the
 * command result. "Name@Property" picks the Value of the row whose Property is Name, the layout
 * of the property tables. "#count" is the number of rows or findings.
 */
function resultValue(result: ExplainResult, call: ExplainCall): string | undefined {
  const rows = firstRows(call.value);
  const findings = call.last?.findings ?? (Array.isArray(call.value) ? call.value : []);
  if (result.field === "#count") {
    if (rows.length > 0) return String(rows.length);
    return call.last || Array.isArray(call.value) ? String(findings.length) : undefined;
  }
  const property = /^(.+)@Property$/.exec(result.field);
  if (property) {
    const row = rows.find((candidate) => candidate.Property === property[1]);
    return row ? formatValue(row.Value, result.kind) : undefined;
  }
  if (rows.length > 0 && result.field in rows[0]) return formatValue(rows[0][result.field], result.kind);
  const source = findings[0] ?? (call.value instanceof DxResult ? undefined : call.value);
  return formatValue(readPath(source, result.field), result.kind);
}

function meaningOf(arg: ExplainArg, token: string): string | undefined {
  if (!arg.values) return undefined;
  const lower = token.toLowerCase();
  for (const [key, meaning] of Object.entries(arg.values)) {
    const prefix = key.endsWith("=") || key.endsWith(" ");
    if (prefix ? lower.startsWith(key.toLowerCase()) : lower === key.toLowerCase()) return meaning;
  }
  return undefined;
}

type Fills = Map<string, string>;

function argumentFills(entry: ExplainEntry, args: unknown[], ran: boolean): { fills: Fills; lines: string[] } {
  const fills: Fills = new Map();
  const lines: string[] = [];
  entry.args.forEach((arg, index) => {
    const given = arg.rest ? args.slice(index) : args[index] === undefined ? [] : [args[index]];
    const shown = given.map((value) => formatValue(value, arg.kind)).filter((value): value is string => value !== undefined);
    const optional = arg.optional ? `optional${arg.default ? `, default ${arg.default}` : ""}` : "required";
    if (shown.length === 0) {
      if (arg.default && ran) fills.set(arg.name, arg.default);
      lines.push(`<${arg.name}> (${optional}): ${arg.meaning}`);
      return;
    }
    fills.set(arg.name, shown.join(", "));
    if (arg.rest) {
      lines.push(`<${arg.name}>: ${arg.meaning}`);
      for (const token of shown) {
        const meaning = meaningOf(arg, token);
        lines.push(`  ${token}${meaning ? `: ${meaning}` : ""}`);
      }
      return;
    }
    const meaning = meaningOf(arg, shown[0]);
    lines.push(`<${arg.name}> = ${shown[0]}: ${arg.meaning}${meaning ? ` Here: ${meaning}` : ""}`);
  });
  if (lines.length === 0) lines.push("None.");
  return { fills, lines };
}

function fill(text: string, fills: Fills): string {
  return text.replace(/<([a-zA-Z][\w-]*)>/g, (match, name: string) => fills.get(name) ?? match);
}

function wrap(text: string): string {
  const lines: string[] = [];
  for (const paragraph of text.split("\n")) {
    const lead = /^\s*/.exec(paragraph)?.[0] ?? "";
    let line = "";
    for (const word of paragraph.trim().split(/\s+/)) {
      if (line && line.length + 1 + word.length > WRAP_WIDTH) {
        lines.push(line);
        line = `${lead}  ${word}`;
      } else {
        line = line ? `${line} ${word}` : `${lead}${word}`;
      }
    }
    lines.push(line);
  }
  return lines.join(`\n${INDENT}`);
}

export function buildExplanation(path: string, entry: ExplainEntry, call: ExplainCall): Explanation {
  const args = entry.positional ? entry.positional(call.args) : call.args;
  const { fills, lines } = argumentFills(entry, args, call.ran || call.args.length > 0);
  for (const result of entry.results ?? []) {
    const value = resultValue(result, call);
    if (value !== undefined) fills.set(result.name, value);
  }
  const results = (entry.results ?? []).map((result) => `<${result.name}>${fills.has(result.name) ? ` = ${fills.get(result.name)}` : ""}: ${result.meaning}`);
  const title = call.args.length > 0 ? `${path}(${call.args.map(formatCallArg).join(", ")})` : path;
  const sections: Array<[string, string]> = [
    ["What it does", wrap(fill(entry.what, fills))],
    ["How it works", wrap(fill(entry.how, fills))],
    ["When to use", wrap(fill(entry.when, fills))],
    ["Arguments", lines.map(wrap).join(`\n${INDENT}`)],
  ];
  if (results.length > 0) sections.push(["Results", results.map(wrap).join(`\n${INDENT}`)]);
  sections.push(
    ["Example", entry.example],
    ["Reading output", wrap(fill(entry.output, fills))],
    ["Report", fill(entry.report, fills)],
  );
  return new Explanation(title, sections);
}

function explanationFor(path: string, call: ExplainCall): Explanation {
  const entry = findExplanation(path);
  if (!entry) return new Explanation(path, [["What it does", `No explanation is registered for ${path}.`]]);
  try {
    return buildExplanation(path, entry, call);
  } catch (error) {
    return buildExplanation(path, entry, { args: call.args, ran: call.ran });
  }
}

/** Gives value an .explain getter, or wraps a primitive so it has one. */
export function withExplain(path: string, args: unknown[], value: unknown, last: LastResult | undefined): unknown {
  if (value instanceof Explanation) return value;
  const explain = () => explanationFor(path, { args, ran: true, value, last });
  if (value !== null && typeof value === "object") {
    try {
      Object.defineProperty(value, "explain", { get: explain, enumerable: false, configurable: true });
      return value;
    } catch (_error) {
      // A frozen object or a fixed explain key falls through to the wrapper.
    }
  }
  return new CommandOutcome(value, last?.success, explain, findExplanation(path)?.primitive);
}

/**
 * Explains path with the arguments given. A quick command also runs, silently and without
 * touching last_result(), so its real results fill the result placeholders.
 */
function explainWithArgs(path: string, args: unknown[], leaf: Leaf | undefined, state: ExplainState): Explanation {
  const entry = findExplanation(path);
  if (!entry || !entry.quick || !leaf || args.length === 0) return explanationFor(path, { args, ran: false });
  const saved = state.getLast();
  try {
    const value = out.quietly(() => leaf(...args));
    const after = state.getLast();
    return explanationFor(path, { args, ran: true, value, last: after !== saved ? after : undefined });
  } catch (_error) {
    return explanationFor(path, { args, ran: false });
  } finally {
    state.setLast(saved);
  }
}

const CATEGORY_ORDER = ["crash", "payload", "target", "seh", "rop", "shellcode", "pe-api", "strings", "format", "tools"];

function printIndex(): number {
  const groups = new Map<string, ExplainEntry[]>();
  for (const entry of EXPLANATIONS) {
    const category = categoryForName(entry.name);
    groups.set(category, [...(groups.get(category) ?? []), entry]);
  }
  out.section(`explain: ${EXPLANATIONS.length} commands`);
  out.print('Append .explain to any call: dx @$osed().sc.resolve("kernel32", "WinExec").explain');
  out.print('One command with placeholders: dx @$osed().explain("sc.resolve")');
  const order = [...CATEGORY_ORDER, ...[...groups.keys()].filter((key) => !CATEGORY_ORDER.includes(key))];
  for (const category of order) {
    const entries = groups.get(category);
    if (!entries) continue;
    out.print("");
    out.print(`[${category}]`);
    for (const entry of entries) {
      const aliases = entry.aliases?.length ? ` (also ${entry.aliases.join(", ")})` : "";
      out.print(`  ${entry.name.padEnd(21)} ${entry.summary}${aliases}`);
    }
  }
  return EXPLANATIONS.length;
}

function leafAt(api: Record<string, unknown>, path: string): Leaf | undefined {
  const value = readPath(api, path);
  return typeof value === "function" ? (value as Leaf) : undefined;
}

export function createExplainCommand(api: Record<string, unknown>, state: ExplainState): Leaf {
  return (...args: unknown[]) => {
    if (args.length === 0 || args[0] === undefined || args[0] === "") return printIndex() > 0;
    const path = String(args[0]).trim();
    const entry = findExplanation(path);
    if (!entry) {
      out.error(`No explanation for '${path}'. Run dx @$osed().explain() for the list.`);
      return false;
    }
    return explainWithArgs(path, args.slice(1), leafAt(api, path), state);
  };
}

function isNamespace(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && Object.getPrototypeOf(value) === Object.prototype;
}

/** Every callable leaf below api gains the "explain" first argument and an .explain on its result. */
export function wrapApi(api: Record<string, unknown>, state: ExplainState): void {
  const walk = (node: Record<string, unknown>, prefix: string): void => {
    for (const key of Object.keys(node)) {
      const value = node[key];
      const path = prefix ? `${prefix}.${key}` : key;
      if (typeof value === "function") {
        const leaf = value as Leaf;
        node[key] = (...args: unknown[]) => {
          if (args[0] === "explain") return explainWithArgs(path, args.slice(1), leaf, state);
          const before = state.getLast();
          const result = leaf(...args);
          const after = state.getLast();
          return withExplain(path, args, result, after !== before ? after : undefined);
        };
      } else if (isNamespace(value)) {
        walk(value, path);
      }
    }
  };
  walk(api, "");
}

export function apiLeafPaths(api: Record<string, unknown>): string[] {
  const paths: string[] = [];
  const walk = (node: Record<string, unknown>, prefix: string): void => {
    for (const key of Object.keys(node)) {
      const path = prefix ? `${prefix}.${key}` : key;
      if (typeof node[key] === "function") paths.push(path);
      else if (isNamespace(node[key])) walk(node[key] as Record<string, unknown>, path);
    }
  };
  walk(api, "");
  return paths;
}
