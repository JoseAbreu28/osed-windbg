// What the classic WinDbg 10.0.19041 JavaScript engine (Chakra) lacks, and a scan of a built bundle for it.
// The lists come from legacy/engine_probe.js run inside cdb x86 10.0.19041.685. Rerun that probe before
// editing them. An API marked polyfilled must be defined by legacy/runtime.js; tests/legacy_engine.test.ts
// checks that against a sandbox stripped to this list.
const ts = require("typescript");

const MISSING_APIS = [
  { path: "String.prototype.matchAll", polyfilled: true },
  { path: "String.prototype.trimStart", polyfilled: true },
  { path: "String.prototype.trimEnd", polyfilled: true },
  { path: "Array.prototype.flat", polyfilled: true },
  { path: "Array.prototype.flatMap", polyfilled: true },
  { path: "Object.fromEntries", polyfilled: true },
  { path: "String.prototype.replaceAll" },
  { path: "String.prototype.at" },
  { path: "String.prototype.isWellFormed" },
  { path: "Array.prototype.findLast" },
  { path: "Array.prototype.findLastIndex" },
  { path: "Array.prototype.at" },
  { path: "Array.prototype.toSorted" },
  { path: "Array.prototype.toReversed" },
  { path: "Array.prototype.with" },
  { path: "Uint8Array.prototype.at" },
  { path: "Object.hasOwn" },
  { path: "Object.groupBy" },
  { path: "Promise.prototype.finally" },
  { path: "Promise.allSettled" },
  { path: "Promise.any" },
  { path: "Symbol.asyncIterator" },
  { path: "Symbol.matchAll" },
  { path: "WeakRef" },
  { path: "BigInt64Array" },
  { path: "TextEncoder" },
  { path: "TextDecoder" },
  { path: "structuredClone" },
  { path: "queueMicrotask" },
  { path: "AggregateError" },
];

// Also missing, but not scanned: BigInt (legacy/bigint_transform.js rewrites it) and globalThis
// (the bundle footer guards it with typeof). The stripped sandbox in the tests removes both.
const ALSO_MISSING = ["BigInt", "globalThis"];

// Regex syntax the engine rejects at compile time. esbuild leaves regexes as written.
const REGEX_FEATURES = [
  { name: "named group", test: (source) => /\(\?<[A-Za-z_$]/.test(source) || /\\k</.test(source) },
  { name: "lookbehind", test: (source) => /\(\?<[=!]/.test(source) },
  { name: "dotAll flag", test: (_source, flags) => flags.includes("s") },
];

function split(path) {
  const parts = path.split(".");
  if (parts.length === 1) return { kind: "global", name: parts[0] };
  if (parts[1] === "prototype") return { kind: "method", owner: parts[0], name: parts[2] };
  return { kind: "static", owner: parts[0], name: parts[1] };
}

const unpolyfilled = MISSING_APIS.filter((api) => !api.polyfilled).map((api) => ({ ...api, ...split(api.path) }));
const methods = new Map();
for (const api of unpolyfilled.filter((a) => a.kind === "method")) {
  methods.set(api.name, [...(methods.get(api.name) || []), api.path]);
}
const statics = new Map(unpolyfilled.filter((a) => a.kind === "static").map((a) => [`${a.owner}.${a.name}`, a.path]));
const globals = new Set(unpolyfilled.filter((a) => a.kind === "global").map((a) => a.name));

// Method calls are matched by name alone: the receiver's type is unknown in the bundle, so `x.at(0)`
// is flagged whatever x is. Rename a local method rather than allow-list it.
function findEngineGaps(source, fileName = "bundle.js") {
  const sf = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  const hits = [];
  const hit = (node, what) => hits.push({ line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1, what, text: node.getText(sf).slice(0, 80) });
  const checkRegex = (node, source, flags) => {
    for (const feature of REGEX_FEATURES) if (feature.test(source, flags)) hit(node, `regex ${feature.name}`);
  };
  (function walk(node) {
    if (ts.isPropertyAccessExpression(node)) {
      const name = node.name.text;
      const owner = ts.isIdentifier(node.expression) ? node.expression.text : undefined;
      if (owner && statics.has(`${owner}.${name}`)) hit(node, statics.get(`${owner}.${name}`));
      else if (methods.has(name) && ts.isCallExpression(node.parent) && node.parent.expression === node) hit(node, methods.get(name).join(" / "));
    } else if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression) && methods.has(node.argumentExpression.text)) {
      hit(node, methods.get(node.argumentExpression.text).join(" / "));
    } else if (ts.isIdentifier(node) && globals.has(node.text) && !isPropertyName(node)) {
      hit(node, node.text);
    } else if (node.kind === ts.SyntaxKind.RegularExpressionLiteral) {
      const text = node.getText(sf);
      const cut = text.lastIndexOf("/");
      checkRegex(node, text.slice(1, cut), text.slice(cut + 1));
    } else if (ts.isNewExpression(node) || ts.isCallExpression(node)) {
      const args = node.arguments || [];
      if (ts.isIdentifier(node.expression) && node.expression.text === "RegExp" && args.length && ts.isStringLiteralLike(args[0])) {
        checkRegex(node, args[0].text, args[1] && ts.isStringLiteralLike(args[1]) ? args[1].text : "");
      }
    }
    ts.forEachChild(node, walk);
  })(sf);
  return hits;
}

function isPropertyName(node) {
  const parent = node.parent;
  return (ts.isPropertyAccessExpression(parent) && parent.name === node) || (ts.isPropertyAssignment(parent) && parent.name === node);
}

function formatGaps(hits) {
  return hits.map((h) => `  line ${h.line}: ${h.what}  ${h.text}`).join("\n");
}

module.exports = { MISSING_APIS, ALSO_MISSING, REGEX_FEATURES, findEngineGaps, formatGaps };
