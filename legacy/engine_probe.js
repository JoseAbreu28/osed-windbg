// Lists the builtins and syntax a WinDbg JavaScript engine lacks. In the debugger: .scriptload <this file>,
// then read the PROBE lines. legacy/engine.js records the result for classic WinDbg 10.0.19041.
"use strict";
var G = Function("return this")();
var apis = [
 "String.prototype.matchAll","String.prototype.replaceAll","String.prototype.at","String.prototype.padStart","String.prototype.padEnd",
 "String.prototype.trimStart","String.prototype.trimEnd","String.prototype.trimLeft","String.prototype.trimRight","String.prototype.startsWith","String.prototype.endsWith",
 "String.prototype.includes","String.prototype.repeat","String.prototype.codePointAt","String.prototype.normalize","String.prototype.isWellFormed","String.raw","String.fromCodePoint",
 "Array.prototype.flat","Array.prototype.flatMap","Array.prototype.includes","Array.prototype.find","Array.prototype.findIndex","Array.prototype.findLast","Array.prototype.findLastIndex",
 "Array.prototype.at","Array.prototype.fill","Array.prototype.copyWithin","Array.prototype.entries","Array.prototype.keys","Array.prototype.values","Array.prototype.toSorted","Array.prototype.toReversed","Array.prototype.with",
 "Array.from","Array.of","Object.entries","Object.values","Object.fromEntries","Object.assign","Object.getOwnPropertyDescriptors","Object.hasOwn","Object.groupBy",
 "Number.isInteger","Number.isSafeInteger","Number.parseInt","Number.parseFloat","Number.EPSILON","Number.MAX_SAFE_INTEGER","Number.isNaN","Number.isFinite",
 "Math.trunc","Math.sign","Math.log2","Math.log10","Math.clz32","Math.imul","Math.fround","Math.hypot","Math.cbrt",
 "Map","Set","WeakMap","WeakSet","WeakRef","Symbol","Symbol.iterator","Symbol.asyncIterator","Symbol.matchAll","Promise","Promise.prototype.finally","Promise.allSettled","Promise.any",
 "globalThis","BigInt","Proxy","Reflect","Uint8Array","Uint8Array.from","Uint8Array.of","Uint8Array.prototype.slice","Uint8Array.prototype.fill","Uint8Array.prototype.includes","Uint8Array.prototype.indexOf","Uint8Array.prototype.at","Uint32Array","Int32Array","Float64Array","DataView","ArrayBuffer.prototype.slice","BigInt64Array",
 "Map.prototype.forEach","Set.prototype.forEach","Map.prototype.entries","Atomics","SharedArrayBuffer","TextEncoder","TextDecoder","structuredClone","queueMicrotask","Intl","JSON","Date.now",
 "Array.prototype.sort","Object.getOwnPropertySymbols","Object.setPrototypeOf","Function.prototype.bind","Error.prototype.cause","AggregateError"
];
function get(path) {
  var parts = path.split("."), cur = parts[0] === "globalThis" ? (typeof globalThis === "undefined" ? undefined : globalThis) : G[parts[0]];
  for (var i = 1; i < parts.length && cur !== undefined && cur !== null; i++) cur = cur[parts[i]];
  return cur;
}
var syntax = {
  "async fn": "async function f(){ await 1; }", "generator": "function* g(){ yield 1; }", "for-of": "for (var x of [1]) {}",
  "object spread": "var a={b:1}; var c={...a};", "object rest": "var {a, ...r} = {a:1,b:2};", "optional catch": "try {} catch {}",
  "nullish": "var a = null ?? 1;", "optional chain": "var a = null; a?.b;", "exponent": "var a = 2 ** 3;", "class": "class A { m(){} }",
  "class field": "class A { x = 1; }", "async iter": "async function* g(){ for await (var x of []) {} }", "let const": "let a=1; const b=2;",
  "template": "var a = `x${1}`;", "destructuring": "var [a,b] = [1,2]; var {c} = {c:1};", "default params": "function f(a=1){}", "arrow": "var f = () => 1;",
  "regex s": "/a.b/s", "regex u": "/a/u", "regex y": "/a/y", "regex named group": "/(?<x>a)/", "regex lookbehind": "/(?<=a)b/", "regex unicode prop": "/\p{L}/u",
  "numeric sep": "var a = 1_000;", "bigint literal": "var a = 1n;", "logical assign": "var a; a ??= 1;"
};
function initializeScript() {
  var miss = [], have = 0;
  apis.forEach(function (p) { var v; try { v = get(p); } catch (e) { v = undefined; } if (v === undefined) miss.push(p); else have++; });
  host.diagnostics.debugLog("PROBE APIS present " + have + " missing " + miss.length + "\n");
  miss.forEach(function (p) { host.diagnostics.debugLog("PROBE MISSING API " + p + "\n"); });
  Object.keys(syntax).forEach(function (k) {
    try { Function(syntax[k]); host.diagnostics.debugLog("PROBE SYNTAX ok " + k + "\n"); }
    catch (e) { host.diagnostics.debugLog("PROBE SYNTAX FAIL " + k + " : " + e.message + "\n"); }
  });
  try { var it = [1,2][Symbol.iterator](); host.diagnostics.debugLog("PROBE array iterator ok " + it.next().value + "\n"); } catch (e) { host.diagnostics.debugLog("PROBE array iterator FAIL\n"); }
  try { var m = "a1b2".match(/\d/g); host.diagnostics.debugLog("PROBE match g " + m.join(",") + "\n"); } catch (e) {}
  return [];
}
