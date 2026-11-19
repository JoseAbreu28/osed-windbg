// Emits a WinDbg script that compiles every regex literal of a bundle in the debugger's own engine.
const fs = require("fs");
const ts = require("typescript");
const [bundle, out] = process.argv.slice(2);
const sf = ts.createSourceFile(bundle, fs.readFileSync(bundle, "utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
const found = [];
(function walk(n) {
  if (n.kind === ts.SyntaxKind.RegularExpressionLiteral) {
    const text = n.getText(); const cut = text.lastIndexOf("/");
    found.push({ line: sf.getLineAndCharacterOfPosition(n.getStart()).line + 1, source: text.slice(1, cut), flags: text.slice(cut + 1) });
  }
  if (ts.isNewExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "RegExp" && n.arguments && n.arguments.length && ts.isStringLiteral(n.arguments[0])) {
    const flags = n.arguments[1] && ts.isStringLiteral(n.arguments[1]) ? n.arguments[1].text : "";
    found.push({ line: sf.getLineAndCharacterOfPosition(n.getStart()).line + 1, source: n.arguments[0].text, flags });
  }
  ts.forEachChild(n, walk);
})(sf);
fs.writeFileSync(out, `"use strict";
var regexes = ${JSON.stringify(found)};
function initializeScript() {
  var bad = 0;
  regexes.forEach(function (r) {
    try { new RegExp(r.source, r.flags); }
    catch (e) { bad++; host.diagnostics.debugLog("REGEX FAIL line " + r.line + " /" + r.source + "/" + r.flags + " : " + e.message + String.fromCharCode(10)); }
  });
  host.diagnostics.debugLog("REGEX checked " + regexes.length + ", failed " + bad + String.fromCharCode(10));
  return [];
}
`);
