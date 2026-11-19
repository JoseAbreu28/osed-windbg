// Type-directed rewrite of bigint operations for engines without BigInt.
// Every expression whose operand is typed bigint is routed through the __bi
// runtime in legacy/runtime.js, which represents bigints as safe-integer Numbers.
const fs = require("fs");
const path = require("path");
const ts = require("typescript");

const K = ts.SyntaxKind;
const BINARY = new Map([
  [K.AmpersandToken, "and"],
  [K.BarToken, "or"],
  [K.CaretToken, "xor"],
  [K.LessThanLessThanToken, "shl"],
  [K.GreaterThanGreaterThanToken, "shr"],
  [K.SlashToken, "div"],
  [K.AsteriskToken, "mul"],
]);
const COMPOUND = new Map([
  [K.AmpersandEqualsToken, "and"],
  [K.BarEqualsToken, "or"],
  [K.CaretEqualsToken, "xor"],
  [K.LessThanLessThanEqualsToken, "shl"],
  [K.GreaterThanGreaterThanEqualsToken, "shr"],
  [K.SlashEqualsToken, "div"],
  [K.AsteriskEqualsToken, "mul"],
]);
const UNSUPPORTED = new Set([
  K.AsteriskAsteriskToken,
  K.AsteriskAsteriskEqualsToken,
  K.GreaterThanGreaterThanGreaterThanToken,
  K.GreaterThanGreaterThanGreaterThanEqualsToken,
]);

const key = (file) => path.resolve(file).replace(/\\/g, "/").toLowerCase();

function listTs(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return listTs(full);
    return entry.name.endsWith(".ts") ? [full] : [];
  });
}

function createLegacyTransformer(rootDir, dirs) {
  const configPath = path.join(rootDir, "tsconfig.json");
  const parsed = ts.getParsedCommandLineOfConfigFile(configPath, {}, { ...ts.sys, onUnRecoverableConfigFileDiagnostic() {} });
  const rootFiles = dirs.flatMap((dir) => listTs(path.join(rootDir, dir)));
  const program = ts.createProgram(rootFiles, parsed.options);
  const checker = program.getTypeChecker();
  const sources = new Map(program.getSourceFiles().map((sf) => [key(sf.fileName), sf]));
  const printer = ts.createPrinter({ newLine: ts.NewLineKind.LineFeed });

  const isBig = (node) => {
    const type = checker.getTypeAtLocation(node);
    const parts = type.isUnion() ? type.types : [type];
    return parts.some((part) => (part.flags & ts.TypeFlags.BigIntLike) !== 0);
  };

  const isGlobalBigInt = (node) => {
    if (node.text !== "BigInt") return false;
    const parent = node.parent;
    if (ts.isPropertyAccessExpression(parent) && parent.name === node) return false;
    if ((ts.isPropertyAssignment(parent) || ts.isPropertyDeclaration(parent) || ts.isMethodDeclaration(parent)) && parent.name === node) return false;
    const symbol = checker.getSymbolAtLocation(node);
    return !!symbol && (symbol.declarations || []).some((decl) => /[\\/]lib\.[^\\/]*\.d\.ts$/.test(decl.getSourceFile().fileName));
  };

  const where = (node) => {
    const sf = node.getSourceFile();
    const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart());
    return `${sf.fileName}:${line + 1}:${character + 1}`;
  };

  function transformer(context) {
    const f = context.factory;
    const call = (op, args) => f.createCallExpression(f.createPropertyAccessExpression(f.createIdentifier("__bi"), op), undefined, args);

    const visit = (node) => {
      if (ts.isBigIntLiteral(node)) {
        const value = BigInt(node.text.replace(/n$/, ""));
        if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < -BigInt(Number.MAX_SAFE_INTEGER)) {
          throw new Error(`${where(node)}: bigint literal ${node.text} does not fit the legacy 53-bit representation`);
        }
        return f.createNumericLiteral(`0x${value.toString(16)}`);
      }
      if (ts.isIdentifier(node) && isGlobalBigInt(node)) return f.createIdentifier("__bi");
      if (ts.isPrefixUnaryExpression(node) && node.operator === K.TildeToken && isBig(node.operand)) {
        throw new Error(`${where(node)}: '~' on bigint is not supported by the legacy build`);
      }
      if (ts.isBinaryExpression(node) && (isBig(node.left) || isBig(node.right))) {
        const kind = node.operatorToken.kind;
        if (UNSUPPORTED.has(kind)) throw new Error(`${where(node)}: '${node.operatorToken.getText()}' on bigint is not supported by the legacy build`);
        const left = ts.visitNode(node.left, visit);
        const right = ts.visitNode(node.right, visit);
        if (BINARY.has(kind)) return call(BINARY.get(kind), [left, right]);
        if (COMPOUND.has(kind)) return f.createAssignment(left, call(COMPOUND.get(kind), [left, right]));
        return f.updateBinaryExpression(node, left, node.operatorToken, right);
      }
      return ts.visitEachChild(node, visit, context);
    };
    return (sf) => ts.visitNode(sf, visit);
  }

  return {
    has: (file) => sources.has(key(file)),
    transformFile(file) {
      const sf = sources.get(key(file));
      if (!sf) throw new Error(`legacy transform: ${file} is not part of the program`);
      const result = ts.transform(sf, [transformer]);
      try {
        return printer.printFile(result.transformed[0]);
      } finally {
        result.dispose();
      }
    },
  };
}

module.exports = { createLegacyTransformer };
