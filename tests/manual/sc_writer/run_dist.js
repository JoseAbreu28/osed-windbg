// Loads a built bundle with a stub host and prints what one osed call writes.
// node run_dist.js <dist file> <sc method> [args...]   e.g. node run_dist.js ../../../dist/osed.js template winexec=calc.exe exit
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const [bundle, method, ...args] = process.argv.slice(2);
let output = "";
const context = {
  host: { diagnostics: { debugLog: (text) => { output += text; } }, currentProcess: { Is64Bit: false, Modules: [] } },
};
context.globalThis = context;
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.resolve(bundle), "utf8"), context);
context.initializeScript();
output = "";
const ok = context.osed.sc[method](...args);
process.stdout.write(output);
process.exitCode = ok === false ? 1 : 0;
