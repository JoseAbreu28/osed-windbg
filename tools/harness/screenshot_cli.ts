// Bundled by run_corpus.py with esbuild and run under node, so the harness grades a real capture with the
// same code the tests pin. Prints {violations, sections} as JSON for one transcript file.
import { readFileSync } from "fs";
import { screenshotViolations, sections } from "../../src/core/screenshot_rule";

const transcript = readFileSync(process.argv[2], "utf8");
process.stdout.write(JSON.stringify({ violations: screenshotViolations(transcript), sections: sections(transcript) }));
