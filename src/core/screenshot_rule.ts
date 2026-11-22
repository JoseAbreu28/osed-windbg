// The screenshot rule from GOAL.md, as a check over what dep_plan printed. Pure: it reads the transcript
// text and nothing else, so the tests run it on fixture output and the corpus harness on real captures.

/**
 * One screen at the guide's font. The guides draw the WinDbg command pane in 15 px Consolas with a 7 px
 * line gap, 22 px a row (lab/v2/guides/Workflows/headless.py). A 1080 px display leaves about 880 px of
 * command pane under the title bar, the ribbon and the input line: 40 rows. The same renderer clamps a
 * figure to 130 columns and cuts every longer line at 130, so a character past it never reaches the guide.
 */
export const SCREEN = { rows: 40, columns: 130 };

export const SEPARATOR = "# ------------------ copy into your exploit ------------------";

export type Rule = "echo" | "height" | "width" | "python-above-separator" | "no-separator" | "evidence-below-separator";
export type Violation = { section: string; rule: Rule; detail: string };

const TOP = /^=== (\[\d+\/\d+\]|DEP |STOP|Verdict|dx @\$osed\(\)\.dep_plan\()/;
const EVIDENCE_PREFIX = /^(\[[+!-]\] |=== |dx @\$osed\(\))/;
// A statement someone would paste: an import, a def or class, or an assignment at column 0. Table rows
// and the register map are indented or carry no `=`, so they never match.
const PYTHON = /^(from [\w.]+ import |import [\w.]+|def \w+\(|class \w+[(:]|[A-Za-z_][\w.]*(\[[^\]]*\])?\s*[-+*|]?=\s*\S)/;
const APIS = ["VirtualAlloc", "VirtualProtect", "WriteProcessMemory"];
const STYLES = ["pushad", "skeleton"];

const trimEnd = (lines: string[]): string[] => {
  let end = lines.length;
  while (end > 0 && lines[end - 1].trim() === "") end -= 1;
  return lines.slice(0, end);
};

/** A top-level section: its title, what a screenshot of it shows, and the lines below its separator. */
export type Section = { title: string; name: string; lines: string[]; evidence: string[]; block: string[]; separated: boolean };

export function sections(transcript: string): Section[] {
  const raw: Array<{ title: string; lines: string[] }> = [];
  for (const line of transcript.replace(/\r/g, "").split("\n")) {
    if (TOP.test(line)) raw.push({ title: line.slice(4, -4), lines: [] });
    else if (raw.length > 0) raw[raw.length - 1].lines.push(line);
  }
  return raw.map(({ title, lines: all }) => {
    const lines = trimEnd(all);
    const cut = lines.indexOf(SEPARATOR);
    return {
      title,
      name: /^\[\d+\/\d+\]/.exec(title)?.[0] ?? title.split(" ")[0],
      lines,
      evidence: trimEnd(cut < 0 ? lines : lines.slice(0, cut)),
      block: cut < 0 ? [] : lines.slice(cut + 1),
      separated: cut >= 0,
    };
  });
}

// The echo is a dx call; its arguments are JSON literals or numbers, so they parse as a JSON array.
function echoArgs(title: string): unknown[] | undefined {
  const match = /^dx @\$osed\(\)\.dep_plan\((.*)\)$/.exec(title);
  if (!match) return undefined;
  try {
    return JSON.parse(`[${match[1]}]`) as unknown[];
  } catch {
    return undefined;
  }
}

function echoViolation(first: Section | undefined, stopped: boolean): string | undefined {
  if (!first) return "the transcript holds no dep_plan section at all";
  const args = echoArgs(first.title);
  if (!args) return `the first line is not a dep_plan call: ${first.title.slice(0, 80)}`;
  const [api, modules, badchars, style, stage] = args;
  if (typeof badchars !== "string" || typeof stage !== "number") return `the call does not write the bad chars and the stage: ${first.title}`;
  // A run that stopped made no choice of API, module or style, so it cannot write one out.
  if (stopped) return undefined;
  const unwritten = [
    APIS.indexOf(String(api)) < 0 ? `api ${JSON.stringify(api)}` : undefined,
    typeof modules !== "string" || modules.trim() === "" ? `module ${JSON.stringify(modules)}` : undefined,
    STYLES.indexOf(String(style)) < 0 ? `style ${JSON.stringify(style)}` : undefined,
  ].filter((item): item is string => item !== undefined);
  return unwritten.length > 0 ? `the echoed call leaves a choice unwritten: ${unwritten.join(", ")}` : undefined;
}

export function screenshotViolations(transcript: string): Violation[] {
  const all = sections(transcript);
  const found: Violation[] = [];
  const stopped = all.some((section) => section.title.indexOf("STOP") === 0);
  const echo = echoViolation(all[0], stopped);
  if (echo) found.push({ section: "echo", rule: "echo", detail: echo });

  for (const section of all.slice(1)) {
    const { name, lines, evidence, block } = section;

    const height = evidence.length + 1;
    if (height > SCREEN.rows) found.push({ section: name, rule: "height", detail: `${height} lines of evidence, the screen holds ${SCREEN.rows}` });

    const wide = [section.title.length + 8, ...lines.map((line) => line.length)];
    const over = wide.filter((width) => width > SCREEN.columns);
    if (over.length > 0) found.push({ section: name, rule: "width", detail: `${over.length} line(s) past ${SCREEN.columns} columns, the widest ${Math.max(...over)}` });

    const pasted = evidence.filter((line) => !EVIDENCE_PREFIX.test(line) && PYTHON.test(line));
    if (pasted.length > 0) found.push({ section: name, rule: "python-above-separator", detail: `${pasted.length} Python line(s) above the separator, first: ${pasted[0].slice(0, 60)}` });

    if (/^\[\d+\/\d+\]/.test(section.title) && !section.separated
      && !evidence.some((line) => /^\[[+-]\] (Nothing to copy here|Skipped)/.test(line))) {
      found.push({ section: name, rule: "no-separator", detail: "no copy separator, no \"Nothing to copy here\" and no \"Skipped\" line" });
    }

    const stray = block.filter((line) => EVIDENCE_PREFIX.test(line));
    if (stray.length > 0) found.push({ section: name, rule: "evidence-below-separator", detail: `${stray.length} evidence line(s) inside the copy block, first: ${stray[0].slice(0, 60)}` });
  }
  return found;
}
