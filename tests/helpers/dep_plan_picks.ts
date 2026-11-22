// Each job of [4/7]: the registers its title says to keep, "(keep edi = the field address)", and its ">" pick.
export type Picked = { title: string; keep: string[]; pick?: { address: string; text: string; writes: string[] } };
export function picksOf(output: string): Picked[] {
  const section = output.slice(output.indexOf("=== [4/7]"), output.indexOf("=== [5/7]"));
  return section.split(/\n(?=  [a-z])/).slice(1).map((block) => {
    const keep = (/\(keep ([^)]*)\)/.exec(block.split("\n")[0])?.[1] ?? "").split(", ").filter(Boolean).map((entry) => entry.split(" ")[0]);
    const pick = /\n  > (0x[0-9A-F]{8})  (.*?)\s{2,}writes ([a-z ]+?)(?:,|\n|$)/.exec(block);
    return {
      title: block.split("\n")[0].trim(),
      keep,
      pick: pick ? { address: pick[1], text: pick[2].trim(), writes: pick[3] === "nothing" ? [] : pick[3].split(" ") } : undefined,
    };
  });
}
