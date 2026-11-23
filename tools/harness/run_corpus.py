"""Run dep_plan over a target corpus on the lab clone, and grade each run by what the target did.

    py -3.12 tools/harness/run_corpus.py <manifest.json> [--only ID|NAME ...] [--ref] [--out DIR]

For each target the manifest lists:

  A. start the target on the clone, attach cdb x86 by PID, load dist/osed-legacy.js, send the target's
     own crash input, and run dep_plan with nothing but the bad chars and stage 1. The transcript is kept
     verbatim and graded against the screenshot rule (src/core/screenshot_rule.ts).
  B. paste the copy blocks of [1/7] to [7/7] into one Python file under OFFSET and BADCHARS, the way the
     user would, put a marker shellcode where [7/7] leaves its shellcode hole, and run it. Any other hole
     stops the file, and that is recorded as the tool's failure.
  C. start the target again under cdb with a breakpoint on each DEP API, fire the payload, and decide by
     observation: the marker file appeared, or the chain reached the API, or neither, and then where the
     process faulted.

--ref replaces A and B with the lab's own reference exploit, which grades the target, not the tool: a
target its reference cannot exploit on the clone tells nothing about dep_plan.

cdb stops on a first-chance access violation, and C records the process where it stops. A target whose
exploit runs through an exception, an SEH overwrite whose fault is the trigger, is marked in the manifest
with "through_exception": true, and only for such a target C passes first-chance access violations on to
the program (sxd av). A second chance still stops it. Every other target keeps the default, because one
that faults and never recovers is dead, and forgiving that fault would hide it.

The manifest, its adapters and every result live outside this repository, because they name course labs.
The manifest's "holdout" list names the targets kept back to judge readiness; this runner refuses any of
them, and refuses a manifest that has no holdout list at all.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DIST = REPO / "dist" / "osed-legacy.js"
CLONE_IP = "192.168.30.150"
APIS = ("VirtualAlloc", "VirtualProtect", "WriteProcessMemory")
PLAN_TIMEOUT = 30 * 60
FIRE_TIMEOUT = 60


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Guest:
    """The clone, through vmctl. Every process it kills is one this run started, by PID."""

    def __init__(self, cfg, work):
        sys.path.insert(0, cfg["lab_root"])
        import vmctl_dev  # noqa: F401  selects the clone before vmctl is used
        import vmctl
        if vmctl.GUEST_IP != CLONE_IP:
            raise SystemExit(f"refusing to run: vmctl points at {vmctl.GUEST_IP}, not the clone {CLONE_IP}")
        self.vm = vmctl
        self.dir = cfg["guest_work"]
        self.cdb = cfg["cdb"]
        self.work = work
        self.started = set()
        self.vm.mkdir(self.dir)

    def path(self, name):
        return f"{self.dir}\\{name}"

    def push_text(self, text, name):
        local = self.work / name
        local.write_bytes(text.replace("\r\n", "\n").replace("\n", "\r\n").encode())
        self.vm.push(str(local), self.path(name))
        return self.path(name)

    def pull_text(self, name):
        local = self.work / name
        local.unlink(missing_ok=True)
        self.vm.guest("CopyFileFromGuestToHost", self.path(name), str(local), check=False)
        return local.read_text(errors="replace").replace(chr(13), "") if local.exists() else ""

    def batch(self, lines, name, wait=True):
        """cmd.exe has no escape for a quote inside /c, so anything quoted travels in a .cmd file."""
        self.vm.cmd(self.push_text("\n".join(["@echo off", *lines, ""]), name), wait=wait)

    def processes(self):
        rows = {}
        for line in self.vm.guest("listProcessesInGuest", check=False).stdout.splitlines():
            if line.startswith("pid="):
                rows[int(line.split(",")[0].split("=")[1])] = line.rsplit("cmd=", 1)[1].strip().lower()
        return rows

    def kill(self, pid):
        if pid in self.started:
            self.vm.guest("killProcessInGuest", str(pid), check=False)
            self.started.discard(pid)

    def kill_all(self):
        for pid in sorted(self.started):
            self.kill(pid)

    def listener(self, port):
        self.vm.delete(self.path("netstat.txt"))
        self.batch([f"netstat -ano -p tcp > {self.path('netstat.txt')}"], "netstat.cmd")
        for line in self.pull_text("netstat.txt").splitlines():
            m = re.match(rf"\s*TCP\s+0\.0\.0\.0:{port}\s+\S+\s+LISTENING\s+(\d+)", line)
            if m:
                return int(m.group(1))
        return None

    def port_open(self, port, timeout):
        end = time.time() + timeout
        while time.time() < end:
            try:
                socket.create_connection((CLONE_IP, port), timeout=2).close()
                return True
            except OSError:
                time.sleep(1)
        return False


class Failed(Exception):
    """Where a run stopped, whose failure it is, and what was seen."""

    def __init__(self, stage, owner, detail):
        super().__init__(detail)
        self.stage, self.owner, self.detail = stage, owner, detail


def start_target(guest, target, lab_root):
    """Starts the target fresh and returns the PID that owns its port."""
    port = target["port"]
    if target.get("service"):
        guest.batch([f'sc stop "{target["service"]}" > nul 2>&1'], "svc.cmd")
        end = time.time() + 30
        while time.time() < end and guest.port_open(port, 1):
            time.sleep(2)
        guest.batch([f'sc start "{target["service"]}" > nul 2>&1'], "svc.cmd")
    else:
        if guest.port_open(port, 1):
            pid = guest.listener(port)
            raise Failed("start", "harness", f"port {port} is already held by pid {pid} ({guest.processes().get(pid)}), which this run did not start")
        lab = Path(lab_root) / target["lab"]
        spec = json.loads((lab / "lab.json").read_text())
        staging = f"C:\\Users\\osed\\labs-v2\\{target['lab']}"
        guest.vm.mkdir("C:\\Users\\osed\\labs-v2")
        guest.vm.mkdir(staging)
        for module in spec["modules"]:
            built = lab / "build" / module["name"]
            if not built.exists():
                raise Failed("deploy", "target", f"{module['name']} is not built")
            guest.vm.push(str(built), f"{staging}\\{module['name']}")
        exe = f"{staging}\\{target['main']}"
        # Windows drops inbound traffic for a new program until a rule names it.
        guest.batch([f'netsh advfirewall firewall delete rule name=all program="{exe}" > nul 2>&1',
                     f'netsh advfirewall firewall add rule name="osed harness {target["main"]}" dir=in action=allow program="{exe}" enable=yes profile=any > nul 2>&1'],
                    "firewall.cmd")
        guest.vm.start(exe)
    if not guest.port_open(port, 120):
        raise Failed("start", "target", f"port {port} never opened")
    pid = guest.listener(port)
    if pid is None:
        raise Failed("start", "harness", f"port {port} answers but netstat shows no LISTENING row")
    if not target.get("service"):
        guest.started.add(pid)
    return pid


def stop_target(guest, target, pid):
    if target.get("service"):
        guest.batch([f'sc stop "{target["service"]}" > nul 2>&1'], "svc.cmd")
    elif pid is not None:
        guest.kill(pid)


def under_cdb(guest, pid, commands, tag, arm_timeout=90):
    """Attaches cdb to pid and runs one ;-joined command line. Returns once the line says it is armed."""
    for name in (f"{tag}.out", f"{tag}.done"):
        guest.vm.delete(guest.path(name))
    cf = guest.push_text("; ".join(commands) + "\n", f"{tag}.cf")
    before = set(guest.processes())
    guest.batch([f'"{guest.cdb}" -p {pid} -cf {cf} > {guest.path(tag + ".out")} 2>&1', f"echo x > {guest.path(tag + '.done')}"],
                f"{tag}.cmd", wait=False)
    end = time.time() + arm_timeout
    while time.time() < end:
        time.sleep(3)
        if mark(guest.pull_text(f"{tag}.out"), "HARNESS_ARMED") >= 0:
            break
    else:
        raise Failed("attach", "harness", f"cdb never armed on pid {pid}: {guest.pull_text(tag + '.out')[-300:]!r}")
    for new_pid, name in guest.processes().items():
        if new_pid not in before and name in ("cdb.exe", "cmd.exe", "conhost.exe"):
            guest.started.add(new_pid)


def wait_done(guest, tag, timeout, also=None):
    end = time.time() + timeout
    while time.time() < end:
        if guest.vm.exists(guest.path(f"{tag}.done")):
            return True
        if also and also():
            return True
        time.sleep(3)
    return False


def mark(text, name):
    """Where a .echo marker printed. cdb echoes the command line first, so only a line of its own counts."""
    m = re.search(rf"^{name}$", text.replace("\r", ""), flags=re.M)
    return m.end() if m else -1


def between(text, start, end):
    a = mark(text, start)
    if a < 0:
        return ""
    rest = text[a:]
    b = mark(rest, end)
    return rest[:b - len(end) if b >= 0 else None]


def plan(guest, target, adapters, run_dir, checker):
    """Phase A: the dep_plan run. Returns the transcript and its parsed sections."""
    pid = start_target(guest, target, adapters.LAB_ROOT)
    try:
        commands = [f".scriptload {guest.path('osed-legacy.js')}", ".echo HARNESS_ARMED", "g", ".echo HARNESS_CRASH", "r",
                    ".echo HARNESS_PLAN", f'dx @$osed().dep_plan("{target["badchars"]}", 1)', ".echo HARNESS_END", "q"]
        under_cdb(guest, pid, commands, "plan")
        crash = adapters.crash(target)
        try:
            adapters.deliver(target, crash)
        except OSError as error:
            (run_dir / "crash_send.txt").write_text(repr(error))
        finished = wait_done(guest, "plan", PLAN_TIMEOUT)
        log = guest.pull_text("plan.out")
        (run_dir / "cdb_plan.log").write_text(log, encoding="utf-8")
    finally:
        guest.kill_all()
        stop_target(guest, target, pid)
    if mark(log, "HARNESS_CRASH") < 0:
        raise Failed("crash", "harness", "the crash input never broke into the debugger")
    regs = between(log, "HARNESS_CRASH", "HARNESS_PLAN")
    eip = re.search(r"eip=([0-9a-f]{8})", regs)
    transcript = between(log, "HARNESS_PLAN", "HARNESS_END")
    transcript = transcript[transcript.find("=== dx @$osed().dep_plan("):] if "=== dx @$osed().dep_plan(" in transcript else transcript
    (run_dir / "transcript.txt").write_text(transcript, encoding="utf-8")
    if not finished or mark(log, "HARNESS_END") < 0:
        raise Failed("dep_plan", "tool", f"dep_plan did not finish in {PLAN_TIMEOUT // 60} minutes")
    graded = json.loads(subprocess.run(["node", str(checker), str(run_dir / "transcript.txt")], capture_output=True, text=True, check=True).stdout)
    return {"crash_eip": eip.group(1) if eip else None, "transcript": transcript, **graded}


def route_of(sections):
    echo = sections[0]["title"] if sections else ""
    verdict = next((s for s in sections if s["name"] == "Verdict"), None)
    stops = [s for s in sections if s["title"].startswith("STOP")]
    last_call = None
    for s in sections:
        for line in s["lines"]:
            m = re.search(r"every choice written out: (dx @\$osed\(\)\.dep_plan\(.*\))", line)
            if m:
                last_call = m.group(1)
    call = last_call or echo
    m = re.match(r"dx @\$osed\(\)\.dep_plan\((.*)\)$", call)
    args = json.loads(f"[{m.group(1)}]") if m else []
    return {
        "call": call,
        "api": args[0] if args else None,
        "modules": args[1] if len(args) > 1 else None,
        "style": args[3] if len(args) > 3 else None,
        "verdict": " ".join(verdict["lines"]) if verdict else None,
        "stop": " ".join(stops[-1]["lines"]) if stops else None,
    }


def assemble(target, sections, shellcode, stage=1):
    """The user's file: his two measured values, then every copy block in order, the marker in the hole."""
    blocks = {s["name"]: s["block"] for s in sections if re.match(r"\[\d/7\]", s["name"]) and s["separated"]}
    missing = [f"[{n}/7]" for n in (1, 2, 4, 5, 6, 7) if f"[{n}/7]" not in blocks]
    if missing:
        raise Failed("assemble", "tool", f"no copy block in {', '.join(missing)}")
    bad = bytes.fromhex(target["badchars"].replace(" ", ""))
    lines = [f"OFFSET = {target['offset']}", f"BADCHARS = {bad!r}", f"SHELLCODE = bytes.fromhex({shellcode.hex()!r})", ""]
    for n in range(1, 8):
        lines += blocks.get(f"[{n}/7]", []) + [""]
    text = "\n".join(lines)
    text, count = re.subn(r'^(\s*)shellcode = hole\("shellcode"\)$', r"\1shellcode = SHELLCODE", text, flags=re.M)
    if count != 1:
        raise Failed("assemble", "tool", f"[7/7] has {count} shellcode holes, not one")
    return text + f"\nimport sys\nopen(sys.argv[1], 'wb').write(payload{stage}())\n"


def gadgets_in(sections):
    """NAME = 0x... lines in [4/7]'s block: what the chain jumps through, for naming where it stopped."""
    found = {}
    for s in sections:
        if s["name"] == "[4/7]":
            for line in s["block"]:
                m = re.match(r"([A-Z][A-Z0-9_]*)\s*=\s*0x([0-9A-Fa-f]{8})\s*#\s*(.*)", line)
                if m:
                    found[int(m.group(2), 16)] = f"{m.group(1)} ({m.group(3).strip()})"
    return found


def modules_in(log):
    """Every image cdb reported loading, as (low, high). A return address outside all of them was not
    pushed by any code the process loaded, so no call the program made could have left it."""
    return [(int(a, 16), int(b, 16)) for a, b in re.findall(r"^ModLoad: ([0-9a-f]{8}) ([0-9a-f]{8})", log, flags=re.M)]


def in_module(address, images):
    return any(low <= address < high for low, high in images)


def fire(guest, target, adapters, run_dir, deliver, marker, gadgets):
    """Phase C: the target under cdb with every DEP API broken on, the payload sent, the marker watched."""
    guest.vm.delete(marker)
    pid = start_target(guest, target, adapters.LAB_ROOT)
    try:
        bps = [f'bp KERNELBASE!{api} ".echo HARNESS_API {api}; dds esp L6; gc"' for api in APIS]
        passes = ["sxd av"] if target.get("through_exception") else []
        under_cdb(guest, pid, [*passes, *bps, ".echo HARNESS_ARMED", "g", ".echo HARNESS_FAULT", "r", "dds esp-10 L10", ".echo HARNESS_END", "q"], "fire")
        note = None
        try:
            note = deliver()
        except Exception as error:  # the adapter's send raising is itself an observation
            note = f"send raised {error!r}"
        landed = wait_done(guest, "fire", FIRE_TIMEOUT, also=lambda: guest.vm.exists(marker))
        time.sleep(3)
        landed = guest.vm.exists(marker)
        log = guest.pull_text("fire.out")
        (run_dir / "cdb_fire.log").write_text(log, encoding="utf-8")
    finally:
        guest.kill_all()
        stop_target(guest, target, pid)
    images = modules_in(log)
    hits = []
    for block in re.split(r"^HARNESS_API ", log, flags=re.M)[1:]:
        api = block.split()[0]
        words = re.findall(r"^([0-9a-f]{8})\s+([0-9a-f]{8})", block, flags=re.M)
        if words:
            esp, ret = int(words[0][0], 16), int(words[0][1], 16)
            # Whose call this is, by the return address. A chain gadget names itself. The staged style's
            # return address is the sled on the stack and no gadget, so what settles it there is that no
            # image holds that address: nothing the program loaded could have pushed it. The near-ESP
            # clause keeps the styles whose frame is the stack the call was reached on.
            from_chain = ret in gadgets or not in_module(ret, images) or abs(ret - esp) < 0x10000
            hits.append({"api": api, "esp": f"{esp:08x}", "return": f"{ret:08x}", "from_chain": from_chain,
                         "return_is": gadgets.get(ret) or (None if in_module(ret, images) else "not in any loaded module")})
    fault = between(log, "HARNESS_FAULT", "HARNESS_END")
    eip = re.search(r"eip=([0-9a-f]{8})", fault)
    stopped = int(eip.group(1), 16) if eip else None
    near = next((name for address, name in gadgets.items() if stopped is not None and 0 <= stopped - address < 16), None)
    return {"marker": landed, "note": note, "api_hits": hits, "fault_eip": f"{stopped:08x}" if stopped is not None else None,
            "fault_in": near, "exception": (re.findall(r"^\([0-9a-f]+\.[0-9a-f]+\): (.*)$", log, flags=re.M) or [None])[-1]}


def claim_of(sections):
    """What [7/7] told the user about the file: its first evidence line."""
    seventh = next((s for s in sections if s["name"] == "[7/7]"), None)
    return seventh["evidence"][0] if seventh and seventh["evidence"] else None


def judge(seen, dirty, dirty_text):
    if seen["marker"]:
        return {"status": "PASS", "stage": "observe", "owner": "-", "detail": "marker landed"}
    where = f"faulted at {seen['fault_eip']}" + (f" in {seen['fault_in']}" if seen["fault_in"] else "")
    if dirty:
        return {"status": "FAIL", "stage": "payload", "owner": "tool", "detail": f"the payload carries bad chars {', '.join(dirty_text)}; {where}"}
    reached = [hit for hit in seen["api_hits"] if hit["from_chain"]]
    if reached:
        return {"status": "FAIL", "stage": "after the API", "owner": "tool",
                "detail": f"reached {reached[-1]['api']} (return {reached[-1]['return']}), no marker; {where}"}
    return {"status": "FAIL", "stage": "chain", "owner": "tool", "detail": f"never reached a DEP API; {where}"}


def run_target(guest, target, adapters, out, checker, ref_mode):
    run_dir = out / target["lab"]
    run_dir.mkdir(parents=True, exist_ok=True)
    result = graded(guest, target, adapters, run_dir, checker, ref_mode)
    (run_dir / "result.json").write_text(json.dumps(result, indent=2))
    return result


def graded(guest, target, adapters, run_dir, checker, ref_mode):
    result = {"id": target.get("id"), "target": target["lab"], "class": target["class"], "main": target["main"]}
    try:
        reason = adapters.not_attempted(target, ref_mode)
        if reason:
            return {**result, "status": "NOT ATTEMPTED", "stage": "-", "owner": "target", "detail": reason}
        if ref_mode:
            ref = adapters.reference(target)
            seen = fire(guest, target, adapters, run_dir, ref["exploit"], ref["marker"], {})
            ok = seen["marker"]
            return {**result, "status": "PASS" if ok else "FAIL", "stage": "observe", "owner": "-" if ok else "target",
                    "detail": f"reference exploit: {'marker landed' if ok else 'no marker'}; {seen['note']}", "seen": seen}

        planned = plan(guest, target, adapters, run_dir, checker)
        result["crash_eip"] = planned["crash_eip"]
        result["violations"] = planned["violations"]
        result["route"] = route_of(planned["sections"])
        result["ground_truth_api"] = target.get("api")

        if target["class"] == "B":
            stop = result["route"]["stop"] or ""
            refused = bool(stop) and "chain" not in (result["route"]["verdict"] or "")
            leak = "leak" in stop.lower()
            status = "PASS" if refused and leak else "FAIL"
            detail = (f"refused: {stop[:160]}" if refused else f"built a chain on a target with nothing fixed: {result['route']['verdict']}")
            if refused and not leak:
                detail += " (the refusal never sends the user to a leak)"
            return {**result, "status": status, "stage": "dep_plan", "owner": "-" if status == "PASS" else "tool", "detail": detail}

        if result["route"]["stop"]:
            raise Failed("dep_plan", "tool", f"refused a class A target: {result['route']['stop'][:200]}")

        shellcode = adapters.marker_shellcode(target)
        script = assemble(target, planned["sections"], shellcode)
        (run_dir / "exploit.py").write_text(script, encoding="utf-8")
        made = subprocess.run([sys.executable, "-I", str(run_dir / "exploit.py"), str(run_dir / "payload.bin")],
                              capture_output=True, text=True, timeout=120)
        if made.returncode != 0:
            raise Failed("payload", "tool", (made.stderr.strip() or made.stdout.strip()).splitlines()[-1][:200])
        payload = (run_dir / "payload.bin").read_bytes()
        bad = bytes.fromhex(target["badchars"].replace(" ", ""))
        dirty = sorted({payload.index(b) for b in bad if b in payload})
        result["payload_bytes"] = len(payload)
        result["payload_bad_chars"] = [f"{payload[i]:02x}@{i} in dword {payload[i - i % 4:i - i % 4 + 4][::-1].hex()}" for i in dirty]
        result["claimed"] = claim_of(planned["sections"])

        gadgets = gadgets_in(planned["sections"])
        seen = fire(guest, target, adapters, run_dir, lambda: adapters.deliver(target, payload), adapters.marker_path(target), gadgets)
        result["seen"] = seen
        verdict = judge(seen, dirty, result["payload_bad_chars"])
        # Never a pass: a hand fix the user would have to know to make, measured to size the failure.
        gap = target.get("post_eip_gap")
        if gap and not seen["marker"]:
            cut = target["offset"] + 4
            fixed = payload[:cut] + b"J" * gap + payload[cut:]
            result["diagnostic"] = {"change": f"{gap} junk bytes after the first chain dword, where the target's ret {gap} lands ESP",
                                    **judge(fire(guest, target, adapters, run_dir, lambda: adapters.deliver(target, fixed),
                                                 adapters.marker_path(target), gadgets), [], [])}
        return {**result, **verdict}
    except Failed as failed:
        return {**result, "status": "FAIL", "stage": failed.stage, "owner": failed.owner, "detail": failed.detail}
    except Exception as error:  # a harness bug must cost one target, not the corpus
        return {**result, "status": "FAIL", "stage": "harness", "owner": "harness", "detail": repr(error)[:300]}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--only", nargs="*", default=[])
    parser.add_argument("--ref", action="store_true", help="grade the targets with their reference exploits")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text())
    holdout = set(manifest.get("holdout") or [])
    if not holdout:
        raise SystemExit("refusing to run: the manifest names no holdout, so nothing would stay unseen")
    asked = [name for name in args.only if name in holdout]
    if asked:
        raise SystemExit(f"refusing to run held-out targets: {', '.join(asked)}")
    cfg = manifest["_harness"]
    # --only takes a target id or a lab name. Ids are what this repo and GOAL.md may say out loud, so a
    # run command written down anywhere uses them; lab names stay for the manifest and the lab tree.
    named = set(args.only)
    targets = [t for t in manifest["targets"]
               if t["lab"] not in holdout and (not named or t["lab"] in named or t.get("id") in named)]
    if named and not targets:
        raise SystemExit(f"--only matched no target: {', '.join(sorted(named))}")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = args.out or (args.manifest.parent / "runs" / f"{stamp}{'-ref' if args.ref else ''}")
    work = out / "_work"
    work.mkdir(parents=True, exist_ok=True)
    checker = work / "screenshot_cli.cjs"
    subprocess.run(["node", str(REPO / "node_modules" / "esbuild" / "bin" / "esbuild"), str(REPO / "tools" / "harness" / "screenshot_cli.ts"),
                    "--bundle", "--platform=node", "--format=cjs", f"--outfile={checker}", "--log-level=warning"], check=True)
    commit = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    sha = hashlib.sha256(DIST.read_bytes()).hexdigest()

    adapters = load_module(args.manifest.parent / cfg["adapters"], "harness_adapters")
    adapters.LAB_ROOT = cfg["lab_root"]
    guest = Guest(cfg, work)
    guest.vm.push(str(DIST), guest.path("osed-legacy.js"))
    adapters.bind(guest.vm)

    results = []
    for target in targets:
        began = time.time()
        print(f"[{datetime.now():%H:%M:%S}] {target['lab']} ...", flush=True)
        result = run_target(guest, target, adapters, out, checker, args.ref)
        result["seconds"] = round(time.time() - began)
        results.append(result)
        print(f"    {result['status']}: {result['stage']} / {result['owner']}: {result['detail']}", flush=True)
        (out / "results.json").write_text(json.dumps({"commit": commit, "dist_sha256": sha, "ref": args.ref, "results": results}, indent=2))
    print(f"results: {out / 'results.json'}")


if __name__ == "__main__":
    main()
