"""Check that check.py's regression cases fail against an older tools/sc_builder.py.

  python catches.py [revision] [case...]

A regression case earns its place only when it fails on the code that had the defect.
This takes the builder from a git revision, the commit before the fixes by default, runs
the named cases of check.py against it, and reports what each one catches. It exits 1 when
a case named in GUARDS passes on the old builder, because then it guards nothing.

The cases not named in GUARDS are the ones that always worked, so they are expected to
pass on both. Run check.py for the ordinary question of whether the current builder is
correct. Run this one after adding a case, to see that the case can fail.
"""

import importlib.util
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = (HERE / "../../..").resolve()
CONFIG = re.compile(r"(# >>> CONFIG\n).*?(# <<< CONFIG\n)", re.S)

# The commit before the buffer, register, encoder, cdecl, DEBUG and pop work.
BASE = "8b05365"

# The cases that must fail on BASE, and the defect each one holds shut.
GUARDS = {
    "buffers": "every use of a buf() allocated a fresh frame offset",
    "lab_badchars": "the resolver kept the module base on ebx, whose ModRM byte is 5c",
    "pop_badchar": "the resolver's two pop esi had one form only, so a bad 5e failed the build",
    "xor_needed": "the plain body's bad bytes failed a build the encoder had made clean",
    "cdecl": "every call assumed the API drops its own arguments",
    "debug": "a lookup that came back 0 was only found when the shellcode called address 0",
}


def load_check():
    spec = importlib.util.spec_from_file_location("sc_builder_check", HERE / "check.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def reasons_it_fails(case, output, code):
    """Why check.py would reject this output. Empty means check.py would accept it."""
    found = []
    if code != 0:
        found.append(f"exit {code}")
    if "[+] 0 bad bytes" not in output:
        found.append("bad bytes")
    if "[+] 0 problems" not in output:
        found.append("problems")
    found += [f"no {piece!r}" for piece in case.expect if piece not in output]
    found += [f"still {piece!r}" for piece in case.absent if piece in output]
    for pattern, wanted in case.distinct.items():
        hits = set(re.findall(pattern, output))
        if len(hits) != wanted:
            found.append(f"{len(hits)} distinct for {pattern}, wanted {wanted}")
    return found


def main():
    check = load_check()
    args = sys.argv[1:]
    takes_revision = bool(args) and args[0] not in check.CASES
    revision = args[0] if takes_revision else BASE
    wanted = args[1:] if takes_revision else args
    wanted = wanted or list(GUARDS)
    old = subprocess.run(["git", "show", f"{revision}:tools/sc_builder.py"],
                         cwd=REPO, capture_output=True, text=True)
    if old.returncode != 0:
        sys.exit(f"cannot read tools/sc_builder.py at {revision}: {old.stderr.strip()}")
    source = old.stdout.replace("\r\n", "\n")

    failures = []
    with tempfile.TemporaryDirectory() as temp:
        for name in wanted:
            if name not in check.CASES:
                sys.exit(f"unknown case {name!r}, pick from {' '.join(check.CASES)}")
            case = check.CASES[name]
            script, count = CONFIG.subn(lambda m: m.group(1) + case.config + m.group(2), source)
            if count != 1:
                sys.exit(f"no CONFIG markers in tools/sc_builder.py at {revision}")
            work = pathlib.Path(temp) / name
            work.mkdir(parents=True)
            (work / "sc_builder.py").write_text(script, encoding="utf-8", newline="\n")
            done = subprocess.run([sys.executable, "sc_builder.py"], cwd=work,
                                  capture_output=True, text=True)
            found = reasons_it_fails(case, done.stdout + done.stderr, done.returncode)
            if found:
                print(f"case {name}: catches {revision}: {'; '.join(found)}")
            else:
                print(f"case {name}: passes on {revision}")
                if name in GUARDS:
                    failures.append(f"case {name} passes on {revision}, so it does not hold shut "
                                    f"that {GUARDS[name]}")

    for failure in failures:
        print("FAIL", failure)
    print("OK" if not failures else f"{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
