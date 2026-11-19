"""Run tools/sc_builder.py on four configs and check each result.

  python check.py [--bundle ../../../dist/osed-legacy.js] [--out DIR]

Each case gets its own CONFIG block, must exit 0, print 0 bad bytes and 0 problems,
and leave a shellcode.bin with no bad byte. With --bundle, sc.builder from that
bundle must print a script that builds the same bytes as case a. With --out, each
case keeps its shellcode.bin and output in DIR/<case>/ for a run in the loader
(tests/manual/sc_writer/loader.c), which then writes the file named in the case.
"""

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
BUILDER = (HERE / "../../../tools/sc_builder.py").resolve()
RUN_DIST = HERE / "../sc_writer/run_dist.js"
CONFIG = re.compile(r"(# >>> CONFIG\n).*?(# <<< CONFIG\n)", re.S)

BAD_A = r'b"\x00\x0a\x0d\x20\x2f"'
CASES = {
    "a": (rf'''BADCHARS = {BAD_A}
MAX_SIZE = None
CALLS = [
    ("kernel32.dll", "WinExec", [s("cmd.exe /c echo ok > C:\\Users\\Public\\sc_builder_a.txt"), 0]),
]
EXIT = "terminate"
XOR_ENCODER = False
''', ["(xor key"]),
    "b": (r'''BADCHARS = b"\x00\x0a\x0d"
MAX_SIZE = 400
CALLS = [
    ("user32.dll", "MessageBoxA", [0, s("Hello from sc_builder"), s("OSED"), 0]),
]
EXIT = "exit"
XOR_ENCODER = False
''', ["LoadLibraryA", "MessageBoxA              user32.dll"]),
    "c": (r'''BADCHARS = b"\x00\x0a\x0d\x20"
MAX_SIZE = None
CALLS = [
    ("kernel32.dll", "CreateFileA", [s("C:\\Users\\Public\\sc_builder_c.txt"), 0x40000000, 0, 0, 2, 0x80, 0]),
    ("kernel32.dll", "WriteFile", [ref(1), s("builder ok"), 10, buf(4), 0]),
    ("kernel32.dll", "CloseHandle", [ref(1)]),
]
EXIT = "ret"
XOR_ENCODER = False
''', ["ref(1) = CreateFileA result", "scratch at ebp-"]),
    "d": (rf'''BADCHARS = {BAD_A}
MAX_SIZE = None
CALLS = [
    ("kernel32.dll", "WinExec", [s("cmd.exe /c echo ok > C:\\Users\\Public\\sc_builder_d.txt"), 0]),
]
EXIT = "terminate"
XOR_ENCODER = True
''', ["[!] XOR_ENCODER:", "page must be writable"]),
}
TEMPLATE_A = ["show=0", "winexec=cmd.exe /c echo ok > C:\\Users\\Public\\sc_builder_a.txt", "terminate", "bad=00 0A 0D 20 2F"]


def bad_set(literal):
    return {0} | set(eval(literal))


def run_builder(script, work):
    work.mkdir(parents=True, exist_ok=True)
    path = work / "sc_builder.py"
    path.write_text(script, encoding="utf-8", newline="\n")
    result = subprocess.run([sys.executable, str(path)], cwd=work, capture_output=True, text=True)
    (work / "output.txt").write_text(result.stdout + result.stderr, encoding="utf-8")
    return result, (work / "shellcode.bin").read_bytes() if (work / "shellcode.bin").exists() else b""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle")
    parser.add_argument("--out")
    options = parser.parse_args()
    source = BUILDER.read_text(encoding="utf-8").replace("\r\n", "\n")
    failures = []
    binaries = {}
    with tempfile.TemporaryDirectory() as temp:
        root = pathlib.Path(options.out).resolve() if options.out else pathlib.Path(temp)
        for name, (config, expected) in CASES.items():
            script, count = CONFIG.subn(lambda m: m.group(1) + config + m.group(2), source)
            assert count == 1, "CONFIG markers not found"
            result, code = run_builder(script, root / name)
            bad = bad_set(re.search(r"BADCHARS = (b\"[^\"]*\")", config).group(1))
            hits = [f"0x{i:04x}:{b:02x}" for i, b in enumerate(code) if b in bad]
            summary = [line for line in result.stdout.splitlines() if re.match(r"\[.\] (\d+ bytes|\d+ bad bytes|0 problems|\d+ problem)", line)]
            print(f"case {name}: exit {result.returncode}, {len(code)} bytes in shellcode.bin | {' | '.join(summary)}")
            if result.returncode != 0 or "[+] 0 bad bytes" not in result.stdout or "[+] 0 problems" not in result.stdout:
                failures.append(f"case {name}: exit {result.returncode}\n{result.stdout[-3000:]}{result.stderr}")
            if not code or hits:
                failures.append(f"case {name}: shellcode.bin is empty or holds bad bytes {hits[:8]}")
            for piece in expected:
                if piece not in result.stdout:
                    failures.append(f"case {name}: output lacks {piece!r}")
            binaries[name] = code

        if options.bundle:
            dist = subprocess.run(["node", str(RUN_DIST), str(pathlib.Path(options.bundle).resolve()), "builder", *TEMPLATE_A],
                                  capture_output=True, text=True, encoding="utf-8")
            marker = "Save everything below this line as sc_builder.py and run: python sc_builder.py\n"
            if dist.returncode != 0 or marker not in dist.stdout:
                failures.append(f"sc.builder from the bundle failed: {dist.stdout[-500:]}{dist.stderr}")
            else:
                result, code = run_builder(dist.stdout.split(marker, 1)[1], root / "a_from_sc_builder")
                same = code == binaries.get("a")
                print(f"sc.builder{tuple(TEMPLATE_A)}: exit {result.returncode}, {len(code)} bytes, same bytes as case a: {same}")
                if result.returncode != 0 or not same:
                    failures.append("sc.builder script from the bundle does not rebuild case a")

    for failure in failures:
        print("FAIL", failure)
    print("OK" if not failures else f"{len(failures)} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
