"""Run tools/sc_builder.py on each config below and check every result.

  python check.py [--bundle ../../../dist/osed-legacy.js] [--out DIR]

Each case gets its own CONFIG block, must exit 0, print 0 bad bytes and 0 problems,
and leave a shellcode.bin with no bad byte. A case also names the text its output must
hold, must not hold, and, in `distinct`, how many different captures a pattern may have,
which is how one frame offset per buffer is checked without naming the offset.
SAME_BYTES names the pairs that must
assemble to identical bytes, which is how the fluent form and the older literal
CALLS form are kept equivalent. REJECTED names the configs that must fail, with the
message each one has to print. With --bundle, sc.builder from that bundle must print
a script that builds the same bytes as case a. With --out, each case keeps its
shellcode.bin and output in DIR/<case>/ for a run in the loader
(tests/manual/sc_writer/loader.c), which then writes the file named in the case.
"""

import argparse
import collections
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
BUILDER = (HERE / "../../../tools/sc_builder.py").resolve()
RUN_DIST = HERE / "../sc_writer/run_dist.js"
CONFIG = re.compile(r"(# >>> CONFIG\n).*?(# <<< CONFIG\n)", re.S)

Case = collections.namedtuple("Case", "config expect absent distinct")
Case.__new__.__defaults__ = ((), {})

BAD_A = r'b"\x00\x0a\x0d\x20\x2f"'
BAD_LAB = r'b"\x00\x0a\x0d\x2e\x3a\x5c"'  # the T05 and T07 transport: '.', ':' and '\' are bad
BAD_EBP = r'b"\x00\x0a\x0d\x45"'  # 45 is the ModRM of every [ebp-disp8] store, so the body needs the encoder
BAD_POP = r'b"\x00\x20\x2b\x5e"'  # T10's bad chars: 5e is the one-byte pop esi opcode
FILE_C = r"C:\\Users\\Public\\sc_builder_c.txt"
CASES = {
    "a": Case(rf'''BADCHARS = {BAD_A}
MAX_SIZE = None
EXIT = "terminate"
XOR_ENCODER = False

k32.WinExec(s("cmd.exe /c echo ok > C:\\Users\\Public\\sc_builder_a.txt"), SW_HIDE)
''', ["(xor key"]),
    "a_literal": Case(rf'''BADCHARS = {BAD_A}
MAX_SIZE = None
CALLS = [
    ("kernel32.dll", "WinExec", [s("cmd.exe /c echo ok > C:\\Users\\Public\\sc_builder_a.txt"), 0]),
]
EXIT = "terminate"
XOR_ENCODER = False
''', ["(xor key"]),
    "b": Case(r'''BADCHARS = b"\x00\x0a\x0d"
MAX_SIZE = 400
EXIT = "exit"
XOR_ENCODER = False

dll("user32.dll").MessageBoxA(NULL, s("Hello from sc_builder"), s("OSED"), MB_OK)
''', ["LoadLibraryA", "MessageBoxA              user32.dll"]),
    "c": Case(rf'''BADCHARS = b"\x00\x0a\x0d\x20"
MAX_SIZE = None
EXIT = "ret"
XOR_ENCODER = False

handle = k32.CreateFileA(s("{FILE_C}"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
k32.WriteFile(handle, s("builder ok"), 10, buf(4), NULL)
k32.CloseHandle(handle)
''', ["ref(1) = CreateFileA result", "scratch at ebp-"]),
    "c_literal": Case(rf'''BADCHARS = b"\x00\x0a\x0d\x20"
MAX_SIZE = None
CALLS = [
    ("kernel32.dll", "CreateFileA", [s("{FILE_C}"), 0x40000000, 0, 0, 2, 0x80, 0]),
    ("kernel32.dll", "WriteFile", [ref(1), s("builder ok"), 10, buf(4), 0]),
    ("kernel32.dll", "CloseHandle", [ref(1)]),
]
EXIT = "ret"
XOR_ENCODER = False
''', ["ref(1) = CreateFileA result", "scratch at ebp-"]),
    "c_inserted": Case(rf'''BADCHARS = b"\x00\x0a\x0d\x20"
MAX_SIZE = None
EXIT = "ret"
XOR_ENCODER = False

k32.CreateDirectoryA(s("C:\\Users\\Public\\scb"), NULL)
handle = k32.CreateFileA(s("{FILE_C}"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
k32.WriteFile(handle, s("builder ok"), 10, buf(4), NULL)
k32.CloseHandle(handle)
''', ["ref(2) = CreateFileA result", "arg1 = ref(2)"], ["CreateDirectoryA result", "ref(1)"]),
    "lab_badchars": Case(rf'''BADCHARS = {BAD_LAB}
MAX_SIZE = None
EXIT = "terminate"
XOR_ENCODER = False

k32.WinExec(s("cmd.exe /c echo ok> C:\\Users\\Public\\sc_builder_lab.txt"), SW_HIDE)
k32.Sleep(2000)
''', ["PEB walk and resolver registers:", "(xor key"], ["base ebx,"]),
    "pop_badchar": Case(rf'''BADCHARS = {BAD_POP}
MAX_SIZE = None
EXIT = "terminate"
XOR_ENCODER = False

k32.WinExec(s("cmd.exe /c echo ok> C:\\Users\\Public\\sc_builder_pop.txt"), SW_HIDE)
k32.Sleep(2000)
''', ["pop esi, whose 0x5e opcode is a bad char"], ["bad byte 0x5e"],
        {r"this is pop (\w+), whose": 1}),
    "buffers": Case(rf'''BADCHARS = b"\x00\x0a\x0d\x20"
MAX_SIZE = None
EXIT = "ret"
XOR_ENCODER = False

path = buf(260)
k32.GetTempPathA(260, path)
k32.lstrcatA(path, s("sc_builder_e.txt"))
handle = k32.CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
k32.WriteFile(handle, s("builder buffers ok"), 18, buf(4), NULL)
k32.CloseHandle(handle)
''', ["buf(260) #1", "buf(4) #2"], (), {
        r"= buf\(260\) #1, scratch at (ebp-0x[0-9a-f]+)": 1,
        r"= buf\(4\) #2, scratch at (ebp-0x[0-9a-f]+)": 1,
        r"scratch at (ebp-0x[0-9a-f]+)": 2,
    }),
    "d": Case(rf'''BADCHARS = {BAD_A}
MAX_SIZE = None
EXIT = "terminate"
XOR_ENCODER = True

k32.WinExec(s("cmd.exe /c echo ok > C:\\Users\\Public\\sc_builder_d.txt"), SW_HIDE)
''', ["[!] XOR_ENCODER:", "page must be writable"]),
    "cdecl": Case(rf'''BADCHARS = {BAD_LAB}
MAX_SIZE = None
EXIT = "exit"
XOR_ENCODER = False
CDECL = ("OnlyInConfig",)

text = buf(64)
pid = k32.GetCurrentProcessId()
dll("user32.dll").wsprintfA(text, s("sc_builder pid=%u"), pid)
dll("user32.dll").OnlyInConfig(text, 1)
dll("user32.dll").OnlyAtCallSite.cdecl(text, 2)
k32.Sleep(100)
k32.lstrlenA(text)
''', ["wsprintfA is cdecl, so the caller drops the arguments",
      "drop 3 argument(s) of wsprintfA",
      "OnlyInConfig is cdecl", "OnlyAtCallSite is cdecl",
      "Sleep pops its own arguments", "lstrlenA pops its own arguments"],
        ["drop 1 argument(s) of Sleep", "drop 1 argument(s) of lstrlenA"],
        {r"drop \d+ argument\(s\) of (\w+)": 3}),
    "xor_needed": Case(rf'''BADCHARS = {BAD_EBP}
MAX_SIZE = None
EXIT = "terminate"
XOR_ENCODER = True

k32.WinExec(s("cmd.exe /c echo ok > C:\\Users\\Public\\sc_builder_f.txt"), SW_HIDE)
k32.Sleep(2000)
''', ["[!] XOR_ENCODER:", "which is what the encoder is for"]),
    "debug": Case(rf'''BADCHARS = {BAD_LAB}
MAX_SIZE = None
EXIT = "terminate"
XOR_ENCODER = False
DEBUG = True

k32.WinExec(s("cmd.exe /c echo ok > C:\\Users\\Public\\sc_builder_g.txt"), SW_HIDE)
k32.Sleep(2000)
''', ["DEBUG: kernel32.dll!WinExec came back 0",
      "DEBUG: kernel32.dll!Sleep came back 0",
      "DEBUG: kernel32.dll!TerminateProcess came back 0"], (),
        {r"int3 +; DEBUG: (\S+) came back 0": 3}),
}
SAME_BYTES = [("a", "a_literal"), ("c", "c_literal")]
REJECTED = {
    "mixed": (rf'''BADCHARS = {BAD_A}
MAX_SIZE = None
CALLS = [
    ("kernel32.dll", "WinExec", [s("calc.exe"), 1]),
]
EXIT = "terminate"
XOR_ENCODER = False

k32.WinExec(s("notepad.exe"), SW_HIDE)
''', "CONFIG mixes both call forms"),
    "xor_impossible": (rf'''BADCHARS = b"\x00\x0a\x0d\x45\xc3"
MAX_SIZE = None
EXIT = "terminate"
XOR_ENCODER = True

k32.WinExec(s("calc.exe"), SW_HIDE)
''', "no XOR key keeps both the stub and the encoded body clean"),
    "debug_needs_int3": (rf'''BADCHARS = b"\x00\x0a\x0d\xcc"
MAX_SIZE = None
EXIT = "terminate"
XOR_ENCODER = False
DEBUG = True

k32.WinExec(s("calc.exe"), SW_HIDE)
''', "DEBUG needs the int3 byte 0xcc, which BADCHARS forbids"),
    "cdecl_one_string": (rf'''BADCHARS = {BAD_A}
MAX_SIZE = None
EXIT = "terminate"
XOR_ENCODER = False
CDECL = "MyPrintf"

k32.WinExec(s("calc.exe"), SW_HIDE)
''', "CDECL takes export names"),
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


def with_config(source, config):
    script, count = CONFIG.subn(lambda m: m.group(1) + config + m.group(2), source)
    assert count == 1, "CONFIG markers not found"
    return script


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
        for name, case in CASES.items():
            result, code = run_builder(with_config(source, case.config), root / name)
            bad = bad_set(re.search(r"BADCHARS = (b\"[^\"]*\")", case.config).group(1))
            hits = [f"0x{i:04x}:{b:02x}" for i, b in enumerate(code) if b in bad]
            summary = [line for line in result.stdout.splitlines() if re.match(r"\[.\] (\d+ bytes|\d+ bad bytes|0 problems|\d+ problem)", line)]
            print(f"case {name}: exit {result.returncode}, {len(code)} bytes in shellcode.bin | {' | '.join(summary)}")
            if result.returncode != 0 or "[+] 0 bad bytes" not in result.stdout or "[+] 0 problems" not in result.stdout:
                failures.append(f"case {name}: exit {result.returncode}\n{result.stdout[-3000:]}{result.stderr}")
            if not code or hits:
                failures.append(f"case {name}: shellcode.bin is empty or holds bad bytes {hits[:8]}")
            for piece in case.expect:
                if piece not in result.stdout:
                    failures.append(f"case {name}: output lacks {piece!r}")
            for piece in case.absent:
                if piece in result.stdout:
                    failures.append(f"case {name}: output still holds {piece!r}")
            for pattern, wanted in case.distinct.items():
                found = set(re.findall(pattern, result.stdout))
                print(f"case {name}: {pattern} -> {sorted(found)}")
                if len(found) != wanted:
                    failures.append(f"case {name}: {pattern} matched {sorted(found)}, wanted {wanted} distinct")
            binaries[name] = code

        for left, right in SAME_BYTES:
            same = binaries.get(left) and binaries[left] == binaries.get(right)
            print(f"{left} and {right}: same bytes: {bool(same)}")
            if not same:
                failures.append(f"{left} and {right} assemble to different bytes")

        for name, (config, message) in REJECTED.items():
            result, code = run_builder(with_config(source, config), root / name)
            said = message in result.stdout
            print(f"case {name}: exit {result.returncode}, says {message!r}: {said}")
            if result.returncode == 0 or not said:
                failures.append(f"case {name}: exit {result.returncode}, wanted a non-zero exit and {message!r}\n{result.stdout[-1000:]}{result.stderr}")

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
