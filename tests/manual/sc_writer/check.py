"""Cross-check the sc.* shellcode writers against Keystone, using a built bundle.

  python check.py ../../../dist/osed-legacy.js

For push_string and call_frame, every printed line is assembled with Keystone and
must match the bytes the command printed, and no byte may be a bad char. For
template, the generated build_sc.py must run, report 0 bad bytes, and keep its
per-line offset map equal to the whole assembly.
"""

import pathlib
import subprocess
import sys
import tempfile

from keystone import Ks, KS_ARCH_X86, KS_MODE_32

HERE = pathlib.Path(__file__).resolve().parent
BUNDLE = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else HERE / "../../../dist/osed.js").resolve()
KS = Ks(KS_ARCH_X86, KS_MODE_32)
failures = []


def run(method, *args):
    result = subprocess.run(["node", str(HERE / "run_dist.js"), str(BUNDLE), method, *args],
                            capture_output=True, text=True, encoding="utf-8")
    return result.returncode, result.stdout


def bad_set(text):
    return {0} | {int(token, 16) for token in text.replace(",", " ").split()}


def check_lines(label, output, bad):
    checked = 0
    for line in output.splitlines():
        if "  ; " not in line or line.startswith(("CODE", "    ")):
            continue
        asm, rest = line.split("  ; ", 1)
        printed = rest.split("  ")[0].strip()
        if printed == "??":
            continue
        encoding, _ = KS.asm(asm.strip(), 0)
        actual = bytes(encoding).hex(" ").upper()
        if actual != printed:
            failures.append(f"{label}: {asm.strip()!r} printed {printed} but Keystone gives {actual}")
        hits = [b for b in bytes(encoding) if b in bad]
        if hits and f'"{asm.strip()}" holds bad byte' not in output:
            failures.append(f"{label}: {asm.strip()!r} holds bad byte(s) {bytes(hits).hex(' ')}")
        checked += 1
    return checked


STRINGS = ["a", "ab", "abc", "abcd", "abcde", "abcdefgh", "calc.exe", "\xff\xff\xff",
           "cmd.exe /c echo ok > C:\\Users\\Public\\sc_ok.txt", "user32.dll"]
BADS = ["", "00 0A 0D", "00 0A 0D 20", "00 0A 0D 20 2E 61 63 FF 68 50"]

lines = 0
for text in STRINGS:
    for bad in BADS:
        code, output = run("push_string", text, bad, "ebx")
        if code != 0:
            failures.append(f"push_string({text!r}, {bad!r}) failed: {output.strip()[-200:]}")
            continue
        lines += check_lines(f"push_string({text!r}, {bad!r})", output, bad_set(bad))

FRAMES = [("WinExec", "ebx", "1"), ("WinExec", "<ptr to cmd>", "0"), ("ExitProcess", "0"),
          ("TerminateProcess", "-1", "0"), ("LoadLibraryA", "ebx"), ("GetProcAddress", "[ebp-0x0c]", "ebx"),
          ("VirtualAlloc", "0", "0x1000", "0x3000", "0x40"), ("NotARealApi", "eax", "0")]
for frame in FRAMES:
    for bad in BADS[:-1] + ["00 0A 0D 20 2E 61 63 68 50"]:
        code, output = run("call_frame", *frame, f"bad={bad}")
        if code != 0:
            failures.append(f"call_frame{frame} {bad!r} failed: {output.strip()[-200:]}")
            continue
        lines += check_lines(f"call_frame{frame} {bad!r}", output, bad_set(bad))

TEMPLATES = [
    ["winexec=calc.exe", "exit"],
    [],
    ["show=0", "winexec=cmd.exe /c echo ok > C:\\Users\\Public\\sc_ok.txt"],
    ["loadlibrary=user32.dll", "getprocaddress=MessageBoxA", "terminate"],
    ["winexec=calc.exe", "terminate", "bad=00 0A 0D 20"],
    ["show=0", "winexec=cmd.exe /c echo ok > C:\\Users\\Public\\sc_ok.txt", "exit", "bad=00 0A 0D 20 25 26 2B 3D"],
]
with tempfile.TemporaryDirectory() as work:
    for tasks in TEMPLATES:
        code, output = run("template", *tasks)
        script = output.split("[+] Save everything below this line as build_sc.py and run: python build_sc.py\n", 1)[-1]
        path = pathlib.Path(work, "build_sc.py")
        path.write_text(script, encoding="utf-8")
        result = subprocess.run([sys.executable, str(path)], cwd=work, capture_output=True, text=True)
        summary = result.stdout.splitlines()[:2]
        if result.returncode != 0 or "approximate" in result.stdout:
            failures.append(f"template{tasks}: exit {result.returncode}\n{result.stdout}{result.stderr}")
        print(f"template{tasks}: {' | '.join(summary)}")

print(f"{lines} lines matched Keystone byte for byte")
for failure in failures:
    print("FAIL", failure)
print("OK" if not failures else f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)
