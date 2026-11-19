"""Run an egghunter stub in a 32-bit process and report whether it reached the egg.

Build once (LLVM on PATH, run from this folder):
  llvm-dlltool -m i386 -d kernel32.def -l kernel32.lib -k
  clang --target=i686-pc-windows-msvc -O1 -ffreestanding -fno-stack-protector -nostdlib ^
        -fuse-ld=lld -Wl,-entry:start@0 -Wl,-subsystem:console -o harness.exe harness.c kernel32.lib

Then pass the hex line that egghunter() prints (tag W00T):
  python run.py 33DB5353...FFE7

On 64-bit Windows the harness runs under WOW64. Exit 1337 means the stub found the egg.
0xC000001D means the stub executed int 0x2e, which WOW64 rejects.
"""

import pathlib
import subprocess
import sys

here = pathlib.Path(__file__).resolve().parent
stub = bytes.fromhex(sys.argv[1])
(here / "hunter.bin").write_bytes(stub)
try:
    code = subprocess.run([str(here / "harness.exe")], cwd=here, timeout=60).returncode & 0xFFFFFFFF
except subprocess.TimeoutExpired:
    subprocess.run(["taskkill", "/f", "/im", "harness.exe"], capture_output=True)
    sys.exit("TIMEOUT: the stub never left the scan loop")
print(f"{len(stub)} bytes, exit 0x{code:08X}: {'egg reached' if code == 1337 else 'FAILED'}")
sys.exit(0 if code == 1337 else 1)
