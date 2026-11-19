// 32-bit loader for sc.template output. Reads shellcode.bin from the current
// directory into RWX memory and calls it. Exit 0x600D means the shellcode
// returned to the loader; an exit task ends the process with its own code.
// Build (LLVM on PATH, run from this folder):
//   llvm-dlltool -m i386 -d kernel32.def -l kernel32.lib -k
//   clang --target=i686-pc-windows-msvc -O1 -ffreestanding -fno-stack-protector -nostdlib
//         -fuse-ld=lld -Wl,-entry:start@0 -Wl,-subsystem:console -o loader.exe loader.c kernel32.lib
typedef unsigned long DWORD;
typedef void *HANDLE;
__declspec(dllimport) void *__stdcall VirtualAlloc(void *, DWORD, DWORD, DWORD);
__declspec(dllimport) HANDLE __stdcall CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
__declspec(dllimport) int __stdcall ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
__declspec(dllimport) void __stdcall ExitProcess(DWORD);

void __stdcall start(void) {
  unsigned char *code = VirtualAlloc(0, 0x10000, 0x3000, 0x40);
  HANDLE f = CreateFileA("shellcode.bin", 0x80000000, 1, 0, 3, 0x80, 0);
  DWORD n = 0;
  if (!code || f == (HANDLE)-1 || !ReadFile(f, code, 0x10000, &n, 0) || n == 0) ExitProcess(2);
  ((void (*)(void))code)();
  ExitProcess(0x600D);
}
