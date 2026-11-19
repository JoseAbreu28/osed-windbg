// 32-bit egghunter harness. Reads the stub from hunter.bin, reserves 0x40000 bytes,
// commits only the last 0x10000-aligned page and puts "W00TW00T" plus a payload
// there, then calls the stub with edx at the start of the reserved range. The stub
// must skip 48 uncommitted pages and reach the payload, which exits with 1337.
typedef unsigned long DWORD;
typedef void *HANDLE;
__declspec(dllimport) void *__stdcall VirtualAlloc(void *, DWORD, DWORD, DWORD);
__declspec(dllimport) HANDLE __stdcall CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
__declspec(dllimport) int __stdcall ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
__declspec(dllimport) void __stdcall ExitProcess(DWORD);

void __stdcall start(void) {
  unsigned char *h = VirtualAlloc(0, 0x1000, 0x3000, 0x40);
  HANDLE f = CreateFileA("hunter.bin", 0x80000000, 1, 0, 3, 0x80, 0);
  DWORD n = 0;
  if (f == (HANDLE)-1 || !ReadFile(f, h, 0x400, &n, 0) || n == 0) ExitProcess(2);
  unsigned char *base = VirtualAlloc(0, 0x40000, 0x2000, 0x01);
  volatile unsigned char *egg = VirtualAlloc(base + 0x30000, 0x1000, 0x1000, 0x40);
  if (!base || !egg) ExitProcess(3);
  // The tag is written byte by byte so no "W00TW00T" literal sits in .rdata.
  volatile unsigned char t0 = 'W', t1 = '0', t3 = 'T';
  for (int i = 0; i < 8; i += 4) { egg[i] = t0; egg[i + 1] = t1; egg[i + 2] = t1; egg[i + 3] = t3; }
  // push 1337 ; mov eax, ExitProcess ; call eax. Works whatever the stub left on the stack.
  DWORD xp = (DWORD)&ExitProcess;
  unsigned char payload[] = {0x68, 0x39, 0x05, 0x00, 0x00, 0xB8, xp & 0xff, (xp >> 8) & 0xff, (xp >> 16) & 0xff, xp >> 24, 0xFF, 0xD0};
  for (int i = 0; i < 12; i++) egg[8 + i] = payload[i];
  DWORD r;
  __asm__ volatile("call *%1" : "=a"(r) : "r"(h), "d"(base) : "ecx", "ebx", "esi", "edi", "memory");
  ExitProcess(r);
}
