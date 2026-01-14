# keystone_module.py
# Exact drop-in replacement for nasm_module.py using Keystone
# Fixed: Removed invalid .close(), improved multi-instruction handling for labels

from typing_extensions import Union, List, Literal
from colorama import Fore, Back, Style
from keystone import (
    Ks,
    KsError,
    KS_ARCH_X86,
    KS_MODE_32,
    KS_MODE_64,
    KS_OPT_SYNTAX_INTEL,
)
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64


def fix_nulls(lines: List[str]) -> None:
    """
    Fix potential null byte issues in assembly lines by replacing problematic instructions.
    """
    i = 0
    while i < len(lines):
        line = lines[i]
        parts = line.split()
        if len(parts) == 2 and parts[0] == 'push' and parts[1].startswith('0x'):
            try:
                val = int(parts[1], 16)
                if val == 0:
                    lines[i] = 'mov eax, 0xffffffff'
                    lines.insert(i + 1, 'not eax')
                    lines.insert(i + 2, 'push eax')
                    i += 3  # skip the inserted lines
                    continue
            except ValueError:
                pass
        elif len(parts) == 3 and parts[0] == 'sub' and parts[1] == 'esp,' and parts[2].startswith('0x'):
            try:
                val = int(parts[2], 16)
                neg_val = (-val) & 0xFFFFFFFF
                lines[i] = f'add esp, 0x{neg_val:08x}'
            except ValueError:
                pass
        elif len(parts) == 3 and parts[0] == 'add' and parts[1] == 'esp,' and parts[2].startswith('0x'):
            try:
                val = int(parts[2], 16)
                neg_val = (-val) & 0xFFFFFFFF
                lines[i] = f'sub esp, 0x{neg_val:08x}'
            except ValueError:
                pass
        i += 1


def keystone_asm(
    CODE: Union[str, List[str]], arch: Literal[32, 64] = 32, debug: bool = False
) -> bytes:
    """
    Assemble x86/x64 ASM using Keystone — identical behavior to nasm_module.py
    """
    mode = KS_MODE_32 if arch == 32 else KS_MODE_64
    
    # Normalize input
    if isinstance(CODE, str):
        lines = CODE.splitlines()
    else:
        lines = list(CODE)

    # Clean: strip comments and empty lines
    cleaned_lines = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        # Strip comments starting with ; or #
        for comment_char in (";", "#"):
            if comment_char in line:
                line = line[: line.find(comment_char)]
        line = line.strip()
        if line:
            cleaned_lines.append(line)

    # Fix potential null bytes
    fix_nulls(cleaned_lines)

    # Best practice for Keystone: join with "; " — perfect for labels and complex code
    asm_source = "; ".join(cleaned_lines)

    if debug:
        print(f"\t{Fore.RED}o Generating Opcode with Keystone:{Style.RESET_ALL}")
        for i, ln in enumerate(cleaned_lines, 1):
            print(f"\t {Fore.CYAN}{i:2d}: {Fore.YELLOW}{ln}{Style.RESET_ALL}")
        print()

    try:
        ks = Ks(KS_ARCH_X86, mode)
        ks.syntax = KS_OPT_SYNTAX_INTEL

        encoding, count = ks.asm(asm_source)

        if encoding is None or not encoding:
            raise RuntimeError(
                "Keystone failed to assemble any instructions (possible label/syntax issue)"
            )

        shellcode = bytes(encoding)

    except KsError as e:
        raise RuntimeError(
            f"{Back.WHITE}{Fore.RED}Keystone assembly failed:{Style.RESET_ALL}\n"
            f"{str(e)}"
        )

    # Strip trailing nulls only
    original_len = len(shellcode)
    shellcode = shellcode.rstrip(b"\x00")

    if debug:
        stripped_count = original_len - len(shellcode)
        if stripped_count:
            print(
                f"\t{Fore.YELLOW}[i] Stripped {stripped_count} trailing null byte(s){Style.RESET_ALL}"
            )
        print(f"\t{Fore.BLUE}o Generated Keystone output:{Style.RESET_ALL}")
        md = Cs(CS_ARCH_X86, mode)
        offset = 0
        for i, (addr, size, mnemonic, op_str) in enumerate(md.disasm_lite(shellcode, 0x1000)):
            if offset >= len(shellcode):
                break
            opcode_bytes = shellcode[offset:offset+size]
            opcode = ''.join(f'{b:02x}' for b in opcode_bytes)
            has_null = '00' in opcode
            color = f"{Fore.RED}{Back.YELLOW}" if has_null else Fore.CYAN
            print(f"\t {Fore.GREEN}{i+1:2d}: {Fore.MAGENTA}{addr:08x}  {color}{opcode:<12}{Style.RESET_ALL} {mnemonic} {op_str}")
            offset += size
        print()
        escaped = "".join(f"\\x{b:02x}" for b in shellcode)
        print(
            f"\t\t{Fore.CYAN}[=] Generated {len(shellcode)} bytes:\n\t\t {Fore.YELLOW}{escaped}{Style.RESET_ALL}"
        )

    if b"\x00" in shellcode:
        print(
            f"{Back.WHITE}{Fore.RED}[!] Warning: Interior null byte(s) detected in shellcode!{Style.RESET_ALL}"
        )

    return shellcode
