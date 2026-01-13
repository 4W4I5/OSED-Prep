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
        escaped = "".join(f"\\x{b:02x}" for b in shellcode)
        print(
            f"\t\t{Fore.CYAN}[=] Generated {len(shellcode)} bytes:\n\t\t {Fore.YELLOW}{escaped}{Style.RESET_ALL}"
        )

    if b"\x00" in shellcode:
        print(
            f"{Back.WHITE}{Fore.RED}[!] Warning: Interior null byte(s) detected in shellcode!{Style.RESET_ALL}"
        )

    return shellcode
