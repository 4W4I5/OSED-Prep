import subprocess
import tempfile
import os
from typing import Literal, Union, List
from colorama import Fore, Back, Style


def nasm_asm(
    CODE: Union[str, List[str]], arch: Literal[32, 64] = 32, debug: bool = False
) -> bytes:
    """
    Assemble x86/x64 ASM using NASM and return raw shellcode bytes.

    CODE can now be:
        - A multiline string (with or without comments)
        - A list of strings (one instruction per line, possibly with comments)

    Comments (starting with ';' or '#') are automatically stripped.
    Labels are preserved (they don't generate bytes anyway).
    Trailing null bytes are stripped automatically.
    Interior null bytes trigger a warning.
    """
    bits_directive = f"BITS {arch}"

    # Normalize input to a list of lines
    if isinstance(CODE, str):
        lines = CODE.splitlines()
    else:
        lines = list(CODE)

    # Clean each line: strip whitespace and remove comments
    cleaned_lines = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line:  # skip empty lines
            continue

        # Remove comments (both ; and # style)
        comment_pos = line.find(";")
        if comment_pos != -1:
            line = line[:comment_pos]
        comment_pos = line.find("#")
        if comment_pos != -1:
            line = line[:comment_pos]

        line = line.strip()
        if line:  # only add non-empty lines after cleaning
            cleaned_lines.append(line)

    # Build final assembly source
    asm_source_lines = [bits_directive] + cleaned_lines
    asm_source = "\n".join(asm_source_lines)

    if debug:
        print(f"\t{Fore.RED}o Generating Opcode for NASM:{Style.RESET_ALL}")
        for i, ln in enumerate(asm_source_lines[1:], 1):
            print(f"\t    {Fore.CYAN}{i:2d}: {Fore.YELLOW}{ln}{Style.RESET_ALL}")
        print()

    with tempfile.TemporaryDirectory() as tmpdir:
        asm_path = os.path.join(tmpdir, "shell.asm")
        bin_path = os.path.join(tmpdir, "shell.bin")

        with open(asm_path, "w") as f:
            f.write(asm_source)

        try:
            subprocess.run(
                ["nasm", "-f", "bin", asm_path, "-o", bin_path],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"{Back.WHITE}{Fore.RED}NASM assembly failed:\n{e.stderr.decode('utf-8', errors='replace')}{Style.RESET_ALL}"
            )

        with open(bin_path, "rb") as f:
            shellcode = f.read()

    original_len = len(shellcode)
    shellcode = shellcode.rstrip(b"\x00")  # strip trailing nulls only

    if debug:
        stripped_count = original_len - len(shellcode)
        if stripped_count:
            print(
                f"\t{Fore.YELLOW}[i] Stripped {stripped_count} trailing null byte(s){Style.RESET_ALL}"
            )

        escaped = "".join(f"\\x{b:02x}" for b in shellcode)
        print(
            f"\t\t{Fore.CYAN}[=] Generated {len(shellcode)} bytes:\n\t\t    {Fore.YELLOW}{escaped}{Style.RESET_ALL}"
        )

    if b"\x00" in shellcode:
        print(
            f"{Back.WHITE}{Fore.RED}[!] Warning: Interior null byte(s) detected in shellcode!{Style.RESET_ALL}"
        )

    return shellcode
