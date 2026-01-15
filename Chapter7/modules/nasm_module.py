import subprocess
import tempfile
import os
from typing_extensions import Literal, Union, List
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
    # Set the BITS directive based on architecture
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

    # Build final assembly source with BITS directive
    asm_source_lines = [bits_directive] + cleaned_lines
    asm_source = "\n".join(asm_source_lines)

    # if debug:
    #     print(f"\t{Fore.RED}o Generating Opcode for NASM:{Style.RESET_ALL}")
    #     for i, ln in enumerate(asm_source_lines[1:], 1):
    #         print(f"\t    {Fore.CYAN}{i:2d}: {Fore.YELLOW}{ln}{Style.RESET_ALL}")
    #     print()

    # Use temporary directory for NASM input/output files
    with tempfile.TemporaryDirectory() as tmpdir:
        asm_path = os.path.join(tmpdir, "shell.asm")
        bin_path = os.path.join(tmpdir, "shell.bin")
        listing_path = os.path.join(tmpdir, "listing.lst")

        # Write the assembly source to a temporary file
        with open(asm_path, "w") as f:
            f.write(asm_source)

        # Assemble the code using NASM
        try:
            subprocess.run(
                ["nasm", "-f", "bin", "-l", listing_path, asm_path, "-o", bin_path],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"{Back.WHITE}{Fore.RED}NASM assembly failed:\n{e.stderr.decode('utf-8', errors='replace')}{Style.RESET_ALL}"
            )

        # If debug mode, analyze the listing for null bytes and attempt automatic fixes
        if debug:
            with open(listing_path, "r") as f:
                listing_lines = f.readlines()
            has_null = any(
                '00' in line.split()[2]
                for line in listing_lines
                if len(line.split()) >= 3 and all(c in '0123456789abcdefABCDEF' for c in line.split()[1])
            )
            if has_null:
                # Attempt to fix null bytes by negating immediates in push/sub/add instructions
                for line in listing_lines:
                    parts = line.strip().split()
                    if len(parts) >= 3 and all(c in '0123456789abcdefABCDEF' for c in parts[1]) and '00' in parts[2]:
                        source = ' '.join(parts[3:]) if len(parts) > 3 else ''
                        for idx, ln in enumerate(cleaned_lines):
                            if ln.strip() == source.strip():
                                if source.startswith("push 0x") and len(source.split()) == 2:
                                    imm = source.split()[1]
                                    try:
                                        imm_val = int(imm, 16)
                                        not_imm = ~imm_val & 0xFFFFFFFF
                                        cleaned_lines[idx] = f"mov eax, 0x{not_imm:08x}"
                                        cleaned_lines.insert(idx + 1, "not eax")
                                        cleaned_lines.insert(idx + 2, "push eax")
                                    except ValueError:
                                        pass
                                elif source.startswith("sub esp, 0x") and len(source.split()) == 3:
                                    imm = source.split()[2]
                                    try:
                                        imm_val = int(imm, 16)
                                        neg_imm = (-imm_val) & 0xFFFFFFFF
                                        cleaned_lines[idx] = f"add esp, 0x{neg_imm:08x}"
                                    except ValueError:
                                        pass
                                elif source.startswith("add esp, 0x") and len(source.split()) == 3:
                                    imm = source.split()[2]
                                    try:
                                        imm_val = int(imm, 16)
                                        neg_imm = (-imm_val) & 0xFFFFFFFF
                                        cleaned_lines[idx] = f"sub esp, 0x{neg_imm:08x}"
                                    except ValueError:
                                        pass
                                break
                # Rebuild and re-assemble the source after applying fixes
                asm_source_lines = [bits_directive] + cleaned_lines
                asm_source = "\n".join(asm_source_lines)
                with open(asm_path, "w") as f:
                    f.write(asm_source)
                subprocess.run(
                    ["nasm", "-f", "bin", "-l", listing_path, asm_path, "-o", bin_path],
                    check=True,
                    capture_output=True,
                )
                with open(listing_path, "r") as f:
                    listing_lines = f.readlines()
            # Print the NASM listing output in debug mode
            print(f"\t{Fore.BLUE}o Generated NASM output:{Style.RESET_ALL}")
            for i, line in enumerate(listing_lines, 1):
                line = line.rstrip()
                if line.strip():
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        # Check if parts[1] is a hex address
                        if all(c in '0123456789abcdefABCDEF' for c in parts[1]):
                            address = parts[1]
                            opcode = parts[2]
                            source = ' '.join(parts[3:]) if len(parts) > 3 else ''
                            cleaned_line = f"{address}  {opcode:<12} {source}"
                            if '00' in opcode:
                                color = f"{Fore.RED}{Back.YELLOW}"
                            else:
                                color = Fore.CYAN
                        else:
                            cleaned_line = ' '.join(parts[1:])
                            if ":" in cleaned_line:
                                color = Fore.MAGENTA
                                cleaned_line = '\t\t  ' + cleaned_line
                            else:
                                color = Fore.CYAN
                    else:
                        cleaned_line = ' '.join(parts[1:]) if parts else line
                        if ":" in cleaned_line:
                            color = Fore.MAGENTA
                            cleaned_line = '\t\t  ' + cleaned_line
                        else:
                            color = Fore.CYAN
                else:
                    cleaned_line = line
                    color = Fore.CYAN

                # Skip BITS directives
                if cleaned_line.strip().startswith("BITS"):
                    continue
                print(f"\t    {Fore.GREEN}{i:2d}: {color}{cleaned_line}{Style.RESET_ALL}")
            print()

        # Read the generated binary shellcode
        with open(bin_path, "rb") as f:
            shellcode = f.read()

    # Strip trailing null bytes from the shellcode
    original_len = len(shellcode)
    shellcode = shellcode.rstrip(b"\x00")  # strip trailing nulls only

    # Debug output for stripped bytes and shellcode
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

    # Warn if interior null bytes are present
    if b"\x00" in shellcode:
        print(
            f"{Back.WHITE}{Fore.RED}[!] Warning: Interior null byte(s) detected in shellcode!{Style.RESET_ALL}"
        )

    return shellcode
