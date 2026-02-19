import os
import re
import subprocess
import tempfile

from colorama import Back, Fore, Style
from typing_extensions import List, Literal, Union


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
    # Track provenance so we can colorize auto-injected/rewritten lines in debug output.
    cleaned_lines: List[str] = []
    line_origins: List[str] = []  # 'user' | 'auto'
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
            line_origins.append("user")

    # Build original line numbers for user lines
    original_line_nums = []
    user_line_counter = 1
    for origin in line_origins:
        if origin == "user":
            original_line_nums.append(user_line_counter)
            user_line_counter += 1
        else:
            original_line_nums.append(None)

    # Process labels: number them sequentially in order of appearance
    labels = []
    for line in cleaned_lines:
        if line.endswith(":"):
            label = line[:-1].strip()
            labels.append(label)

    label_map = {}
    for i, label in enumerate(labels, 1):
        label_map[label] = f"{label}_{i:02d}"

    # Replace all label references with numbered versions
    for i, line in enumerate(cleaned_lines):
        for old, new in label_map.items():
            line = re.sub(r"\b" + re.escape(old) + r"\b", new, line)
        cleaned_lines[i] = line

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
        result = None
        try:
            result = subprocess.run(
                ["nasm", "-f", "bin", "-l", listing_path, asm_path, "-o", bin_path],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"{Back.WHITE}{Fore.RED}NASM assembly failed:\n{e.stderr.decode('utf-8', errors='replace')}{Style.RESET_ALL}"
            )

        # Check for warnings and fix them always
        has_warnings = "warning" in result.stderr.decode("utf-8", errors="replace")
        if has_warnings:
            # Apply push fixes for warnings
            for i in range(len(cleaned_lines) - 1, -1, -1):  # reverse to handle inserts
                line = cleaned_lines[i].strip()
                if line.startswith("push 0x") and len(line.split()) == 2:
                    imm = line.split()[1]
                    try:
                        int(imm, 16)
                        cleaned_lines[i] = f"mov edi, {imm}"
                        line_origins[i] = "auto"
                        cleaned_lines.insert(i + 1, "push rdi")
                        line_origins.insert(i + 1, "auto")
                        original_line_nums.insert(i + 1, None)
                    except ValueError:
                        pass
            # Re-assemble after fixes
            asm_source_lines = [bits_directive] + cleaned_lines
            asm_source = "\n".join(asm_source_lines)
            with open(asm_path, "w") as f:
                f.write(asm_source)
            result = subprocess.run(
                ["nasm", "-f", "bin", "-l", listing_path, asm_path, "-o", bin_path],
                check=True,
                capture_output=True,
            )

            # Analyze the listing for null bytes and attempt automatic fixes always

            def _parse_listing_line(raw: str):
                """Parse a NASM listing line.

                Expected (common) format:
                    <src_line_no> <address> <bytes> <source...>
                Returns (src_line_no, address, bytes, source) or None.
                """
                parts = raw.strip().split()
                if len(parts) < 3:
                    return None
                if not parts[0].isdigit():
                    return None
                # parts[1] is address in hex for typical NASM listings
                if not all(c in "0123456789abcdefABCDEF" for c in parts[1]):
                    return None
                src_line_no = int(parts[0])
                address = parts[1]
                opcode_bytes = parts[2]
                source = " ".join(parts[3:]) if len(parts) > 3 else ""
                return src_line_no, address, opcode_bytes, source

            def _opcode_has_null_byte(opcode_hex: str) -> bool:
                """Return True if opcode hex string contains a literal 0x00 byte.

                Important: don't use substring matching ('00' in opcode_hex) because
                it can false-positive across byte boundaries (e.g. 'C002').
                """
                opcode_hex = re.sub(r"[^0-9a-fA-F]", "", opcode_hex or "")
                for j in range(0, len(opcode_hex) - 1, 2):
                    if opcode_hex[j : j + 2].lower() == "00":
                        return True
                return False

            with open(listing_path, "r") as f:
                listing_lines = f.readlines()

            has_null = any(
                (parsed is not None and _opcode_has_null_byte(parsed[2]))
                for parsed in (_parse_listing_line(ln) for ln in listing_lines)
            )
            if has_null:
                # Attempt to fix null bytes by negating immediates in push/sub/add instructions.
                # Use source line numbers from the NASM listing to avoid ambiguity when the same
                # instruction text appears multiple times in the user's input.
                fixes = []  # (body_index, source_text)
                for raw in listing_lines:
                    parsed = _parse_listing_line(raw)
                    if parsed is None:
                        continue
                    src_line_no, _addr, opcode_bytes, source = parsed
                    if not _opcode_has_null_byte(opcode_bytes):
                        continue
                    # Our asm file is: line 1 = BITS, then cleaned_lines start at line 2.
                    body_index = src_line_no - 2
                    if 0 <= body_index < len(cleaned_lines):
                        fixes.append((body_index, source))

                # Apply from bottom to top so insertions don't invalidate upcoming indices.
                seen = set()
                for body_index, source in sorted(
                    fixes, key=lambda x: x[0], reverse=True
                ):
                    if body_index in seen:
                        continue
                    seen.add(body_index)

                    def _norm(s: str) -> str:
                        return re.sub(r"\s+", " ", s.strip())

                    if _norm(cleaned_lines[body_index]) != _norm(source):
                        continue

                    if source.startswith("push 0x") and len(source.split()) == 2:
                        imm = source.split()[1]
                        try:
                            imm_val = int(imm, 16)
                            cleaned_lines[body_index] = f"mov edi, {imm}"
                            line_origins[body_index] = "auto"
                            cleaned_lines.insert(body_index + 1, "push rdi")
                            line_origins.insert(body_index + 1, "auto")
                            original_line_nums.insert(body_index + 1, None)
                        except ValueError:
                            pass
                    elif source.startswith("sub esp, 0x") and len(source.split()) == 3:
                        imm = source.split()[2]
                        try:
                            imm_val = int(imm, 16)
                            neg_imm = (-imm_val) & 0xFFFFFFFF
                            cleaned_lines[body_index] = f"add esp, 0x{neg_imm:08x}"
                            line_origins[body_index] = "auto"
                        except ValueError:
                            pass
                    elif source.startswith("add esp, 0x") and len(source.split()) == 3:
                        imm = source.split()[2]
                        try:
                            imm_val = int(imm, 16)
                            neg_imm = (-imm_val) & 0xFFFFFFFF
                            cleaned_lines[body_index] = f"sub esp, 0x{neg_imm:08x}"
                            line_origins[body_index] = "auto"
                        except ValueError:
                            pass

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

            if debug:
                # Build origin map for the *current* asm source (line numbers in listing are 1-based).
                # Line 1 is BITS; remaining lines correspond to cleaned_lines.
                asm_line_origins = ["directive"] + list(line_origins)

                # Print the NASM listing output in debug mode
                print(f"\t{Fore.BLUE}o Generated NASM output:{Style.RESET_ALL}")
                if "auto" in asm_line_origins:
                    print(
                        f"\t{Fore.RED}[i] Auto-injected/rewritten lines highlighted{Style.RESET_ALL}"
                    )
                user_line_num = 1
                for i, line in enumerate(listing_lines, 1):
                    line = line.rstrip()
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            # Check if parts[1] is a hex address
                            if all(c in "0123456789abcdefABCDEF" for c in parts[1]):
                                parsed = _parse_listing_line(line)
                                if parsed is None:
                                    address = parts[1]
                                    opcode = parts[2]
                                    source = (
                                        " ".join(parts[3:]) if len(parts) > 3 else ""
                                    )
                                    src_line_no = None
                                else:
                                    src_line_no, address, opcode, source = parsed
                                cleaned_line = f"{address}    {opcode:<16} {source}"
                                if _opcode_has_null_byte(opcode):
                                    plain_padded = opcode.ljust(16)
                                    colored_padded = plain_padded.replace(
                                        "00", f"{Fore.RED}00{Fore.GREEN}"
                                    )
                                    cleaned_line = (
                                        f"{address}    {colored_padded} {source}"
                                    )
                                    color = f"{Back.WHITE}{Fore.GREEN}"
                                else:
                                    if (
                                        src_line_no is not None
                                        and 1 <= src_line_no <= len(asm_line_origins)
                                        and asm_line_origins[src_line_no - 1] == "auto"
                                    ):
                                        color = Fore.RED
                                    else:
                                        color = Fore.CYAN
                            else:
                                cleaned_line = " ".join(parts[1:])
                                if ":" in cleaned_line:
                                    color = Fore.MAGENTA
                                    cleaned_line = "\t " + cleaned_line
                                else:
                                    color = Fore.CYAN
                        else:
                            cleaned_line = " ".join(parts[1:]) if parts else line
                            if ":" in cleaned_line:
                                color = Fore.MAGENTA
                                cleaned_line = "\t " + cleaned_line
                            else:
                                color = Fore.CYAN
                    else:
                        cleaned_line = line
                        color = Fore.CYAN

                    # Skip BITS directives
                    if cleaned_line.strip().startswith("BITS"):
                        continue

                    # Determine line number to display
                    is_auto = False
                    if (
                        parsed is not None
                        and src_line_no is not None
                        and src_line_no > 1
                    ):
                        body_index = src_line_no - 2
                        if 0 <= body_index < len(line_origins):
                            is_auto = line_origins[body_index] == "auto"
                    line_num_str = f"{user_line_num:03d}"
                    user_line_num += 1

                    print(
                        f"\t    {Fore.GREEN}{line_num_str}: {color}{cleaned_line}{Style.RESET_ALL}"
                    )
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
            f"{Back.WHITE}{Fore.RED}[!] Warning: Interior null byte(s) detected in shellcode! Enable debug mode to see highlighted lines.{Style.RESET_ALL}"
        )

    return shellcode
