import builtins
import os
import re
import subprocess
import tempfile

from colorama import Back, Fore, Style
from typing_extensions import List, Literal, Optional, Union


def nasm_asm(
    CODE: Union[str, List[str]],
    arch: Literal[32, 64] = 32,
    print: bool = False,
    inject_fixes: bool = True,
    hex_split: Literal["joined", "db", "dw", "dd", "dq"] = "joined",
    build_exe: bool = False,
    exe_path: Optional[str] = None,
    linker: Optional[str] = None,
) -> bytes:
    """
    Assemble x86/x64 ASM using NASM and return raw assembly_code bytes.

    CODE can now be:
        - A multiline string (with or without comments)
        - A list of strings (one instruction per line, possibly with comments)

    Comments (starting with ';' or '#') are automatically stripped.
    Labels are preserved (they don't generate bytes anyway).
    Trailing null bytes are stripped automatically.
    Interior null bytes trigger a warning.

    print enables/disables NASM listing and shellcode output.
    inject_fixes enables/disables automatic code-fix injections.
    hex_split controls opcode display grouping in print mode:
        - joined (default): no spaces
        - db: byte groups (2 hex chars)
        - dw: word groups (4 hex chars)
        - dd: dword groups (8 hex chars)
        - dq: qword groups (16 hex chars)

    build_exe enables/disables emitting a Windows PE executable (.exe) that calls the assembled
    code from a minimal `main` entrypoint. When enabled, a C toolchain linker is required
    (e.g. MinGW-w64 `gcc`/`clang`).

    exe_path optionally overrides where the executable is written. If omitted and build_exe is True,
    defaults to `nasm_payload_<arch>.exe` in the current working directory.

    linker optionally forces the linker command (e.g. `x86_64-w64-mingw32-gcc`). If omitted,
    common candidates are auto-detected.
    """
    # Set the BITS directive based on architecture
    bits_directive = f"BITS {arch}"
    push_reg = "rdi" if arch == 64 else "edi"
    mov_reg = push_reg

    # Normalize input to a list of lines
    # If CODE is a string, split it into source lines.
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
        # Skip blank lines early.
        if not line:  # skip empty lines
            continue

        # Remove comments (both ; and # style)
        comment_pos = line.find(";")
        # Strip semicolon comments when present.
        if comment_pos != -1:
            line = line[:comment_pos]
        comment_pos = line.find("#")
        # Strip hash comments when present.
        if comment_pos != -1:
            line = line[:comment_pos]

        line = line.strip()
        # Keep only non-empty lines after comment removal.
        if line:  # only add non-empty lines after cleaning
            cleaned_lines.append(line)
            line_origins.append("user")

    # Build original line numbers for user lines
    original_line_nums = []
    user_line_counter = 1
    for origin in line_origins:
        # Assign sequential user-facing line numbers.
        if origin == "user":
            original_line_nums.append(user_line_counter)
            user_line_counter += 1
        else:
            original_line_nums.append(None)

    # Process labels: number them sequentially in order of appearance
    labels = []
    for line in cleaned_lines:
        # Capture label definitions to support deterministic renaming.
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

        def _write_asm_source(source: str) -> None:
            try:
                with open(asm_path, "w") as f:
                    f.write(source)
            except OSError as e:
                raise RuntimeError(
                    f"{Back.WHITE}{Fore.RED}Failed to write NASM source file:\n{e}{Style.RESET_ALL}"
                )

        def _run_nasm() -> subprocess.CompletedProcess:
            try:
                return subprocess.run(
                    ["nasm", "-f", "bin", "-l", listing_path, asm_path, "-o", bin_path],
                    check=True,
                    capture_output=True,
                )
            except FileNotFoundError:
                raise RuntimeError(
                    f"{Back.WHITE}{Fore.RED}NASM executable not found. Ensure 'nasm' is installed and in PATH.{Style.RESET_ALL}"
                )
            except subprocess.CalledProcessError as e:
                raise RuntimeError(
                    f"{Back.WHITE}{Fore.RED}NASM assembly failed:\n{e.stderr.decode('utf-8', errors='replace')}{Style.RESET_ALL}"
                )

        def _read_listing_lines() -> List[str]:
            try:
                with open(listing_path, "r") as f:
                    return f.readlines()
            except OSError as e:
                raise RuntimeError(
                    f"{Back.WHITE}{Fore.RED}Failed to read NASM listing file:\n{e}{Style.RESET_ALL}"
                )

        def _read_binary_output() -> bytes:
            try:
                with open(bin_path, "rb") as f:
                    return f.read()
            except OSError as e:
                raise RuntimeError(
                    f"{Back.WHITE}{Fore.RED}Failed to read NASM binary output:\n{e}{Style.RESET_ALL}"
                )

        # Write the assembly source to a temporary file
        _write_asm_source(asm_source)

        # Assemble the code using NASM
        result = _run_nasm()

        def _parse_listing_line(raw: str):
            """Parse a NASM listing line.

            Expected (common) format:
                <src_line_no> <address> <bytes> <source...>
            Returns (src_line_no, address, bytes, source) or None.
            """
            parts = raw.strip().split()
            # Ignore lines too short to contain NASM listing fields.
            if len(parts) < 3:
                return None
            # Ignore lines that don't begin with a source line number.
            if not parts[0].isdigit():
                return None
            # parts[1] is address in hex for typical NASM listings
            # Ignore lines that don't have a hex address field.
            if not all(c in "0123456789abcdefABCDEF" for c in parts[1]):
                return None
            src_line_no = int(parts[0])
            address = parts[1]
            # Collect all consecutive hex parts for opcode_bytes.
            # Normalize into full 2-hex-character byte chunks only.
            i = 2
            opcode_tokens: List[str] = []
            # NASM emits opcode bytes as even-length hex tokens (00, 4883c160, ...).
            # Require an even-length token so instructions like "add" don't get misparsed
            # as opcode bytes (since "add" is hex letters but not a byte sequence).
            while (
                i < len(parts)
                and re.match(r"^[0-9a-fA-F]+$", parts[i])
                and (len(parts[i]) % 2 == 0)
                and (len(parts[i]) >= 2)
            ):
                token = parts[i]
                # Keep only complete byte pairs from each token.
                for j in range(0, len(token), 2):
                    opcode_tokens.append(token[j : j + 2])
                i += 1
            opcode_bytes = "".join(opcode_tokens)
            source = " ".join(parts[i:]) if i < len(parts) else ""
            return src_line_no, address, opcode_bytes, source

        def _opcode_has_null_byte(opcode_hex: str) -> bool:
            """Return True if opcode hex string contains a literal 0x00 byte.

            The opcode hex string represents raw instruction bytes.
            Each byte is exactly two hex characters.
            Validates even-length hex, splits strictly into 2-character byte chunks,
            checks every byte (including the last byte), and returns True only if
            any full byte equals "00".
            """
            cleaned = re.sub(r"[^0-9a-fA-F]", "", opcode_hex or "")
            # Evaluate only full bytes; ignore any trailing half-byte.
            full_len = len(cleaned) - (len(cleaned) % 2)
            for i in range(0, full_len, 2):
                byte = cleaned[i : i + 2].lower()
                # Flag true null bytes only.
                if byte == "00":
                    return True
            return False

        def _opcode_to_byte_pairs(opcode_hex: str) -> List[str]:
            """Convert opcode hex text to normalized byte-pair tokens."""
            cleaned = re.sub(r"[^0-9a-fA-F]", "", opcode_hex or "")
            full_len = len(cleaned) - (len(cleaned) % 2)
            return [cleaned[i : i + 2].lower() for i in range(0, full_len, 2)]

        def _format_opcode_for_display(opcode_hex: str, split_mode: str) -> str:
            """Format opcode for display according to requested grouping."""
            pairs = _opcode_to_byte_pairs(opcode_hex)
            # Fall back to raw text if no full byte pairs exist.
            if not pairs:
                return opcode_hex

            group_bytes = {
                "db": 1,
                "dw": 2,
                "dd": 4,
                "dq": 8,
            }.get(split_mode)

            # Joined mode: return contiguous hex.
            if group_bytes is None:
                return "".join(pairs)

            tokens = []
            for i in range(0, len(pairs), group_bytes):
                tokens.append("".join(pairs[i : i + group_bytes]))
            return " ".join(tokens)

        def _format_opcode_with_null_highlight(opcode_hex: str, split_mode: str) -> str:
            """Format opcode and highlight exact 00 bytes in display output."""
            pairs = _opcode_to_byte_pairs(opcode_hex)
            # Fall back to raw text if no full byte pairs exist.
            if not pairs:
                return opcode_hex

            highlighted_pairs = []
            for pair in pairs:
                # Highlight exact null-byte tokens.
                if pair == "00":
                    highlighted_pairs.append(
                        f"{Fore.WHITE}{Back.RED}00{Style.RESET_ALL}{Fore.CYAN}"
                    )
                else:
                    highlighted_pairs.append(pair)

            group_bytes = {
                "db": 1,
                "dw": 2,
                "dd": 4,
                "dq": 8,
            }.get(split_mode)

            # Joined mode: return contiguous highlighted hex.
            if group_bytes is None:
                return "".join(highlighted_pairs)

            tokens = []
            for i in range(0, len(highlighted_pairs), group_bytes):
                tokens.append("".join(highlighted_pairs[i : i + group_bytes]))
            return " ".join(tokens)

        # Check for warnings and fix them
        has_warnings = "warning" in result.stderr.decode("utf-8", errors="replace")
        # Apply warning-driven rewrites only when injection is enabled.
        if inject_fixes and has_warnings:
            # Apply push fixes for warnings
            for i in range(len(cleaned_lines) - 1, -1, -1):  # reverse to handle inserts
                line = cleaned_lines[i].strip()
                # Rewrite direct push-immediate patterns.
                if line.startswith("push 0x") and len(line.split()) == 2:
                    imm = line.split()[1]
                    try:
                        int(imm, 16)
                        cleaned_lines[i] = f"mov {mov_reg}, {imm}"
                        line_origins[i] = "auto"
                        cleaned_lines.insert(i + 1, f"push {push_reg}")
                        line_origins.insert(i + 1, "auto")
                        original_line_nums.insert(i + 1, None)
                    except ValueError:
                        pass
            # Re-assemble after fixes
            asm_source_lines = [bits_directive] + cleaned_lines
            asm_source = "\n".join(asm_source_lines)
            _write_asm_source(asm_source)
            result = _run_nasm()

        # Analyze the listing for null bytes and attempt automatic fixes
        listing_lines = _read_listing_lines()

        has_null = any(
            (parsed is not None and _opcode_has_null_byte(parsed[2]))
            for parsed in (_parse_listing_line(ln) for ln in listing_lines)
        )
        # Apply null-byte rewrites only when injection is enabled.
        if inject_fixes and has_null:
            fixes = []  # (body_index, source_text)
            for raw in listing_lines:
                parsed = _parse_listing_line(raw)
                # Skip listing rows that don't parse as code entries.
                if parsed is None:
                    continue
                src_line_no, _addr, opcode_bytes, source = parsed
                # Keep only entries whose opcode bytes contain a null byte.
                if not _opcode_has_null_byte(opcode_bytes):
                    continue
                body_index = src_line_no - 2
                # Keep only rows mapped to current source body lines.
                if 0 <= body_index < len(cleaned_lines):
                    fixes.append((body_index, source))

            seen = set()
            for body_index, source in sorted(fixes, key=lambda x: x[0], reverse=True):
                # Prevent duplicate rewrites on the same source line.
                if body_index in seen:
                    continue
                seen.add(body_index)

                def _norm(s: str) -> str:
                    return re.sub(r"\s+", " ", s.strip())

                # Ensure listing source still matches current source text.
                if _norm(cleaned_lines[body_index]) != _norm(source):
                    continue

                # Rewrite push-immediate instructions to avoid problematic bytes.
                if source.startswith("push 0x") and len(source.split()) == 2:
                    imm = source.split()[1]
                    try:
                        int(imm, 16)
                        cleaned_lines[body_index] = f"mov {mov_reg}, {imm}"
                        line_origins[body_index] = "auto"
                        cleaned_lines.insert(body_index + 1, f"push {push_reg}")
                        line_origins.insert(body_index + 1, "auto")
                        original_line_nums.insert(body_index + 1, None)
                    except ValueError:
                        pass
                # Rewrite sub esp immediate by using equivalent add with negated immediate.
                elif source.startswith("sub esp, 0x") and len(source.split()) == 3:
                    imm = source.split()[2]
                    try:
                        imm_val = int(imm, 16)
                        neg_imm = (-imm_val) & 0xFFFFFFFF
                        cleaned_lines[body_index] = f"add esp, 0x{neg_imm:08x}"
                        line_origins[body_index] = "auto"
                    except ValueError:
                        pass
                # Rewrite add esp immediate by using equivalent sub with negated immediate.
                elif source.startswith("add esp, 0x") and len(source.split()) == 3:
                    imm = source.split()[2]
                    try:
                        imm_val = int(imm, 16)
                        neg_imm = (-imm_val) & 0xFFFFFFFF
                        cleaned_lines[body_index] = f"sub esp, 0x{neg_imm:08x}"
                        line_origins[body_index] = "auto"
                    except ValueError:
                        pass

            asm_source_lines = [bits_directive] + cleaned_lines
            asm_source = "\n".join(asm_source_lines)
            _write_asm_source(asm_source)
            _run_nasm()
            listing_lines = _read_listing_lines()

        # Emit detailed listing output only when print mode is enabled.
        if print:
            # Build origin map for the *current* asm source (line numbers in listing are 1-based).
            # Line 1 is BITS; remaining lines correspond to cleaned_lines.
            asm_line_origins = ["directive"] + list(line_origins)
            opcode_col_width = 23
            for preview_line in listing_lines:
                preview_parsed = _parse_listing_line(preview_line)
                # Skip non-instruction listing lines when sizing the opcode column.
                if preview_parsed is None:
                    continue
                _src_line_no, _address, preview_opcode, _source = preview_parsed
                preview_display = _format_opcode_for_display(preview_opcode, hex_split)
                opcode_col_width = max(opcode_col_width, len(preview_display))

            # Print the NASM listing output in debug mode
            builtins.print(f"\t{Fore.BLUE}o Generated NASM output:{Style.RESET_ALL}")
            # Announce when auto-injected lines are present in output.
            if "auto" in asm_line_origins:
                builtins.print(
                    f"\t{Fore.RED}[i] Auto-injected/rewritten lines highlighted{Style.RESET_ALL}"
                )
            user_line_num = 1
            for i, line in enumerate(listing_lines, 1):
                line = line.rstrip()
                parsed = None
                src_line_no = None
                # Process populated listing lines.
                if line.strip():
                    parts = line.strip().split()
                    # Process lines that can contain address/opcode/source fields.
                    if len(parts) >= 3:
                        # Check if parts[1] is a hex address
                        # Parse instruction-like listing rows with a valid hex address.
                        if all(c in "0123456789abcdefABCDEF" for c in parts[1]):
                            parsed = _parse_listing_line(line)
                            # Use fallback extraction when structured parsing fails.
                            if parsed is None:
                                address = parts[1]
                                opcode = parts[2]
                                source = " ".join(parts[3:]) if len(parts) > 3 else ""
                            else:
                                src_line_no, address, opcode, source = parsed
                            opcode_display = _format_opcode_for_display(
                                opcode, hex_split
                            )
                            opcode_padding = " " * (
                                opcode_col_width - len(opcode_display) + 1
                            )
                            cleaned_line = (
                                f"{address}    {opcode_display}{opcode_padding}{source}"
                            )
                            # Highlight opcode column when null bytes are present.
                            if _opcode_has_null_byte(opcode):
                                colored_display = _format_opcode_with_null_highlight(
                                    opcode, hex_split
                                )
                                cleaned_line = f"{address}    {colored_display}{opcode_padding}{source}"
                                color = Fore.CYAN
                            else:
                                # Color auto-injected instruction rows differently.
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
                            # Color label-style rows distinctly.
                            if ":" in cleaned_line:
                                color = Fore.MAGENTA
                                cleaned_line = "\t " + cleaned_line
                            else:
                                color = Fore.CYAN
                    else:
                        cleaned_line = " ".join(parts[1:]) if parts else line
                        # Color short label-like rows distinctly.
                        if ":" in cleaned_line:
                            color = Fore.MAGENTA
                            cleaned_line = "\t " + cleaned_line
                        else:
                            color = Fore.CYAN
                else:
                    cleaned_line = line
                    color = Fore.CYAN

                # Skip BITS directives
                # Omit assembler directive rows from user-facing listing output.
                if cleaned_line.strip().startswith("BITS"):
                    continue

                line_num_str = f"{user_line_num:03d}"
                user_line_num += 1

                builtins.print(
                    f"\t    {Fore.GREEN}{line_num_str}: {color}{cleaned_line}{Style.RESET_ALL}"
                )
            builtins.print()

        # Read the generated binary assembly_code
        assembly_code = _read_binary_output()

        def _try_run_version(cmd: str) -> bool:
            try:
                subprocess.run(
                    [cmd, "--version"],
                    check=True,
                    capture_output=True,
                )
                return True
            except Exception:
                return False

        def _pick_linker(arch_bits: int) -> str:
            if linker:
                return linker

            # Prefer explicit MinGW-w64 triplet compilers when available.
            candidates: List[str]
            if arch_bits == 64:
                candidates = [
                    "x86_64-w64-mingw32-gcc",
                    "clang",
                    "gcc",
                ]
            else:
                candidates = [
                    "i686-w64-mingw32-gcc",
                    "clang",
                    "gcc",
                ]

            for cmd in candidates:
                if _try_run_version(cmd):
                    return cmd

            raise RuntimeError(
                f"{Back.WHITE}{Fore.RED}No suitable linker toolchain found to build an .exe.\n"
                f"Install MinGW-w64 (gcc) or clang, or pass linker=...{Style.RESET_ALL}"
            )

        def _build_exe_from_payload(payload_lines: List[str]) -> str:
            """Build a minimal .exe that calls `payload` and returns 0.

            This is intended for quick debugging/running code, not for position-independent shellcode.
            """
            exe_out = exe_path
            if not exe_out:
                exe_out = os.path.join(os.getcwd(), f"nasm_payload_{arch}.exe")
            if not exe_out.lower().endswith(".exe"):
                exe_out += ".exe"

            obj_fmt = "win64" if arch == 64 else "win32"
            exe_asm_path = os.path.join(tmpdir, "exe.asm")
            obj_path = os.path.join(tmpdir, "exe.obj")

            # Wrap user code in a callable label; add a `ret` to allow returning to `main`.
            wrapper: List[str] = [
                f"BITS {arch}",
                "global main",
                "section .text",
                "main:",
                "    call payload",
                "    xor eax, eax",
                "    ret",
                "payload:",
            ]

            for ln in payload_lines:
                # Keep labels and directives unindented; indent instructions for readability only.
                if ln.endswith(":") or ln.lower().startswith("section "):
                    wrapper.append(ln)
                else:
                    wrapper.append(f"    {ln}")
            wrapper.append("    ret")

            try:
                with open(exe_asm_path, "w") as f:
                    f.write("\n".join(wrapper))
            except OSError as e:
                raise RuntimeError(
                    f"{Back.WHITE}{Fore.RED}Failed to write EXE NASM source file:\n{e}{Style.RESET_ALL}"
                )

            try:
                subprocess.run(
                    ["nasm", "-f", obj_fmt, exe_asm_path, "-o", obj_path],
                    check=True,
                    capture_output=True,
                )
            except FileNotFoundError:
                raise RuntimeError(
                    f"{Back.WHITE}{Fore.RED}NASM executable not found. Ensure 'nasm' is installed and in PATH.{Style.RESET_ALL}"
                )
            except subprocess.CalledProcessError as e:
                raise RuntimeError(
                    f"{Back.WHITE}{Fore.RED}NASM EXE assembly failed:\n{e.stderr.decode('utf-8', errors='replace')}{Style.RESET_ALL}"
                )

            cc = _pick_linker(arch)
            link_cmd: List[str] = [cc]
            # Try to enforce target bitness when using generic gcc/clang.
            if cc in {"gcc", "clang"}:
                link_cmd.append("-m64" if arch == 64 else "-m32")
            link_cmd.extend([obj_path, "-o", exe_out])

            try:
                subprocess.run(
                    link_cmd,
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                stderr = e.stderr.decode("utf-8", errors="replace")
                raise RuntimeError(
                    f"{Back.WHITE}{Fore.RED}Linking EXE failed using '{cc}'.\n{stderr}{Style.RESET_ALL}"
                )

            return exe_out

        # Optionally build an .exe in addition to returning raw shellcode bytes.
        if build_exe:
            exe_out = _build_exe_from_payload(cleaned_lines)
            if print:
                builtins.print(
                    f"\t{Fore.GREEN}[=] Wrote executable: {Fore.YELLOW}{exe_out}{Style.RESET_ALL}"
                )

    # Strip trailing null bytes from the assembly_code
    original_len = len(assembly_code)
    assembly_code = assembly_code.rstrip(b"\x00")  # strip trailing nulls only

    # Debug output for stripped bytes and assembly_code
    # Emit summary output only when print mode is enabled.
    if print:
        stripped_count = original_len - len(assembly_code)
        # Report how many trailing null bytes were removed.
        if stripped_count:
            builtins.print(
                f"\t{Fore.YELLOW}[i] Stripped {stripped_count} trailing null byte(s){Style.RESET_ALL}"
            )

        escaped = "".join(f"\\x{b:02x}" for b in assembly_code)
        builtins.print(
            f"\t\t{Fore.CYAN}[=] Generated {len(assembly_code)} bytes:\n\t\t    {Fore.YELLOW}{escaped}{Style.RESET_ALL}"
        )

    # Warn if interior null bytes are present
    # Warn when null bytes still exist inside the payload body.
    if b"\x00" in assembly_code:
        builtins.print(
            f"{Back.WHITE}{Fore.RED}[!] Warning: Interior null byte(s) detected in assembly_code! Enable print mode to see highlighted lines.{Style.RESET_ALL}"
        )

    return assembly_code
