# win_syscalls.py

import json
import requests
from pathlib import Path
from typing import Optional, Tuple

# Cache directory (next to this script)
CACHE_DIR = Path(__file__).parent / "syscall_cache"
CACHE_DIR.mkdir(exist_ok=True)

# Architecture mapping
ARCH_SUBDIR = {
    "x64": "x64",
    "x86": "x86",
    "64": "x64",
    "32": "x86",
    "amd64": "x64",
    "arm64": "arm64",
}

# Base raw URL
BASE_RAW_URL = "https://raw.githubusercontent.com/j00ru/windows-syscalls/master/"

# JSON files
JSON_FILES_PER_SYSTEM = ["nt-per-system.json", "win32k-per-system.json"]
JSON_FILES_PER_SYSCALL = ["nt-per-syscall.json", "win32k-per-syscall.json"]


def _download_and_cache(url: str, cache_path: Path) -> dict:
    if cache_path.exists():
        with open(cache_path, "r", encoding="utf-8") as f:
            return json.load(f)

    response = requests.get(url)
    if response.status_code != 200:
        raise ValueError(f"Failed to download {url} (status {response.status_code})")

    data = response.json()
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(data, f)

    return data


def get_syscall_number(
    syscall_name: str,
    windows_version: str,
    build: str,
    arch: str = "x64",
) -> Tuple[Optional[str], Optional[str], bool]:
    """
    Look up a Windows syscall number.

    Args:
        syscall_name: e.g., "NtCreateFile"
        windows_version: e.g., "Windows 10", "Windows 11"
        build: e.g., "19045", "22H2", "26100"
        arch: "x64" or "x86" (default: "x64")

    Returns:
        (
            syscall_hex: str or None,     # Final usable syscall number in hex.
                                         # For x64/x86: if raw_number < 0x1000 (leading null bytes in LE DWORD),
                                         # returns the inverted value (e.g., "0xfffffed7" for raw 0x0129).
            source: "NT" | "WIN32K" | None,
            was_inverted: bool           # True if inversion was applied due to leading null bytes
        )
    """
    subdir = ARCH_SUBDIR.get(arch.lower())
    if not subdir:
        raise ValueError("Unsupported architecture. Use 'x64', 'x86', or equivalents.")

    cache_subdir = CACHE_DIR / subdir / "json"
    build = build.upper().strip()

    # Try per-system JSON first
    for json_file in JSON_FILES_PER_SYSTEM:
        cache_path = cache_subdir / json_file
        url = BASE_RAW_URL + f"{subdir}/json/{json_file}"

        try:
            data = _download_and_cache(url, cache_path)

            if windows_version in data and build in data[windows_version]:
                syscalls = data[windows_version][build]
                if syscall_name in syscalls:
                    raw_number = syscalls[syscall_name]
                    source = json_file.split("-")[0].upper()

                    # For x86/x64: Invert if raw_number < 0x1000
                    # This covers cases like 0x001c9 → bytes 0xc9 01 00 00 (two leading nulls)
                    # Inversion gives ~0x1c9 = 0xffffe36, & 0xFFFFFFFF = 0xffffe37
                    # Then NEG yields original 0x1c9 without null bytes
                    if subdir in {"x64", "x86"} and raw_number < 0x1000:
                        inverted = (~raw_number) & 0xFFFFFFFF
                        syscall_hex = hex(inverted)
                        was_inverted = True
                    else:
                        syscall_hex = hex(raw_number)
                        was_inverted = False

                    return syscall_hex, source, was_inverted
        except Exception:
            continue

    # Fallback: per-syscall JSON
    for json_file in JSON_FILES_PER_SYSCALL:
        cache_path = cache_subdir / json_file
        url = BASE_RAW_URL + f"{subdir}/json/{json_file}"

        try:
            data = _download_and_cache(url, cache_path)

            if syscall_name in data:
                versions = data[syscall_name]
                key = f"{windows_version} {build}" if build else windows_version
                if key in versions:
                    raw_number = versions[key]
                    source = json_file.split("-")[0].upper()

                    if subdir in {"x64", "x86"} and raw_number < 0x1000:
                        inverted = (~raw_number) & 0xFFFFFFFF
                        syscall_hex = hex(inverted)
                        was_inverted = True
                    else:
                        syscall_hex = hex(raw_number)
                        was_inverted = False

                    return syscall_hex, source, was_inverted
        except Exception:
            continue

    return None, None, False
