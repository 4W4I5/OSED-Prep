from colorama import Back, Fore, Style


class Payload:
    def __init__(self, payload=None, badchars=None):
        self.payload = bytearray()  # Holds the Payload
        self.alignment = 4  # x86 stack alignment boundary
        self.badchars = set(badchars or [])  # Use set for O(1) membership checks
        self._logLevel = "INFO"  # Internal flag for setting logLevel
        self.endianess = "L"  # L = little-endian, B = big-endian

        # Constructor supports both paths: with initial payload or empty start.
        if payload is not None and len(payload) > 0:
            self._log("Got constructor payload")
            self.append(payload)
        else:
            self._log("No constructor payload")

    def append(self, data=None):
        # Optional arg path: calling _append() should be a safe no-op.
        if data is None:
            self._log("No bytes were sent in", "WARN")
            return False

        data_bytes = self._coerceToBytes(data)

        if len(data_bytes) == 0:
            self._log("No bytes were sent in", "WARN")
            return False

        self._log(f"Appending bytes: \n{data_bytes}")

        # Keep validation order explicit and deterministic.
        if not self._testAlignment(data_bytes):
            return False

        if not self._testBadChars(data_bytes):
            return False

        # extend adds a byte sequence, unlike append which expects one int byte.
        self.payload.extend(data_bytes)
        self._log("Payload after append:")
        self._printBuffer(width="dd")
        return True

    def setBadChars(self, badCharsList):
        self.badchars = badCharsList
        self._log(f"Bad chars set! New badchars are:\n{self.badchars}")
        self._testBadChars()

    def getBadChars(self):
        return self.badchars

    def setEndianess(self, endianess):
        normalized = str(endianess).casefold()
        if normalized not in ["l", "b"]:
            raise ValueError("endianess must be 'L' or 'B'")
        self.endianess = normalized.upper()

    def setLogLevel(self, logLevel):
        normalized = str(logLevel).casefold()
        if normalized not in ["info", "warn", "error", "debug"]:
            self._log("Wrong logLevel set, using DEBUG", "WARN")
            self._logLevel = "DEBUG"
        else:
            self._logLevel = normalized.upper()

    def _coerceToBytes(self, data):
        self.setEndianess(self.endianess)

        if isinstance(data, int):
            if data < 0 or data > 0xFFFFFFFF:
                raise ValueError("int value must fit in an unsigned 32-bit dword")
            if self.endianess == "L":
                return data.to_bytes(4, byteorder="little", signed=False)
            return data.to_bytes(4, byteorder="big", signed=False)

        if isinstance(data, str):
            cleaned = data.strip().replace(" ", "").replace("_", "")
            cleaned = cleaned.replace("\\x", "")
            if cleaned.casefold().startswith("0x"):
                cleaned = cleaned[2:]
            if len(cleaned) == 0:
                return b""
            if len(cleaned) % 2 != 0:
                raise ValueError("hex string length must be even")
            raw = bytes.fromhex(cleaned)
            if self.endianess == "L":
                return b"".join(raw[i : i + 4][::-1] for i in range(0, len(raw), 4))
            return raw

        if isinstance(data, (bytes, bytearray)):
            return bytes(data)

        raise TypeError("append expects bytes, bytearray, int, or hex string")

    def _testAlignment(self, data=None) -> bool:

        testBytes = b""
        self._log(f"Testing Alignment over 4")

        # If bytes are supplied, test those; otherwise test current payload state.
        if data is not None:
            self._log(f"Bytes passed into _testAlignment, testing byte alignment")
            testBytes = data
        else:
            self._log(f"Nothing passed into _testAlignment, testing total payload alignment")
            testBytes = self.payload

        # Test alignment of selected byte sequence
        if len(testBytes) % self.alignment != 0:
            self._log(f"Payload not aligned over multiples of {self.alignment}:\n{testBytes}", "ERROR")
            return False
        else:
            self._log(f"Payload length is: {len(testBytes)}")
        return True

    def _testBadChars(self, data=None) -> bool:
        # Mirrors _testAlignment behavior: explicit bytes or full payload.
        testBytes = self.payload if data is None else data

        if len(self.badchars) == 0:
            self._log(f"No Bad chars to test against", "WARN")
            return True

        self._log(f"Testing BadChars")
        bad_hits = [(idx, b) for idx, b in enumerate(testBytes) if b in self.badchars]
        if bad_hits:
            hit_summary = ", ".join([f"{hex(b)} @ +0x{idx:04x}" for idx, b in bad_hits])
            self._log(f"Found bad chars at offsets: {hit_summary}", "ERROR")
            self._log("Highlighted offending bytes:", "ERROR")
            self._printBuffer(buf=testBytes, width="dd")
            return False

        self._log("No bad chars found")
        return True

    def _log(self, message, level="INFO"):
        colorCode = ""
        normalized_level = str(level).casefold()
        if normalized_level == "error":
            colorCode = f"{Fore.LIGHTRED_EX}{Style.BRIGHT}[!!!] "
        elif normalized_level == "warn":
            colorCode = f"{Fore.LIGHTRED_EX}[!] "
        elif normalized_level == "debug":
            colorCode = f"{Fore.LIGHTYELLOW_EX}[>] "
        elif normalized_level == "info":
            colorCode = f"{Fore.MAGENTA}[o] "
        else:
            print(f"Invalid Level Type passed")

        print(f"{colorCode}{message}{Style.RESET_ALL}")

    def _printBuffer(self, buf=None, width="dd"):

        if buf is None:
            buf = self.payload
            self._log(f"Buffer not passed, printing payload.")

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
            self._log(f"ERR: Invalid width {width}", "ERROR")
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
                            if byte_val in self.badchars:
                                print(f"{Fore.RED}{Back.WHITE}{byte_val:02x}{Style.RESET_ALL}", end=" ")
                            else:
                                print(f"{byte_val:02x}", end=" ")
                        else:
                            print("  ", end="")
                else:
                    val = 0
                    bad_in_group = False
                    for j in range(w):
                        if start + j < len(buf):
                            val |= buf[start + j] << (8 * (w - 1 - j))
                            if buf[start + j] in self.badchars:
                                bad_in_group = True
                    if width == "dw":
                        if bad_in_group:
                            print(f"{Fore.RED}{Back.WHITE}{val:04x}{Style.RESET_ALL}", end=" ")
                        else:
                            print(f"{val:04x}", end=" ")
                    elif width == "dd":
                        if bad_in_group:
                            dd_bytes = []
                            for j in range(w):
                                if start + j < len(buf):
                                    byte_val = buf[start + j]
                                    if byte_val in self.badchars:
                                        dd_bytes.append(f"{Fore.BLACK}{Back.LIGHTRED_EX}{byte_val:02x}{Style.RESET_ALL}")
                                    else:
                                        dd_bytes.append(f"{Fore.BLACK}{Back.LIGHTGREEN_EX}{byte_val:02x}{Style.RESET_ALL}")
                            print("".join(dd_bytes), end=" ")
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


# Testing
def test():

    # Init empty class
    print(f"{Back.LIGHTGREEN_EX}{Style.BRIGHT}o Creating Empty Class{Style.RESET_ALL}")
    emptyPayload = Payload()
    emptyPayload.append()

    # Init constructor class
    print(f"\n{Back.LIGHTGREEN_EX}{Style.BRIGHT}o Creating Class with 4-byte NOP payload{Style.RESET_ALL}")
    payload = Payload(b"\x41" * 4)

    # Test Alignment checks
    print(f"\n{Back.LIGHTGREEN_EX}{Style.BRIGHT}o Testing Alignment Checks{Style.RESET_ALL}")
    payload = Payload(b"\x41" * 4)
    payload.append(b"\x41")
    payload.append(b"\x41\x42")
    payload.append(b"\x41\x42\x43")
    payload.append(b"\x41\x42\x43\x44")
    payload.append(b"\x41\x42\x43\x44\x45")

    # Bad Char Test
    print(f"\n{Back.LIGHTGREEN_EX}{Style.BRIGHT}o Testing BadChar Checks{Style.RESET_ALL}")
    payload.setBadChars(b"\x42")

    # Int append tests
    print(f"\n{Back.LIGHTGREEN_EX}{Style.BRIGHT}o Testing int append with endianess{Style.RESET_ALL}")
    payload_int = Payload()
    payload_int.setEndianess("L")
    payload_int.append(0x11223344)
    payload_int.append(0x112233)
    payload_int.setEndianess("B")
    payload_int.append(0x55667788)
    payload_int.append(0x556677)

    # Hex string append tests
    print(f"\n{Back.LIGHTGREEN_EX}{Style.BRIGHT}o Testing hex string append with endianess{Style.RESET_ALL}")
    payload_hex = Payload()
    payload_hex.setEndianess("L")
    payload_hex.append("11223344")
    payload_hex.append("112233")
    payload_hex.setEndianess("B")
    payload_hex.append("aabbccdd")
    payload_hex.append("aabbcd")
    # Test Alignment checks
    print(f"\n{Back.LIGHTGREEN_EX}{Style.BRIGHT}o Testing Alignment Checks{Style.RESET_ALL}")
    payload = Payload(b"\x41" * 4)
    payload.append(b"\x41")
    payload.append(b"\x41\x42")
    payload.append(b"\x41\x42\x43")
    payload.append(b"\x41\x42\x43\x44")
    payload.append(b"\x41\x42\x43\x44\x45")
    payload.append(b"\x41\x42\x43\x44\x45\x46")
    payload.append(b"\x41\x42\x43\x44\x45\x46\x47")
    payload.append(b"\x41\x42\x43\x44\x45\x46\x47\x48")


if __name__ == "__main__":
    test()
