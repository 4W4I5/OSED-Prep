def hexIP(ipAddress, byteorder: str = "big"):
    """Return an *immediate* 32-bit hex value for use in little-endian x86 ASM.

    This is designed for patterns like `push {hexIP("A.B.C.D")}` where the goal is
    for the *bytes in memory* (on the stack) to match the requested byte order.

    - `byteorder='big'` (network order) means bytes in memory will be `A B C D`.
      Because x86 `push imm32` writes little-endian, the returned integer will look
      byte-swapped compared to the human-readable IP.
    """
    octets = [int(x) for x in ipAddress.split(".")]
    if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
        raise ValueError(f"Invalid IPv4 address: {ipAddress}")

    ip_bytes = bytes(octets)
    if byteorder == "little":
        ip_bytes = ip_bytes[::-1]
    elif byteorder != "big":
        raise ValueError("byteorder must be 'big' or 'little'")

    imm = int.from_bytes(ip_bytes, byteorder="little")
    ip_hex = f"0x{imm:08x}"
    print(
        f"[+] Converted IP Address {ipAddress} to immediate: {ip_hex} (bytes in memory: {ip_bytes.hex()})"
    )
    return ip_hex

def hexPort(portNumber, byteorder: str = "big"):
    """Return an *immediate* 16-bit hex value for use in little-endian x86 ASM.

    This is designed for patterns like `mov ax, {hexPort(PORT)}` followed by pushing
    that value into a sockaddr structure, where the goal is for the *bytes in memory*
    to be in network order.

    Note: if you pack using `byteorder` and then interpret using the same `byteorder`,
    the integer value will not change. To make endianness visible (and correct for ASM
    immediates), we always interpret the desired bytes as little-endian.
    """
    if not isinstance(portNumber, int) or not (0 <= portNumber <= 65535):
        raise ValueError(f"Invalid port: {portNumber}. Ensure type is int")

    port_bytes = portNumber.to_bytes(2, byteorder="big")
    if byteorder == "little":
        port_bytes = port_bytes[::-1]
    elif byteorder != "big":
        raise ValueError("byteorder must be 'big' or 'little'")

    imm = int.from_bytes(port_bytes, byteorder="little")
    port_hex = f"0x{imm:04x}"
    print(
        f"[+] Converted Port {portNumber} to immediate: {port_hex} (bytes in memory: {port_bytes.hex()})"
    )
    return port_hex