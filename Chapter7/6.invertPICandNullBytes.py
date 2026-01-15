"""
OMER: Generated this template for following along on Ch7
started the base a little further than needed since i
had to get my head around ctypes anyway

so far figured out how to
- allocate mem (VirtualAlloc)
- copy shellcode into allocated mem (RtlMoveMemory)
- start a thread to run shellcode (CreateThread)
- wait for thread to finish (WaitForSingleObject)

>13jan_218p: attaching windbg is easy, i added a line to fetch the currentPID
- noted that i needed 5 NOPs to align int 3 properly, weird

>13jan_420p: turns out python arch is important, was running 64bit python3.14
- switched to 32bit python3.7 
- had to disable sysCallFinder, requests is set on using a new SSL lib


>13jan_515p: works, EBX holds the kernel32.dll base addr after ret
but a crash is triggered since theres no cleanup code after ret

0:004> g
(7798.4a10): Break instruction exception - code 80000003 (first chance)
eax=043afe38 ebx=00000000 ecx=04170000 edx=04170000 esi=04170000 edi=04170000
eip=04170000 esp=043afde4 ebp=043afdf0 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
04170000 cc              int     3

0:004> pt
eax=043afe38 ebx=76cc0000 ecx=00000000 edx=04170000 esi=0176b388 edi=0176de50
eip=04170020 esp=043afd84 ebp=043afde4 iopl=0         nv up ei pl zr na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
04170020 c3              ret

0:004> du edi
0176de50  "KERNEL32.DLL"

0:004> lm m kernel32
Browse full module list
start    end        module name
76cc0000 76db0000   KERNEL32   (pdb symbols)          C:\ProgramData\Dbg\sym\wkernel32.pdb\3B90FDE089777866BB8D6D6FE2B7FB401\wkernel32.pdb


> 13jan_515p: now we need to resolve symbols i.e.
the function name + starting addr in order to
call TerminateProcess via the Export Address Table (EAT)
of kernel32.dll

0:004> dt ntdll!_IMAGE_DOS_HEADER 
   +0x000 e_magic          : Uint2B
   +0x002 e_cblp           : Uint2B
   +0x004 e_cp             : Uint2B
   +0x006 e_crlc           : Uint2B
   +0x008 e_cparhdr        : Uint2B
   +0x00a e_minalloc       : Uint2B
   +0x00c e_maxalloc       : Uint2B
   +0x00e e_ss             : Uint2B
   +0x010 e_sp             : Uint2B
   +0x012 e_csum           : Uint2B
   +0x014 e_ip             : Uint2B
   +0x016 e_cs             : Uint2B
   +0x018 e_lfarlc         : Uint2B
   +0x01a e_ovno           : Uint2B
   +0x01c e_res            : [4] Uint2B
   +0x024 e_oemid          : Uint2B
   +0x026 e_oeminfo        : Uint2B
   +0x028 e_res2           : [10] Uint2B
   +0x03c e_lfanew         : Int4B          <- offset to PE header


0:004> dt ntdll!_IMAGE_NT_HEADERS 
   +0x000 Signature        : Uint4B
   +0x004 FileHeader       : _IMAGE_FILE_HEADER
   +0x018 OptionalHeader   : _IMAGE_OPTIONAL_HEADER     <- offset to DataDirectory

0:004> dt ntdll!_IMAGE_OPTIONAL_HEADER 
   +0x000 Magic            : Uint2B
   +0x002 MajorLinkerVersion : UChar
   +0x003 MinorLinkerVersion : UChar
   +0x004 SizeOfCode       : Uint4B
   +0x008 SizeOfInitializedData : Uint4B
   +0x00c SizeOfUninitializedData : Uint4B
   +0x010 AddressOfEntryPoint : Uint4B
   +0x014 BaseOfCode       : Uint4B
   +0x018 BaseOfData       : Uint4B
   +0x01c ImageBase        : Uint4B
   +0x020 SectionAlignment : Uint4B
   +0x024 FileAlignment    : Uint4B
   +0x028 MajorOperatingSystemVersion : Uint2B
   +0x02a MinorOperatingSystemVersion : Uint2B
   +0x02c MajorImageVersion : Uint2B
   +0x02e MinorImageVersion : Uint2B
   +0x030 MajorSubsystemVersion : Uint2B
   +0x032 MinorSubsystemVersion : Uint2B
   +0x034 Win32VersionValue : Uint4B
   +0x038 SizeOfImage      : Uint4B
   +0x03c SizeOfHeaders    : Uint4B
   +0x040 CheckSum         : Uint4B
   +0x044 Subsystem        : Uint2B
   +0x046 DllCharacteristics : Uint2B
   +0x048 SizeOfStackReserve : Uint4B
   +0x04c SizeOfStackCommit : Uint4B
   +0x050 SizeOfHeapReserve : Uint4B
   +0x054 SizeOfHeapCommit : Uint4B
   +0x058 LoaderFlags      : Uint4B
   +0x05c NumberOfRvaAndSizes : Uint4B
   +0x060 DataDirectory    : [16] _IMAGE_DATA_DIRECTORY     <- offset to Export Directory
   
 typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;        // +0x00 → almost always 0 in real files
    DWORD   TimeDateStamp;          // +0x04 → linker timestamp
    WORD    MajorVersion;           // +0x08 → usually 0
    WORD    MinorVersion;           // +0x0A → usually 0
    DWORD   Name;                   // +0x0C → RVA to ASCII module name
    DWORD   Base;                   // +0x10 → ordinal base (usually 1)
    DWORD   NumberOfFunctions;      // +0x14 → total exported functions
    DWORD   NumberOfNames;          // +0x18 → number of named exports
    DWORD   AddressOfFunctions;     // +0x1C → RVA to Export Address Table (EAT)
    DWORD   AddressOfNames;         // +0x20 → RVA to Export Name Pointer Table
    DWORD   AddressOfNameOrdinals;  // +0x24 → RVA to Export Ordinal Table
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;


> 14jan_1010a: wasted most of the first session

- walk AddressOfNames to get the index
- use index in AddressOfNameOrdinals to get the ordinal
- use ordinal in AddressOfFunctions to get the function addr 

we will resolve LoadLibraryA so we do not have to bother with 
GetProcAddress

> 14jan_1142a: got the asm from the book but having a tough time getting my head around this
first modification was to first ensure kernel32 is found before looking for other funcs
- store regState in stack
- ebx holds kernel32 base addr
- at offset 0x3c

FS:[0x30]
  ↓
PEB
  ↓ +0x0C
PEB_LDR_DATA
  ↓ +0x1C
LDR_DATA_TABLE_ENTRY
  ↓ +0x18
IMAGE_DOS_HEADER
  ↓ +0x3C (e_lfanew)
IMAGE_NT_HEADER
  ↓ +0x18 (_IMAGE_OPTIONAL_HEADER) <- can straight up use +0x78 from here
IMAGE_OPTIONAL_HEADER              
  ↓ +0x60 (_IMAGE_DATA_DIRECTORY)
IMAGE_DATA_DIRECTORY
  -> +0x0 (VirtualAdress)


14jan_103p: hash function was pretty easy to understand and implement

14jan_134p: it works, was able to exit cleanly. dont understand the compare code still though,
gna move forward still

okay so note that the warning for null byte detection has been popping up this whole time, 
need alternate instructions to avoid null bytes

(probably should update the nasm/keystone modules to autodetect null bytes in an instruction and
attempt at swapping it for an alternate)

"""

import ctypes

# Generic Imports
import socket
import struct
import sys
import platform
from tkinter.tix import Tree
from colorama import Back, Fore, Style

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
        sub esp, 0x210                              ; Allocate 528 bytes of local stack space
        

    FIND_KERNEL32:
        xor ecx, ecx                                ; ECX = 0
        mov esi, fs:[ecx + 0x30]                    ; ESI = PEB (Process Environment Block)
        mov esi, [esi + 0x0C]                       ; ESI = PEB_LDR_DATA (loader data structure)
        mov esi, [esi + 0x1C]                       ; ESI = InInitializationOrderModuleList (first module entry)

    FIND_NEXT_MODULE:
        mov ebx, [esi + 0x08]                       ; EBX = base address of current module
        mov edi, [esi + 0x20]                       ; EDI = pointer to module name (wide string)
        mov esi, [esi]                              ; ESI = next module in linked list (FLINK)
        cmp [edi + 12*2], cx                        ; Check for null terminator at offset 24 (12th wide char)
        jne FIND_NEXT_MODULE                        ; If not kernel32, loop to next module


    FIND_FUNCTION_SHORTEN:
        jmp FIND_FUNCTION_SHORTEN_BNC               ; Skip over the actual function code
    
    FIND_FUNCTION_RET:
        pop esi                                     ; Pop return address from call
        mov [ebp + 0x04], esi                       ; Store function address pointer on stack
        jmp RESOLVE_SYMBOLS_KERNEL32                ; Jump to resolve kernel32 symbols

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

    RESOLVE_SYMBOLS_KERNEL32:
        push {hashFuncName("TerminateProcess")}     ; Push ROR hash of "TerminateProcess" function name
        call [ebp + 0x04]                           ; Call FIND_FUNCTION to resolve address
        mov [ebp + 0x10], eax                       ; Store TerminateProcess address in [EBP+0x10]
    
    EXEC_SHELLCODE:
        xor ecx, ecx                                ; ECX = 0
        push ecx                                    ; Push 0 as exit code parameter
        push 0xFFFFFFFF                             ; Push -1 (current process handle constant)
        call eax                                    ; Call TerminateProcess(hProcess=-1, uExitCode=0)

    """

    return asm


# Keystone
def get_shellcode():
    asm = ret_asm()

    shellcode = b""
    # shellcode += keystone_asm(CODE=asm, debug=True)
    shellcode += nasm_asm(CODE=asm, debug=True)

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
        print(f"{Fore.LIGHTWHITE_EX}[+] Python Architecture: {plat[0]}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTWHITE_EX}[+] Platform: {plat[1]}{Style.RESET_ALL}")
        stuff = stuff_ctypes()

        print(f"{Fore.LIGHTRED_EX}[+]{Fore.LIGHTYELLOW_EX} Done!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.LIGHTRED_EX}{e}")
    except KeyboardInterrupt:
        print(f"{Fore.LIGHTRED_EX}\n\n[!] Caught CTRL+C \nExiting...{Style.RESET_ALL}")
