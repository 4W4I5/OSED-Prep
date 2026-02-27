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


"""

import ctypes

# Generic Imports
import socket
import struct
import sys
import platform
from colorama import Back, Fore, Style

# Custom modules
from modules.keystone_module import keystone_asm
from modules.msfvenom_module import generatePayload
from modules.nasm_module import nasm_asm
from modules.rorHash_module import hashFuncName
# from modules.syscallFinder_module import get_syscall_number    # cant use on <python3.8


def ret_asm() -> str:

    asm = f"""
    START:
        int3                                        ; Remove when not debugging  
    
    SETUP_STACK:
        mov ebp, esp                                ; Move ESP to EBP, setup stack frame
        sub esp, 0x200                              ; Allocate 512 bytes
        call find_kernel32                          ; Call find_kernel32
        push {hashFuncName("TerminateProcess")}     ; Push hash of TerminateProcess
        call find_function                          ; Call find_function
        xor ecx, ecx                                ; Zero out ECX
        push ecx                                    ; Push 0 (exit code)
        push 0xFFFFFFFF                             ; Push -1 (current process handle)
        call eax                                    ; Call TerminateProcess

    find_kernel32:
        xor ecx, ecx                                ; Zero out ECX
        mov esi, fs:[ecx + 0x30]                    ; move PEB to ESI
        mov esi, [esi + 0x0C]                       ; move PEB_LDR_DATA to ESI
        mov esi, [esi + 0x1C]                       ; move InInitializationOrderModuleList to ESI

    find_next_module:
        mov ebx, [esi + 0x08]                       ; move base addr of module to EBX
        mov edi, [esi + 0x20]                       ; move module name to EDI
        mov esi, [esi]                              ; move pointer to [FLINK] next module to ESI
        cmp [edi + 12*2], cx                        ; find null terminator at offset 24 (12th wchar)
        jne find_next_module                        ; if not NULL, keep looking
        ret

    ; At this point, EBX holds the base address of kernel32.dll

    find_function:
        pushad                                      ; Save all registers
        mov eax, [ebx + 0x3C]                       ; Offset to IMAGE_NT_HEADERS (BASE + 0x3C)
        mov edi, [ebx + eax + 0x78]                 ; Export Table Dir RVA (IMAGE_NT_HEADERS + 0x78)
        add edi, ebx                                ; Export Table Dir VMA (BASE + RVA)
        mov ecx, [edi + 0x18]                       ; Number of Names
        mov eax, [edi + 0x20]                       ; Address of Names RVA
        add eax, ebx                                ; Address of Names VMA (RVA + BASE)
        mov [ebp - 4], eax                          ; Store Address of Names VMA in [EBP-4] for later

    search_loop:
        jecxz find_function_done                    ; If ECX is 0, we are done
        dec ecx                                     ; Decrement ECX
        mov eax, [ebp - 4]                          ; Load Address of Names VMA
        mov esi, [eax + ecx*4]                      ; Get RVA of function name
        add esi, ebx                                ; Get VMA of function name

    compute_hash:
        xor eax, eax                                ; Zero out EAX (hash accumulator)
        cdq                                         ; Clear EDX (Takes sign bit of EAX and fills EDX with 0s or 1s)
        cld                                         ; Clear direction flag

    hash_loop:
        lodsb                                       ; Load byte at DS:ESI into AL, increment ESI
        test al, al                                 ; Test if AL is NULL terminator
        jz hash_done                                ; If zero, we are done
        ror edx, 0xd                                ; Rotate EDX right by 13
        add edx, eax                                ; Add AL to EDX
        jmp hash_loop                               ; Repeat
    hash_done:

    compare_hash_to_function:
        cmp edx, [esp + 0x24]                       ; Compare computed hash (EDX) to target hash (on stack)
        jnz search_loop                             ; If not equal, continue searching
        mov edx, [edi + 0x24]                       ; AddressofNameOrdinals RVA
        add edx, ebx                                ; AddressofNameOrdinals VMA
        mov cx, [edx + ecx*2]                       ; Get the ordinal
        mov edx, [edi + 0x1C]                       ; AddressofFunctions RVA
        add edx, ebx                                ; AddressofFunctions VMA
        mov eax, [edx + ecx*4]                      ; Get function RVA
        add eax, ebx                                ; Get function VMA
        mov [esp + 0x1c], eax                       ; Store function address in EAX(stack) for return
    find_function_done:
        popad                                       ; Restore all registers
        ret



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
        print(f"{Fore.LIGHTBLUE_EX}{buf}{Style.RESET_ALL}")

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
