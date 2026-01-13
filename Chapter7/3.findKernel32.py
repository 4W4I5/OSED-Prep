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


but a crash is triggered since theres no cleanup code after ret




"""

import ctypes

# Generic Imports
import socket
import struct
import sys

from colorama import Back, Fore, Style

# Custom modules
from modules.keystone_module import keystone_asm
from modules.msfvenom_module import generatePayload
from modules.nasm_module import nasm_asm
# from modules.syscallFinder_module import get_syscall_number    # cant use on <python3.8


def ret_asm() -> str:

    asm = f"""
    ; This compares all modules in InitializationOrderModuleList
    ; since kernel32.dll is always the 1st module to be initialized,
    ; we can just return when we find the first module with a NULL
    ; at offset 24 (12th wchar) of the module name
    START:
        int3                           ; Remove when not debugging  
    
    EMULATE_FUNC_CALL:
        mov ebp, esp                    ; Move ESP to EBP, setup stack frame
        sub esp, 0x60                   ; Allocate 60 bytes
    
    find_kernel32:
        xor ecx, ecx                    ; Zero out ECX
        mov esi, fs:[ecx + 0x30]        ; move PEB to ESI
        mov esi, [esi + 0x0C]           ; move PEB_LDR_DATA to ESI
        mov esi, [esi + 0x1C]           ; move InInitializationOrderModuleList to ESI

    find_next_module:
        mov ebx, [esi + 0x08]           ; move base addr of module to EBX
        mov edi, [esi + 0x20]           ; move module name to EDI
        mov esi, [esi]                  ; move pointer to [FLINK] next module to ESI
        cmp [edi + 12*2], cx            ; find null terminator at offset 24 (12th wchar)
        jne find_next_module            ; if not NULL, keep looking
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
        stuff = stuff_ctypes()
        print(f"{Fore.LIGHTRED_EX}[+]{Fore.LIGHTYELLOW_EX} Done!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.LIGHTRED_EX}{e}")
