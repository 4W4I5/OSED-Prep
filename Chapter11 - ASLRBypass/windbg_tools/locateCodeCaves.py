"""
Pykd Code Cave Locator Tool
"""

import sys
import time
from operator import contains

from pykd import *

HEADER = "#" * 80 + "\r\n"
HEADER += "# locateCodeCaves.py - pykd module for Code Cave Discovery\r\n"
HEADER += "#" * 80 + "\r\n\r\n"

# MEM_ACCESS = {
# 0x1   : "PAGE_NOACCESS"                                                    ,
# 0x2   : "PAGE_READONLY"                                                    ,
# 0x4   : "PAGE_READWRITE"                                                   ,
# 0x8   : "PAGE_WRITECOPY"                                                   ,
# 0x10  : "PAGE_EXECUTE"                                                     ,
# 0x20  : "PAGE_EXECUTE_READ"                                                ,
# 0x40  : "PAGE_EXECUTE_READWRITE"                                           ,
# 0x80  : "PAGE_EXECUTE_WRITECOPY"                                           ,
# 0x101 : "PAGE_NOACCESS PAGE_GUARD"                                         ,
# 0x102 : "PAGE_READONLY PAGE_GUARD "                                        ,
# 0x104 : "PAGE_READWRITE PAGE_GUARD"                                        ,
# 0x108 : "PAGE_WRITECOPY PAGE_GUARD"                                        ,
# 0x110 : "PAGE_EXECUTE PAGE_GUARD"                                          ,
# 0x120 : "PAGE_EXECUTE_READ PAGE_GUARD"                                     ,
# 0x140 : "PAGE_EXECUTE_READWRITE PAGE_GUARD"                                ,
# 0x180 : "PAGE_EXECUTE_WRITECOPY PAGE_GUARD"                                ,
# 0x301 : "PAGE_NOACCESS PAGE_GUARD PAGE_NOCACHE"                            ,
# 0x302 : "PAGE_READONLY PAGE_GUARD PAGE_NOCACHE"                            ,
# 0x304 : "PAGE_READWRITE PAGE_GUARD PAGE_NOCACHE"                           ,
# 0x308 : "PAGE_WRITECOPY PAGE_GUARD PAGE_NOCACHE"                           ,
# 0x310 : "PAGE_EXECUTE PAGE_GUARD PAGE_NOCACHE"                             ,
# 0x320 : "PAGE_EXECUTE_READ PAGE_GUARD PAGE_NOCACHE"                        ,
# 0x340 : "PAGE_EXECUTE_READWRITE PAGE_GUARD PAGE_NOCACHE"                   ,
# 0x380 : "PAGE_EXECUTE_WRITECOPY PAGE_GUARD PAGE_NOCACHE"                   ,
# 0x701 : "PAGE_NOACCESS PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"          ,
# 0x702 : "PAGE_READONLY PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"          ,
# 0x704 : "PAGE_READWRITE PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"         ,
# 0x708 : "PAGE_WRITECOPY PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"         ,
# 0x710 : "PAGE_EXECUTE PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"           ,
# 0x720 : "PAGE_EXECUTE_READ PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"      ,
# 0x740 : "PAGE_EXECUTE_READWRITE PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE" ,
# 0x780 : "PAGE_EXECUTE_WRITECOPY PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE" ,
# }

MEM_ACCESS_EXE = {
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
}

PAGE_SIZE = 0x1000


def log(msg, type="info"):
    """
    Log a message to console.
    @param msg: Message string
    @return: None
    """
    if type == "info":
        print("[>] " + msg)
    elif type == "error":
        print("[!!!] " + msg)
    elif type == "success":
        print("[+] " + msg)
    elif type == "warn":
        print("[!] " + msg)


def getModule(base_addr):
    """
    Return a module object.
    @param base_addr: int base address
    @return: pykd module object
    """
    return module(base_addr)


def getCodeSection(mod):
    """
    Get the code section (.text) of the module.
    @param mod: module object
    @return: (va, size) or (None, None)
    """
    base_addr = mod.begin()
    # dd baseAddress + 0x3c -> first dword is offset2
    offset2 = ptrDWord(base_addr + 0x3C)
    # dd baseAddress + 0x2c + offset2 -> offsetOfCodeSection
    offsetOfCodeSection = ptrDWord(base_addr + 0x2C + offset2)
    va = base_addr + offsetOfCodeSection
    # Get size from SizeOfCode
    size = ptrDWord(base_addr + 0x1C + offset2)
    # Run !address on the code section
    dprintln("!address " + hex(va))
    return va, size


def has_null_bytes(value):
    """
    Check if the value has null bytes in its byte representation (32-bit).
    @param value: int value
    @return: Bool
    """
    return (value & 0xFF) == 0 or ((value >> 8) & 0xFF) == 0 or ((value >> 16) & 0xFF) == 0 or ((value >> 24) & 0xFF) == 0


if __name__ == "__main__":
    print("#" * 63)
    print("# locateCodeCaves.py pykd Code Cave Locator module #")
    print("#" * 63)

    try:
        base_addr_hex = sys.argv[1]
        base_addr = int(base_addr_hex, 16)
    except (IndexError, ValueError):
        log("Syntax: locateCodeCaves.py base_address_hex", type="error")
        log("Example: locateCodeCaves.py 0x77400000", type="error")
        sys.exit()

    mod = getModule(base_addr)
    if not mod:
        log("Module not found at address 0x%08x" % base_addr, type="error")
        sys.exit()

    va, size = getCodeSection(mod)
    if not va:
        log("Code section not found", type="error")
        sys.exit()

    log("Scanning code section for code caves...")
    end_addr = va + size
    log("Code section starts at 0x%08x and ends at 0x%08x" % (va, end_addr))

    # Since we're at the end of the supposed cave, iterate backwards until we encounter a non
    # null byte, and calculate the size of the cave. Report back on the offset of the cave
    cave_size = 0
    for addr in range(end_addr - 1, va - 1, -1):
        if ptrByte(addr) == 0:
            cave_size += 1
            # after every 250 bytes report back on the cave size and offset
            if cave_size % 250 == 0:
                log(f"At address 0x{addr:08x}, found {cave_size} null bytes. Continuing...")
        else:
            if cave_size >= 400:
                offset = addr + 1 - va
                log("Found code cave at offset +%x | address 0x%08x with size %d bytes" % (offset, addr + 1, cave_size), type="success")
            cave_size = 0

    # Code to run after the loop ends
    log("Finished scanning code section for code caves.")

    # Null byte check for the last address checked
    if ptrByte(end_addr - 1) == 0:
        log("Null byte detected", type="warn")
