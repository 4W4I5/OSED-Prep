"""
Pykd Code Cave Locator Tool
"""

from pykd import *
import sys
import time

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

def log(msg):
    """
    Log a message to console.
    @param msg: Message string
    @return: None
    """
    print("[+] " + msg)

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
    pe_info = getPEInfo(mod.name())
    sections = pe_info['sections']
    for sec in sections:
        if sec['name'].lower() == '.text':
            return sec['va'], sec['size']
    return None, None

def isPageReadWrite(address):
    """
    Return True if a mem page is marked as read-write
    @param address: address
    @return: Bool
    """
    try:
        protect = getVaProtect(address)
    except:
        protect = 0x1
    return protect in MEM_ACCESS_RW.keys()

def has_null_bytes(value):
    """
    Check if the value has null bytes in its byte representation (32-bit).
    @param value: int value
    @return: Bool
    """
    return (value & 0xFF) == 0 or ((value >> 8) & 0xFF) == 0 or ((value >> 16) & 0xFF) == 0 or ((value >> 24) & 0xFF) == 0

def findCodeCaves(va, size, min_length):
    """
    Find code caves (consecutive null bytes) in the given range.
    @param va: start address
    @param size: size
    @param min_length: minimum length
    @return: list of (start, length)
    """
    caves = []
    ptr = va
    end = va + size
    while ptr < end:
        if loadSignBytes(ptr, 1)[0] == 0:
            start = ptr
            while ptr < end and loadSignBytes(ptr, 1)[0] == 0:
                ptr += 1
            length = ptr - start
            if length >= min_length:
                caves.append((start, length))
        else:
            ptr += 1
    return caves

if __name__ == "__main__":
    print("#" * 63)
    print("# locateCodeCaves.py pykd Code Cave Locator module #")
    print("#" * 63)

    try:
        base_addr_hex = sys.argv[1]
        base_addr = int(base_addr_hex, 16)
    except (IndexError, ValueError):
        log("Syntax: locateCodeCaves.py base_address_hex [min_length]")
        log("Example: locateCodeCaves.py 0x77400000 100")
        sys.exit()

    min_length = 100
    if len(sys.argv) > 2:
        try:
            min_length = int(sys.argv[2])
        except ValueError:
            log("min_length must be an integer")
            sys.exit()

    mod = getModule(base_addr)
    if not mod:
        log("Module not found at address 0x%x" % base_addr)
        sys.exit()

    va, size = getCodeSection(mod)
    if not va:
        log("Code section not found")
        sys.exit()

    log("Scanning code section for code caves...")
    caves = findCodeCaves(va, size, min_length)
    usable_caves = []
    for start, length in caves:
        if isPageReadWrite(start) and not has_null_bytes(start):
            offset = start - mod.begin()
            if not has_null_bytes(offset):
                usable_caves.append((offset, length))

    if usable_caves:
        for offset, length in usable_caves:
            log("Code cave at offset 0x%x, length %d bytes" % (offset, length))
    else:
        log("No usable code caves found with read-write permissions")
