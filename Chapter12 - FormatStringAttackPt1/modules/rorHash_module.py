import numpy
import sys
import colorama

def _ror_str(byte, count):
    """Rotate right a byte string by count bits."""
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[:-1]
        count -= 1
    return int(binb, 2)

def hashFuncName(functionName):
    edx = 0x00
    ror_count = 0 
    esi = functionName
    for eax in esi:
        edx = edx + ord(eax)
        if ror_count < len(esi)-1:
            edx = _ror_str(edx, 0x0D)
        ror_count += 1
    print(f"\t {colorama.Fore.GREEN}o Function: {functionName} --> Hash: {hex(edx)}{colorama.Style.RESET_ALL}")
    return hex(edx)