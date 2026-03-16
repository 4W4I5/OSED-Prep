"""
Pykd Gadget Discovery Tool using rp++
"""

import os
import subprocess
import sys
import time

from pykd import *

HEADER = "#" * 80 + "\r\n"
HEADER += "# rop86.py - pykd module for Gadget Discovery using rp++\r\n"
HEADER += "#" * 80 + "\r\n\r\n"


def log(msg):
    """
    Log a message to console.
    @param msg: Message string
    @return: None
    """
    print("[+] " + msg)


def getModule(modname):
    """
    Return a module object.
    @param modname: string module name
    @return: pykd module object
    """
    return module(modname)


def get_gadget_score(gadget):
    """
    Assign a score to a gadget based on ROP desirability (0-100).
    Higher scores indicate more valuable gadgets for building ROP chains.
    Based on control gained, side effects, length, and generality.
    """
    score = 0
    gadget_lower = gadget.lower()
    instructions = [inst.strip() for inst in gadget.split(";") if inst.strip()]
    num_instructions = len(instructions)

    # Base scores based on gadget type
    if "syscall" in gadget_lower or "int" in gadget_lower:
        score = 92  # Syscall trigger
    elif "pop" in gadget_lower:
        pop_count = gadget_lower.count("pop")
        if pop_count == 1:
            score = 100  # Single register pop
        elif pop_count > 1:
            score = 90 - 5 * (pop_count - 1)  # Multi-pop: 90 for 2, 85 for 3, etc.
    elif "mov" in gadget_lower and "[" in gadget and "]" in gadget:
        score = 82  # Memory write
    elif "mov" in gadget_lower and not ("[" in gadget):
        score = 75  # Register move
    elif ("xor" in gadget_lower or "sub" in gadget_lower) and any(reg in gadget_lower for reg in ["eax", "ebx", "ecx", "edx"]):
        score = 70  # Zeroing
    elif any(op in gadget_lower for op in ["add", "sub"]) and not "xor" in gadget_lower:
        score = 65  # Arithmetic
    elif any(op in gadget_lower for op in ["inc", "dec"]):
        score = 60  # Increment/decrement
    elif "call" in gadget_lower or "jmp" in gadget_lower:
        score = 88  # Indirect call/jump
    elif "xchg" in gadget_lower or "leave" in gadget_lower:
        score = 85  # Stack pivot
    elif "push" in gadget_lower and "pop" in gadget_lower:
        score = 50  # Push/pop combos
    elif "cmp" in gadget_lower or any(cond in gadget_lower for cond in ["je", "jne", "jg", "jl"]):
        score = 40  # Conditional
    elif num_instructions > 3:
        score = 30  # Long chains
    else:
        score = 10  # Partial control or other

    # Side-effect penalties
    # Clobbers useful registers (count register mentions)
    registers = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"]
    clobbered_count = sum(1 for reg in registers if reg in gadget_lower)
    if clobbered_count > 1:
        score -= 20

    # Modifies stack pointer
    if "esp" in gadget_lower:
        score -= 15

    # >3 instructions (already partially handled in base score)
    if num_instructions > 3:
        score -= 10

    # Requires controlled memory
    if "[" in gadget and "]" in gadget:
        score -= 10

    # Ensure score doesn't go below 0
    score = max(0, score)

    return score


if __name__ == "__main__":
    print("#" * 63)
    print("# rop86.py pykd Gadget Discovery module using rp++ #")
    print("#" * 63)

    try:
        arg1 = sys.argv[1].strip()
    except IndexError:
        log("Syntax: rop86.py <module_name_or_address> [num_gadgets] [sort]")
        log("Example: rop86.py ntdll 5 sort")
        sys.exit()

    try:
        num_gadgets = int(sys.argv[2])
    except IndexError:
        num_gadgets = 5
    except ValueError:
        log("num_gadgets must be an integer")
        sys.exit()

    try:
        arg3 = sys.argv[3].strip()
        sort_by_score = arg3.lower() == "sort"
    except IndexError:
        sort_by_score = False

    if arg1.startswith("0x"):
        try:
            addr = int(arg1, 16)
            mod = module(addr)
        except ValueError:
            log("Invalid address format")
            sys.exit()
    else:
        mod = getModule(arg1)

    if not mod:
        log("Module not found")
        sys.exit()

    # Get base address
    base_addr = mod.begin()
    log("Image base address: 0x{:08x}".format(base_addr))

    # Get image path using !lmi command
    lmi_output = dbgCommand("!lmi " + mod.name())
    image_path = None
    for line in lmi_output.split("\n"):
        if "Image Name:" in line:
            image_path = line.split("Image Name:")[1].strip()
            break
    if not image_path:
        log("Could not find image path for module " + mod.name())
        sys.exit()

    exe_path = os.path.join(os.path.dirname(sys.argv[0]), "rp-win-x86.exe")
    output_file = os.path.join(os.path.dirname(sys.argv[0]), mod.name() + "_rop_gadgets.txt")

    log("Running rp++ on " + image_path)
    start = time.time()
    try:
        with open(output_file, "w") as f:
            subprocess.run([exe_path, "-f", image_path, "-r", str(num_gadgets), "--unique", "-i", "2"], stdout=f, check=True)
    except subprocess.CalledProcessError as e:
        log("Error running rp++: " + str(e))
        sys.exit()
    except FileNotFoundError:
        log("rp-win-x86.exe not found in " + os.path.dirname(sys.argv[0]))
        sys.exit()

    end = time.time()
    log("rp++ completed in %d secs." % int(end - start))

    # Process the output file to add offsets and sort by usefulness
    try:
        with open(output_file, "r") as f:
            lines = f.readlines()
        gadgets = []
        for line in lines:
            line = line.strip()
            if line.startswith("0x"):
                try:
                    addr_str, gadget = line.split(":", 1)
                    addr = int(addr_str, 16)
                    offset = addr - base_addr
                    new_line = "+0x{:08x} {}: {}".format(offset, addr_str, gadget.strip())
                    score = get_gadget_score(gadget.strip())
                    gadgets.append((score, new_line))
                except ValueError:
                    gadgets.append((0, line))  # Low score for unparseable lines
            else:
                gadgets.append((0, line))  # Headers or other non-gadget lines

        # Sort by score descending if requested, otherwise by offset ascending
        if sort_by_score:
            gadgets.sort(key=lambda x: x[0], reverse=True)
        else:
            gadgets.sort(key=lambda x: int(x[1].split()[0][1:], 16))

        with open(output_file, "w") as f:
            for score, line in gadgets:
                f.write(line + "\n")
    except FileNotFoundError:
        log("Output file not created")

    # Read and print the output
    try:
        with open(output_file, "r"):
            pass  # Just check if file exists
        log("Gadgets saved to " + output_file)
        # Open the file in Notepad++ if available, otherwise Notepad
        notepad_pp_paths = ["C:\\Program Files\\Notepad++\\notepad++.exe", "C:\\Program Files (x86)\\Notepad++\\notepad++.exe"]
        notepad_pp = None
        for path in notepad_pp_paths:
            if os.path.exists(path):
                notepad_pp = path
                break
        if notepad_pp:
            subprocess.Popen([notepad_pp, output_file])
        else:
            subprocess.Popen(["notepad.exe", output_file])
    except FileNotFoundError:
        log("Output file not created")
