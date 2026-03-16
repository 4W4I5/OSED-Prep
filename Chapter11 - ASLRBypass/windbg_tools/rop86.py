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


if __name__ == "__main__":
    print("#" * 63)
    print("# rop86.py pykd Gadget Discovery module using rp++ #")
    print("#" * 63)

    try:
        arg1 = sys.argv[1].strip()
    except IndexError:
        log("Syntax: rop86.py <module_name_or_address> [num_gadgets]")
        log("Example: rop86.py ntdll 5")
        sys.exit()

    try:
        num_gadgets = int(sys.argv[2])
    except IndexError:
        num_gadgets = 5
    except ValueError:
        log("num_gadgets must be an integer")
        sys.exit()

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
            subprocess.run([exe_path, "-f", image_path, "-r", str(num_gadgets), "--unique"], stdout=f, check=True)
    except subprocess.CalledProcessError as e:
        log("Error running rp++: " + str(e))
        sys.exit()
    except FileNotFoundError:
        log("rp-win-x86.exe not found in " + os.path.dirname(sys.argv[0]))
        sys.exit()

    end = time.time()
    log("rp++ completed in %d secs." % int(end - start))

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
