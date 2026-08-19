r"""Test decoder logic."""
from modules.shellcode_module import getShellcode, buf
from modules.util_module import bad_chars

enc, reps = getShellcode(encoded=True, bad_chars=bad_chars)

print("Replacements:")
for r in reps:
    print(f"  idx={r['index']}: orig=0x{r['original']:02x} -> repl=0x{r['replacement']:02x} (corr=0x{r['correction']:02x})")

print("\n--- Manual decode (what verify_decoder.py does) ---")
orig = bytearray(enc)
for r in reps:
    idx, corr = r['index'], r['correction']
    orig[idx] = (r['replacement'] + corr) & 0xFF
print(bytes(orig)[:40].hex())

print("\n--- buf[:40]: ---")
print(buf[:40].hex())

print("\nMatch:", bytes(orig) == buf)