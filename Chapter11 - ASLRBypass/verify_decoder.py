r"""Verify that decoder matches the encoder."""
import sys
sys.path.insert(0, '.')

from modules.shellcode_module import getShellcode, generateShellcodeDecoder
from modules.util_module import bad_chars

print('bad_chars:', bad_chars)
enc, reps = getShellcode(encoded=True, bad_chars=bad_chars, debug=False)

print('\nEncoded bytes (first 40):', enc[:40].hex())
print('\nReplacements count:', len(reps))

# Apply corrections in order (simulating ROP decoder execution)
orig = bytearray(enc)
for i, r in enumerate(reps):
    idx, corr = r['index'], r['correction']
    orig[idx] = (r['replacement'] + corr) & 0xFF

print('\nDecoded bytes (first 40):', bytes(orig)[:40].hex())

# Show a few specific indices to verify corrections match
print('\nVerification of correction values:')
for i in range(min(5, len(reps))):
    r = reps[i]
    idx, orig_val, repl_val, corr = r['index'], r['original'], r['replacement'], r['correction']
    decoded_add = (repl_val + corr) & 0xFF
    print(f'  idx={idx:#06x}: original=0x{orig_val:02x}, replacement=0x{repl_val:02x}, correction=0x{corr:02x}')
    print(f'           ADD decode = (0x{repl_val:02x}+0x{corr:02x})&0xFF = 0x{decoded_add:02x}')

# Check if corrections are addition-based
print('\nCorrection type analysis:')
add_based = all((r['replacement'] + r['correction']) & 0xFF == r['original'] for r in reps)
print(f'  Addition-based: {add_based}')

if add_based:
    print('\n[OK] All corrections correctly decode back to original values.')

# Verify against raw buf
from modules.shellcode_module import buf
if bytes(orig) == buf:
    print('\n[OK] Decoded output matches original shellcode!')
else:
    print('\n[MISMATCH] Decoded output differs from original.')
    diff = 0
    for i, (a, b) in enumerate(zip(bytes(orig), buf)):
        if a != b:
            diff += 1
    print(f'  {diff} byte(s) differ out of {len(buf)}')
