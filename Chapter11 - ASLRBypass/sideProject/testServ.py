import random
from http.server import BaseHTTPRequestHandler, HTTPServer

# Test server that returns a random 32-bit address on each request
# only reason to make this was so that i dont bother w resetting tivoli

class AddressHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Generate a random 32-bit address
        random_address = random.randint(0, 0xFFFFFFFF)

        # Format as hex string
        address_str = f"0x{random_address:08x}"

        # Create response
        response = f"Address: {address_str}".encode("utf-8")

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-Length", len(response))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        # Suppress default logging
        pass


if __name__ == "__main__":
    server = HTTPServer(("localhost", 11460), AddressHandler)
    print("Server running on http://localhost:11460")
    server.serve_forever()
