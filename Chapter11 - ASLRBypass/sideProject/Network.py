# This is the class to send over buffer/process responses

class Connection:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
    def connect(self):
        # code to connect to the server
        pass
    def send(self, data):
        # code to send data to the server
        pass    
    def receive(self):
        # code to receive data from the server
        pass
    