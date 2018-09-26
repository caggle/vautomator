
class Port:
    def __init__(self, port):
        self.port = port

    def valid(self):
        if not isinstance(self.port, int):
            return False
        elif self.port > 65535:
            return False

        return self.port
