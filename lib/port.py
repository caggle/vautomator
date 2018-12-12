
class Port:
    def __init__(self, port):
        self.port = port

    def valid(self):
        try:
            if not isinstance(self.port, int):
                self.port = int(self.port)
        except BaseException:
            return False
        
        if self.port > 65535:
            return False

        return self.port
       