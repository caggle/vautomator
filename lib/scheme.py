from urllib.parse import urlparse


class Scheme:
    def __init__(self, target):
        self.url = target

    def valid(self):
        try:
            scheme = urlparse(self.url).scheme
            if scheme == 'http' or scheme == 'https':
                return True
            else:
                return False
        except BaseException:
            return False

