import socket
import sys
import logging
from scans import NessusTask, MozillaHTTPObservatoryTask
from scans import MozillaTLSObservatoryTask, SSHScanTask, Port


class Target:
    # TODO: Change this class

    def __init__(self, target, port):
        self.target = target
        self.port = Port(port)

    def valid_ip(self):
        try:
            socket.ipaddress.ip_address(self.target)
            return True
        except:
            return False

    def valid_fqdn(self):
        try:
            socket.gethostbyname(self.target)
            return True
        except socket.error:
            return False

    def valid(self):
        # Needed for Python2 unicode nuances
        if sys.version_info[0] < 3:
            if not type(self.target) in [str, unicode]:
                return False
        else:
            if not isinstance(self.target, str):
                return False

        starts_with_anti_patterns = [
            '127.0.0',
            '10.',
            '172.',
            '192.168',
            '169.254.169.254'
        ]

        for pattern in starts_with_anti_patterns:
            if self.target.startswith(pattern):
                return False

        if self.valid_ip() or self.valid_fqdn():
            return True
        
        return False

    def addTask(self, new_task):
        if isinstance(new_task, NessusTask):
            nessus_result = NessusTask.runNessusScan(self.target)
            return nessus_result
        elif isinstance(new_task, MozillaHTTPObservatoryTask):
            httpobs_result = MozillaHTTPObservatoryTask.runHTTPObsScan(self.target)
            return httpobs_result
        elif isinstance(new_task, MozillaTLSObservatoryTask):
            tlsobs_result = MozillaTLSObservatoryTask.runTLSObsScan(self.target)
            return tlsobs_result
        elif isinstance(new_task, SSHScanTask):
            sshscan_result = SSHScanTask.runSSHScan(self.target)
            return sshscan_result
        else:
            logging.error("No or unidentified task specified!")
            return False
