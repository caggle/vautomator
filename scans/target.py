import socket
import sys
import logging
from scans import NessusTask, MozillaHTTPObservatoryTask
from scans import MozillaTLSObservatoryTask, SSHScanTask, Port


class Target:

    # Here, tasklist is a list of Task objects
    def __init__(self, target, port=80, scanID=''):
        self.targetname = target
        self.port = Port(port)
        self.id = scanID
        self.tasklist = []

    def valid_ip(self):
        try:
            socket.ipaddress.ip_address(self.targetname)
            return True
        except:
            return False

    def valid_fqdn(self):
        try:
            socket.gethostbyname(self.targetname)
            return True
        except socket.error:
            return False

    def valid(self):
        # Needed for Python2 unicode nuances
        if sys.version_info[0] < 3:
            if not type(self.targetname) in [str, unicode]:
                return False
        else:
            if not isinstance(self.targetname, str):
                return False

        starts_with_anti_patterns = [
            '127.0.0',
            '10.',
            '172.',
            '192.168',
            '169.254.169.254'
        ]

        for pattern in starts_with_anti_patterns:
            if self.targetname.startswith(pattern):
                return False

        if self.valid_ip() or self.valid_fqdn():
            return True
        
        return False

    def addTask(self, new_task):
        self.tasklist.append(new_task)

    def runTasks(self):

        # TODO: Change the flow of checking status 
        for task in self.tasklist:
            if isinstance(task, NessusTask):
                nessus_result = task.runNessusScan(self.target)
                if (nessus_result and task.checkScanStatus(nessus_result) == "COMPLETE"):
                    # Need additional checks here to see if the scan is actually finished
                    # Don't update without making sure it's finished
                    task.update()
    
            elif isinstance(task, MozillaHTTPObservatoryTask):
                httpobs_result = task.runHTTPObsScan(self.target)
                if (httpobs_result and task.checkScanStatus(httpobs_result) == "COMPLETE"):
                    task.update()
                
            elif isinstance(task, MozillaTLSObservatoryTask):
                tlsobs_result = task.runTLSObsScan(self.target)
                if (tlsobs_result and task.checkScanStatus(tlsobs_result) == "COMPLETE"):
                    task.update()
                
            elif isinstance(task, SSHScanTask):
                sshscan_result = task.runSSHScan(self.target)
                if (sshscan_result and task.checkScanStatus(sshscan_result) == "COMPLETE"):
                    task.update()
                
            else:
                logging.error("No or unidentified task specified!")
                return False

        return (nessus_result & httpobs_result & tlsobs_result & sshscan_result)

