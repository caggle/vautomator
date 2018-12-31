import socket
import logging
from netaddr import valid_ipv4
from urllib.parse import urlparse
from lib import port, task


class Target:

    # Here, tasklist is a list of Task objects
    def __init__(self, target, default_port=80, scanID=''):
        self.targetname = target
        self.targetdomain = ""
        self.port = port.Port(default_port)
        self.id = scanID
        self.tasklist = []

    def isURL(self):
        if not self.valid() and "http" in self.targetname:
            self.targetdomain = urlparse(self.targetname).netloc
            return True
        else:
            self.targetdomain = self.targetname
            return False

    def valid_ip(self):
        return valid_ipv4(self.targetname)

    def valid_fqdn(self):
        try:
            socket.gethostbyname(self.targetname)
            return True
        except Exception:
            return False

    def valid(self):
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
        
        # result_list = []
        result_dict = {'nmap': False, 'nessus': False, 'tlsobs': False, 'httpobs': False, 'sshscan': False, 'zapscan': False, 'dirbrute': False}

        for one_task in self.tasklist:

            if isinstance(one_task, task.NmapTask):
                nmap_results = one_task.runNmapScan()
                if nmap_results:
                    logging.info("Nmap port scan(s) successfully ran.")
                    result_dict.update({'nmap': True})

            elif isinstance(one_task, task.NessusTask):
                nessus_results = one_task.runNessusScan()
                if (nessus_results):
                    logging.info("Tenable.io scan successfully ran.")
                    result_dict.update({'nessus': True})

                # and one_task.checkScanStatus(nessus_result) == "COMPLETE"):
                #     # Need additional checks here to see if the scan is actually finished
                #     # Don't update without making sure it's finished
                #     one_task.update(nessus_result)

            elif isinstance(one_task, task.MozillaTLSObservatoryTask):
                tlsobs_results = one_task.runTLSObsScan()
                if (tlsobs_results and tlsobs_results.returncode == 0):
                    logging.info("TLS Observatory scan successfully ran.")
                    result_dict.update({'tlsobs': True})

            elif isinstance(one_task, task.MozillaHTTPObservatoryTask):
                httpobs_results = one_task.runHttpObsScan()
                # 0 is the returncode for successful execution
                if (httpobs_results and httpobs_results.returncode == 0):
                    logging.info("HTTP Observatory scan successfully ran.")
                    result_dict.update({'httpobs': True})
                    print(result_dict)

            elif isinstance(one_task, task.SSHScanTask):
                sshscan_results = one_task.runSSHScan()
                if (sshscan_results and sshscan_results.returncode == 0):
                    logging.info("SSH scan successfully ran.")
                    result_dict.update({'sshscan': True})

            elif isinstance(one_task, task.ZAPScanTask):
                zapscan_results = one_task.runZAPScan()
                if (zapscan_results and zapscan_results.returncode == 0):
                    logging.info("ZAP scan successfully ran.")
                    result_dict.update({'zapscan': True})

            elif isinstance(one_task, task.DirectoryBruteTask):
                dirbrute_results = one_task.runDirectoryBruteScan()
                if (dirbrute_results and dirbrute_results.returncode == 0):
                    logging.info("Directory brute scan successfully ran.")
                    result_dict.update({'dirbrute': True})

            else:
                logging.error("No or unidentified task specified")
                return False

        return result_dict
