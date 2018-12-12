import socket
import logging
from netaddr import valid_ipv4
from lib import port, task


logger = logging.getLogger()
logger.setLevel(logging.INFO)


class Target:

    # Here, tasklist is a list of Task objects
    def __init__(self, target, default_port=80, scanID=''):
        self.targetname = target
        self.port = port.Port(default_port)
        self.id = scanID
        self.tasklist = []

    def valid_ip(self):
        try:
            valid_ipv4(self.targetname)
            return True
        except BaseException:
            return False

    def valid_fqdn(self):
        try:
            socket.gethostbyname(self.targetname)
            return True
        except socket.error:
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
        
        result_list = []

        for one_task in self.tasklist:

            if isinstance(one_task, task.NmapTask):
                nmap_results = one_task.runNmapScan()
                if nmap_results:
                    logger.info("Nmap port scan(s) successfully ran.")
                    result_list.append(nmap_results)
                else:
                    return False

            elif isinstance(one_task, task.NessusTask):
                nessus_result = one_task.runNessusScan()
                if (nessus_result):
                    logger.info("Tenable.io scan successfully ran.")
                    result_list.append(nessus_result)
                else:
                    return False

                # and one_task.checkScanStatus(nessus_result) == "COMPLETE"):
                #     # Need additional checks here to see if the scan is actually finished
                #     # Don't update without making sure it's finished
                #     one_task.update(nessus_result)

            elif isinstance(one_task, task.MozillaTLSObservatoryTask):
                tlsobs_result = one_task.runTLSObsScan()
                if (tlsobs_result):
                    logger.info("TLS Observatory scan successfully ran.")
                    result_list.append(tlsobs_result)
                else:
                    return False

            elif isinstance(one_task, task.MozillaHTTPObservatoryTask):
                httpobs_result = one_task.runHttpObsScan()
                if (httpobs_result):
                    logger.info("HTTP Observatory scan successfully ran.")
                    result_list.append(httpobs_result)
                else:
                    return False

            elif isinstance(one_task, task.SSHScanTask):
                sshscan_result = one_task.runSSHScan()
                if (sshscan_result):
                    logger.info("SSH scan successfully ran.")
                    result_list.append(sshscan_result)
                else:
                    return False

            elif isinstance(one_task, task.ZAPScanTask):
                zapscan_result = one_task.runZAPScan()
                if (zapscan_result):
                    logger.info("ZAP scan successfully ran.")
                    result_list.append(zapscan_result)
                else:
                    return False

            elif isinstance(one_task, task.DirectoryBruteTask):
                dirbrute_result = one_task.runDirectoryBruteScan()
                if (dirbrute_result):
                    logger.info("Directory brute scan successfully ran.")
                    result_list.append(dirbrute_result)
                else:
                    return False

            else:
                logger.error("No or unidentified task specified")
                return False

        return result_list
