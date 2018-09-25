import nmap
import os
import requests
import json
import time
from scans import utils
from tenable_io.api.scans import ScanExportRequest
from tenable_io.client import TenableIOClient
from tenable_io.exceptions import TenableIOApiException
from httpobs.scanner.local import scan


class Task:
    # One target will have at least one task
    # One task will have one target at a time
    def __init__(self, target):
        self.target = target

    def run(self,):
        # DO stuff
        return


class PortScanTask(Task):
    def __init__(self, target):
        super().__init__(self, target)

    # Not sure how these would work, as python-nmap still depends
    # on nmap as the executable to be present locally

    def runTCPPortScan(self):

        target_IPs = utils.resolveDNS(self.target, 'A')

        nm = nmap.PortScanner()
        nmap_arguments = '-v -Pn -sT -sV --top-ports 1000 --open -T4 --dns-servers 8.8.8.8'

        results = nm.scan(hosts=target_IPs, arguments=nmap_arguments, sudo=False)
        return nm

    def runUDPPortScan(self):

        target_IPs = utils.resolveDNS(self.target, 'A')

        udp_ports = "17,19,53,67,68,123,137,138,139,"\
          "161,162,500,520,646,1900,3784,3785,5353,27015,"\
          "27016,27017,27018,27019,27020,27960"

        nm = nmap.PortScanner()
        nmap_arguments = '-v -Pn -sU -sV --open -T4 --dns-server 8.8.8.8'

        results = nm.scan(hosts=target_IPs, arguments=nmap_arguments, sudo=True)
        return nm


class NessusTask(Task):

    def __init__(self, target):
        super().__init__(self, target)

    def runNessusScan():

        # Reference file: https://github.com/tenable/Tenable.io-SDK-for-Python/blob/master/examples/scans.py
        try:
            # According to documentation TenableIO client can be initialised
            # in a number of ways. I choose here the environment variable option.
            # On the same tty, the user needs to set TENABLEIO_ACCESS_KEY and
            # TENABLEIO_SECRET_KEY variables. I prefer this over storing keys
            # in a config file on disk.
            client = TenableIOClient(access_key=os.environ('TENABLEIO_ACCESS_KEY'), secret_key=os.environ('TENABLEIO_SECRET_KEY'))
        
            # Run a basic network scan
            nessus_scan = client.scan_helper.create(name='Scan_for_ ' + self.target, text_targets=self.target, template='basic')

            # Let's allow up to 30 minutes for the scan to run and finish, otherwise cancel
            starttime = time()
            nessus_scan.launch().wait_or_cancel_after(30)
            assert time() - starttime >= 30

            # We need to return the results here
            return client.scan_helper.id(nessus_scan.id)

        except TenableIOApiException as TIOException:
            # return False
            return TIOException

        return True


class ZAPScanTask(Task):

    # Not sure if this is feasible with serverless as it relies on a Docker image
    # Leaving here for completeness for now
    def __init__(self, target):
        super().__init__(self, target)


class MozillaHTTPObservatoryTask(Task):

    def __init__(self, target):
        super().__init__(self, target)

    def runHTTPObsScan():

        try:
            httpobs_result = scan(self.target)
            return httpobs_result

        except Exception as httpobsError:
            # return False
            return httpobsError


class MozillaTLSObservatoryTask(Task):

    def __init__(self, target):
        super().__init__(self, target)

    def runTLSObsScan():

        # Will have to invoke the API manually here
        # Ref: https://github.com/mozilla/tls-observatory#api-endpoints
        try:
            tlsobs_API_base = os.environ('TLSOBS_API_URL')
            tlsbobs_API_scan_URL = "{0}/api/v1/scan?target={1}&rescan=true".format(tlsobs_API_base, self.target)
            tlsobs_response = requests.post(tlsbobs_API_scan_URL, data='')

            if (tlsobs_response.status == '200'):
                tlsobs_scanID = json.loads(tlsobs_response.text)
                # Wait for a little bit for the scan to finish
                time.sleep(10)
                tlsbobs_API_result_URL = "{0}/api/v1/results?id={1}".format(tlsobs_API_base, tlsobs_scanID['id'])
                response = requests.get(tlsbobs_API_result_URL)
                return response.text
            else:
                return False

        except Exception as TLSObsError:
            # return False
            return TLSObsError


class SSHScanTask(Task):

    def __init__(self, target):
        super().__init__(self, target)

    # We will probably talk to ssh_scan_api here directly
    # Ref: https://github.com/mozilla/ssh_scan_api/blob/master/examples/client.py

    def runSSHScan(port=22):

        try:
            sshscan_API_base = os.environ('SSHSCAN_API_URL')
            sshscan_API_scan_URL = "{0}/api/v1/scan?target={1}".format(sshscan_API_base, self.target)
            body = 'port={0}'.format(port)
            sshscan_response = requests.post(sshscan_API_scan_URL, data=body)

            if (sshscan_response.status == '200'):
                sshscan_uuid = json.loads(tlsobs_response.text)
                # Wait for a little bit for the scan to finish
                time.sleep(5)
                sshscan_API_result_URL = "{0}/api/v1/scan/results?uuid={1}".format(sshscan_API_base, sshscan_uuid['uuid'])
                response = requests.get(sshscan_API_result_URL)
                return response.text
            else:
                return False

        except Exception as SSHScanError:
            # return False
            return SSHScanError


class DirBruteTask(Task):

    # Not sure if this is feasible with serverless as it relies on a Docker image or a binary being installed
    # Leaving here for completeness for now
    def __init__(self, target):
        super().__init__(self, target)
