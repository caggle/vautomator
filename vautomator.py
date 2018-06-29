#!/usr/bin/env python

from __future__ import print_function
import sys
import argparse
import re
import subprocess
import nmap
import docker
import shlex
import logging
import verboselogs
import coloredlogs
import socket
import os
import tarfile
import time
from distutils.spawn import find_executable
from netaddr import valid_ipv4, valid_ipv6, IPNetwork
from urllib.parse import urlparse
from tenable_io.api.scans import ScanExportRequest
from tenable_io.client import TenableIOClient
from tenable_io.exceptions import TenableIOApiException
from httpobs.scanner.local import scan

# TODO: 
# 1) Write tests

verboselogs.install()
logger = logging.getLogger(__name__)
# Default logging level is INFO
coloredlogs.install(level='INFO', logger=logger, reconfigure=True,
fmt='[%(hostname)s] %(asctime)s %(levelname)s %(message)s')


def checkUserPrivilege():
    # The script needs sudo rights, check if the user needs password on sudo
    return (subprocess.call(['sudo', '-n', 'true'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))


def compressOutput(outpath):
    tarball = tarfile.open(outpath + ".tar.gz", 'w:gz')

    for entry in os.scandir(outpath):
        if (entry.is_file() and entry.path != os.path.basename(__file__)) or 'error' not in entry.path:
            tarball.add(entry.path, arcname=entry.name)
                 
    tarball.close()


def createOutputDirectory(target, output_dir):

    target_dir = target[0]
    out_dir = output_dir['output_dir']
    if target[1] == 'URL':
        target_dir = urlparse(target[0]).netloc
    final_path = os.path.join(out_dir, target_dir) + "_scan_output"
    try:
        os.makedirs(final_path)
        return final_path
    except OSError as exception:
        logger.warning("[!] Unable to create directory. Ensure a directory with"
         "the same name does not already exist. Tool output will be saved in the"
         "current directory")
        
        return False


# Various helper functions are defined first
def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        # Strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False

    labels = hostname.split(".")

    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False

    allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(label) for label in labels)


def is_valid_ipv4(ip_str):
    if ('/' in ip_str):
        # The entered IP is CIDR notation
        try:
            IPNetwork(ip_str)
            return True
        except:
            logger.error("[-] Incorrect IP in CIDR notation.")
            return False
    else:
        return valid_ipv4(ip_str)


def is_valid_ipv6(ip_str):
    return valid_ipv6(ip_str)


def is_valid_ip(ip_notation):
    """Check the validity of an IP address"""
    if (is_valid_ipv4(ip_notation) or is_valid_ipv6(ip_notation)):
        if ('/' in ip_notation):
            # The entered IP is CIDR notation
            # Let's convert it into a string of sequential IPs
            for ip in ip_notation:
                expanded_ip = ip + " "
            return expanded_ip      # A string containing IP addresses separated by a space
        else:
            return ip_notation      # just a single IP address
    else:
        return False


def is_go_installed():
    try:
        status, output = subprocess.getstatusoutput('which go')
        if status == 0:
            return True
        else:
            return False

    except OSError:
        return False


def is_nmap_installed():
    try:
        status, output = subprocess.getstatusoutput('which nmap')
        if status == 0:
            return True
        else:
            return False

    except OSError:
        return False


def is_docker_installed():
    try:
        status, output = subprocess.getstatusoutput('docker')
        if status == 0:
            return True
        else:
            return False

    except OSError:
        return False


def is_observatory_installed():
    try:
        status, output = subprocess.getstatusoutput('observatory')
        if status == 0:
            return True
        else:
            return False

    except OSError:
        return False


def is_TLSobservatory_installed():

    # TLSObs is a go-based tool, check if go is available first
    if not is_go_installed():
        return False
    else:   
        try:
            status, output = subprocess.getstatusoutput('tlsobs')
            if status == 0:
                return True
            else:
                return False

        except OSError:
            return False


def is_sshscan_installed():
    try:
        status, output = subprocess.getstatusoutput('ssh_scan')
        if status == 0:
            return True
        else:
            return False

    except OSError:
        return False


def is_dirb_installed():
    try:
        status, output = subprocess.getstatusoutput('dirb')
        if status == 0:
            return True
        else:
            return False

    except OSError:
        return False


def is_gobuster_installed():
    try:
        status, output = subprocess.getstatusoutput('gobuster')
        if status == 0:
            return True
        else:
            return False

    except OSError:
        return False


def validate_target(target):

    # Is the target a URL?
    if urlparse(target).scheme:
        url = target

        # Is the domain/hostname in the URL valid?
        if (is_valid_hostname(urlparse(url).netloc)):
            verified_url_target = url
            target_type = 'URL'
            return verified_url_target, target_type

    elif (is_valid_ip(target)):
        target_type = 'IP'
        return target, target_type

    # The target is not a URL, it's either a hostname...
    elif (is_valid_hostname(target)):
        target_type = 'DOMAIN'
        return target, target_type

    else:
        target = False
        target_type = False
        return target, target_type


def perform_nmap_tcp_scan(target, outpath):
    # Check to see if nmap is installed
    logger.info("[+] Attempting to run Nmap TCP scan...")
    
    if (is_nmap_installed()):
        # Using python-nmap package here

        domain = target[0]
        if (target[1] == 'URL'):
            domain = urlparse(target[0]).netloc

        # Get target's resolved IP using system DNS
        target_ip = socket.gethostbyname(domain)

        nm = nmap.PortScanner()
        nmap_arguments = '-v -Pn -sT -sV --top-ports 1000 --open -T4 --system-dns'
        
        results = nm.scan(domain, arguments=nmap_arguments, sudo=False)
        if (target_ip == "".join(nm.all_hosts())):
            # This output we should send it somewhere, for now logging to a file
            nmap_tcp_file = open(os.path.join(outpath, domain + '__nmap_tcp.json'), 'w+')
            nmap_tcp_file.write(str(results))
            # Printing to screen if verbose
            logger.debug("Nmap TCP scan output:" + str(results))
            return nm
        else:
            logger.error("[-] Nmap TCP scan error!")
            return False

    else:
        logger.warning("[!] Nmap is either not installed or is not in your $PATH. Skipping nmap port scan.")
        return False


def perform_nmap_udp_scan(target, outpath):
    logger.info("[+] Attempting to run Nmap UDP scan...")

    # Nmap UDP scans require sudo, check here if the user can sudo passwordless
    if (checkUserPrivilege()):
        logger.info("[+] Note: UDP scan requires sudo. You will be prompted for your local account password.")
        time.sleep(1)
    
    # Check to see if nmap is installed
    if (is_nmap_installed()):
        # Currently the nmap UDP scan ports are known. Therefore will hardcode them here.
        # Using python-nmap package here

        domain = target[0]
        if (target[1] == 'URL'):
            domain = urlparse(target[0]).netloc

        # Get target's resolved IP using system DNS
        target_ip = socket.gethostbyname(domain)

        udp_ports = "17,19,53,67,68,123,137,138,139,\
        161,162,500,520,646,1900,3784,3785,5353,27015,\
        27016,27017,27018,27019,27020,27960"

        nm = nmap.PortScanner()
        nmap_arguments = '-v -Pn -sU -sV --open -T4 --system-dns'

        # nmap UDP scan requires sudo, setting it to true
        results = nm.scan(domain, ports=udp_ports, arguments=nmap_arguments, sudo=True)
        if (target_ip == "".join(nm.all_hosts())):
            # This output we should send it somewhere, for now logging to a file
            nmap_udp_file = open(os.path.join(outpath, domain + '__nmap_udp.json'), 'w+')
            nmap_udp_file.write(str(results))
            # Printing to screen if verbose
            logger.debug("Nmap UDP scan output: " + str(results))
            return nm
        else:
            logger.error("[-] Nmap UDP scan error!")
            return False

    else:
        logger.warning("[!] Nmap is either not installed or is not in your $PATH. Skipping nmap port scan.")
        return False


def perform_sshscan_scan(target, outpath, ssh_port=22):
    # Since we are already utilising Docker for other tasks,
    # we will use Docker here as well.
    # Note that target parameter here is NOT a tuple
    
    logger.info("[+] Attempting to run ssh_scan as an SSH service was identified on target...")
    sshport = ssh_port.__str__()

    # Check if Docker is installed
    if (is_docker_installed()):
        try:
            docker_client = docker.APIClient(base_url='unix://var/run/docker.sock')
        except Exception as DockerNotRunningError:
            logger.warning("[!] Docker is installed but not running. Skipping ssh_scan scan.")
            return False

        # Clean up containers with the same name which may be leftovers
        # from the last time this tool was run
        try:
            docker_client.remove_container('sshscan-container')
        except docker.errors.APIError as ContainerNotExistsError:
            logger.notice("[*] No container with the same name already exists, nothing to remove.")
        # Check if image exists first
        try:
            docker_client.inspect_image('mozilla/ssh_scan')
        except docker.errors.APIError as ImageNotExistsError:
            docker_client.pull('mozilla/ssh_scan')

        sshscan_cmd = '/app/bin/ssh_scan -p ' + sshport + ' -t ' + target

        container = docker_client.create_container('mozilla/ssh_scan', sshscan_cmd, name='sshscan-container')
        docker_client.start(container)
        docker_client.wait(container.get('Id'))
        sshscan_output = docker_client.logs(container.get('Id'))
        # This output, we should send it somewhere, for now logging to a file in the current directory
        outfile = open(os.path.join(outpath, target + '__sshscan.json'), 'w+')
        outfile.write(str(sshscan_output))
        return True

    # Here only testing if it may have been installed as a Ruby gem
    elif (is_sshscan_installed()):
        tool_path = find_executable('ssh_scan')
        sshscan_out_handler = open(target + "__ssh_scan.json", "w+")
        proc = subprocess.call([tool_path, "-p", sshport, "-t", target],
                        shell=False, stdout=sshscan_out_handler, stderr=subprocess.DEVNULL)
        return proc

    else:
        logger.warning("[!] Either Docker or ssh_scan is either not installed or is not in your $PATH. Skipping ssh_scan scan.")
        return False


def perform_nessus_scan(target, outpath):

    logger.info("[+] Attempting to run Nessus scan on the target...")
    # Reference file: https://github.com/tenable/Tenable.io-SDK-for-Python/blob/master/examples/scans.py
    try:
        # According to documentation TenableIO client can be initialised
        # in a number of ways. I choose here the environment variable option.
        # On the same tty, the user needs to set TENABLEIO_ACCESS_KEY and
        # TENABLEIO_SECRET_KEY variables. I prefer this over storing keys
        # in a config file on disk
        client = TenableIOClient()
        
        # Running basic network scan
        nessus_scan = client.scan_helper.create(name='Scan_for_ ' + target[0], text_targets=target[0], template='basic')

        # Let's allow up to 60 minutes for the scan to run and finish
        nessus_scan.launch().wait_or_cancel_after(60)
        # Downloading the results in .nessus format
        # We will likely need to post this to somewhere else too
        nessus_scan.download(os.path.join(outpath, target[0] + '.nessus'), nessus_scan.histories()[0].history_id, format=ScanExportRequest.FORMAT_NESSUS)
    except TenableIOApiException as TIOException:
        logger.warning("[!] Nessus scan could not run. Make sure you have\
         provided API keys to communicate with Tenable.io.")
        return False

    return True


# There are 2 ways to implement this: first attempt to run the scan
# programmatically. If there is an error/exception, try to run it
# with the standalone observatory binary.
def perform_httpobs_scan(target, outpath):

    logger.info("[+] Attempting to run HTTP Observatory scan...")

    domain = urlparse(target[0]).netloc
    try:
        httpobs_result = scan(domain)
        logger.debug("HTTP Observatory output: " + httpobs_result)
        # TODO: Implement write to file here
        return True
    except Exception as httpobsError:
        tool_path = find_executable('observatory')
        if (is_observatory_installed()):
            # We'd like to capture the tool output and save to a file
            httpobs_out_handler = open(os.path.join(outpath, domain + "__httpobs_scan.json"), "w+")
            proc = subprocess.call([tool_path, "--format json", "-z", "--rescan", domain],
                            shell=False, stdout=httpobs_out_handler, stderr=subprocess.DEVNULL)
            return proc
        else:
            logger.warning("[!] HTTP Observatory is either not installed or is not in your $PATH. Skipping HTTP Observatory scan.")
            return False


def perform_tlsobs_scan(target, outpath):

    logger.info("[+] Attempting to run TLS Observatory scan...")

    domain = urlparse(target[0]).netloc
    tool_path = find_executable('tlsobs')

    if (is_TLSobservatory_installed()):
        # We'd like to capture the tool output and save to a file
        tlsobs_out_handler = open(os.path.join(outpath, domain + "__tlsobs_scan.json"), "w+")
        proc = subprocess.call([tool_path, "-r", "-raw", domain],
                        shell=False, stdout=tlsobs_out_handler, stderr=subprocess.DEVNULL)

        return proc

    # This tool is also available as a docker image
    elif (is_docker_installed()):
        try:
            docker_client = docker.APIClient(base_url='unix://var/run/docker.sock')
        except Exception as DockerNotRunningError:
            logger.warning("[!] Docker is installed but not running. Skipping TLS Observatory scan.")
            return False
        # Clean up containers with the same name which may be leftovers
        # from the last time this tool was run
        try:
            docker_client.remove_container("tlsobs-container")
        except docker.errors.APIError as ContainerNotExistsError:
            logger.notice("[*] No container with the same name already exists, nothing to remove.")
        # Check if image exists first
        try:
            docker_client.inspect_image('mozilla/tls-observatory')
        except docker.errors.APIError as ImageNotExistsError:
            docker_client.pull('mozilla/tls-observatory')

        container = docker_client.create_container('mozilla/tls-observatory', 'tlsobs -r -raw ' + domain)
        docker_client.start(container)
        docker_client.wait(container.get('Id'))
        tlsobs_output = docker_client.logs(container.get('Id'))
        # This tlsobs_output we should send it somewhere, for now logging to a file
        outfile = open(os.path.join(outpath, domain + '__tlsobs_scan.json'), 'w+')
        outfile.write(str(tlsobs_output))
        return True

    else:
        logger.warning("[!] Either Docker or TLS Observatory or go is not installed or is not in your $PATH. Skipping TLS Observatory scan.")
        return False


def perform_directory_bruteforce(target, wordlist, outpath):
    # TODO: This is a non-ideal implementation to say the least. The tools
    # here take approx. 2 hours to finish. Also, based on what's available
    # on the system, we are running different tools. For instance, if go
    # & gobuster installed, we use that. If not, we check if dirb is already
    # installed. If not that either, we then use attempt to download
    # Metasploit Framework docker image, and run the module
    # "scanner/http/dir_scanner" off that (woah!)

    logger.info("[+] Attempting to run directory brute-forcing on the target URL...")
    logger.info("[+] This may take a while, go have lunch or something.")
    domain = urlparse(target[0]).netloc

    # Check if go is installed
    if (is_go_installed() and is_gobuster_installed()):
        tool_path = find_executable('gobuster')
        # We'd like to capture the tool output and save to a file
        gobuster_out_handler = open(os.path.join(outpath, domain + "__gobuster_scan.txt"), "w+")
        proc = subprocess.call([tool_path, "-u " + target[0], "-w " + wordlist],
                        shell=False, stdout=gobuster_out_handler, stderr=subprocess.DEVNULL)

        return proc
    
    elif (is_dirb_installed()):
        tool_path = find_executable('dirb')
        dirb_out_handler = open(os.path.join(outpath, domain + "__dirb_scan.txt"), "w+")
        proc = subprocess.call([tool_path, target[0], wordlist, "-f", "-w", "-r", "-S"],
                        shell=False, stdout=dirb_out_handler, stderr=subprocess.DEVNULL)

        return proc

    elif (is_docker_installed()):
        logger.notice("[*] Neither gobuster nor dirb is found locally, resorting to Metasploit docker image...")

        try:
            docker_client = docker.APIClient(base_url='unix://var/run/docker.sock')
        except Exception as DockerNotRunningError:
            logger.warning("[!] Docker is installed but not running. Skipping directory brute-force scan.")
            return False

        # Clean up containers with the same name which may be leftovers
        # from the last time this tool was run
        try:
            docker_client.remove_container("msf-container")
        except docker.errors.APIError as ContainerNotExistsError:
            logger.notice("[*] No container with the same name already exists, nothing to remove.")
    
        msfmodule = "auxiliary/scanner/http/dir_scanner"
        msfcommand = './msfconsole -x "use ' + msfmodule + '; set RHOSTS ' + domain +\
         '; set RPORT 443; set SSL true; set THREADS 2; set VHOST ' + domain + '; set sslversion Auto; run"'
        
        # Check if image exists first
        try:
            docker_client.inspect_image('metasploitframework/metasploit-framework')
        except docker.errors.APIError as ImageNotExistsError:
            logger.notice("[*] Metasploit container image not found locally, downloading...")
            docker_client.pull('metasploitframework/metasploit-framework')

        container = docker_client.create_container('metasploitframework/metasploit-framework', msfcommand, name="msf-container")
        docker_client.start(container)
        docker_client.wait(container.get('Id'))
        # Get the container logs anyway in case the tool did not run due to an error etc.
        msf_logs = docker_client.logs(container.get('Id'))
        # This output we should send it somewhere, for now logging to a file
        msf_file = open(os.path.join(outpath, domain + '__directory_brute.txt'), 'w+')
        msf_file.write(str(msf_logs))
        # Printing to screen if verbose
        logger.debug("Directory brute-force output: " + str(msf_logs))
        return True
        
    else:
        logger.warning("[!] Directory brute-force could not be performed. Skipping, perform it manually.")
        return False


def perform_zap_scan(target, tool_arguments, outpath):

    logger.info("[+] Attempting to run ZAP scan on the target URL...")
    domain = urlparse(target[0]).netloc

    if (is_docker_installed()):
        
        if (tool_arguments['safe_scan']):
            file_suffix = "__ZAP_baseline.json"
            zap_command = "zap-baseline.py -t " + target[0] + " -J " + domain + file_suffix
        else:
            file_suffix = "__ZAP_full.json"
            zap_command = "zap-full-scan.py -m 1 -T 5 -d -t " + target[0] + " -J " + domain + file_suffix

        try:
            docker_client = docker.APIClient(base_url='unix://var/run/docker.sock')
        except Exception as DockerNotRunningError:
            logger.warning("[!] Docker is installed but not running. Skipping ZAP scan.")
            return False

        # Clean up containers with the same name which may be leftovers
        # from the last time this tool was run
        try:
            docker_client.remove_container("ZAP-container")
        except docker.errors.APIError as ContainerNotExistsError:
            logger.notice("[*] No container with the same name already exists, nothing to remove.")
        # Check if image exists first
        try:
            docker_client.inspect_image('owasp/zap2docker-weekly')
        except docker.errors.APIError as ImageNotExistsError:
            docker_client.pull('owasp/zap2docker-weekly')

        # ZAP requires certain paths to be mounted if outputting to a file
        container = docker_client.create_container('owasp/zap2docker-weekly', zap_command, name="ZAP-container",
        volumes=['/zap/wrk'], host_config=docker_client.create_host_config(binds=[
        os.getcwd() + ':/zap/wrk/:rw']))
        docker_client.start(container)
        docker_client.wait(container.get('Id'))
        # TODO: Need to get the output file here
        # Get the container logs anyway in case the tool did not run due to an error etc.
        zap_logs = docker_client.logs(container.get('Id'))
        # This output we should send it somewhere, for now logging to a file
        zap_file = open(domain + '__ZAP_logs.json', 'w+')
        zap_file.write(str(zap_logs))
        # Printing to screen if verbose
        logger.debug("ZAP output: " + str(zap_logs))
        
        if "ERROR" in zap_logs.__str__():
            logger.error("[-] ERROR in ZAP scan.")
            return False
        return True

    else:
        logger.warning("[!] ZAP scan relies on Docker, but Docker is not installed or is not in your $PATH. Skipping ZAP scan.")
        return False


# Trying to minimise likelihood of OS command injection
# into subprocess.popen calls
def sanitise_shell_command(command):
    return shlex.split(shlex.quote(command))


def showScanSummary(task_dictionary):
    coloredlogs.install(level='INFO', logger=logger, reconfigure=True,
        fmt='%(levelname)s:\t %(message)s')

    print("\n====== SCAN SUMMARY ======")
    for task, status in task_dictionary.items():
        if status:
            logger.success("[\o/] " + task + " completed successfully!")
        else:
            logger.error("[:(] " + task + " failed to run. Please investigate or run manually.")
    
    print("====== END OF SCAN ======\n")


def main():
    
    # Tracking script arguments here, default values
    args_dict = {'safe_scan': False, 'web_app_scan': False, 'compress_output': False,
    'verbose_output': False, 'quiet_run': False, 'output_dir': ""}

    # Default wordlist
    wordlist = "/usr/share/wordlists/dirb/common.txt"

    # Parse the command line
    parser = argparse.ArgumentParser(usage='%(prog)s [options] target', description="Sequentially run a number of\
     tasks to perform a vulnerability assessment on a target.")
    argument_group = parser.add_mutually_exclusive_group()
    argument_group.add_argument('-v', '--verbose', action='store_true', help='increase'\
    ' tool verbosity', default=False)
    argument_group.add_argument('-q', '--quiet', action='store_true', help='quiet run, '\
    'show almost no output', default=False)
    # target is a positional argument, must be specifieds
    parser.add_argument('target', help='host(s) to scan - this could be an \
    IP address, FQDN or a hostname')
    parser.add_argument('--safe-scan', action='store_true', help='use this \
    flag on production targets', default=False)
    parser.add_argument('--web-scan', action='store_true', help='perform a web app \
    scan additionally (ZAP and directory brute-forcing)', default=False)
    parser.add_argument('-x',
                        action='store_true',
                        help='compress all tool outputs into a single file', default=False)
    parser.add_argument('-w', dest='wordlist', action='store', help='specify\
     location of a custom wordlist for directory brute-forcing')
    parser.add_argument('-o', dest='outputdir', action='store', default="/tmp",
    help='specify output directory to store all tool output - default is /tmp')

    args = parser.parse_args()
    print(args)

    # Target validation happens here. Target_OK here is a tuple.
    # First index is either a boolean False, or a string of IP
    # address(es), or a hostname or a URL
    target_OK = validate_target(args.target)

    if (target_OK[0]):
        # If target_OK is a tuple whose first element is not False, we can start running the tasks
        # At a minimum, the following tasks are required for a VA:
        #  1. UDP port scan
        #  2. TCP port scan
        #  3. Nessus scan
        # Running UDP first as it would prompt for sudo, the rest of the script should be 
        # non-interactive

        # tasklist = ['udp-port-scan', 'tcp-port-scan', 'nessus-scan']
        task_dict = {'udp-port-scan': True, 'tcp-port-scan': True, 'nessus-scan': True\
        ,'ssh-scan': True, 'httpobs-scan': True, 'tlsobs-scan': True, 'zap-scan': True\
        ,'dir-scan': True}

        if args.safe_scan:
            args_dict['safe_scan'] = True

        if args.web_scan or target_OK[1] == 'URL':
            args_dict['web_app_scan'] = True
            # tasklist.append('webapp-scan')

        if args.outputdir:
            args_dict['output_dir'] = args.outputdir

        if args.verbose:
            args_dict['verbose_output'] = True
            # In verbose mode we shall show messages starting from DEBUG severity
            coloredlogs.install(level='DEBUG', logger=logger, reconfigure=True)

        if args.quiet:
            args_dict['quiet_run'] = True
            # In quiet mode we shall only show ERROR or more severe
            coloredlogs.install(level='ERROR', logger=logger, reconfigure=True)

        output_path = createOutputDirectory(target_OK, args_dict)
        if not output_path:
            output_path = os.getcwd()
        # Let's start running the tasks...
        ssh_found = False

        for task in task_dict:
            if 'tcp' in task:
                    # Run nmap TCP scan
                    nmap_tcp_results = perform_nmap_tcp_scan(target_OK, output_path)
                    if (nmap_tcp_results):
                        # if ssh is exposed, run SSH scan...
                        
                        if (target_OK[1] != 'IP'):
                            # Get target's resolved IP using system DNS
                            try:
                                target_ip = socket.gethostbyname(target_OK[0])
                            except:
                                # means we have URL
                                target_ip = socket.gethostbyname(urlparse(target_OK[0]).netloc)

                            if nmap_tcp_results[target_ip].has_tcp(22):
                                ssh_found = True
                                if not (perform_sshscan_scan(target_ip, output_path, 22)):
                                    task_dict['ssh-scan']=False
                            else:
                                # Need to find the actual SSH port, in case it is not 22
                                for proto in nmap_tcp_results[target_ip].all_protocols():
                                    lport = nmap_tcp_results[target_ip][proto].keys()
                                    for port in lport:
                                        banner = nmap_tcp_results[target_ip][proto][port]['product'] + "|" + nmap_tcp_results[target_ip][proto][port]['name']
                                        if 'ssh' in map(str.lower, banner):
                                            ssh_found = True
                                            ssh_port = port
                                            if not (perform_sshscan_scan(target_ip, output_path, ssh_port)):
                                                task_dict['ssh-scan']=False
                            if (not ssh_found):
                                logger.info("[+] SSH service not identified on \"" + target_OK[0] + "\", skipping SSH scan.")

                        else:   # Means we have IP address(es)
                            if (target_OK[0].count(' ') >= 0):
                                # We have more than 1 IP, need a loop
                                ip_list = target_OK[0].split(' ') 
                                for ip in ip_list:
                                    if nmap_tcp_results[ip].has_tcp(22):
                                        ssh_found = True
                                        if not (perform_sshscan_scan(ip, output_path, 22)):
                                            task_dict['ssh-scan']=False
                                    else:
                                        # Need to find the actual SSH port, in case it's not 22
                                        for proto in nmap_tcp_results[ip].all_protocols():
                                            lport = nmap_tcp_results[ip][proto].keys()
                                            for port in lport:
                                                banner = nmap_tcp_results[ip][proto][port]['product'] + "|" + nmap_tcp_results[ip][proto][port]['name']
                                                if 'ssh' in map(str.lower, banner):
                                                    ssh_found = True
                                                    ssh_port = port
                                                    if not (perform_sshscan_scan(ip, output_path, ssh_port)):
                                                        task_dict['ssh-scan']=False
                                    if (not ssh_found):
                                        logger.info("[+] SSH service not identified on \"" + ip + "\", skipping SSH scan.")
                        
                    else:
                        # Something wrong with TCP port scan
                        task_dict[task]=False
                        logger.warning("[!] Unable to run TCP port scan. Make sure the target is reachable, or run the scan manually.")

            if 'udp' in task:
                # Run nmap UDP scan
                nmap_udp_results = perform_nmap_udp_scan(target_OK, output_path)
                if not nmap_udp_results:
                    task_dict[task]=False
                    logger.warning("[!] Unable to run UDP port scan. Make sure the target is reachable, or run the scan manually.")
            if 'nessus' in task:
                # Run nessus scan
                if not(perform_nessus_scan(target_OK, output_path)):
                    logger.warning("[!] Unable to run Nessus scan. Make sure the target is reachable, or run the scan manually via Tenable.io console.")
                    task_dict[task]=False
            if 'web' in task:
                # Run HTTP Observatory scan
                httpobs_scan_results = perform_httpobs_scan(target_OK, output_path)
                if not httpobs_scan_results:
                    logger.warning("[!] Unable to run HTTP Observatory scan. Make sure the target is reachable, or run the scan manually.")
                    task_dict[task]=False
                # Run TLS Observatory scan
                tlsobs_scan_results = perform_tlsobs_scan(target_OK, output_path)
                if not tlsobs_scan_results:
                    logger.warning("[!] Unable to run TLS Observatory scan. Make sure the target is reachable, or run the scan manually.")
                    task_dict[task]=False
                # Run ZAP scan(s)
                zap_scan_results = perform_zap_scan(target_OK, args_dict, output_path)
                if not zap_scan_results:
                    logger.warning("[!] Unable to run ZAP scan. Make sure the target is reachable, or run the scan manually.")
                    task_dict[task]=False
                # Run dirb scan
                directory_scan_results = perform_directory_bruteforce(target_OK, wordlist, output_path)
                if not directory_scan_results:
                    logger.warning("[!] Unable to run ZAP scan. Make sure the target is reachable, or run the scan manually.")
                    task_dict[task]=False
        if args.x:
            args_dict['compress_output'] = True
            compressOutput(output_path)
        
        time.sleep(1)
        showScanSummary(task_dict)
    else:
        logger.critical("[X] Unrecognised target(s) specified. Targets must be "\
        "an IP address/range, FQDN or a hostname, or a URL.")
        sys.exit(-1)


if __name__ == "__main__":
    main()
