#!/usr/bin/env python

from __future__ import print_function
import sys
import argparse
import re
import subprocess
import nmap
import docker
import shlex
import importlib
import getpass
import json
import logging
import coloredlogs
import socket
import os
from distutils.spawn import find_executable
from netaddr import valid_ipv4, valid_ipv6, IPNetwork
from urllib.parse import urlparse
from tenable_io.api.scans import ScanExportRequest
from tenable_io.client import TenableIOClient
from tenable_io.exceptions import TenableIOApiException
from httpobs.scanner.local import scan

# TODO: 
# 1) Make ZAP work - DONE
# 2) Make dirb work - DONE
# 3) Introduce exception handling - DONE
# 4) Clean up argparse - DONE
# 5) Add debug/verbose flag and output - DONE
# 6) Fix docker copy stuff (assign tool results to a variable) - DONE
# 7) Make it so it does not require user interaction (i.e. password prompt etc.) - DONE
# 8) Change log format, clean up "prints" - DONE
# 9) Prepare requirements.txt and README.md - in readme include what the tool currently does, and future plans
# 10) Write tests

logger = logging.getLogger(__name__)
# Default logging level is INFO
coloredlogs.install(level='INFO', logger=logger, reconfigure=True,
fmt='[%(hostname)s] %(asctime)s %(levelname)s %(message)s')


def checkUserPrivilege():
    # The script needs sudo rights, check if the user needs password on sudo
    return (subprocess.call(['sudo', '-n', 'true'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))


# Various helper functions are defined first
def is_valid_hostname(hostname):
    if hostname[-1] == ".":
        # strip exactly one dot from the right, if present
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
            # let's convert it into a string of sequential IPs
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


def perform_nmap_tcp_scan(target):
    # Check to see if nmap is installed
    logger.info("[+] Attempting to run Nmap TCP scan...")

    if (is_nmap_installed()):
        # Currently the nmap TCP scan parameters are known. Therefore will hardcode them here.
        # TODO: Parametrise these options for more flexibility in the future
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
            # Make this write to file before return
            logger.debug("Nmap TCP scan output:" + str(results))
            return nm
        else:
            logger.error("[-] Nmap TCP scan error!")
            return False

    else:
        logger.warning("[!] Nmap is either not installed or is not in your $PATH. Skipping nmap port scan.")
        return False


def perform_nmap_udp_scan(target):
    # Check to see if nmap is installed
    logger.info("[+] Attempting to run Nmap UDP scan...")
    if (checkUserPrivilege()):
        logger.info("[+] Note: UDP scan requires sudo. You will be prompted for your local account password.")

    if (is_nmap_installed()):
        # Currently the nmap UDP scan ports are known. Therefore will hardcode them here.
        # TODO: Parametrise these options for more flexibility in the future
        # Using python-nmap package here

        domain = target[0]
        if (target[1] == 'URL'):
            domain = urlparse(target[0]).netloc

        # Get target's resolved IP using system DNS
        target_ip = socket.gethostbyname(domain)

        udp_ports = "17,19,53,67,68,123,137,138,139,161,162,500,520,646,1900,3784,3785,5353,27015,27016,27017,27018,27019,27020,27960"

        nm = nmap.PortScanner()
        nmap_arguments = '-v -Pn -sU -sV --open -T4 --system-dns'

        # nmap UDP scan requires sudo, setting it to true
        # Assume this will prompt the user to enter their password?
        results = nm.scan(domain, ports=udp_ports, arguments=nmap_arguments, sudo=True)
        if (target_ip == "".join(nm.all_hosts())):
            # Make this write to file before return
            logger.debug("Nmap UDP scan output: " + results)
            return nm
        else:
            logger.error("[-] Nmap UDP scan error!")
            return False

    else:
        logger.warning("[!] Nmap is either not installed or is not in your $PATH. Skipping nmap port scan.")
        return False


def perform_sshscan_scan(target, ssh_port=22):
    # Since we are already utilising Docker for other tasks,
    # will use Docker here as well
    # Note that target parameter here is NOT a tuple
    
    logger.info("[+] Attempting to run ssh_scan as an SSH service was identified on target...")
    sshport = ssh_port.__str__()

    if (is_docker_installed()):
        try:
            docker_client = docker.APIClient(base_url='unix://var/run/docker.sock')
        except Exception as DockerNotRunningError:
            logger.error("[-] Docker is installed but not running. Skipping ssh_scan scan.")
            return False

        # Clean up containers with the same name which may be leftovers
        try:
            docker_client.remove_container("sshscan-container")
        except docker.errors.APIError as ContainerNotExistsError:
            # Log for debug, change pass later
            pass
        # Check if image exists first
        try:
            docker_client.inspect_image('mozilla/ssh_scan')
        except docker.errors.APIError as ImageNotExistsError:
            docker_client.pull('mozilla/ssh_scan')

        container = docker_client.create_container('mozilla/ssh_scan', '/app/bin/ssh_scan -p' + sshport + ' -t ' + target, name='sshscan-container')
        docker_client.start(container)
        docker_client.wait(container.get('Id'))
        sshscan_output = docker_client.logs(container.get('Id'))
        # This tlsobs_output we should send it somewhere, for now logging to a file
        outfile = open(target + '__sshscan.json', 'w+')
        outfile.write(str(sshscan_output, 'utf-8'))
        return True

        # docker_client.containers.run('mozilla/ssh_scan', '/app/bin/ssh_scan -p' + sshport + ' -o /tmp/' + target + '__sshscan.json -t ' + target)
        # # Copy the resulting file back to local system, same directory
        # container_name = docker_client.containers.list(filters={'ancestor': 'mozilla/ssh_scan'}, limit=1)[0].name
        # # Potential OS command injection venue here?
        # p = subprocess.Popen('docker cp ' + container_name + ':/tmp/' + target + '__sshscan.json .', stdin=None, stdout=None, stderr=None, shell=True)
        # return True

    # Here only testing if it may have been installed as a Ruby gem
    elif (is_sshscan_installed()):
        cmd = "ssh_scan -p " + sshport + " -o " + target + "__sshscan.json -t " + target
        sanitised_cmd = sanitise_shell_command(cmd)
        # TODO: Is there a way to run this without shell=True ?
        p = subprocess.Popen(sanitised_cmd, shell=True)
        p.wait()

        return p.returncode

    else:
        logger.warning("[!] Either Docker or ssh_scan is either not installed or is not in your $PATH. Skipping ssh_scan scan.")
        return False


def perform_nessus_scan(target):

    logger.info("[+] Attempting to run Nessus scan on the target...")
    # Reference file: https://github.com/tenable/Tenable.io-SDK-for-Python/blob/master/examples/scans.py
    try:
        client = TenableIOClient()
        nessus_scan = client.scan_helper.create(name='Scan_for_ ' + target[0], text_targets=target[0], template='basic')
        # Let's allow up to 60 minutes for the scan to run and finish
        nessus_scan.launch().wait_or_cancel_after(60) 
        nessus_scan.download(target[0] + '.nessus', nessus_scan.histories()[0].history_id, format=ScanExportRequest.FORMAT_NESSUS)
    except:
        logger.warning("[!] Nessus scan could not run. Make sure you have provided API keys to communicate with Tenable.io.")
        return False

    return True


# There are 2 ways to implement this, first I will check if the CLI version of observatory is available
# If it is, use that. If not, try to run the scan programmatically.
def perform_httpobs_scan(target):

    logger.info("[+] Attempting to run HTTP Observatory scan...")

    domain = urlparse(target[0]).netloc
    try:
        httpobs_result = scan(domain)
        logger.debug("HTTP Observatory output: " + httpobs_result)
        return True
    except Exception as httpobsError:
        tool_path = find_executable('observatory')
        if (is_observatory_installed()):
            cmd = tool_path + " --format json -z --rescan " + domain + " > " + domain + "__httpobs_scan.json"
            sanitised_cmd = sanitise_shell_command(cmd)
            p = subprocess.Popen(sanitised_cmd, shell=True)
            p.wait()
            return p.returncode
        else:
            logger.warning("[!] HTTP Observatory is either not installed or is not in your $PATH. Skipping HTTP Observatory scan.")
            return False


def perform_tlsobs_scan(target):

    logger.info("[+] Attempting to run TLS Observatory scan...")

    domain = urlparse(target[0]).netloc
    tool_path = find_executable('tlsobs')

    if (is_TLSobservatory_installed()):
        cmd = tool_path + " -r " + domain + " > " + domain + "__tlsobs_scan.json"
        sanitised_cmd = sanitise_shell_command(cmd)
        p = subprocess.Popen(sanitised_cmd, shell=True)
        p.wait()

        return p.returncode

    # This tool is also available as a docker image
    elif (is_docker_installed()):
        try:
            docker_client = docker.APIClient(base_url='unix://var/run/docker.sock')
        except Exception as DockerNotRunningError:
            logger.error("[-] Docker is installed but not running. Skipping TLS Observatory scan.")
            return False
        # Clean up containers with the same name which may have left
        try:
            docker_client.remove_container("tlsobs-container")
        except docker.errors.APIError as ContainerNotExistsError:
            # Log for debug, change pass later
            pass
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
        outfile = open(domain + '__tlsobs_scan.json', 'w+')
        outfile.write(str(tlsobs_output, 'utf-8'))
        return True

    else:
        logger.warning("[!] Either Docker or TLS Observatory or go is either not installed or is not in your $PATH. Skipping TLS Observatory scan.")
        return False


def perform_directory_bruteforce(target, wordlist):
    # TODO: This is a terrible implementation. The tools here take approx. 2
    # hours to finish. Also, based on what's available on the system, we are
    # running different tools. For instance, if go & gobuster installed, we
    # use that. If not, we check if dirb is already installed. If not that
    # either, then we use attempt to download Metasploit Framework docker
    # image, and run module "scanner/http/dir_scanner" off that (woah!)

    logger.info("[+] Attempting to run directory brute-forcing on the target URL...")
    logger.info("[+] This may take a while, go have lunch or something.")

    # Check if go is installed
    if (is_go_installed() and is_gobuster_installed()):
        cmd = "gobuster -u " + target[0] + " -w " + wordlist + " -o " + target[0] + "__gobuster_scan.txt"
        sanitised_cmd = sanitise_shell_command(cmd)
        p = subprocess.Popen(sanitised_cmd, shell=True)
        p.wait()
        return p.returncode
    
    elif (is_dirb_installed()):
        cmd = "dirb " + target[0] + " " + wordlist + " -f -w -r -S -o " + target[0] + "__dirb_scan.txt"
        sanitised_cmd = sanitise_shell_command(cmd)
        p = subprocess.Popen(sanitised_cmd, shell=True)
        p.wait()
        return p.returncode

    elif (is_docker_installed()):
        logger.info("[+] Neither gobuster nor dirb is found locally, resorting to Metasploit docker image...")
        domain = urlparse(target[0]).netloc

        try:
            docker_client = docker.APIClient(base_url='unix://var/run/docker.sock')
        except Exception as DockerNotRunningError:
            logger.error("[-] Docker is installed but not running. Skipping directory brute-force scan.")
            return False

        # Clean up containers with the same name which may be left-overs
        try:
            docker_client.remove_container("msf-container")
        except docker.errors.APIError as ContainerNotExistsError:
            logger.warning("[!] No container with the same name already exists, nothing to remove.")
    
        msfmodule = "auxiliary/scanner/http/dir_scanner"
        msfcommand = './msfconsole -x "use ' + msfmodule + '; set RHOSTS ' + domain +\
         '; set RPORT 443; set SSL true; set THREADS 2; set VHOST ' + domain + '; set sslversion Auto; run"'
        # Check if image exists first
        try:
            docker_client.inspect_image('metasploitframework/metasploit-framework')
        except docker.errors.APIError as ImageNotExistsError:
            logger.info("[+] Metasploit container image not found locally, downloading...")
            docker_client.pull('metasploitframework/metasploit-framework')

        container = docker_client.create_container('metasploitframework/metasploit-framework', msfcommand, name="msf-container")
        docker_client.start(container)
        docker_client.wait(container.get('Id'))
        # Get the container logs anyway in case the tool did not run due to an error etc.
        # Need to do something with this
        msf_logs = docker_client.logs(container.get('Id'))
        print(msf_logs)
        return True

        # Potential OS command injection venue here?
        # p = subprocess.Popen('docker cp ' + container_name + ':/tmp/' + target[0] + '__dirb_scan.txt .', stdin=None, stdout=None, stderr=None, shell=True)
        #return p.returncode
        
    else:
        logger.warning("[!] Directory brute-force could not be performed. Skipping, perform it manually.")
        return False


def perform_zap_scan(target, tool_arguments):

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
            logger.error("[-] Docker is installed but not running. Skipping ZAP scan.")
            return False

        # Clean up containers with the same name which may have left
        try:
            docker_client.remove_container("ZAP-container")
        except docker.errors.APIError as ContainerNotExistsError:
            # Log for debug, change pass later
            pass
        # Check if image exists first
        try:
            docker_client.inspect_image('owasp/zap2docker-weekly')
        except docker.errors.APIError as ImageNotExistsError:
            docker_client.pull('owasp/zap2docker-weekly')

        container = docker_client.create_container('owasp/zap2docker-weekly', zap_command, name="ZAP-container",
        volumes=['/zap/wrk'], host_config=docker_client.create_host_config(binds=[
        os.getcwd() + ':/zap/wrk/:rw']))
        docker_client.start(container)
        docker_client.wait(container.get('Id'))
        # Get the container logs anyway in case the tool did not run due to an error etc.
        # Need to do something with this
        zap_logs = docker_client.logs(container.get('Id'))
        if "ERROR" in zap_logs.__str__():
            logger.error("[-] ERROR in ZAP scan.")
        return True

    else:
        logger.warning("[!] ZAP scan relies on Docker, but Docker is not installed or is not in your $PATH. Skipping ZAP scan.")
        return False


def sanitise_shell_command(command):
    return shlex.split(shlex.quote(command))


def main():
    
    global args

    args_dict = {'safe_scan': False, 'web_app_scan': False, 'compress_output': False,
    'verbose_output': False, 'quiet_run': False}

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
    parser.add_argument('-w', dest='<wordlist>', action='store', help='specify\
     location of a custom wordlist for directory brute-forcing')

    args = parser.parse_args()

    # Target validation happens here
    target_OK = validate_target(args.target)
    # Target_OK here is a tuple now
    # First index is either a boolean False, or a string of IP address(es), or a hostname or a URL

    if (target_OK[0]):
        # If target_OK is a tuple whose first element is not False, we can start running the tasks
        # At a minimum, the following tasks are required for a VA:
        #  1. TCP port scan
        #  2. UDP port scan
        #  3. Nessus scan

        tasklist = ['tcp-port-scan', 'udp-port-scan', 'nessus-scan']

        if args.safe_scan:
            args_dict['safe_scan'] = True

        if args.web_scan or target_OK[1] == 'URL':
            args_dict['web_app_scan'] = True
            tasklist.append('web-app-scan')

        if args.x:
            args_dict['compress_output'] = True

        if args.verbose:
            args_dict['verbose_output'] = True
            # In verbose more we shall show DEBUG messages and more
            coloredlogs.install(level='DEBUG', logger=logger, reconfigure=True)

        if args.quiet:
            args_dict['quiet_run'] = True
            # In quiet mode we shall only show ERROR or more severe
            coloredlogs.install(level='ERROR', logger=logger, reconfigure=True)

        # Let's start running the tasks...

        ssh_found = False

        for task in tasklist:
            if 'tcp' in task:
                # if (target_OK[1] != 'URL'):
                    # Run nmap TCP scan
                    nmap_tcp_results = perform_nmap_tcp_scan(target_OK)
                
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
                                perform_sshscan_scan(target_ip, 22)
                            else:
                                # or ('ssh' in (nmap_tcp_results[target_ip].name or nmap_tcp_results[target_ip].product)):
                                # Need to find the actual SSH port, in case it's not 22
                                for proto in nmap_tcp_results[target_ip].all_protocols():
                                    lport = nmap_tcp_results[target_ip][proto].keys()
                                    for port in lport:
                                        banner = nmap_tcp_results[target_ip][proto][port]['product'] + "|" + nmap_tcp_results[target_ip][proto][port]['name']
                                        if ('SSH' or 'ssh') in banner:
                                            ssh_found = True
                                            ssh_port = port
                                            perform_sshscan_scan(target_ip, ssh_port)
                            if (not ssh_found):
                                logger.info("[+] SSH service not identified on \"" + target_OK[0] + "\", skipping SSH scan.")

                        else:   # Means we have IP address(es)
                            if (target_OK[0].count(' ') >= 0):
                                # We have more than 1 IP, need a loop
                                ip_list = target_OK[0].split(' ') 
                                for ip in ip_list:
                                    if nmap_tcp_results[ip].has_tcp(22):
                                        ssh_found = True
                                        perform_sshscan_scan(ip, 22)
                                    else:
                                        # or ('ssh' in (nmap_tcp_results[ip].name or nmap_tcp_results[ip].product)):
                                        # Need to find the actual SSH port, in case it's not 22
                                        for proto in nmap_tcp_results[ip].all_protocols():
                                            lport = nmap_tcp_results[ip][proto].keys()
                                            for port in lport:
                                                banner = nmap_tcp_results[ip][proto][port]['product'] + "|" + nmap_tcp_results[ip][proto][port]['name']
                                                if ('SSH' or 'ssh') in banner:
                                                    ssh_found = True
                                                    ssh_port = port
                                                    perform_sshscan_scan(ip, ssh_port)
                                    if (not ssh_found):
                                        logger.info("[+] SSH service not identified on \"" + ip + "\", skipping SSH scan.")
                    else:  # Something wrong with TCP port scan
                        logger.warning("[!] Unable to run TCP port scan. Make sure the target is reachable, or run the scan manually.")

            if 'udp' in task:
                # Run nmap UDP scan
                nmap_udp_results = perform_nmap_udp_scan(target_OK)
            # if 'nessus' in task:
                # Run nessus scan
                # perform_nessus_scan(target_OK)
            if 'web' in task:
                # Run HTTP Observatory scan
                httpobs_scan_results = perform_httpobs_scan(target_OK)
                # Run TLS Observatory scan
                tlsobs_scan_results = perform_tlsobs_scan(target_OK)
                # Run ZAP scan(s)
                zap_scan_results = perform_zap_scan(target_OK, args_dict)
                # Run dirb scan
                directory_scan_results = perform_directory_bruteforce(target_OK, wordlist)

    else:
        logger.critical("[X] Unrecognised target(s) specified. Targets must be "\
        "an IP address/range, subnet mask notation, FQDN or a hostname.")
        sys.exit(-1)


if __name__ == "__main__":
    main()
