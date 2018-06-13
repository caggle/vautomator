#!/usr/bin/env python

from __future__ import print_function
import sys
import time
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
from distutils.spawn import find_executable
from netaddr import valid_ipv4, valid_ipv6, IPNetwork
from urllib.parse import urlparse


logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG', logger=logger)


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
            logger.error("Incorrect IP in CIDR notation.")
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


def is_nessus_installed():
    # TODO: Figure this one out, this needs to be integrated with Tenable.io

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


def perform_nmap_tcp_scan(target, tool_arguments):
    # Check to see if nmap is installed
    logger.info("[+] Attempting to run Nmap TCP scan...")

    if (is_nmap_installed()):
        # Currently the nmap TCP scan parameters are known. Therefore will hardcode them here.
        # TODO: Parametrise these options for more flexibility in the future
        # Using python-nmap package here

        domain = target[0]
        if (target[1] == 'URL'):
            domain = urlparse(target[0]).netloc
            print(domain)

        # Get target's resolved IP using system DNS
        target_ip = socket.gethostbyname(domain)
        print(target_ip)

        nm = nmap.PortScanner()
        nmap_arguments = '-v -Pn -sT -sV --top-ports 1000 --open -T4 --system-dns'
        if (tool_arguments['force_dns_lookup']):
            nmap_arguments += " -R"
        
        results = nm.scan(domain, arguments=nmap_arguments, sudo=False)
        if (target_ip == "".join(nm.all_hosts())):
            # Make this write to file before return
            print(results)
            return nm
        else:
            logger.error("Nmap TCP scan error!")
            return False

    else:
        print("nmap is either not installed or is not in your $PATH. Skipping nmap port scan.")
        return False


def perform_nmap_udp_scan(target, tool_arguments):
    # Check to see if nmap is installed
    logger.info("[+] Attempting to run Nmap UDP scan...")
    logger.warning("[!] Note: UDP scan requires sudo. You will be prompted for your local account password.")

    if (is_nmap_installed()):
        # Currently the nmap UDP scan ports are known. Therefore will hard code them here.
        # TODO: Parametrise these options for more flexibility in the future
        # Using python-nmap package here

        domain = target[0]
        if (target[1] == 'URL'):
            domain = urlparse(target[0]).netloc

        # Get target's resolved IP using system DNS
        target_ip = socket.gethostbyname(domain)
        print(target_ip)

        udp_ports = "17,19,53,67,68,123,137,138,139,161,162,500,520,646,1900,3784,3785,5353,27015,27016,27017,27018,27019,27020,27960"

        nm = nmap.PortScanner()
        nmap_arguments = '-v -Pn -sU -sV --open -T4 --system-dns'
        if (tool_arguments['force_dns_lookup']):
            nmap_arguments += " -R"

        # nmap UDP scan requires sudo, setting it to true
        # Assume this will prompt the user to enter their password?
        results = nm.scan(domain, ports=udp_ports, arguments=nmap_arguments, sudo=True)
        if (target_ip == "".join(nm.all_hosts())):
            # Make this write to file before return
            print(results)
            return nm
        else:
            logger.error("Nmap UDP scan error!")
            return False

    else:
        print("nmap is either not installed or is not in your $PATH. Skipping nmap port scan.")
        return False


def perform_sshscan_scan(target, ssh_port=22):
    """Since we are already utilising Docker for other tasks,
    will use Docker here as well
    """
    logger.info("[+] Attempting to run ssh_scan as an SSH service was identified on target...")
    sshport = ssh_port.__str__()

    if (is_docker_installed()):
        docker_client = docker.from_env()
        docker_client.images.pull('mozilla/ssh_scan')
        docker_client.containers.run('mozilla/ssh_scan', '/app/bin/ssh_scan -p' + sshport + ' -o /tmp/' + target + '__sshscan.json -t ' + target)
        # Copy the resulting file back to local system, same directory
        container_name = docker_client.containers.list(filters={'ancestor': 'mozilla/ssh_scan'}, limit=1)[0].name
        # Potential OS command injection venue here?
        p = subprocess.Popen('docker cp ' + container_name + ':/tmp/' + target + '__sshscan.json .', stdin=None, stdout=None, stderr=None, shell=True)
        return True

    # Here only testing if it may have been installed as a Ruby gem
    elif (is_sshscan_installed()):
        cmd = "ssh_scan -p " + sshport + " -o " + target + "__sshscan.json -t " + target
        sanitised_cmd = sanitise_shell_command(cmd)
        # TODO: Is there a way to run this without shell=True ?
        p = subprocess.Popen(sanitised_cmd, shell=True)
        p.wait()

        if (not p.returncode):
            return False
        else:
            return True
    else:
        print("Either Docker or ssh_scan is either not installed or is not in your $PATH. Skipping ssh_scan scan.")
        return False


def perform_nessus_scan(target, tool_arguments):

    # logger.info("[+] Attempting to run a Nessus scan...")

    print("Nessus scan is not yet supported. Skipping.")
    return False


# There are 2 ways to implement this, first I will check if the CLI version of observatory is available
# If it is, use that. If not, I will use a provided script (in the package) to run it.
def perform_httpobs_scan(target):

    logger.info("[+] Attempting to run HTTP Observatory scan...")

    domain = urlparse(target[0]).netloc
    tool_path = find_executable('observatory')
    
    if (is_observatory_installed()):
        cmd = tool_path + " --format json -z --rescan " + domain + " > " + domain + "__httpobs_scan.json"
        sanitised_cmd = sanitise_shell_command(cmd)
        print(sanitised_cmd)
        p = subprocess.Popen(sanitised_cmd, shell=True)
        p.wait()

        if (not p.returncode):
            return False
        else:
            return True

    # It's not installed, but the python package is. However programmatic
    # way does not allow us to capture output. Therefore
    # we will use a script provided instead (httpobs-local-scan)
    elif (importlib.util.find_spec("httpobs.scanner.local")):
        script = "httpobs-local-scan --format json \"" + domain + "\" > " + domain + "__httpobs_scan.json"
        sanitised_script = sanitise_shell_command(script)
        p = subprocess.Popen(sanitised_script, shell=True)
        p.wait()

        if (not p.returncode):
            return False
        else:
            return True
    else:
        print("HTTP Observatory is either not installed or is not in your $PATH. Skipping HTTP Observatory scan.")
        return False


def perform_tlsobs_scan(target):

    logger.info("[+] Attempting to run TLS Observatory scan...")

    if (is_TLSobservatory_installed()):
        cmd = "tlsobs -r " + target + " > " + target + "__tlsobs_scan.json"
        sanitised_cmd = sanitise_shell_command(cmd)
        p = subprocess.Popen(sanitised_cmd, shell=True)
        p.wait()

        if (not p.returncode):
            return False
        else:
            return True
    # This tool is also available as a docker image
    elif (is_docker_installed()):
        docker_client = docker.from_env()
        docker_client.images.pull('mozilla/tls-observatory')
        # Potential OS command injection venue here?
        docker_client.containers.run('mozilla/tls-observatory', 'tlsobs -r ' + target + ' > /tmp/' + target + '__tlsobs_scan.json')
        # Copy the resulting file back to local system
        p = subprocess.Popen('docker cp mozilla/tls-observatory:/tmp/' + target + '__tlsobs_scan.json .', stdin=None, stdout=None, stderr=None)
        return True

    else:
        print("Either Docker or TLS Observatory is either not installed or is not in your $PATH. Skipping HTTP Observatory scan.")
        return False


def perform_dirb_scan(target):
    # TODO: This is a terrible implementation. dirb takes approx. 2
    # hours to run. We cannot wait till it finishes
    # This will require some proper multi-threading.
    # For now, let's run this as the last task.

    logger.info("[+] Attempting to run directory brute-forcing on the target URL...")
    logger.info("[+] This may take a while, go get a coffee or something.")

    if (is_dirb_installed()):
        cmd = "dirb " + target + " -f -w -r -S -o " + target + "__dirb_scan.txt"
        sanitised_cmd = sanitise_shell_command(cmd)
        p = subprocess.Popen(sanitised_cmd, shell=True)
        p.wait()

        if (not p.returncode):
            return False
        else:
            return True
    else:
        print("dirb is either not installed or is not in your $PATH. Skipping dirb scan.")
        return False


def perform_zap_scan(target, tool_arguments):

    logger.info("[+] Attempting to run ZAP scan on the target URL...")

    if (is_docker_installed()):
        docker_client = docker.from_env()
        docker_client.images.pull('owasp/zap2docker-weekly')
        # Potential OS command injection venue here?
        if (tool_arguments['safe-scan']):
            docker_client.containers.run('owasp/zap2docker-weekly', 'zap-baseline.py -t ' + target + ' -J /tmp/' + target + '__ZAP_baseline.json')
            # Copy the resulting file back to local system
            p = subprocess.Popen('docker cp owasp/zap2docker-weekly:/tmp/' + target + '__ZAP_baseline.json .', stdin=None, stdout=None, stderr=None)
            return True
        else:
            docker_client.containers.run('owasp/zap2docker-weekly', 'zap-full-scan.py -m 1 -T 5 -d -t ' + target + ' -J /tmp/' + target + '__ZAP_full.json')
            # Copy the resulting file back to local system
            p = subprocess.Popen('docker cp owasp/zap2docker-weekly:/tmp/' + target + '__ZAP_full.json .', stdin=None, stdout=None, stderr=None)
            return True

    else:
        print("ZAP scan relies on Docker, but Docker is not installed or is not in your $PATH. Skipping ZAP scan.")
        return False


def sanitise_shell_command(command):
    return shlex.split(shlex.quote(command))


def main():

    global args

    """
    safe_scan = False
    web_app_scan = False
    compress_output = False
    verbose_output = False
    force_dns_lookup = False
    """

    args_dict = {'safe_scan': False, 'web_app_scan': False, 'compress_output': False,
    'verbose_output': False, 'force_dns_lookup': False}

    # Parse the command line
    parser = argparse.ArgumentParser(usage='%(prog)s [options] target')
    parser.add_argument('target', help='host(s) to scan - this could be an "\
    IP address/range, subnet mask notation, FQDN or a hostname')
    parser.add_argument('--safe-scan', action='store_true', help='Use this "\
    flag on production targets')
    parser.add_argument('-w', action='store_true', help='Perform a web app "\
    scan additionally (dirb and ZAP)')
    parser.add_argument('-x',
                        action='store_true',
                        help='Compress all tool outputs into a single file')
    parser.add_argument('-v', '--verbose', action='store_true', help='display'\
    ' progress indicator')
    parser.add_argument('-r', action='store_true', help='Force perform'\
    ' a DNS lookup')
    # parser.add_argument('-h', help='Display this help text')

    args = parser.parse_args()

    # Target validation
    target_OK = validate_target(args.target)
    # Target_OK here is a tuple now
    # First index is either a boolean False, or a string of IP address(es), or a hostname or a URL
    print(target_OK)

    if (target_OK[0]):
        # If target_OK is a tuple whose first element is not False, we can start running the tasks

        """At a minimum, the following tasks are required for a VA:
           1. TCP port scan
           2. UDP port scan
           3. Nessus scan
        """
        tasklist = ['tcp-port-scan', 'udp-port-scan', 'nessus-scan']

        if args.safe_scan:
            args_dict['safe_scan'] = True

        if args.w | ("http" in urlparse(args.target).scheme):
            args_dict['web_app_scan'] = True
            tasklist.append('web-app-scan')

        if args.x:
            args_dict['compress_output'] = True

        if args.verbose:
            args_dict['verbose_output'] = True

        if args.r:
            args_dict['force_dns_lookup'] = True

        # Let's start running the tasks...

        ssh_found = False

        for task in tasklist:
            if 'tcp' in task:
                # if (target_OK[1] != 'URL'):
                    # Run nmap TCP scan
                    nmap_tcp_results = perform_nmap_tcp_scan(target_OK, args_dict)
                
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
                                logger.info("SSH service not identified on \"" + target_OK[0] + "\", skipping SSH scan.")

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
                                        logger.info("SSH service not identified on \"" + ip + "\", skipping SSH scan.")
                    else:  # Something wrong with TCP port scan
                        logger.warning("Unable to run TCP port scan. Make sure the target is reachable, or run the scan manually.")

            if 'udp' in task:
                # Run nmap UDP scan
                nmap_udp_results = perform_nmap_udp_scan(target_OK, args_dict)
            if 'nessus' in task:
                # Run nessus scan
                perform_nessus_scan(target_OK, args_dict)
            if 'web' in task:
                # Run HTTP Observatory scan
                httpobs_scan_results = perform_httpobs_scan(target_OK)
                # Run TLS Observatory scan
                # Run ZAP scan(s)
                # Run dirb scan

    else:
        logger.error("Unrecognised target(s) specified. Targets must be an IP address/range, subnet mask notation, FQDN or a hostname")
        sys.exit(-1)


if __name__ == "__main__":
    main()
