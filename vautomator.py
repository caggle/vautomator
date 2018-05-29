#!/usr/bin/env python

from __future__ import print_function
import sys
import time
import argparse
import re
import socket
import subprocess
import nmap
import docker
import shlex
import importlib
import getpass
import json
import logging
import coloredlogs
from urllib.parse import urlparse
from ipaddress import ip_interface


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
    """Check the validity of an IPv4 address"""
    try:
        socket.inet_pton(socket.AF_INET, ip_str)
    except AttributeError:
        try:
            socket.inet_aton(ip_str)
        except socket.error:
            return False
        return ip_str.count('.') == 3
    except socket.error:
        return False
    return True


def is_valid_ipv6(ip_str):
    """Check the validity of an IPv6 address"""
    try:
        socket.inet_pton(socket.AF_INET6, ip_str)
    except socket.error:
        return False
    return True


def is_valid_ip(ip_str):
    """Check the validity of an IP address"""
    return is_valid_ipv4(ip_str) or is_valid_ipv6(ip_str)


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
    # Is Nessus locally installed?
    # Note that we should not return False here if it's not locally installed,
    # we want to be able to use scan_api to initiate a remote connection to Nessus over its API
    # TODO: Figure this one out

    return False


def validate_target(target):

    # Is the target a URL?
    if urlparse(target).scheme:
        url = target

        # Is the domain/hostname in the URL valid?
        if (is_valid_hostname(urlparse(url).netloc)):
            verified_url_target = url
            return verified_url_target

    # The target is not a URL, it's either a hostname...
    elif (is_valid_hostname(target)):
        return target

    # ... or an IP address or subnet mask notation
    elif (is_valid_ip(target)):
        ip_list = []
        ipaddr = ip_interface(target)
        ip = ipaddr.ip
        for ip in ipaddr.network:
            ip_list.append(ip)                   # This needs to be a list
        return ip_list                           # This also needs to be a list

    else:
        return False


def perform_nmap_tcp_scan(target, tool_arguments):
    # Check to see if nmap is installed

    if (is_nmap_installed()):
        # Currently the nmap TCP scan parameters are known. Therefore will hardcode them here.
        # TODO: Parametrise these options for more flexibility in the future
        # Using python-nmap package here

        if isinstance(target, (list,)):
            # This means target is an IP address, in a list with either 1 or more IPs
            if len(target) == 1:
                ip_target = target[0]._ip.__str__()
            else:
                for ip in target:
                    ip_target += ip + " "

        nm = nmap.PortScanner()
        nmap_arguments = '-v -Pn -sT --top-ports 1000 --open -T4 '
        if (tool_arguments['force_dns_lookup']):
            nmap_arguments += " -n"
        results = nm.scan(ip_target, arguments=nmap_arguments, sudo=False)
        print(nm.get_nmap_last_output())
        return results

        # Add logic here to check for SSH, if open we need to create a new task to scan SSH with ssh_scan
    else:
        print("nmap is either not installed or is not in your $PATH. Skipping nmap port scan.")
        return False


def perform_nmap_udp_scan(target, tool_arguments):
    # Check to see if nmap is installed

    if (is_nmap_installed()):
        # Currently the nmap UDP scan ports are known. Therefore will hard code them here.
        # TODO: Parametrise these options for more flexibility in the future
        # Using python-nmap package here

        if isinstance(target, (list,)):
            # This means target is an IP address, in a list with either 1 or more IPs
            if len(target) == 1:
                ip_target = target[0]
            else:
                for ip in target:
                    ip_target += ip + " "

        udp_ports = "17,19,53,67,68,123,137,138,139,161,162,500,520,646,1900,3784,3785,5353,27015,27016,27017,27018,27019,27020,27960"

        nm = nmap.PortScanner()
        nmap_arguments = '-v -Pn -sU -sV --open -T4 -oX ' + target + '__scan_udp.xml'
        if (tool_arguments['force_dns_lookup']):
            nmap_arguments += " -n"

        # nmap UDP scan requires sudo, setting it to true
        # Assume this will prompt the user to enter their password?
        return nm.scan(target, ports=udp_ports, arguments=nmap_arguments, sudo=True)

    else:
        print("nmap is either not installed or is not in your $PATH. Skipping nmap port scan.")
        return False


def perform_sshscan_scan(target):
    """Since we are already utilising Docker for other tasks,
    will use Docker here as well
    """

    if (is_docker_installed()):
        docker_client = docker.from_env()
        docker_client.images.pull('mozilla/sshscan')
        # Potential OS command injection venue here?
        docker_client.containers.run('mozilla/sshscan', '/app/bin/ssh_scan -o /tmp/' + target + '__sshscan.json -t ' + target)
        # Copy the resulting file back to local system
        p = subprocess.Popen('docker cp mozilla/sshscan:/tmp/' + target + '__sshscan.json .', stdin=None, stdout=None, stderr=None)
        return True

    # Here only testing if it may have been installed as a Ruby gem
    elif (is_sshscan_installed()):
        cmd = "ssh_scan -o " + target + "__sshscan.json -t " + target
        sanitised_cmd = shlex.quote(cmd)
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

    print("Nessus scan is not yet supported. Skipping.")
    return False


# There are 2 ways to implement this, first I will check if the CLI version of observatory is available
# If it is, use that. If not, I will use a provided script (in the package) to run it.
def perform_httpobs_scan(target):

    if (is_observatory_installed()):
        cmd = "observatory --format json -z -q --rescan " + target + " > " + target + "__httpobs_scan.json"
        sanitised_cmd = shlex.quote(cmd)
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
        script = "httpobs-local-scan --format json " + target + " > " + target + "__httpobs_scan.json"
        sanitised_script = shlex.quote(script)
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

    if (is_TLSobservatory_installed()):
        cmd = "tlsobs -r " + target + " > " + target + "__tlsobs_scan.json"
        sanitised_cmd = shlex.quote(cmd)
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

    if (is_dirb_installed()):
        cmd = "dirb " + target + " -f -w -r -S -o " + target + "__dirb_scan.txt"
        sanitised_cmd = shlex.quote(cmd)
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


def main():

    global args

    logger = logging.getLogger(__name__)
    coloredlogs.install(level='DEBUG', logger=logger)

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
    parser.add_argument('-n', action='store_true', help='Force perform'\
    ' a DNS lookup')
    # parser.add_argument('-h', help='Display this help text')

    args = parser.parse_args()

    # Target validation
    # Try to parse the hostname, in case a URL is given

    target_OK = validate_target(args.target)

    if (target_OK):
        # At this stage, we have a valid hostname or IP address(es) here to work with
        # target_OK is either a boolean, or a list of host(s)

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

        if args.n:
            args_dict['force_dns_lookup'] = True

        # Let's start running the tasks...

        for task in tasklist:
            if 'tcp' in task:
                # Run nmap TCP scan
                nmap_tcp_results = perform_nmap_tcp_scan(target_OK, args_dict)
                if (nmap_tcp_results):
                    # if ssh is exposed, run SSH scan...
                    # Fix this, target_OK here is a list which may or may not contain multiple IPs (at least 1 IP)
                    if nmap_tcp_results[target_OK[0]._ip.__str__()].has_tcp(22) or ('ssh' in (nmap_tcp_results[target_OK[0]._ip.__str__()].name or nmap_tcp_results[target_OK[0]._ip.__str__()].product)):
                        # Need to find the actual SSH port, in case it's not 22
                        for proto in nmap_tcp_results[target_OK].all_protocols():
                            lport = nmap_tcp_results[target_OK][proto].keys()
                            for port in lport:
                                if port == 22:
                                    ssh_port = port
                                else:
                                    banner = nmap_tcp_results[target_OK][proto][port]['product']
                                    if ('SSH' or 'ssh') in banner:
                                        ssh_port = port
                        tasklist.append('ssh_scan-scan')
                        perform_sshscan_scan(target_OK, ssh_port)
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
            if 'ssh' in task:
                # Added for completeness, we implicitly run ssh_scan
                # as a part of nmap TCP scan, if required
                continue
            else:
                return False

    else:
        logger.error("Unrecognised target(s) specified. Targets must be an IP address/range, subnet mask notation, FQDN or a hostname")
        sys.exit(-1)


if __name__ == "__main__":
    main()
