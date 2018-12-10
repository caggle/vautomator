# A minimally viable automated work-flow of VA Automation that we can incrementally improve on...
import sys
import os
import time
import logging
from urllib.parse import urlparse
from lib import target, port, scheme
from lib import task

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Get targeting info
destination = sys.argv[1]

if not target.Target(destination).valid():
    # Maybe we have a URL, or it is an invalid target
    if not scheme.Scheme(destination).valid():
        # Invalid target
        logger.error("Invalid target, please use an FQDN or a URL.")

domain = urlparse(target[0]).netloc
output_path = "/app/results/" + destination + "/"

# Create a location to store our outputs
try:
  os.stat(output_path)
except:
  os.mkdir(output_path) 

# Do procedure NMAP scans (save output to /app/results)
os.system("nmap -v -Pn -sT -n --top-ports 1000 --open -T4 -oA " + output_path + "scan_tcp_" + fqdn + " " + fqdn)
os.system("nmap -v -Pn -sU -sV -n -p 17,19,53,67,68,123,137,138,139,161,162,500,520,646,1900,3784,3785,5353,27015,27016,27017,27018,27019,27020,27960 --open -T4 -oA " + output_path + "scan_udp_" + fqdn + " " + fqdn)

# Do procedure dirb/ssh scans (save output to directory outside container)
nmap_tcp_gnmap_file = open("/app/results/" + fqdn + "/scan_tcp_" + fqdn + ".gnmap", "r")
lines = nmap_tcp_gnmap_file.readlines()
for line in lines:
  if (("Host:" in line) and ("Ports:" in line) and ("443/open/tcp" in line)):
    print("https is open, so we'll dirb it...")
    command = "/app/vendor/dirb222/dirb https://" + fqdn + "/ /app/vendor/dirb222/wordlists/common.txt -o /app/results/" + fqdn + "/https_dirb_common.txt"
    os.system(command)
  if (("Host:" in line) and ("Ports:" in line) and ("80/open/tcp" in line)):
    print("http is open, so we'll dirb it...")
    command = "/app/vendor/dirb222/dirb http://" + fqdn + "/ /app/vendor/dirb222/wordlists/common.txt -o /app/results/" + fqdn + "/http_dirb_common.txt"
    os.system(command)
  if (("Host:" in line) and ("Ports:" in line) and ("80/open/tcp" in line or "443/open/tcp" in line)):
    print("http/https is open, so we'll observatory it...")
    command = "curl -X POST -d '' https://http-observatory.security.mozilla.org/api/v1/analyze?host=" + fqdn + " > /app/results/" + fqdn + "/observatory.txt"
    os.system(command)
    print("Giving observatory some time to complete scan before grabbing results...")
    time.sleep(20)
    os.system(command)
  if (("Host:" in line) and ("Ports:" in line) and ("22/open/tcp" in line)):
    print("ssh is open, so we'll ssh_scan it...")
    command = "ssh_scan -t " + fqdn + " -o /app/results/" + fqdn + "/ssh_scan.txt"
    os.system(command)

# Do procedure X (save output to /app/results)


# Do procedure Y (save output to /app/results)


# Do procedure Z (save output to /app/results)


# Do reporting (take all the output from the prior runs, zip it up, and attach to BMO)
command = "tar -zcvf /app/results/" + fqdn + ".tar.gz /app/results/" + fqdn + "/"
os.system(command)