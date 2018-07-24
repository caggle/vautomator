# A minimally viable automated work-flow of VA Automation that we can incrementally improve on...
import sys
import os

# Get targeting info
fqdn = sys.argv[1]

# Poor man's FQDN checking
if not fqdn:
  print("FQDN was not provided, please provide an FQDN (Example: foo.example.com)")
  exit(1) 

if "http" in fqdn:
  print("FQDN provided is not an FQDN, please use an FQDN (Example: foo.example.com)")
  exit(1) 

#TODO: make this dependant on NMAP results/protocol fingerprints
# In the mean time, just toggle and rebuild it, maybe we'll just take a URL as a seed? dunno.
scheme = "https"

output_path = "/app/results/" + fqdn + "/"

# Create a location to store our outputs
try:
  os.stat(output_path)
except:
  os.mkdir(output_path) 

# Do procedure NMAP scans (save output to /app/results)
os.system("nmap -v -Pn -sT -n -p 443 --open -T4 -oX " + output_path + "scan_tcp_" + fqdn + ".xml " + fqdn)
os.system("nmap -v -Pn -sU -sV -n -p 17,19,53,67,68,123,137,138,139,161,162,500,520,646,1900,3784,3785,5353,27015,27016,27017,27018,27019,27020,27960 --open -T4 -oX " + output_path + "scan_udp_" + fqdn + ".xml " + fqdn)

# Do procedure dirb scans (save output to directory outside container)
command = "/app/vendor/dirb222/dirb " + scheme + "://" + fqdn + "/ /app/vendor/dirb222/wordlists/common.txt -o /app/results/" + fqdn + "/" + scheme + "_dirb_common.txt"
os.system(command)

# Do procedure X (save output to /app/results)


# Do procedure Y (save output to /app/results)


# Do procedure Z (save output to /app/results)


# Do reporting (take all the output from the prior runs, zip it up, and attach to BMO)
command = "tar -zcvf /app/results/" + fqdn + ".tar.gz /app/results/" + fqdn + "/"
os.system(command)