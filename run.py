# A minimally viable automated work-flow of VA Automation that we can incrementally improve on...
import sys
import os

# Get targeting info
fqdn = "blog.rubidus.com"
output_path = "/app/results/" + fqdn + "/"

# Create a location to store our outputs
os.system("mkdir " + output_path)

# TODO: make this dependant on NMAP results/protocol fingerprints
# In the mean time, just toggle and rebuild it, maybe we'll just take a URL as a seed? dunno.
scheme = "https"

# Do procedure NMAP scans (save output to directory outside container)
os.system("nmap -v -Pn -sT -n -p 443 --open -T4 -oX " + output_path + "scan_tcp_" + fqdn + ".xml " + fqdn)
os.system("nmap -v -Pn -sU -sV -n -p 17,19,53,67,68,123,137,138,139,161,162,500,520,646,1900,3784,3785,5353,27015,27016,27017,27018,27019,27020,27960 --open -T4 -oX " + output_path + "scan_udp_" + fqdn + ".xml " + fqdn)

# Do procedure dirb scans (save output to directory outside container)
#os.system("/app/vendor/dirb222/dirb " + scheme + "://" + fqdn + "/ /app/vendor/dirb222/wordlists/common.txt" )

# Do procedure X (save output to directory outside container)


# Do procedure Y (save output to directory outside container)


# Do procedure Z (save output to directory outside container)


# Do reporting (take all the output from the prior runs, zip it up, and attach to BMO)
