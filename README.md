# vautomator
Iterative automation of common VA tasks using functional programming.

Currently it "does the job", albeit inefficiently with some areas for improvements.

If you'd like to contribute, please reach out to [me](https://mozillians.org/en-US/u/Cag/) and I'd be happy to add you as a contributor.

## What it does

Using **Python 3**, runs a bunch of tools (on the local system, or in a Docker image) against a URL and saves tool outputs for later analysis, as a part of a vulnerability assessment.

### What it actually does

If run without any optional argument, this tool:
* Determines if the the target is a URL, an IP address or a hostname/FQDN
* If URL, it will run (in this order):
  * An nmap UDP scan for about 25 selected UDP services
  * An nmap TCP scan for top 1000 services
  * ssh_scan (if an SSH service is identified)
  * A Nessus (Tenable.io) "Basic Network Scan" (provided if you have valid Tenable.io API keys)
  * HTTP Observatory scan
  * TLS Observatory scan
  * OWASP ZAP baseline scan
  * Directory bruteforcing against a wordlist
  
* If hostname/FQDN or IP address, it will only run (in order):
  * An nmap UDP scan for about 25 selected UDP services
  * An nmap TCP scan for top 1000 services
  * ssh_scan (if an SSH service is identified)
  * A Nessus (Tenable.io) "Basic Network Scan" (provided if you have valid Tenable.io API keys)

  *Note that the tool is not intelligent enough to pick up if an HTTP(S) port is open and to subsequently kick off web app related scans (TODO)*
  
In the current implementation these tasks are performed sequentially with the intent being "run and forget" for a couple of hours, while you are doing other important work. Ideally this should be improved with multi-threading / asynchronous queuing mechanism (TODO).

#### Port scans

For TCP and UDP port scans, [python-nmap](https://pypi.org/project/python-nmap/) is used.

##### SSH scan

For SSH scan, Dockerized instance of [ssh_scan](https://github.com/mozilla/ssh_scan) is used.

#### Nessus scan

Nessus scans will fail unless you have a pair of valid Tenable.io API keys authorised to kick off scans. If you do, set these keys as environment variables on the shell you are running the tool from:

```
$ export TENABLEIO_ACCESS_KEY=<ACCESS_KEY>
$ export TENABLEIO_SECRET_KEY=<SECRET_KEY>
```

#### Web App scans

If you are running the tool against a URL, a number of additional external tools will be utilised:
* [HTTP Observatory](https://github.com/mozilla/http-observatory) is used as a package.
* [TLS Observatory](https://github.com/mozilla/tls-observatory) Docker instance is used (I could have just used HTTP Observatory, TODO)
  * *If you have `tlsobs` client installed, that will be used instead*
 * [OWASP ZAP](https://github.com/zaproxy/zaproxy) Docker instance is used
 * For directory brute-forcing:
   * If you have `gobuster` locally installed, that will be used,
   * If you have `dirb` locally installed, that will be used,
   * If neither, then a Docker instance of [Metasploit framework](https://hub.docker.com/r/metasploitframework/metasploit-framework/) is used (with the auxiliary/scanner/http/dir_scanner module)
   
Note that these Docker images, if not present locally, will be downloaded first. The tool also deletes the containers post-run, however the images remain.

## But...Why?

I wanted to learn Python and automate running a vulnerability assessment at work, which happens fairly often.

## Requirements

The tool is written to work with Python 3. You will also need `nmap` binary installed locally.

Other than that:
```
$ cat requirements.txt

verboselogs==1.7
httpobs==0.9.2
tenable_io==1.3.0
python_nmap==0.6.1
coloredlogs==10.0
netaddr==0.7.19
docker_py==1.10.6
nmap==0.0.1
```

## Install & Running 

1. First, download the repo: `git clone https://github.com/caggle/vautomator.git && cd vautomator`
2. Install the requirements: `pip3 install -r requirements.txt`
3. Run it!: `python3 vautomator.py <URL>`

   *Note: The tool should be able to handle a URL with HTTP(S) scheme, a single IP address or a hostname (e.g. mymachine.local). If you find bugs or have feature requests with non-URL targets in particular, let me know.*

Example run:
```
$ python3 vautomator.py https://www.mozilla.org
[gorgoroth] 2018-08-13 17:38:38     INFO [+] Attempting to run Nmap UDP scan...
[gorgoroth] 2018-08-13 17:38:38     INFO [+] Note: UDP scan requires sudo. You will be prompted for your local account password.
Password:
[gorgoroth] 2018-08-13 17:40:24     INFO [+] Attempting to run Nmap TCP scan...
[gorgoroth] 2018-08-13 17:40:38     INFO [+] Attempting to run ssh_scan as an SSH service was identified on target...
[gorgoroth] 2018-08-13 17:40:43  WARNING [!] Unable to run Nessus scan. Make sure the target is reachable, or run the scan manually via Tenable.io console.
[gorgoroth] 2018-08-13 17:40:43     INFO [+] Attempting to run HTTP Observatory scan...
[gorgoroth] 2018-08-13 17:40:45     INFO [+] Attempting to run TLS Observatory scan...
[gorgoroth] 2018-08-13 17:40:46   NOTICE [*] No container with the same name already exists, nothing to remove.
[gorgoroth] 2018-08-13 17:41:07     INFO [+] Attempting to run ZAP scan on the target URL...
[gorgoroth] 2018-08-13 17:41:24    ERROR [-] Error in ZAP scan.
[gorgoroth] 2018-08-13 17:41:24  WARNING [!] Unable to run ZAP scan. Make sure the target is reachable, or run the scan manually.
[gorgoroth] 2018-08-13 17:41:24     INFO [+] Attempting to run directory brute-forcing on the target URL...
[gorgoroth] 2018-08-13 17:41:24     INFO [+] This may take a while, go have lunch or something.
[gorgoroth] 2018-08-13 17:41:24   NOTICE [*] Neither gobuster nor dirb is found locally, resorting to Metasploit docker image...

====== SCAN SUMMARY ======
SUCCESS   [\o/] udp-port-scan completed successfully!
SUCCESS   [\o/] tcp-port-scan completed successfully!
ERROR     [ :(] nessus-scan failed to run. Please investigate or run manually.
SUCCESS   [\o/] ssh-scan completed successfully!
SUCCESS   [\o/] httpobs-scan completed successfully!
SUCCESS   [\o/] tlsobs-scan completed successfully!
ERROR     [ :(] zap-scan failed to run. Please investigate or run manually.
SUCCESS   [\o/] dir-scan completed successfully!
====== END OF SCAN =======

```

Verbose scan option will increase the output, in particular, it will show the full command run on the screen as well as tool outputs from each scan.

To see help: `python3 vautomator.py -h`
```
$ python3 vautomator.py -h
usage: vautomator.py [options] target

Sequentially run a number of tasks to perform a vulnerability assessment on a
target.

positional arguments:
  target         host(s) to scan - this could be an IP address, FQDN or a
                 hostname

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  increase tool verbosity
  -q, --quiet    quiet run, show almost no output
  --full-scan    use this flag on non-production targets (currently only
                 affects ZAP scan options)
  --web-scan     perform a web app scan additionally (ZAP and directory brute-
                 forcing)
  -x             compress all tool outputs into a single file
  -w WORDLIST    specify location of a custom wordlist for directory brute-
                 forcing
  -o OUTPUTDIR   specify output directory to store all tool output - default
                 is /tmp
```

**Note:** Custom wordlist argument currently does not work. At the time of writing, dirb's [common wordlist](https://github.com/v0re/dirb/blob/master/wordlists/common.txt) is used by default for directory brute-forcing.

## Future Work

The intention is to create an interface with a "click and forget" capability for running vulnerability assessments, in which a user can enter a URL, hostname or an IP address(es), click a button and a few hours later is presented with results (as well as the results posted to another location with a likelihood indicator).

A rough use-case of the tool would be:
* End-user navigates to web front-end, gets prompted with some kind of authentication (ideally Auth0)
* After authentication, end-user enters a host or a collection of hosts / IP addresses, or a URL
* Web component checks if there has been a recent scan of the host, if not, passes it to scanner component. The criteria of "recent" is not decided yet.
* Scanner component creates a scan "job", and starts running the tools successively.
* When the scan is finished, the scanner stores all tool output as a BLOB in a DB. It also creates a tarball/ZIP of all tool output, creates a link and emails the user who initiated the scan to notify the scan is finished. This link could be used to directly download the tool output (so it could be attached as evidence to Bugzilla VA bugs if required)
* Scanner component could perform some analysis on the scan result and feed the result of the VA as a single likelihood indicator to another system.

For this, the below points needs to be taken into account:
* A web front-end (most likely using Flask)
* A scanner component/micro-service which runs actual tools (e.g. nmap, ZAP, HTTP Observatory, Nessus etc.)
* To help prevent abuse, we would like this to be behind SSO
* Where would we want to deploy this? To a system in DC? Some other VPS in the cloud?
* ~If this becomes useful, it could be Dockerized~. This tool SHOULD be Dockerized as soon as possible (**TODO**)
