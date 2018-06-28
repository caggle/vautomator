# vautomator
Iterative automation of common VA tasks using functional programming.

Currently it "does the job", albeit inefficiently with many areas for improvements (see Issues).

## What it does






## But...Why?

I wanted to learn Python and automate running a vulnerability assessment at work, which happens fairly often.


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
* If this becomes useful, it could be Dockerized
