#!/usr/bin/python3
# A minimally viable automated work-flow of VA Automation that we can incrementally improve on...

import sys
import os
import time
import logging
from urllib.parse import urlparse
from lib import target, port, scheme
from lib import task, utils

logging.basicConfig(level=logging.INFO)


def setupVA(va_target):

    # Need to make some logic here as to which tasks we should run
    # Port scans are always a go
    # va_target.addTask(task.NmapTask(va_target))
    # Nessus scan is also always a go
    va_target.addTask(task.NessusTask(va_target))
    # print(va_target.targetname)
    if va_target.isURL():
        # We have a URL, means HTTP Obs, TLS Obs,
        # ZAP scans and directory brute scans are a go
        # va_target.addTask(task.MozillaHTTPObservatoryTask(va_target))
        # va_target.addTask(task.MozillaTLSObservatoryTask(va_target))
        # TODO: ZAP scans do not work yet in Docker, needs more work
        # va_target.addTask(task.ZAPScanTask(va_target))
        va_target.addTask(task.DirectoryBruteTask(va_target, tool="dirb"))
    
    return va_target


def runVA(scan_with_tasks, outpath):
    logging.info("Running all the scans now. This may take a while...")
    results = scan_with_tasks.runTasks()
    # results here is a dict
    time.sleep(1)
    if utils.package_results(outpath):
        logging.info("All done. Tool output from the scan can be found at " + outpath)
        return results


def main():
    # Get targeting info
    destination = sys.argv[1]
    output_path = "/app/results/" + destination + "/"
    va_target = target.Target(destination)
    print(va_target.valid())

    if va_target.isURL():
        # We have a URL
        domain = urlparse(va_target.targetname).netloc
        output_path = "/app/results/" + domain + "/"

    elif not va_target.valid():
        # Maybe we have a URL, or it is an invalid target
        if not scheme.Scheme(va_target.targetname).valid():
            # Invalid target
            logging.error("Invalid target, please use an FQDN or a URL.")
            sys.exit(-1)

    # Create a location to store our outputs
    try:
        os.stat(output_path)
    except Exception:
        os.mkdir(output_path)
    
    va_scan = setupVA(va_target)
    job = runVA(va_scan, output_path)


if __name__ == "__main__":
    main()
