#!/usr/bin/python3
# A minimally viable automated work-flow of VA Automation that we can incrementally improve on...

import sys
import os
import time
import logging
from urllib.parse import urlparse
from lib import target, port, scheme
from lib import task, utils

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def main():
    # Get targeting info
    destination = sys.argv[1]

    if not target.Target(destination).valid():
        # Maybe we have a URL, or it is an invalid target
        output_path = "/app/results/" + destination + "/"
        if not scheme.Scheme(destination).valid():
            # Invalid target
            logger.error("Invalid target, please use an FQDN or a URL.")
            sys.exit(-1)
        else:
            domain = urlparse(destination).netloc
            output_path = "/app/results/" + domain + "/"

    # Create a location to store our outputs
    try:
        os.stat(output_path)
    except:
        os.mkdir(output_path)

    scan_target = target.Target(destination)
    va_scan = setupVA(scan_target)
    job = runVA(va_scan, output_path)


if __name__ == "__main__":
    main()


def setupVA(va_target):

    # Need to make some logic here as to which tasks we should run
    # Port scans are always a go
    va_target.addTask(task.NmapTask(va_target, type="full"))
    # Nessus scan is also always a go
    va_target.addTask(task.NessusTask(va_target))
    if "http" in va_target.targetname:
        # We have a URL, means HTTP Obs, TLS Obs,
        # ZAP scans and directory brute scans are a go
        va_target.addTask(task.MozillaHTTPObservatoryTask(va_target))
        va_target.addTask(task.MozillaTLSObservatoryTask(va_target))
        va_target.addTask(task.ZAPScanTask(va_target))
        va_target.addTask(task.DirectoryBruteTask(va_target, tool="dirb"))
    
    return va_target


def runVA(scan_with_tasks, outpath):
    logger.info("Running all the scans now. This may take a while...")
    result = scan_with_tasks.runTasks()
    time.sleep(1)
    if utils.package_results(outpath):
        logger.info("All done. Tool output from the scan can be found at " + outpath)
        return result
