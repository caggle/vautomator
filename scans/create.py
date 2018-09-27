import json
import logging
import os
import time
import uuid
import boto3
from scans import Target, Response, Port
from scans import MozillaHTTPObservatoryTask, MozillaTLSObservatoryTask
from scans import SSHScanTask, NessusTask

dynamodb = boto3.resource('dynamodb')


def create(event, context):
    data = json.loads(event['body'])
    if not Target(data.get('target')).valid():
        logging.error("Target Validation Failed of: " +
                      json.dumps(data))
        return Response({
            "statusCode": 200,
            "body": json.dumps({'error': 'target was not valid or missing'})
        }).with_security_headers()

    if not Port(data.get('port')).valid():
        logging.error("Port Validation Failed of: " + json.dumps(data))
        return Response({
            "statusCode": 200,
            "body": json.dumps({'error': 'port was not valid or missing'})
        }).with_security_headers()

    timestamp = int(time.time() * 1000)
    table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])

    item = {
        'id': str(uuid.uuid1()),
        'target': data['target'],
        'port': data['port'],
        'TCPScanTask': 'false',
        'UDPScanTask': 'false',
        'NessusTask': 'false',
        'ZAPScanTask': 'false',
        'HTTPObsTask': 'false',
        'TLSObsTask': 'false',
        'SSHScanTask': 'false',
        'DirbruteTask': 'false',
        'createdAt': timestamp,
        'updatedAt': timestamp,
    }

    # write the item to the database
    table.put_item(Item=item)

    va_target = Target(data.get('target'), data.get('port'), item['id'])
    # From here on va_target is a Target object

    scan_with_tasks = setupScan(va_target)
    runScan(scan_with_tasks)

    # create a response
    return Response({
        "statusCode": 200,
        "body": json.dumps(item)
    }).with_security_headers()


def setupScan(target):
    
    target.addTask(MozillaHTTPObservatoryTask(target))
    target.addTask(MozillaTLSObservatoryTask(target))
    target.addTask(SSHScanTask(target))
    target.addTask(NessusTask(target))

    return target


def runScan(target_with_tasks):
    result = target_with_tasks.runTasks()
    return result
