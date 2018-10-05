import json
import logging
import os
import time
import uuid
import boto3
from classes import response, target, port, scheme
from classes import task

dynamodb = boto3.resource('dynamodb')
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def createScan(event, context):
    data = json.loads(event['body'])

    if not scheme.Scheme(data['target']).valid():
        logger.error("Scheme Validation Failed of: " +
                      json.dumps(data))
        return response.Response({
             "statusCode": 200,
             "body": json.dumps({'error': 'Invalid scheme'})
         }).with_security_headers()

    if not target.Target(data['target']).valid():
        logger.error("Target Validation Failed of: " +
                      json.dumps(data))
        return response.Response({
             "statusCode": 200,
             "body": json.dumps({'error': 'Invalid or missing target'})
         }).with_security_headers()

    if not port.Port(data['port']).valid():
        logger.error("Port Validation Failed of: " + json.dumps(data))
        return response.Response({
            "statusCode": 200,
            "body": json.dumps({'error': 'Invalid or missing port'})
        }).with_security_headers()

    # timestamp = int(time.time() * 1000)
    # table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])

    # item = {
    #      'id': str(uuid.uuid1()),
    #      'target': data.get['target'],
    #      'port': data.get['port'],
    #      'TCPScanTask': 'false',
    #      'UDPScanTask': 'false',
    #      'NessusTask': 'false',
    #      'ZAPScanTask': 'false',
    #      'HTTPObsTask': 'false',
    #      'TLSObsTask': 'false',
    #      'SSHScanTask': 'false',
    #      'DirbruteTask': 'false',
    #      'createdAt': timestamp,
    #      'updatedAt': timestamp,
    # }

    # write the item to the database
    # table.put_item(Item=item)

    # if valid(data['target']):
    #     statuscode = 200
    #     logging.error("Event structure: " +
    #                   json.dumps(event))
    # else:
    #     statuscode = 500
    #     logging.error("Event structure: " +
    #                   json.dumps(event))

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

    va_target = target.Target(data['target'], data['port'], item['id'])
    # From here on va_target is a Target object

    va_scan = setupScan(va_target)
    job = runScan(va_scan)

    if (job):
        return response.Response({
            "statusCode": 200,
            "body": json.dumps(job)
        }).with_security_headers()
    
    else:
        return response.Response({
            "statusCode": 500,
            "body": json.dumps({'error': 'Check CloudWatch logs'})
        }).with_security_headers()


def setupScan(va_target):

    # target.addTask(task.MozillaHTTPObservatoryTask(target))
    va_target.addTask(task.MozillaTLSObservatoryTask(va_target))
    # va_target.addTask(task.SSHScanTask(va_target))
    # va_target.addTask(task.NessusTask(va_target))
    return va_target


def runScan(scan_with_tasks):
    result = scan_with_tasks.runTasks()
    return result
