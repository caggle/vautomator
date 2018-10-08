
import os
import time
import logging
import requests
import json
from classes import target, port
from tenable_io.client import TenableIOClient
from tenable_io.exceptions import TenableIOApiException
import boto3


dynamodb = boto3.resource('dynamodb')
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class Task:
    # One target will have at least one task
    # One task will have one target at a time
    # self.tasktarget here is a Target object
    def __init__(self, target_obj):
        self.tasktarget = target_obj

    def updateStatus(self):

        timestamp = int(time.time() * 1000)
        table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])

        # HTTP Observatory currently missing here due to
        # its package not being available in pypi

        if isinstance(self, NessusTask):
            db_ExpressionAttributeNames = {
                '#nessus_status': 'NessusTask'
            }
            db_ExpressionAttributeValues = {
                ':NessusTask': 'true',
                ':updatedAt': timestamp,
            }
            db_UpdateExpression = 'SET #nessus_status = :NessusTask, updatedAt = :updatedAt'
        elif isinstance(self, MozillaTLSObservatoryTask):
            db_ExpressionAttributeNames = {
                '#tlsobs_status': 'TLSObsTask'
            }
            db_ExpressionAttributeValues = {
                ':TLSObsTask': 'true',
                ':updatedAt': timestamp,
            }
            db_UpdateExpression = 'SET #tlsobs_status = :TLSObsTask, updatedAt = :updatedAt'
        elif isinstance(self, SSHScanTask):
            db_ExpressionAttributeNames = {
                '#sshscan_status': 'SSHScanTask'
            }
            db_ExpressionAttributeValues = {
                ':SSHScanTask': 'true',
                ':updatedAt': timestamp,
            }
            db_UpdateExpression = 'SET #sshscan_status = :SSHScanTask, updatedAt = :updatedAt'
        else:
            logger.error("Unknown or undefined task.")
            return False

        # update the task status in the database
        table.update_item(
            Key={
                'id': self.tasktarget.id
            },
            ExpressionAttributeNames=db_ExpressionAttributeNames,
            ExpressionAttributeValues=db_ExpressionAttributeValues,
            UpdateExpression=db_UpdateExpression
        )
        return True


class NessusTask(Task):

    def __init__(self, target_obj):
        super().__init__(target_obj)
        # According to documentation TenableIO client can be initialised
        # in a number of ways. I choose here the environment variable option.
        # The env variables are specified in serverless.yml
        self.client = TenableIOClient(access_key=os.getenv('TENABLEIO_ACCESS_KEY'), secret_key=os.getenv('TENABLEIO_SECRET_KEY'))

    def runNessusScan(self):

        # Reference: https://github.com/tenable/Tenable.io-SDK-for-Python/blob/master/examples/scans.py
        try:
            # Run a basic network scan
            nessus_scan = self.client.scan_helper.create(name='Scan_for_ ' + self.tasktarget.targetname, text_targets=self.tasktarget.targetname, template='basic')

            # We don't want this blocking, so don't wait
            nessus_scan.launch(wait=False)
            # We will need to use the scan id later to check for status
            return nessus_scan

        except TenableIOApiException as TIOException:
            logger.error("Tenable.io scan failed: ".format(TIOException))
            return False

    def checkScanStatus(self, scan):
        # Query Tenable API to check if the scan is finished
        status = self.client.status(scan.id)
        if status == scan.STATUS_COMPLETED:
            return "COMPLETE"
        elif status == scan.STATUS_ABORTED:
            return "ABORTED"
        elif status == scan.STATUS_INITIALIZING:
            return "INITIALIZING"
        elif status == scan.STATUS_PENDING:
            return "PENDING"
        elif status == scan.STATUS_RUNNING:
            return "RUNNING"
        else:
            logger.error("Something is wrong with Tenable.io scan. Check the TIO console manually.")
            return False

    def update(self, data):
        super().updateStatus(self, data)


class MozillaTLSObservatoryTask(Task):

    def __init__(self, target_obj):
        super().__init__(target_obj)

    def runTLSObsScan(self):

        # Will have to invoke the API manually here
        # Ref: https://github.com/mozilla/tls-observatory#api-endpoints
        try:
            tlsobs_API_base = os.getenv('TLSOBS_API_URL')
            logger.info(json.dumps({'error': tlsobs_API_base}))
            tlsbobs_API_scan_URL = "{0}/api/v1/scan?target={1}&rescan=true".format(tlsobs_API_base, self.tasktarget.targetname)
            logger.info(json.dumps({'error': tlsbobs_API_scan_URL}))
            tlsobs_req = requests.Request('POST', tlsbobs_API_scan_URL, data='')
            prepared = tlsobs_req.prepare()
            # pretty_printed_httpreq = '{}\n{}\n\n\n{}'.format(
            #                          prepared.method + ' ' + prepared.url,
            #                          '\n'.join('{}: {}'.format(k, v) for k, v in prepared.headers.items()),
            #                          prepared.body
            #                          )

            # tlsobs_response = requests.post(tlsbobs_API_scan_URL, data='')
            # logger.info(json.dumps({'TLS Observatory raw request': pretty_printed_httpreq}))
            session = requests.Session()
            tlsobs_response = session.send(prepared)

            if (tlsobs_response.status_code == requests.codes.ok):
                tlsobs_scanID = json.loads(tlsobs_response.text)
                # Wait for a little bit for the scan to finish
                time.sleep(7)
                tlsbobs_API_result_URL = "{0}/api/v1/results?id={1}".format(tlsobs_API_base, tlsobs_scanID['scan_id'])
                response = requests.get(tlsbobs_API_result_URL)
                status = json.loads(response.text)
                logger.info(json.dumps({'TLS Observatory result - completion status': status['completion_perc']}))
                # Returning a JSON formatted response text, as it is a JSON response
                return response.json()
            elif (tlsobs_response.status_code == 429):
                tlsbobs_API_scan_URL = "{0}/api/v1/scan?target={1}".format(tlsobs_API_base, self.tasktarget.targetname)
                tlsobs_req = requests.Request('POST', tlsbobs_API_scan_URL, data='')
                prepared = tlsobs_req.prepare()
                session = requests.Session()
                tlsobs_response = session.send(prepared)
                if (tlsobs_response.status_code == requests.codes.ok):
                    tlsobs_scanID = json.loads(tlsobs_response.text)
                    tlsbobs_API_result_URL = "{0}/api/v1/results?id={1}".format(tlsobs_API_base, tlsobs_scanID['scan_id'])
                    response = requests.get(tlsbobs_API_result_URL)
                    return response.text
                logger.info(json.dumps({'TLS Observatory result - completion status': response.text['completion_perc']}))

            else:
                return False

        except BaseException as TLSObsError:
            logger.error(json.dumps({'error': str(TLSObsError)}))
            return False

    def checkScanStatus(self, tlsobs_scan):
        # Query TLS Observatory API to check if the scan is finished
        # TODO: This needs to be re-worked

        status = tlsobs_scan.status_code
        if status == 200:
            return "COMPLETE"
        else:
            logger.error("Something is wrong with TLS Observatory scan. ",
                          "Check the scan manually at {0}/analyze/{1}#tls".format(os.getenv('HTTPOBS_URL'), self.tasktarget.targetname))
            return False

    def update(self, data):
        super().updateStatus(self, data)


class SSHScanTask(Task):

    def __init__(self, target_obj):
        super().__init__(target_obj)

    # We will probably talk to ssh_scan_api here directly
    # Ref: https://github.com/mozilla/ssh_scan_api/blob/master/examples/client.py

    def runSSHScan(self, sshport=22):

        try:
            sshscan_API_base = os.getenv('SSHSCAN_API_URL')
            logger.info(json.dumps({'error': sshscan_API_base}))
            sshscan_API_scan_URL = "{0}/api/v1/scan?target={1}".format(sshscan_API_base, self.tasktarget.targetname)
            body = 'port={0}'.format(sshport.__str__())
            sshscan_response = requests.post(sshscan_API_scan_URL, data=body)

            if (sshscan_response.status_code == requests.codes.ok):
                sshscan_uuid = json.loads(sshscan_response.text)
                # Wait for a little bit for the scan to finish
                time.sleep(5)
                sshscan_API_result_URL = "{0}/api/v1/scan/results?uuid={1}".format(sshscan_API_base, sshscan_uuid['uuid'])
                response = requests.get(sshscan_API_result_URL)
                return response.json()
            else:
                return False

        except BaseException as SSHScanError:
            logger.error("SSH scan failed: ".format(SSHScanError))
            return False

    def checkScanStatus(self, ssh_scan):
        # Query SSH scan API to check if the scan is finished
        ssh_scan_response = json.loads(ssh_scan)
        if ssh_scan_response['status'] == "COMPLETED":
            return "COMPLETE"
        else:
            logger.error("Something is wrong with ssh_scan scan. ",
                          "Try running the scan manually.")
            return False

    def update(self, data):
        super().updateStatus(self, data)
    