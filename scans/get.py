import os
import json
import boto3
import logging
from scans import decimalencoder, Response, Target

dynamodb = boto3.resource('dynamodb')
# TODO: Shore this functionality up


def get(event, context, target):

    if (getTaskStatus(event, target)):
        # create a response
        return Response({
            "statusCode": 200,
            "body": json.dumps(result['Item'],
                               cls=decimalencoder.DecimalEncoder)
        }).with_security_headers()
    else:
        return Response({
            "statusCode": 404,
            "body": "Scan does not exist."
        }).with_security_headers()


def getTaskStatus(event, target):
    # This may be used for this: https://serverless.com/framework/docs/providers/aws/events/apigateway#request-parameters
    # Will likely require getting rid of the entire get function
    table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])

    # fetch from the database
    result = table.get_item(
        Key={
            'id': event['pathParameters']['id']
        }
    )
    # Record exists in database, before displaying we should check
    # the status of each task
    if result['Item']['id'] == target.id:
        return True

    else:
        logging.error("Scan with the requested UUID:{0} does not exist.".format(event['pathParameters']['id']))
        return False
        