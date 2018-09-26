import json
import os
import boto3
from scans import decimalencoder, Response

dynamodb = boto3.resource('dynamodb')


def list(event, context):
    table = dynamodb.Table(os.environ['DYNAMODB_TABLE'])

    # fetch all from the database
    result = table.scan()

    # create a response
    return Response({
        "statusCode": 200,
        "body": json.dumps(result['Items'], cls=decimalencoder.DecimalEncoder)
    }).with_security_headers()
