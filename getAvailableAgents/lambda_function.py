#Get Available Agents in Queue
import json
import boto3
import os
import base64
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    print(event)
    
    CONFIG_SECRET= os.environ['CONFIG_SECRET']
    connect_config=json.loads(get_config(CONFIG_SECRET))
    CONNECT_INSTANCE_ID = connect_config['CONNECT_INSTANCE_ID']
    CONNECT_QUEUE_ID =connect_config['CONNECT_QUEUE_ID']

    
    connect_client = boto3.client('connect')
    response = connect_client.get_current_metric_data(
    InstanceId=CONNECT_INSTANCE_ID,
    Filters={
        'Queues': [
            CONNECT_QUEUE_ID,
        ],
        'Channels': [
            'VOICE',
        ]
    },
    CurrentMetrics=[
        {
            'Name': 'AGENTS_AVAILABLE',
            'Unit': 'COUNT'
        },
    ],
)
    print("Available Agents Metriics :" + str(response['MetricResults']))
    
    if(response['MetricResults']):availAgents = int(response['MetricResults'][0]['Collections'][0]['Value'])
    else: availAgents =0
    return {"availAgents":availAgents}

def get_config(secret_name):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager'
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
    return secret