## Healthcheck
import json
import os
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

CONFIG_PARAMETER= os.environ['CONFIG_PARAMETER']
WATOKEN = 'FonitoSaysOK'

def lambda_handler(event, context):
    print(event)
    connect_config=json.loads(get_config(CONFIG_PARAMETER))
    WHATS_VERIFICATION_TOKEN= connect_config['WHATS_VERIFICATION_TOKEN']
    
    ## Verify token
    if('params' in event and 'hub.challenge' in event['params']['querystring']):
        print(event['params']['querystring'])
        print("Token challenge")
        if(event['params']['querystring']['hub.verify_token'] == WHATS_VERIFICATION_TOKEN):
            print("Token verified")
            print(event['params']['querystring']['hub.challenge'])
            response = event['params']['querystring']['hub.challenge']
        else:
            response = ''
    else:
        print("Not challenge related")
        response = '<html><head></head><body> No key, no fun!</body></html>'
    return response
    
def get_config(secret_name):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager'
    )

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
            secret = None
    return secret