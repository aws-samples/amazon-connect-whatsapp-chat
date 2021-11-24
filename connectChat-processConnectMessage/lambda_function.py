##connect Message Processing Function
import json
import boto3
import os
import base64
from twilio.rest import Client as TwilioClient

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

ACTIVE_CONNNECTIONS= os.environ['ACTIVE_CONNNECTIONS']


def lambda_handler(event, context):
    print(event)
    for record in event['Records']:
        message = json.loads(record['Sns']['Message'])
        message_type= message['Type']
        
        if(message_type == 'MESSAGE'):
            message_attributes = record['Sns']['MessageAttributes']
            message_body = message['Content']
            contactID = message['ContactId']

            ParticipantRole= message['ParticipantRole']
            MessageVisibility= message_attributes['MessageVisibility']['Value']
            if((MessageVisibility == 'CUSTOMER' or MessageVisibility == 'ALL')  and ParticipantRole != 'CUSTOMER' ):
                print("contactID:" + str(contactID))
                custID = get_custID(contactID, ACTIVE_CONNNECTIONS)
                if(custID):
                    print("custID:" + str(custID))
                    send_message(custID,message_body)
                else:
                    print('Contact not found')
        if(message_type == 'EVENT'):
            message_attributes = record['Sns']['MessageAttributes']
            message_type = message_attributes['ContentType']['Value']
            if(message_type == 'application/vnd.amazonaws.connect.event.participant.left' or message_type == 'application/vnd.amazonaws.connect.event.chat.ended'):
                print('participant left')
                contactID = message['InitialContactId']
                #custID = get_custID(contactID, ACTIVE_CONNNECTIONS)
                remove_contactId(contactID,ACTIVE_CONNNECTIONS)

    response = {
                "statusCode": 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                    },
                "body": "",
            }
        
    return response

def send_message(userContact,message):
    CONFIG_PARAMETER= os.environ['CONFIG_PARAMETER']
    connect_config=json.loads(get_config(CONFIG_PARAMETER))


    TWILIO_SID= connect_config['TWILIO_SID']
    TWILIO_AUTH_TOKEN= connect_config['TWILIO_AUTH_TOKEN']
    TWILIO_FROM_NUMBER=connect_config['TWILIO_FROM_NUMBER']
    
    contactSplit = userContact.split(":")
    contactPrefix = contactSplit[0]
    
    if(contactPrefix=='whatsapp'):
        print("Create Twilio Client")
        client = TwilioClient(TWILIO_SID, TWILIO_AUTH_TOKEN)
        print("Send message:"+ str(message) + ":" + str(TWILIO_FROM_NUMBER) +":" + userContact )
        message = client.messages.create(
                              body=str(message),
                              from_=TWILIO_FROM_NUMBER,
                              to=str(userContact)
                          )
        print(message.sid)
    elif(contactPrefix=='sms'):
        pass;
    elif(contactPrefix=='facebook'):
        pass;
    else:
        pass;

def get_custID(contactId, table):
    dynamodb = boto3.resource('dynamodb')
    
    table = dynamodb.Table(table)
    response = table.query(
        KeyConditionExpression=Key('contactId').eq(contactId)
    )
    if(response['Items']):
        custID =response['Items'][0]['custID']
    else:
        custID=None
    return custID



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


def get_contactID(index, table):
    dynamodb = boto3.resource('dynamodb')

    table = dynamodb.Table(table)
    response = table.query(
        KeyConditionExpression=Key('contactId').eq(index)
    )
    return response['Items'][0]

def remove_contactId(contactID,table):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table)

    try:
        response = table.delete_item(
            Key={
                'contactId': contactID
            }
        )
    except Exception as e:
        print (e)
    else:
        return response