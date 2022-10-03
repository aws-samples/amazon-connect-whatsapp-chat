##connect Message Processing Function
import json
import boto3
import os
import requests
from twilio.rest import Client as TwilioClient

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

ACTIVE_CONNNECTIONS= os.environ['ACTIVE_CONNNECTIONS']

def lambda_handler(event, context):
    print(event)
    for record in event['Records']:
        message = json.loads(record['Sns']['Message'])
        print("Message")
        print(message)
        message_type= message['Type']
        
        if(message_type == 'MESSAGE'):
            message_attributes = record['Sns']['MessageAttributes']
            message_body = message['Content']
            contactID = message['ContactId']

            ParticipantRole= message['ParticipantRole']
            MessageVisibility= message_attributes['MessageVisibility']['Value']
            if((MessageVisibility == 'CUSTOMER' or MessageVisibility == 'ALL')  and ParticipantRole != 'CUSTOMER' ):
                print("contactID:" + str(contactID))
                customer = get_customer(contactID, ACTIVE_CONNNECTIONS)
                if(customer):
                    print("custID:" + str(customer))

                    channel = customer['channel']
                    phone = customer['custID']
                    systemNumber = customer['systemNumber']
                    send_message(phone,channel,message_body,systemNumber)
                else:
                    print('Contact not found')
        if(message_type == 'ATTACHMENT' and message['ParticipantRole'] != 'CUSTOMER'):
            contactID = message['ContactId']
            customer = get_customer(contactID, ACTIVE_CONNNECTIONS)
            print("Retrieved customer")
            print(customer)
            for attachment in message['Attachments']:
                print("AttachmentID")
                print(attachment['AttachmentId'])
                attachmentId = attachment['AttachmentId']
                attachmentName = attachment['AttachmentName']
                contentType = attachment['ContentType']
                presignedUrl = get_signed_url(customer['connectionToken'],attachmentId)
                print('Presigned URL')
                print(presignedUrl)
                send_attachment(customer['custID'],customer['channel'],presignedUrl,attachmentName,contentType,systemNumber)
        
        if(message_type == 'EVENT'):
            message_attributes = record['Sns']['MessageAttributes']
            message_type = message_attributes['ContentType']['Value']
            if(message_type == 'application/vnd.amazonaws.connect.event.participant.left' or message_type == 'application/vnd.amazonaws.connect.event.chat.ended'):
                print('participant left')
                contactID = message['InitialContactId']
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

def get_signed_url(connectionToken,attachment):
    participant_client = boto3.client('connectparticipant')
    try:
        response = participant_client.get_attachment(
            AttachmentId=attachment,
            ConnectionToken=connectionToken
            )
    except ClientError as e:
        print("Get attachment failed")
        print(e.response['Error']['Code'])
        return None
    else:
        return response['Url']


def send_message(userContact,channel,message,systemNumber):
    CONFIG_PARAMETER= os.environ['CONFIG_PARAMETER']
    connect_config=json.loads(get_config(CONFIG_PARAMETER))
    
    if(channel=='twilio'):
        TWILIO_SID= connect_config['TWILIO_SID']
        TWILIO_AUTH_TOKEN= connect_config['TWILIO_AUTH_TOKEN']
        TWILIO_FROM_NUMBER=connect_config['TWILIO_FROM_NUMBER']
        print("Create Twilio Client")
        client = TwilioClient(TWILIO_SID, TWILIO_AUTH_TOKEN)
        print("Send message:"+ str(message) + ":" + str(systemNumber) +":" + userContact )
        message = client.messages.create(
                              body=str(message),
                              from_=systemNumber,
                              to=str(userContact)
                          )
        print(message.sid)
    elif(channel=='whatsapp'):
        WHATS_PHONE_ID = connect_config['WHATS_PHONE_ID']
        WHATS_TOKEN = 'Bearer ' + connect_config['WHATS_TOKEN']
        URL = 'https://graph.facebook.com/v13.0/'+systemNumber+'/messages'
        headers = {'Authorization': WHATS_TOKEN, 'Content-Type': 'application/json'}
        data = { "messaging_product": "whatsapp", "to": normalize_phone(userContact), "type": "text", "text": json.dumps({ "preview_url": False, "body": message}) }
        print("Sending")
        print(data)
        response = requests.post(URL, headers=headers, data=data)
        responsejson = response.json()
        print("Responses: "+ str(responsejson))
        
    elif(channel=='facebook'):
        pass;
    else:
        pass;

def send_attachment(userContact,channel,url,fileName,mimeType,systemNumber):
    CONFIG_PARAMETER= os.environ['CONFIG_PARAMETER']
    connect_config=json.loads(get_config(CONFIG_PARAMETER))
    
    if(channel=='twilio'):
        TWILIO_SID= connect_config['TWILIO_SID']
        TWILIO_AUTH_TOKEN= connect_config['TWILIO_AUTH_TOKEN']
        TWILIO_FROM_NUMBER=connect_config['TWILIO_FROM_NUMBER']
        print("Create Twilio Client")
        client = TwilioClient(TWILIO_SID, TWILIO_AUTH_TOKEN)
        print("Send attachment:" + str(systemNumber) +":" + userContact )
        message = client.messages.create(
                              from_=systemNumber,
                              media_url=url,
                              to=str(userContact)
                          )
        print(message.sid)
    elif(channel=='whatsapp'):
        WHATS_PHONE_ID = connect_config['WHATS_PHONE_ID']
        WHATS_TOKEN = connect_config['WHATS_TOKEN']
        URL = 'https://graph.facebook.com/v13.0/'+WHATS_PHONE_ID+'/messages'
        headers = {'Authorization': WHATS_TOKEN}
        fileType = get_file_category(mimeType)
        data = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": normalize_phone(userContact),
            "type": fileType,
            fileType: json.dumps({"link" : url})
            }
        print("Sending")
        print(data)
        response = requests.post(URL, headers=headers, data=data)
        responsejson = response.json()
        print("Responses: "+ str(responsejson))

def get_customer(contactId, table):
    dynamodb = boto3.resource('dynamodb')
    
    table = dynamodb.Table(table)
    response = table.query(
        KeyConditionExpression=Key('contactId').eq(contactId)
    )
    if(response['Items']):
        customer =response['Items'][0]
    else:
        customer=None
    return customer

def get_connectionToken(contactId, table):
    dynamodb = boto3.resource('dynamodb')
    
    table = dynamodb.Table(table)
    response = table.query(
        KeyConditionExpression=Key('contactId').eq(contactId)
    )
    if(response['Items']):
        connectionToken =response['Items'][0]['connectionToken']
    else:
        connectionToken=None
    return connectionToken


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
            secret = None
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

def normalize_phone(phone):
    ### Country specific changes required on phone numbers
    
    ### Mexico specific, remove 1 after 52
    if(phone[1:3]=='52' and phone[3] == '1'):
        normalized = phone[1:3] + phone[4:]
    else:
        normalized  = phone[1:]
    return normalized
    ### End Mexico specific
def get_file_category(mimeType):
    ## Possible {AUDIO, CONTACTS, DOCUMENT, IMAGE, TEXT, TEMPLATE, VIDEO, STICKER, LOCATION, INTERACTIVE, REACTION}
    if('application' in mimeType): return 'document'
    elif('image' in mimeType): return 'image' 
    elif('audio' in mimeType): return 'audio'
    elif('video' in mimeType): return 'video'