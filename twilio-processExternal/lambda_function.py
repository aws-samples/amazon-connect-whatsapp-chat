## Twilio external message
import json
import boto3
import os
import sys
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
import requests

ACTIVE_CONNNECTIONS= os.environ['ACTIVE_CONNNECTIONS']
participant_client = boto3.client('connectparticipant')
connect_client = boto3.client('connect')
dynamodb = boto3.resource('dynamodb')

def lambda_handler(event, context):
    print(str(event))
    
    CONFIG_PARAMETER= os.environ['CONFIG_PARAMETER']
    connect_config=json.loads(get_config(CONFIG_PARAMETER))
    INSTANCE_ID= connect_config['CONNECT_INSTANCE_ID']
    CONTACT_FLOW_ID= connect_config['CONTACT_FLOW_ID']
    ACTIVE_CONNNECTIONS= os.environ['ACTIVE_CONNNECTIONS']
    SNS_TOPIC = os.environ['SNS_TOPIC']
    
    ##Twilio specific
    channel = 'twilio'
    message = event['Body']
    name = event['ProfileName']
    customerID = event['From']
    phone = customerID.split(':')[-1]
    
    
    contact = get_contact(customerID, ACTIVE_CONNNECTIONS, 'custID-index')
    if('MediaContentType0' in event):
        fileName = event['MessageSid'] + '.' +event['MediaContentType0'].split('/')[1]
    if(contact):
        print("Found contact, sending message")
        try:
            ##Handle media content
            if('MediaContentType0' in event):
                attachmentResponse = attach_file(event['MediaUrl0'],fileName,event['MediaContentType0'],contact['connectionToken'])
                if(not attachmentResponse):
                    print("Attachment was not successfull")
                    send_message_response = send_message(event['MediaUrl0'], phone, contact['connectionToken'])
            else:
                send_message_response = send_message(message, phone, contact['connectionToken'])
        except:
            print('Invalid Connection Token')
            remove_contactId(contact['contactId'],ACTIVE_CONNNECTIONS)
            print('Initiating connection')
            ##Handle media content
            if('MediaContentType0' in event):
                start_chat_response = start_chat('Attachment', phone, 'whatsapp',CONTACT_FLOW_ID,INSTANCE_ID)
            else:
                start_chat_response = start_chat(message, phone, 'whatsapp',CONTACT_FLOW_ID,INSTANCE_ID)
            start_stream_response = start_stream(INSTANCE_ID, start_chat_response['ContactId'], SNS_TOPIC)
            create_connection_response = create_connection(start_chat_response['ParticipantToken'])
            if('MediaContentType0' in event):
                attachmentResponse = attach_file(event['MediaUrl0'],fileName,event['MediaContentType0'],create_connection_response['ConnectionCredentials']['ConnectionToken'])
                if(not attachmentResponse):
                    print("Attachment was not successfull")
                    send_message_response = send_message(event['MediaUrl0'], phone, create_connection_response['ConnectionCredentials']['ConnectionToken'])
            update_contact(customerID,channel,start_chat_response['ContactId'],start_chat_response['ParticipantToken'],create_connection_response['ConnectionCredentials']['ConnectionToken'],name)
            
    else:
        print("Creating new contact")
        ##Handle media content
        if('MediaContentType0' in event):
            start_chat_response = start_chat('Attachment', phone, 'whatsapp', CONTACT_FLOW_ID, INSTANCE_ID)
        else:
            start_chat_response = start_chat(message, phone, 'whatsapp',CONTACT_FLOW_ID,INSTANCE_ID)
        start_stream_response = start_stream(INSTANCE_ID, start_chat_response['ContactId'], SNS_TOPIC)
        create_connection_response = create_connection(start_chat_response['ParticipantToken'])
        
        print("Creating Connection")
        print(create_connection_response)

        if('MediaContentType0' in event):
            attachmentResponse = attach_file(event['MediaUrl0'],fileName,event['MediaContentType0'],create_connection_response['ConnectionCredentials']['ConnectionToken'])
            if(not attachmentResponse):
                print("Attachment was not successfull")
                send_message_response = send_message(event['MediaUrl0'], phone, create_connection_response['ConnectionCredentials']['ConnectionToken'])
        insert_contact(customerID,channel,start_chat_response['ContactId'],start_chat_response['ParticipantToken'],create_connection_response['ConnectionCredentials']['ConnectionToken'],name)
        

    return {
        'statusCode': 200,
        'body': json.dumps('All good!')
    }
    

def attach_file(fileUrl,fileName,fileType,ConnectionToken):
    
    fileContents = download_file(fileUrl)
    fileSize = sys.getsizeof(fileContents) - 33 ## Removing BYTES overhead
    
    try:
        attachResponse = participant_client.start_attachment_upload(
        ContentType=fileType,
        AttachmentSizeInBytes=fileSize,
        AttachmentName=fileName,
        ConnectionToken=ConnectionToken
        )
    except ClientError as e:
        print("Error while creating attachment")
        if(e.response['Error']['Code'] =='AccessDeniedException'):
            print(e.response['Error'])
            raise e
        elif(e.response['Error']['Code'] =='ValidationException'):
            print(e.response['Error'])
            return None
    else:
        try:
            filePostingResponse = requests.put(attachResponse['UploadMetadata']['Url'], 
            data=fileContents,
            headers=attachResponse['UploadMetadata']['HeadersToInclude'])
        except ClientError as e:
            print("Error while uploading")
            print(e.response['Error'])
            raise e
        else:
            print(filePostingResponse.status_code) 
            verificationResponse = participant_client.complete_attachment_upload(
                AttachmentIds=[attachResponse['AttachmentId']],
                ConnectionToken=ConnectionToken)
            print("Verification Response")
            print(verificationResponse)
            return attachResponse['AttachmentId']

def download_file(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.content
    else:
        return None

def upload_data_to_s3(bytes_data,bucket_name, s3_key):
    s3_resource = boto3.resource('s3')
    obj = s3_resource.Object(bucket_name, s3_key)
    obj.put(ACL='private', Body=bytes_data)

    s3_url = f"https://{bucket_name}.s3.amazonaws.com/{s3_key}"
    return s3_url

def send_message(message, name,connectionToken):
    
    response = participant_client.send_message(
        ContentType='text/plain',
        Content= message,
        ConnectionToken= connectionToken
        )
        
    return response    

    
    
def start_chat(message,phone,channel,contactFlow,connectID):

    start_chat_response = connect_client.start_chat_contact(
            InstanceId=connectID,
            ContactFlowId=contactFlow,
            Attributes={
                'Channel': channel,
                'phone':phone
            },
            ParticipantDetails={
                'DisplayName': phone
            },
            InitialMessage={
                'ContentType': 'text/plain',
                'Content': message
            }
            )
    return start_chat_response

def start_stream(connectID, ContactId, topicARN):
    
    start_stream_response = connect_client.start_contact_streaming(
        InstanceId=connectID,
        ContactId=ContactId,
        ChatStreamingConfiguration={
            'StreamingEndpointArn': topicARN
            }
        )
    return start_stream_response

def create_connection(ParticipantToken):
    
    create_connection_response = participant_client.create_participant_connection(
        Type=['CONNECTION_CREDENTIALS'],
        ParticipantToken=ParticipantToken,
        ConnectParticipant=True
        )
    return(create_connection_response)
    
    
def insert_contact(custID,channel,contactID,participantToken, connectionToken,name):
    
    table = dynamodb.Table(ACTIVE_CONNNECTIONS)
    
    try:
        response = table.update_item(
            Key={
                'contactId': contactID
            }, 
            UpdateExpression='SET #item = :newState, #item2 = :newState2, #item3 = :newState3, #item4 = :newState4,#item5 = :newState5,#item6 = :newState6 ',  
            ExpressionAttributeNames={
                '#item': 'custID',
                '#item2': 'participantToken',
                '#item3': 'connectionToken',
                '#item4': 'name',
                '#item5': 'initialContactID',
                '#item6': 'channel'
            },
            ExpressionAttributeValues={
                ':newState': custID,
                ':newState2': participantToken,
                ':newState3': connectionToken,
                ':newState4': name,
                ':newState5': contactID,
                ':newState6': channel
            },
            ReturnValues="UPDATED_NEW")
        print (response)
    except Exception as e:
        print (e)
    else:
        return response    


def update_contact(custID,channel,contactID,participantToken, connectionToken,name):
    
    table = dynamodb.Table(ACTIVE_CONNNECTIONS)
    
    try:
        response = table.update_item(
            Key={
                'contactId': contactID
            }, 
            UpdateExpression='SET #item = :newState, #item2 = :newState2, #item3 = :newState3, #item4 = :newState4, #item5 = :newState5, #item6 = :newState6',  
            ExpressionAttributeNames={
                '#item': 'custID',
                '#item2': 'participantToken',
                '#item3': 'connectionToken',
                '#item4': 'name',
                '#item5': 'initialContactID',
                '#item6': 'channel'
            },
            ExpressionAttributeValues={
                ':newState': custID,
                ':newState2': participantToken,
                ':newState3': connectionToken,
                ':newState4': name,
                ':newState5': contactID,
                ':newState6': channel
            },
            ReturnValues="UPDATED_NEW")
        print (response)
    except Exception as e:
        print (e)
    else:
        return response

def get_contact(custID, table, index):
    
    
    table = dynamodb.Table(table)
    response = table.query(
        IndexName=index,
        KeyConditionExpression=Key('custID').eq(custID)
    )
    if(response['Items']):
        contactId =response['Items'][0]
    else:
        contactId=None
    return contactId


def remove_contactId(contactId,table):
    
    table = dynamodb.Table(table)

    try:
        response = table.delete_item(
            Key={
                'contactId': contactId
            }
        )
    except Exception as e:
        print (e)
    else:
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
