## process external message
import json
import boto3
import os
#from datetime import datetime
from boto3.dynamodb.conditions import Key

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
    message = event['Body']
    name = event['ProfileName']
    customerID = event['From']


    contact = get_contact(customerID, ACTIVE_CONNNECTIONS, 'custID-index')

    if(contact):
        print("Found contact, sending message")
        try:
            send_message_response = send_message(message, name, contact['connectionToken'])
        except:
            print('Invalid Connection Token')
            print('Initiating connection')
            start_chat_response = start_chat(message, name, CONTACT_FLOW_ID,INSTANCE_ID)
            start_stream_response = start_stream(INSTANCE_ID, start_chat_response['ContactId'], SNS_TOPIC)
            create_connection_response = create_connection(start_chat_response['ParticipantToken'])
            update_contact(customerID,start_chat_response['ContactId'],start_chat_response['ParticipantToken'],create_connection_response['ConnectionCredentials']['ConnectionToken'],name)
            #send_message_response = send_message(message, name, contact['connectionToken'])
    else:
        print("Creating new contact")
        start_chat_response = start_chat(message, name, CONTACT_FLOW_ID,INSTANCE_ID)
        start_stream_response = start_stream(INSTANCE_ID, start_chat_response['ContactId'], SNS_TOPIC)
        create_connection_response = create_connection(start_chat_response['ParticipantToken'])
        print("Create Connection")
        print(create_connection_response)
        #send_message_response = send_message(message, name, create_connection_response['ConnectionCredentials']['ConnectionToken'])
        insert_contact(customerID,start_chat_response['ContactId'],start_chat_response['ParticipantToken'],create_connection_response['ConnectionCredentials']['ConnectionToken'],name)
        

    return {
        'statusCode': 200,
        'body': json.dumps('All good!')
    }
    

def send_message(message, name,connectionToken):
    
    response = participant_client.send_message(
        ContentType='text/plain',
        Content= message,
        ConnectionToken= connectionToken
        )
        
    return response    

    
    
def start_chat(message,name,contactFlow,connectID):


    start_chat_response = connect_client.start_chat_contact(
        InstanceId=connectID,
        ContactFlowId=contactFlow,
        Attributes={
            'Channel': "CHAT"
        },
        ParticipantDetails={
            'DisplayName': name
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
    
    
def insert_contact(custID,contactID,participantToken, connectionToken,name):
    
    table = dynamodb.Table(ACTIVE_CONNNECTIONS)
    
    try:
        response = table.update_item(
            Key={
                'contactId': contactID
            }, 
            UpdateExpression='SET #item = :newState, #item2 = :newState2, #item3 = :newState3, #item4 = :newState4,#item5 = :newState5 ',  
            ExpressionAttributeNames={
                '#item': 'custID',
                '#item2': 'participantToken',
                '#item3': 'connectionToken',
                '#item4': 'name',
                '#item5': 'initialContactID'
            },
            ExpressionAttributeValues={
                ':newState': custID,
                ':newState2': participantToken,
                ':newState3': connectionToken,
                ':newState4': name,
                ':newState5': contactID
            },
            ReturnValues="UPDATED_NEW")
        print (response)
    except Exception as e:
        print (e)
    else:
        return response    


def update_contact(custID,contactID,participantToken, connectionToken,name):
    
    table = dynamodb.Table(ACTIVE_CONNNECTIONS)
    
    try:
        response = table.update_item(
            Key={
                'contactId': contactID
            }, 
            UpdateExpression='SET #item = :newState, #item2 = :newState2, #item3 = :newState3, #item4 = :newState4',  
            ExpressionAttributeNames={
                '#item': 'custID',
                '#item2': 'participantToken',
                '#item3': 'connectionToken',
                '#item4': 'name'
            },
            ExpressionAttributeValues={
                ':newState': custID,
                ':newState2': participantToken,
                ':newState3': connectionToken,
                ':newState4': name
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


def remove_contactId(phoneNumber,table):
    
    table = dynamodb.Table(table)

    try:
        response = table.delete_item(
            Key={
                'phoneNumber': phoneNumber
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