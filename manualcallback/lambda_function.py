##startScheduledCalls Function
import json
import boto3
import os


def lambda_handler(event, context):

    MACHINE_ID= os.environ['MACHINE_ID']
    contact = str("+" + event['Details']['ContactData']['Attributes']['callbackNumber'])
    start_machine(contact, MACHINE_ID)
    
    return True


def start_machine(phoneNumber,machine):
    client = boto3.client('stepfunctions')
    response = client.start_execution(
        stateMachineArn=machine,
        input="{\"contacts\":{\"phoneNumber\":\"" + phoneNumber + "\"}}"
    )