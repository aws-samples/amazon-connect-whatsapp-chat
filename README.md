# Amazon Connect Whatsapp Integration
This project contains source code and supporting files for supporting whatsapp chat integration using Twilio as broker. Conversations can be escalated from chat to voice.

## Deployed resources

The project includes a cloud formation template with a Serverless Application Model (SAM) transform to deploy resources as follows:

### AWS Lambda functions
- dial: Place calls on user request.
- getAvailableAgents. Check for available agents before placing calls.
- manualCallback. Initiate the calling process based on user request.
- processConnectMessage. Process Amazon Connect responses.
- twilioIncomingMessage. Process incoming messages from Twilio.
- cloudAPIIncomingMessage. Process incoming messages from Twilio.
- healthcheck. Reply to whatsapp challenge.

### DynamoDB Table
- ActiveConnections: Table holding the active connections.

### API Gateway
- messageAPI. API endpoint for message reception.

### SNS Topic
- messageExchange. SNS Topic for message reception from Amazon Connect.

## Prerequisites.
1. Amazon Connect Instance already set up with contact flow for handling tasks. Incoming emails will generate a new task with subject, source and content.
2. AWS Console Access with administrator account.
3. Cloud9 IDE or AWS and SAM tools installed and properly configured with administrator credentials.

## Deploy the solution
1. Clone this repo.

`git clone https://github.com/aws-samples/amazon-connect-whatsapp-chat`

2. Build the solution with SAM.

`sam build` 

if you get an error message about requirements you can try using containers.

`sam build -u` 


3. Deploy the solution.

`sam deploy -g`

SAM will ask for the name of the application (use "whatsapp-to-connect" or something similar) as all resources will be grouped under it; Region and a confirmation prompt before deploying resources, enter y.
SAM can save this information if you plan un doing changes, answer Y when prompted and accept the default environment and file name for the configuration.

### Twilio Configuration
Twilio can be used as a broker for integrations.
1. Open the applications section in the AWS console. Pick the name of the deployed application.
2. Copy the endpoint URL and add it to the Twilio console configuration for whatsapp messages (Messaging -> Settings -> WhatsApp Sandbox settings for sandbox testing ). 
3. Append the following paths.

| Event Name | Description | 
|:--------:|:-------------:|
|WHEN A MESSAGE COMES IN | [ENDPOINT URL] **/twilio** | 
|STATUS CALLBACK URL |[ENDPOINT URL] **/twilio/callback**| 

### WhatsApp Cloud API Configuration
WhatsApp Cloud API released in April 2022 allows direct connections. 
1. Open the applications section in the AWS console. Pick the name of the deployed application.
2. Copy the endpoint URL and add it to the webhook WhatsApp configuration, append the path  **/cloudapi**.
3. Specify a token to be used for verification. Make a note of it.

### Application Configuration
1. Open the Secrets Manager console and edit the ConnectChatConfig secret. Complete the following parameters (only complete the parameters for the integration being used):

| Key | Description | 
|:--------:|:-------------:|
|CONNECT_INSTANCE_ID | Amazon Connect Instance ID | 
|CONTACT_FLOW_ID |Amazon Connect contact flow for chat messages| 
|CONNECT_QUEUE_ID |Amazon Connect Queue for placing outbound calls | 
|TWILIO_SID |Twilio Account SID| 
|TWILIO_AUTH_TOKEN |Twilio Authentication Token| 
|TWILIO_FROM_NUMBER |Twilio FROM number.|
|WHATS_TOKEN| Token from WhatsApp.
|WHATS_PHONE_ID| Phone ID (not number) from WhatsApp.
|WHATS_VERIFICATION_TOKEN| Verification token defined as webhook setup.

## Usage
1. Initiate conversations from whatsapp using the designated number (for instance the sandbox defined one).
2. Messages will be converted to Amazon Connect chat messages and placed on the associated queue.

## Resource deletion
1. Back on the cloudformation console, select the stack and click on Delete and confirm it by pressing Delete Stack. 
