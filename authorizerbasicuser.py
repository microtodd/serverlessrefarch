# Copyright (c) 2018, T.S. Davenport
#
# BasicUser authorizer; all it checks is whether the session is valid
#
# Expects:      method.request.header.x-ap-auth
# Returns:      AWS Policydocument
#
# An example token:
#
# x-ap-auth:    base64-encoded "username:sessionid"
# Ex: email@test.com:20d16087-90e5-4b68-acd4-3a3ca14d0a7a
#     ZW1haWxAdGVzdC5jb206MjBkMTYwODctOTBlNS00YjY4LWFjZDQtM2EzY2ExNGQwYTdhCg==
#
import boto3
import base64
import os
import time
def handler(event,context):

    # Debug
    print 'Event: ' + str(event)
    print 'Context: ' + str(context)

    # From the event, need:
    #
    # event['methodArn']:                              Full resource ARN of what is being requested
    # event['resource']:                               /<apipath> (i.e. /listservices)
    # event['headers']['x-ap-auth']:                   base64-encoded username and sessionid
    # event['requestContext']['identity']['sourceIp']: x.x.x.x
    #

    # Make sure a session token was passed at all
    if 'x-ap-auth' not in event['headers']:
        raise Exception('Unauthorized')

    # Decode the session token and validate it against the session table
    isAuth = False
    try:

        sessionToken = base64.decodestring(event['headers']['x-ap-auth'])
        [username,sessionid] = sessionToken.split(':',2)
        sessionid = sessionid.rstrip()

        dynamoClient = boto3.client('dynamodb')
        if dynamoClient is None:
            raise Exception('couldnt get dynamo client')

        response = dynamoClient.get_item(
            TableName='sessions',
            Key={
                'sessionid': {'S':sessionid}
            },
            AttributesToGet=['username','sourceip','createddatetime'])
        if 'Item' in response:

            # Validate username and sourceip
            if (response['Item']['username']['S'] == username
                and response['Item']['sourceip']['S'] == event['requestContext']['identity']['sourceIp']):

                # Also validate the session lifetime
                #
                # if (num of seconds since session established) < maxSessionLifetime
                # then token still valid
                if time.time() - float(response['Item']['createddatetime']['N']) < float(os.environ['maxTokenLifetime']):
                    isAuth = True

                else:
                    # Token is expired. Delete it from session table.
                    response = dynamoClient.delete_item(
                        TableName='sessions',
                        Key={
                            'sessionid': {'S':sessionid}
                        }
                    )

    except Exception as e:
        print 'Internal error: ' + str(event) + ' :' + str(e)
        raise Exception('Internal error')

    # Explicit allow...did we ever find a case where we are allowing?
    if isAuth:

        # Build the return PolicyDocument
        #
        # Allow the invoke of the specific method being requested
        myOut = {}
        myOut['principalId'] = ''
        myOut['policyDocument'] = {}
        myOut['policyDocument']['Version'] = '2012-10-17'
        myOut['policyDocument']['Statement'] = []
        statement = {}
        statement['Action'] = 'execute-api:Invoke'
        statement['Effect'] = 'Allow'
        statement['Resource'] = event['methodArn']
        myOut['policyDocument']['Statement'].append(statement)
        return myOut

    else:
        raise Exception('Unauthorized')