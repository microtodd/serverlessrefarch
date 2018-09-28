# Copyright (c) 2018, T.S. Davenport
#
# Returns:
#
# 200: {body}
# 400: Client sent bad input                {errorMessage:"message"}
# 401: Client did not send auth token       {errorMessage:"message"}
# 403: Client auth token was invalid        {errorMessage:"message"}
# 500: Server-side had an error             {errorMessage:"message"}
#
import json
import os
import sys
import boto3
import base64
def handler(event,context):

    # Debug
    print 'event: ' + str(event)
    print 'context: ' + str(context)

    # Prepare return
    myOut = {}
    myOut['statusCode'] = '200'
    myPayload = {}
    myPayload['status'] = 'unknown'
    myOut['body'] = json.dumps(myPayload)

    # Find out who the caller is
    # Since we got past the authorizer, we can trust the caller is who he says he is
    if 'x-ap-auth' not in event['headers']:
        print 'unauthorized (how did it get past authorizer?): ' + str(e)
        myOut['statusCode'] = '401'
        myPayload['status'] = 'unauthorized'
        myPayload['errorMessage'] = 'Unauthorized'
        myOut['body'] = json.dumps(myPayload)
        return myOut
    try:

        # x-ap-auth:    base64-encoded "username:sessionid"
        # Ex: email@test.com:20d16087-90e5-4b68-acd4-3a3ca14d0a7a
        #     ZW1haWxAdGVzdC5jb206MjBkMTYwODctOTBlNS00YjY4LWFjZDQtM2EzY2ExNGQwYTdhCg==
        sessionToken = base64.decodestring(event['headers']['x-ap-auth'])
        [username,sessionid] = sessionToken.split(':',2)
        if len(username) == 0:
            raise Exception('No username was found')
    except Exception as e:
        print 'error: parse: ' + str(e)
        myOut['statusCode'] = '400'
        myPayload['status'] = 'error'
        myPayload['errorMessage'] = 'Couldnt parse payload'
        myOut['body'] = json.dumps(myPayload)
        return myOut

    # Process

    # Set 'statusCode' to the http response code

    # Return
    myPayload['status'] = 'success'
    myPayload['errorMessage'] = ''
    myOut['body'] = json.dumps(myPayload)

    # successful exit
    return myOut

