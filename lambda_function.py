import os
import logging
import boto3
import json
import re
import hashlib
import hmac
from datetime import datetime
from random import randint
from urllib.parse import parse_qs

print('## Loading Function')
logger = logging.getLogger()
logger.setLevel(logging.INFO)
date = datetime.now()
dattoLocation = os.environ["DATTO_LOCATION"]
#dattoLocation = "ww4"
dattoUrl = "https://" + dattoLocation + ".autotask.net/Autotask/AutotaskExtend/ExecuteCommand.aspx?Code="
dattoTicketDetail = "OpenTicketDetail&TicketNumber="
dattoTaskDetail = "OpenTaskDetail&TaskNumber="


def verify_slack_request(slack_signature=None, slack_request_timestamp=None, request_body=None):
    basestring = f"v0:{slack_request_timestamp}:{request_body}".encode('utf-8')
    slack_signing_secret = boto3.client('ssm').get_parameter(Name='slack_signing_secret', WithDecryption=True)['Parameter']['Value']
    slack_signing_secret = bytes(slack_signing_secret, 'utf-8')
    my_signature = 'v0=' + hmac.new(slack_signing_secret, basestring, hashlib.sha256).hexdigest()
    if hmac.compare_digest(my_signature, slack_signature):
        return True
    else:
        logger.warning(f"Verification failed. my_signature: {my_signature}")
        return False


def lambda_handler(event, context):
    logger.info('## ENVIRONMENT VARIABLES')
    logger.info(os.environ)
    logger.info('## EVENT')
    logger.info(event)

    try:
        slack_signature = event['headers']['X-Slack-Signature']
        slack_request_timestamp = event['headers']['X-Slack-Request-Timestamp']

        if not verify_slack_request(slack_signature, slack_request_timestamp, event['body']):
            logger.info('Bad request.')
            return {
                "statusCode": 400,
                "body": ''
            }
    except Exception as f:
        logger.error(f"ERROR: {f}")
        return {
            "statusCode": 200,
            "body": ''
        }

    def fetch_user_input(e, target):
        # DataProcessing function
        body = e.get("body")
        data = parse_qs(body)
        resp = json.dumps(data[target])
        resp = resp.strip('[]"')
        return resp

    try:
        matchtext = fetch_user_input(event, 'text')
    except KeyError:
        # Skip match to hit default return if missing input
        print('## KeyError, missing input')
        matchtext = ""

    matchobj = re.match(r'^T[0-9]{8}.[0-9]{4}$', matchtext, re.M | re.I)
    if matchobj:
        dattoticketurl = dattoUrl + dattoTicketDetail + str(matchtext).capitalize()
        dattotaskurl = dattoUrl + dattoTaskDetail + str(matchtext).capitalize()
        return {
            # Return 200
            'statusCode': 200,
            'body': json.dumps(
                {
                    "response_type": "ephemeral",
                    "attachments": [
                        {
                            "title": "Datto links generated successfully",
                            "text": "" + str(matchtext).capitalize() + "",
                            "color": "#FF9900",
                            "fallback": "Ticket: " + dattoticketurl + "",
                            "actions": [
                                {
                                    "type": "button",
                                    "text": "Ticket",
                                    "url": "" + dattoticketurl + ""
                                },
                                {
                                    "type": "button",
                                    "text": "Task",
                                    "url": "" + dattotaskurl + ""
                                }
                            ],
                            "footer": "" + str(event['resource']) + "",
                            "footer_icon": "https://d3rzxc3t2mi4fc.cloudfront.net/dist-7c664b75af166da66f2ecaf3a18fadbdd0c5583d/img/favicon.ico",
                            "ts": "" + str(event['headers']['X-Slack-Request-Timestamp']) + "",
                        }
                    ]
                }
            )
        }
    return {
        'statusCode': 200,
        'body': json.dumps(
            'Generate links `/at T' + date.strftime("%Y%m%d") + '.' + str(randint(0, 9999)).zfill(4) + '`'
        )
    }
