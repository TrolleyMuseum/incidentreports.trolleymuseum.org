import json
import boto3
import uuid
import datetime
from os import getenv

def http_response(status_code=201, status="success", message=""):
  headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': "Content-Type",
    "Access-Control-Allow-Methods": "OPTIONS,GET,POST"
  }

  return {
    'statusCode': str(status_code),
    #'status': status,
    'body': message,
    'headers': headers
  }

def lambda_handler(event, context):

  body = event.get('body', '{}')
  print("body: {}".format(body))
  form_data = {}
  try:
    form_data = json.loads(body)
  except Exception as e:
    print("Unable to parse form data")
    print(e)
  print("form_data: {}".format(json.dumps(form_data)))
  if form_data == {}:
    print("form_data is empty. Not recording the report.")

    r = http_response(406, "failure", 'form_data is empty. Not recording the report.')
    print(json.dumps(r))
    return r


  else:
    report_id = str(uuid.uuid1())
    now_iso8601 = datetime.datetime.now().isoformat()
    table_name = getenv("INCIDENT_REPORT_TABLE_NAME", "incident_reports")

    item = {
      "report-id": { "S": report_id},
      "created":  { "S": now_iso8601},
    }
    for k in form_data:
      if k != "":
        item[k] = { "S": form_data[k]}

    ddb = boto3.client('dynamodb')

    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/client/put_item.html
    try:
      print("Storing item in DynamoDB")
      response = ddb.put_item(
        TableName=table_name,
        Item=item
      )
    except Exception as e:
      print("Unable to write to DynamoDB table: {}".format(table_name))
      print(e)
      print("Item:")
      print(json.dumps(item))

    print("Stored item in DynamoDB")
    r = http_response(201, "success", 'recorded the report')
    print(json.dumps(r))
    return r

  r = http_response(500, "error", 'something went wrong.')
  print(json.dumps(r))
  return r



