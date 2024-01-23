import json
import boto3
from boto3.dynamodb.conditions import (Key, Attr)
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
    print("form_data is empty. Not pulling the report.")

    r = http_response(406, "failure", 'form_data is empty. Not pulling the report.')
    print(json.dumps(r))
    return r

  report_id = ""
  try:
    if "report-id" in form_data:
      report_id = form_data["report-id"]
    else:
      print("Unable to find report id in form data")
      r = http_response(406, "failure", 'form_data does not include report id.')
      print(json.dumps(r))
      return r
  except Exception as e:
    r = http_response(406, "failure", 'form_data does not include report id.')
    print(json.dumps(r))
    return r



  table_name = getenv("INCIDENT_REPORT_TABLE_NAME", "incident_reports")

  ddb = boto3.client('dynamodb')
  dynamodb = boto3.resource('dynamodb')
  paginator = ddb.get_paginator('query')
  rows = []
  cars = {}
  operators = {}
  weather = {}
  cars_by_operator = {}
  operators_by_car = {}

  incident_report_table = dynamodb.Table(table_name)


  # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/paginator/Query.html
  # Either the KeyConditions or KeyConditionExpression parameter must be specified in the request.
  try:
    print("Getting Report from DynamoDB")

    response = incident_report_table.query(
      Select='ALL_ATTRIBUTES',
      ReturnConsumedCapacity='NONE',
      KeyConditionExpression=Key('report-id').eq(report_id), #'0e23a749-b94b-11ee-af14-b3389e7c833d'),
      #KeyConditions = {
      #  "report-id": {'AttributeValueList':[
      #    {'S': '0e23a749-b94b-11ee-af14-b3389e7c833d'},
      #  ]}
      #},
      ConsistentRead=False
    )
    print(response)

    items = response.get("Items", [])
    print("Items:",items)
    for item in items:
      print("Item:",item)
      rows.append(item)

    print("Retrieved report from DynamoDB")
    r = http_response(201, "success", json.dumps({
      "report":rows,
    }))
    print(json.dumps(r))
    return r

  except Exception as e:
    print("Unable read from DynamoDB table: {}".format(table_name))
    print(e)

    r = http_response(500, "error", 'something went wrong.')
    print(json.dumps(r))
    return r



