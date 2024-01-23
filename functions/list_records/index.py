import json
import boto3
from boto3.dynamodb.conditions import (Key, Attr)
import uuid
import datetime
from os import getenv
from faker import Faker



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

  table_name = getenv("INCIDENT_REPORT_TABLE_NAME", "incident_reports")

  fake = Faker()
  pseudo_name_map = {}
  pseudo_phone_map = {}
  pseudo_email_map = {}

  ddb = boto3.client('dynamodb')
  paginator = ddb.get_paginator('query')
  rows = []
  cars = {}
  operators = {}
  weather = {}
  cars_by_operator = {}
  operators_by_car = {}
  incidents_by_dates = {}

  # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/paginator/Query.html
  # Either the KeyConditions or KeyConditionExpression parameter must be specified in the request.
  try:
    print("Listing items in DynamoDB")

    response = ddb.scan(
      TableName=table_name,
      #IndexName='report-id',
      #Limit=123,
      Select='ALL_ATTRIBUTES',
      ReturnConsumedCapacity='NONE',
      #TotalSegments=123,
      #Segment=123,
      #ProjectionExpression='string',
      #FilterExpression='string',
      #ExpressionAttributeNames={'string': 'string'},
      ConsistentRead=False
    )

    for items in response.get("Items", []):
      row = {}
      for item in items:
        # 'date-report-written': {'S': '2024-01-22T02:32:12.540Z'}
        for t in items[item]:
          row[item] = items[item][t]
          print("item:[{}] = [{}]".format(item, items[item][t]))

      operator_name = row["name"]

      ##
      ## Set the operator name to a fake pseudonomized name
      ##
      fake_name = ""
      if operator_name not in pseudo_name_map:
        fake_name = fake.name()
        pseudo_name_map[operator_name] = fake_name
      else:
        fake_name = pseudo_name_map[operator_name]
      row["name"] = fake_name
      operator_name = fake_name

      ##
      ## Set the operator phone to a fake pseudonomized phone
      ##
      fake_phone = ""
      if operator_name not in pseudo_phone_map:
        fake_phone = fake.phone_number()
        pseudo_phone_map[operator_name] = fake_phone
      else:
        fake_phone = pseudo_phone_map[operator_name]
      row["phone"] = fake_phone
      operator_phone = fake_phone

      ##
      ## Set the operator email to a fake pseudonomized email
      ##
      fake_email = ""
      if operator_name not in pseudo_email_map:
        fake_email = "it+"+fake_name.replace(" ", "").lower()+"@trolleymuseum.org"
        pseudo_email_map[operator_name] = fake_email
      else:
        fake_email = pseudo_email_map[operator_name]


      if operator_name not in operators:
        operators[operator_name] = []
      operators[operator_name].append(row["date-of-incident"])

      if row["date-of-incident"] not in incidents_by_dates:
        incidents_by_dates[row["date-of-incident"]] = 1
      else:
        incidents_by_dates[row["date-of-incident"]] = 1 + incidents_by_dates[row["date-of-incident"]]

      if "cars-involved" in row:
        cars_involved = row["cars-involved"].split(",")
        for car_involved in cars_involved:
          if car_involved not in cars:
            cars[car_involved] = []
          cars[car_involved].append(row["date-of-incident"])

      if operator_name not in cars_by_operator:
        cars_by_operator[operator_name] = []
      cars_by_operator[operator_name].append(car_involved)

      if car_involved not in operators_by_car:
        operators_by_car[car_involved] = []
      operators_by_car[car_involved].append(operator_name)


      if "weather-conditions" in row:
        weather_conditions = row["weather-conditions"].split(",")
        for weather_condition in weather_conditions:
          if weather_condition not in weather:
            weather[weather_condition] = []
          weather[weather_condition].append(row["date-of-incident"])



        #item:[date-report-written] = [2024-01-22T02:32:12.540Z]
        #item:[everything-is-true] = [on]
        #item:[first-name] = [Alexander]
        #item:[last-name] = [Hamilton]
        #item:[created] = [2024-01-22T14:12:04.228284]
        #item:[report-id] = [37e3543a-b930-11ee-b57c-c1b44d09ef46]
        #item:[email] = [devon+hamilton@hubner.org]
        #item:[name] = [Alexander Hamilton]
        #item:[time-of-incident] = [21:32]
        #item:[date-of-incident] = [2024-01-21]
        #item:[phone] = [207-867-5309]
        #item:[weather-conditions] = [Sun]
        #item:[cars-involved] = [303,1160]


      rows.append(row)

    print("Retrieved list of items from DynamoDB")
    r = http_response(201, "success", json.dumps({
      "rows":rows,
      "cars":cars,
      "operators":operators,
      "weather":weather,
      "cars_by_operator":cars_by_operator,
      "operators_by_car":operators_by_car,
      "incidents_by_dates":incidents_by_dates,
    }))
    print(json.dumps(r))
    return r

  except Exception as e:
    print("Unable read from DynamoDB table: {}".format(table_name))
    print(e)

    r = http_response(500, "error", 'something went wrong.')
    print(json.dumps(r))
    return r



