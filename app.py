from os import popen

from aws_cdk import App
from lib.incident_reports_stack import IncidentReportsStack

#print(popen("cd functions ; bash make_zips.sh").read())

app = App()
env = {'region': 'us-east-1'}

IncidentReportsStack(app, "IncidentReportsStack", env=env)

app.synth()
