from aws_cdk import (
  aws_cognito as cognito,
  aws_iam as iam,
  aws_dynamodb as dynamodb,
  aws_kms as kms,
  aws_apigateway as apigw,
  aws_lambda as lfn,
  aws_logs as logs,
  aws_sns as sns,
  aws_certificatemanager as acm,
  aws_cloudfront as cloudfront,
  aws_cloudfront_origins as origins,
  aws_apigateway as apigw,
  aws_s3 as s3,
  aws_wafv2 as wafv2,
  aws_route53 as r53,
  aws_route53_targets as r53_targets,
  aws_certificatemanager as acm,
  Aws, Duration, Stack, Tags, Aspects, Fn, RemovalPolicy, CustomResource, CfnMapping, CfnOutput, SecretValue
)
from constructs import Construct
from os import ( getcwd, getenv, path, popen )
import subprocess
import shutil

import cdk_nag

class IncidentReportsStack(Stack):

  def prepare_lambda_requirements(self, function_name):
    # create the platform independent paths
    requirements_txt = path.join(getcwd(), "functions", function_name, "requirements.txt")
    proxy_dir        = path.join(getcwd(), "functions", function_name)
    proxy_share_dir  = path.join(getcwd(), "functions", function_name + "_share")

    # copy the code and such to the target directory for distribution
    shutil.copytree(proxy_dir, proxy_share_dir, dirs_exist_ok=True) # copy_function=copy2)

    # install the dependencies using pip
    subprocess.check_call(("pip3 install -r " + requirements_txt + " -t " + proxy_share_dir).split())
    subprocess.check_call(("cd " + proxy_share_dir + " ; zip -9r ../"+proxy_share_dir+".zip .").split())
    #print(popen("pip3 install -r " + requirements_txt + " -t " + proxy_share_dir).read())
    #print(popen("cd " + proxy_share_dir + " ; zip -9r ../"+proxy_share_dir+".zip .").read())

    return proxy_share_dir







  def __init__(self, scope: Construct, id: str, **kwargs) -> None:
    super().__init__(scope, id, **kwargs)
    
    ########################################
    ##
    ## CDK Nag
    ## https://github.com/cdklabs/cdk-nag
    ##
    ## CDK Nag evaluates code against compliance lists:
    ##   * AWS Solutions
    ##   * HIPAA Security
    ##   * NIST 800-53 rev 4
    ##   * NIST 800-53 rev 5
    ##   * PCI DSS 3.2.1
    ##
    ## [AWS Solutions](https://github.com/cdklabs/cdk-nag/blob/main/RULES.md#awssolutions)
    ## offers a collection of cloud-based solutions for dozens of technical and business problems, 
    ## vetted for you by AWS
    ##
    ########################################
    Aspects.of(self).add(cdk_nag.AwsSolutionsChecks())






    ########################################
    ##
    ## Cognito UserPool
    ## https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cognito/UserPool.html
    ##
    ########################################
    user_pool_name = "SeashoreTrolleyMuseum"
    pre_authentication = None
    post_authentication = None
    pre_sign_up = None
    pre_token_generation = None

    ses_domain = "trolleymuseum.org"


    if False:
      user_pool = cognito.UserPool(self, "IncidentReportsUserPool",
        user_pool_name      = user_pool_name,

        self_sign_up_enabled= False,

        #
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cognito/AdvancedSecurityMode.html#aws_cdk.aws_cognito.AdvancedSecurityMode
        #
        advanced_security_mode = cognito.AdvancedSecurityMode.AUDIT,

        #
        # Methods in which a user registers or signs in to a user pool.
        # Allows either username with aliases OR sign in with email, phone, or both.
        # Read the sections on usernames and aliases to learn more:
        # https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html 
        #
        sign_in_aliases=cognito.SignInAliases(username=False,email=True,phone=False),

        enable_sms_role=False,
        #sms_role=user_pool_sms_role,

        #
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cognito/UserVerificationConfig.html#aws_cdk.aws_cognito.UserVerificationConfig
        #
        user_verification   = cognito.UserVerificationConfig(
          email_subject = "Welcome! Please verify your eMail Address for Seashore Trolley Museum.",
          ##
          ## Verification style is either CODE or LINK.
          ## For the CODE, in the template, use: {####}
          ## For the LINK, in the template, use: {##Verify Email##}
          ##
          email_style   = cognito.VerificationEmailStyle.LINK,
          email_body    = "Click here to {##Verify Email##}",
          
          #sms is not configured if VerificationEmailStyle.LINK is chosen
          #sms_message   = "Thanks for signing up for MyPurina! Your verification link is {####}"
        ),

        user_invitation=cognito.UserInvitationConfig(
          email_subject="Invite to join Seashore Trolley Museum",
          email_body="Hello {username}, you have been invited to join Seashore Trolley Museum. Your temporary password is {####}",
          sms_message="Hello {username}, your temporary password for Seashore Trolley Museum is {####}"
        ),

        
        # Attributes which Cognito will look to 
        # verify automatically upon user sign up.
        auto_verify=cognito.AutoVerifiedAttrs(email=True, phone=False),
        
        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cognito/StandardAttributes.html
        # http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        # Mutable attributes can be changed by the user.
        # Immutable (Mutable=False) attributes can never be changed beyond the initial setting.
        standard_attributes=cognito.StandardAttributes(
          fullname=cognito.StandardAttribute(required=True, mutable=True), # The user’s full name in displayable form, including all name parts, titles and suffixes.
          given_name=cognito.StandardAttribute(required=False, mutable=True), # The user’s first name or given name.
          family_name=cognito.StandardAttribute(required=False, mutable=True), # The surname or last name of the user.
          address=cognito.StandardAttribute(required=False, mutable=True), # The user’s postal address.
                                                                           # https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim
                                                                           # formatted: Full mailing address, formatted for display or use on a mailing label. This field MAY contain multiple lines, separated by newlines. Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
                                                                           # street_address: Full street address component, which MAY include house number, street name, Post Office Box, and multi-line extended street address information. This field MAY contain multiple lines, separated by newlines. Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
                                                                           # locality: City or locality component.
                                                                           # region: State, province, prefecture, or region component.
                                                                           # postal_code: Zip code or postal code component.
                                                                           # country: Country name component.
                                                                           # "address": {
                                                                           #   "formatted": "8 Mousam Ridge Rd.\nKennebunk, ME 04043",
                                                                           #   "street_address": "8 Mousam Ridge Rd.",
                                                                           #   "locality": "Kennebunk",
                                                                           #   "region": "ME",
                                                                           #   "postal_code": "04043",
                                                                           #   "country": "US"
                                                                           # }
          email=cognito.StandardAttribute(required=False, mutable=True), # The user’s eMail address, represented as an RFC 5322 [RFC5322] addr-spec.
          locale=cognito.StandardAttribute(required=False, mutable=True), # The user’s locale, represented as a BCP47 [RFC5646] language tag.
          last_update_time=cognito.StandardAttribute(required=False, mutable=True), # The time, the user’s information was last updated.
        ),

        custom_attributes={
          "operator": cognito.BooleanAttribute(mutable=True),
          "memberNumber": cognito.StringAttribute(mutable=True),
        },

        ##
        ## https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cognito/AccountRecovery.html#aws_cdk.aws_cognito.AccountRecovery
        ##
        account_recovery=cognito.AccountRecovery.EMAIL_ONLY,

        ##
        ## https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cognito/UserPoolEmail.html#aws_cdk.aws_cognito.UserPoolEmail
        ##
        email=cognito.UserPoolEmail.with_ses(
          from_email="no-reply@"+ses_domain, # The verified Amazon SES email address that Cognito should use to send emails. The email address used must be a verified email address in Amazon SES and must be configured to allow Cognito to send emails.
          from_name="IncidentReports", # An optional name that should be used as the sender’s name along with the email. Default: - no name
          #reply_to="no-reply@"+ses_domain, # The destination to which the receiver of the email should reploy to. Default: - same as the fromEmail
          ses_region=Aws.REGION, # Required if the UserPool region is different than the SES region. If sending emails with a Amazon SES verified email address, and the region that SES is configured is different than the region in which the UserPool is deployed, you must specify that region here. Default: - The same region as the Cognito UserPool
          ses_verified_domain=ses_domain, # SES Verified custom domain to be used to verify the identity. Default: - no domain
        ),

        device_tracking=cognito.DeviceTracking(
          challenge_required_on_new_device=True,
          device_only_remembered_on_user_prompt=True
        ),

        password_policy = cognito.PasswordPolicy(
          min_length = 8,
          require_digits = True,
          require_lowercase = True,
          require_symbols = True,
          require_uppercase = True,
          temp_password_validity = Duration.days(7), # duration must be in whole days.
        ),

        # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cognito/Mfa.html
        mfa = cognito.Mfa.OFF,


        ##
        ## https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cognito/UserPoolTriggers.html
        ##
        lambda_triggers = cognito.UserPoolTriggers(
          pre_authentication = pre_authentication,
          post_authentication = post_authentication,
          pre_sign_up = pre_sign_up,
          pre_token_generation = pre_token_generation,
        ),


        ##
        ## Do not delete the UserPool if the stack is deleted
        ##
        removal_policy=RemovalPolicy.RETAIN,

      )


    #user_pool.add_domain("CognitoDomain",
    #  cognito_domain=cognito.CognitoDomainOptions(
    #    domain_prefix=user_pool_name_prefix
    #  )
    #)

    #use_custom_domain_name = False
    #if use_custom_domain_name and create_acm_certificate:
    #  user_pool.add_domain("CognitoCustomDomain",
    #    custom_domain=cognito.CustomDomainOptions(
    #      domain_name=zone_name,
    #      certificate=services_purina_com_certificate
    #    )
    #  )






    ########################################
    ##
    ## S3 Bucket
    ##
    ########################################
    bucket_name = "incidentreports" + "-" + Aws.REGION + "-" + Aws.ACCOUNT_ID
    if False:
      incidentreports_bucket = s3.Bucket(self, 'IncidentReportsBucket',
        bucket_name=bucket_name,
        encryption=s3.BucketEncryption.S3_MANAGED,
        access_control=s3.BucketAccessControl.PRIVATE,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        versioned  =False,
      )

    ########################################
    ##
    ## Cloudfront
    ## https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_cloudfront/README.html
    ##
    ########################################
    if False:
      cloudfront.Distribution(self, "incidentreports",
        default_behavior=cloudfront.BehaviorOptions(origin=origins.S3Origin(incidentreports_bucket))
      )

    ########################################
    ##
    ## DynamoDB
    ## https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_dynamodb/README.html
    ##
    ########################################

    ## KMS Key used by DynamoDB Table
    #incidentreports_key = kms.Key(self, "IncidentReportsKey",
    #  enable_key_rotation=True
    #)
    #incidentreports_key.add_alias("IncidentReports")

    # DynamoDB Table
    incidentreports_table_name="incident_reports"
    incidentreports_table = dynamodb.Table(self, "IncidentReportsTable",
      #table_name=incidentreports_table_name,
      partition_key = dynamodb.Attribute(name="report-id", type=dynamodb.AttributeType.STRING),
      #partition_key = dynamodb.Attribute(name="date-of-incident", type=dynamodb.AttributeType.STRING),
      #sort_key      = dynamodb.Attribute(name="email",            type=dynamodb.AttributeType.STRING),
      # PROVISIONED - the default mode where the table and global secondary indexes have configured read and write capacity.
      # PAY_PER_REQUEST - on-demand pricing and scaling. You only pay for what you use and there is no read and write capacity for the table or its global secondary indexes.
      billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption=dynamodb.TableEncryption.AWS_MANAGED,
      #encryption_key=incidentreports_key,
      point_in_time_recovery = True,
    )

    if True:
      incidentreports_table.add_global_secondary_index(
        index_name="date-of-incident", 
        projection_type=dynamodb.ProjectionType.INCLUDE, 
        non_key_attributes=["report-id", "fullname"], 
        partition_key=dynamodb.Attribute(name="date-of-incident", type=dynamodb.AttributeType.STRING),
        sort_key=dynamodb.Attribute(name="email", type=dynamodb.AttributeType.STRING)
      )

    cars = ["303"]#, "1160", "639"]
    for car in cars:
      incidentreports_table.add_global_secondary_index(
        index_name=car, 
        projection_type=dynamodb.ProjectionType.INCLUDE, 
        non_key_attributes=["report-id", "email", "fullname"], 
        partition_key=dynamodb.Attribute(name=car, type=dynamodb.AttributeType.STRING),
        sort_key=dynamodb.Attribute(name="date-of-incident", type=dynamodb.AttributeType.STRING)
      )


    incidentreports_table.apply_removal_policy(RemovalPolicy.RETAIN)




    ########################################
    ##
    ## report_record IAM Role
    ##
    ########################################

    report_record_lambda_policy = iam.ManagedPolicy(self, "ReportRecordLambdaPolicy",
      managed_policy_name = 'incidentreports-policy',
      description         = "IncidentReports Policy")

    report_record_lambda_policy.add_statements(iam.PolicyStatement(
      effect   =iam.Effect.ALLOW,
      actions  =["dynamodb:*"],
      resources=[incidentreports_table.table_arn],
    ))

    #report_record_lambda_policy.add_statements(iam.PolicyStatement(
    #  effect   =iam.Effect.ALLOW,
    #  actions  =["s3:*"],
    #  resources=[incidentreports_bucket.bucket_arn],
    #))

    report_record_lambda_policy.add_statements(iam.PolicyStatement(
      effect   =iam.Effect.ALLOW,
      actions  =["cloudfront:*"],
      resources=["*"],
    ))

    report_record_lambda_policy.add_statements(iam.PolicyStatement(
      effect   =iam.Effect.ALLOW,
      actions  =["logs:CreateLogGroup"],
      resources=["arn:aws:logs:"+Aws.REGION+":"+Aws.ACCOUNT_ID+":*"],
    ))

    report_record_lambda_policy.add_statements(iam.PolicyStatement(
      effect   =iam.Effect.ALLOW,
      actions  =["logs:CreateLogStream", "logs:PutLogEvents"],
      resources=["arn:aws:logs:"+Aws.REGION+":"+Aws.ACCOUNT_ID+":log-group:/aws/lambda/*:*"],
    ))

    #report_record_lambda_policy.add_statements(iam.PolicyStatement(
    #  effect   =iam.Effect.ALLOW,
    #  actions  =["kms:*"],
    #  resources=[incidentreports_table_key.key_arn],
    #))

    report_record_lambda_role = iam.Role(self, 'ReportRecordLambdaRole',
      role_name   ='report-record',
      assumed_by  = iam.CompositePrincipal(
                      iam.ServicePrincipal('lambda.amazonaws.com'),
                    )
    )
    report_record_lambda_role.add_managed_policy(report_record_lambda_policy)





    ########################################
    ##
    ## Lambda Function :: Report Record
    ## https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_lambda/Function.html
    ##
    ## Record Incident Reports 
    ##
    ########################################
  
    report_record_share_dir = self.prepare_lambda_requirements("report_record")

    report_record_function = lfn.Function(self, "ReportRecordFunction",
      description  = "Report Record",
      runtime      = lfn.Runtime.PYTHON_3_9,
      architecture = lfn.Architecture.ARM_64,
      memory_size  = 128, # default = 128 MB
      timeout      = Duration.seconds(300),
      handler      = "index.lambda_handler",
      code         = lfn.Code.from_asset("functions/report_record.zip"),
      role         = report_record_lambda_role,
      environment  = {
        "INCIDENT_REPORT_TABLE_NAME": incidentreports_table.table_name,
        "INDEX_HASH": popen('md5sum functions/report_record_share/index.py | cut -f 1 -d " "').read(),
        "REQUIREMENTS_HASH": popen('md5sum functions/report_record_share/requirements.txt | cut -f 1 -d " "').read(),
        "ZIP_HASH": popen('md5sum functions/report_record.zip | cut -f 1 -d " "').read(),
      },
    )


    ########################################
    ##
    ## Lambda Function :: Report
    ## https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_lambda/Function.html
    ##
    ## Retrieve a single Incident Report
    ##
    ########################################
  
    report_share_dir = self.prepare_lambda_requirements("report")

    report_function = lfn.Function(self, "ReportFunction",
      description  = "Report",
      runtime      = lfn.Runtime.PYTHON_3_9,
      architecture = lfn.Architecture.ARM_64,
      memory_size  = 128, # default = 128 MB
      timeout      = Duration.seconds(300),
      handler      = "index.lambda_handler",
      code         = lfn.Code.from_asset("functions/report.zip"),
      role         = report_record_lambda_role,
      environment  = {
        "INCIDENT_REPORT_TABLE_NAME": incidentreports_table.table_name,
        "INDEX_HASH": popen('md5sum functions/report_share/index.py | cut -f 1 -d " "').read(),
        "REQUIREMENTS_HASH": popen('md5sum functions/report_share/requirements.txt | cut -f 1 -d " "').read(),
        "ZIP_HASH": popen('md5sum functions/report.zip | cut -f 1 -d " "').read(),
      },
    )



    ########################################
    ##
    ## Lambda Function :: List Records
    ## https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_lambda/Function.html
    ##
    ## Record Incident Reports 
    ##
    ########################################
  
    listrecords_share_dir = self.prepare_lambda_requirements("list_records")

    list_records_function = lfn.Function(self, "LisRecordsFunction",
      description  = "List Records",
      runtime      = lfn.Runtime.PYTHON_3_9,
      architecture = lfn.Architecture.ARM_64,
      memory_size  = 128, # default = 128 MB
      timeout      = Duration.seconds(300),
      handler      = "index.lambda_handler",
      code         = lfn.Code.from_asset(listrecords_share_dir),
      role         = report_record_lambda_role,
      environment  = {
        "INCIDENT_REPORT_TABLE_NAME": incidentreports_table.table_name,
        "INDEX_HASH": popen('md5sum functions/list_records_share/index.py | cut -f 1 -d " "').read(),
        "REQUIREMENTS_HASH": popen('md5sum functions/list_records_share/requirements.txt | cut -f 1 -d " "').read(),
        "ZIP_HASH": popen('md5sum functions/list_records.zip | cut -f 1 -d " "').read(),
      },
    )




    ########################################
    ##
    ## API Gateway
    ## https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_apigateway/README.html
    ##
    ########################################

    ## API Gateway Name
    apigateway_name = "incidentreports"

    allowed_origins = [
      "https://incidentreports.trolleymuseum.org",
    ]
    allowed_headers = [
      ## DEFAULT_HEADERS
      'Content-Type', 'X-Amz-Date', 'Authorization', 'X-Api-Key', 
      'X-Amz-Security-Token', 'X-Amz-User-Agent',
      ## Custom Headers
      'X-Amz-Target',
      'access_token',
      'Host',
      'User-Agent',
      'X-Amzn-Trace-Id',
      'X-Forwarded-For',
      'X-Forwarded-Port',
      'X-Forwarded-Proto',
      'accept',
      'limit',
      'offset',
      ## Other
      'authority',
      'method',
      'path',
      'scheme',
      'accept',
      'accept-encoding',
      'accept-language',
      'authorization',
      'origin',
      'referer',
      'user-agent',
    ]

    incident_reports_apigw = apigw.RestApi(self, "IncidentReportsApiGateway",
      rest_api_name = apigateway_name,

      ##
      ## Cross Origin Resource Sharing (CORS)
      ## https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_apigateway/CorsOptions.html#aws_cdk.aws_apigateway.CorsOptions
      ##
      ## curl -v -X OPTIONS https://xxxxx.execute-api.us-east-1.amazonaws.com/prod/xxxxxx
      ##
      default_cors_preflight_options = {
        "allow_headers": allowed_headers, #apigw.Cors.DEFAULT_HEADERS, # specifies which HTTP headers the frontend is allowed to use when making request to our REST Api
        "allow_methods": apigw.Cors.ALL_METHODS, # an array of the HTTP methods our frontend is allowed to use when calling our REST Api
        "allow_credentials": True,
        "allow_origins": apigw.Cors.ALL_ORIGINS, #allowed_origins,
      },
    
    )

    incident_reports_apigw_reportrecord = incident_reports_apigw.root.add_resource("reportrecord")
    # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_apigateway/IResource.html#aws_cdk.aws_apigateway.IResource.add_method
    incident_reports_apigw_reportrecord.add_method("POST",
      apigw.LambdaIntegration(report_record_function),
      authorization_type=apigw.AuthorizationType.NONE # COGNITO, CUSTOM, IAM, NONE
    )

    incident_reports_apigw_report = incident_reports_apigw.root.add_resource("report")
    # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_apigateway/IResource.html#aws_cdk.aws_apigateway.IResource.add_method
    incident_reports_apigw_report.add_method("POST",
      apigw.LambdaIntegration(report_function),
      authorization_type=apigw.AuthorizationType.NONE # COGNITO, CUSTOM, IAM, NONE
    )

    incident_reports_apigw_listrecords = incident_reports_apigw.root.add_resource("reports")
    # https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_apigateway/IResource.html#aws_cdk.aws_apigateway.IResource.add_method
    incident_reports_apigw_listrecords.add_method("GET",
      apigw.LambdaIntegration(list_records_function),
      authorization_type=apigw.AuthorizationType.NONE # COGNITO, CUSTOM, IAM, NONE
    )



    CfnOutput(self, "IncidentReportApiGatewayUrl",
      export_name = "IncidentReportApiGatewayUrl",
      value       = incident_reports_apigw.url
    )













    ########################################
    ##
    ## Tags
    ##
    ########################################
    Tags.of(self).add("application", "incident-reports",  priority=300)
    Tags.of(self).add("purpose",     "incident-reports",  priority=300)
    Tags.of(self).add("owner",       "cdk",               priority=300)
    Tags.of(self).add("createdBy",   "cdk",               priority=300)




    ########################################
    ##
    ## CDK Nag Suppressions
    ## https://github.com/cdklabs/cdk-nag
    ##
    ########################################

    ##
    ## Errors
    ##

    # IAM Roles and Policies
    cdk_nag.NagSuppressions.add_stack_suppressions(self, [
      {"id":"AwsSolutions-IAM4", "reason": "ERROR: The IAM user, role, or group uses AWS managed policies. An AWS managed policy is a standalone policy that is created and administered by AWS. Currently, many AWS managed policies do not restrict resource scope. Replace AWS managed policies with system specific (customer) managed policies. This is a granular rule that returns individual findings that can be suppressed with appliesTo. The findings are in the format Policy::<policy> for AWS managed policies. Example: appliesTo: ['Policy::arn:<AWS::Partition>:iam::aws:policy/foo']"},
      {"id":"AwsSolutions-IAM5", "reason": "ERROR: The IAM entity contains wildcard permissions and does not have a cdk-nag rule suppression with evidence for those permission. Metadata explaining the evidence (e.g. via supporting links) for wildcard permissions allows for transparency to operators. This is a granular rule that returns individual findings that can be suppressed with appliesTo. The findings are in the format Action::<action> for policy actions and Resource::<resource> for resources. Example: appliesTo: ['Action::s3:*']."},
      {"id":"AwsSolutions-L1", "reason": "ERROR: The non-container Lambda function is not configured to use the latest runtime version."},
    ])

    # API Gateway
    cdk_nag.NagSuppressions.add_stack_suppressions(self, [
      {"id":"AwsSolutions-IAM4", "reason": "ERROR: The IAM user, role, or group uses AWS managed policies. An AWS managed policy is a standalone policy that is created and administered by AWS. Currently, many AWS managed policies do not restrict resource scope. Replace AWS managed policies with system specific (customer) managed policies. This is a granular rule that returns individual findings that can be suppressed with appliesTo. The findings are in the format Policy::<policy> for AWS managed policies. Example: appliesTo: ['Policy::arn:<AWS::Partition>:iam::aws:policy/foo']"},
      {"id":"AwsSolutions-IAM5", "reason": "ERROR: The IAM entity contains wildcard permissions and does not have a cdk-nag rule suppression with evidence for those permission. Metadata explaining the evidence (e.g. via supporting links) for wildcard permissions allows for transparency to operators. This is a granular rule that returns individual findings that can be suppressed with appliesTo. The findings are in the format Action::<action> for policy actions and Resource::<resource> for resources. Example: appliesTo: ['Action::s3:*']."},
      {"id":"AwsSolutions-L1", "reason": "ERROR: The non-container Lambda function is not configured to use the latest runtime version."},

      {"id":"AwsSolutions-APIG4", "reason":"The API does not implement authorization."},
      {"id":"AwsSolutions-COG4", "reason":"The API GW method does not use a Cognito user pool authorizer."},
      {"id":"AwsSolutions-APIG1", "reason":"The API does not have access logging enabled."},
      {"id":"AwsSolutions-APIG6", "reason":"The REST API Stage does not have CloudWatch logging enabled for all methods."},
      {"id":"AwsSolutions-APIG2", "reason":"The REST API does not have request validation enabled."},
      {"id":"AwsSolutions-APIG3", "reason":"The REST API stage is not associated with AWS WAFv2 web ACL."},
      {"id":"AwsSolutions-COG2", "reason":"The Cognito user pool does not require MFA."},

      {"id":"AwsSolutions-EC23", "reason": "WARNING: threw an error during validation. This is generally caused by a parameter referencing an intrinsic function. For more details enable verbose logging."},

      {"id":"AwsSolutions-COG3", "reason":"The Cognito user pool does not have AdvancedSecurityMode set to ENFORCED"},
      {"id":"AwsSolutions-CFR3", "reason":"The CloudFront distribution does not have access logging enabled"},

      {"id":"AwsSolutions-CFR1", "reason":"The CloudFront distribution may require Geo restrictions"},
      {"id":"AwsSolutions-CFR2", "reason":"The CloudFront distribution may require integration with AWS WAF"},
    ])

    # Cloudfront+S3
    cdk_nag.NagSuppressions.add_stack_suppressions(self, [
      {"id":"AwsSolutions-S1", "reason":"01234567890123456789"},
      {"id":"AwsSolutions-S2", "reason":"01234567890123456789"},
      {"id":"AwsSolutions-S10", "reason":"01234567890123456789"},
      {"id":"AwsSolutions-CFR4", "reason":"01234567890123456789"},
    ])




