## Question 1

create S3 bucket from AWS CLI

## A Create an IAM role with S3 full access

Ensuring that we have a file named trust-policy.json in the current directory
```
echo '{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
' > trust-policy.json
```
Then create an IAM role with S3 full access

```
aws iam attach-role-policy --role-name s3_role --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
```
Here the trust policy Json contains the following information

```
{
    "InstanceProfile": {
        "Path": "/",
        "InstanceProfileName": "s3_role_profile",
        "InstanceProfileId": "AIPAZADJDTXH7S6HZAAAV",
        "Arn": "arn:aws:iam::618695728591:instance-profile/s3_role_profile",
        "CreateDate": "2023-05-17T10:18:07+00:00",
        "Roles": []
    }
}
```
<img width="887" alt="Screenshot 2023-05-17 at 5 40 53 PM" src="https://github.com/Rajkeshav12/AWS_Assignment/assets/123532501/63af8ffc-d18c-47fd-be1a-c156849671cb">

Providing the role with S3 full access

```
 aws iam attach-role-policy --role-name s3_role --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
```
Create an EC2 instance with above role Creating an instance profile
```
aws iam create-instance-profile --instance-profile-name s3_role_profile
```
Attaching the role to the instance profile
```
aws iam add-role-to-instance-profile --instance-profile-name s3_role_profile --role-name s3_role
```
Running the instance

```
aws ec2 run-instances --image-id ami-0a79730daaf45078a --instance-type t3.micro --key-name key12pair --iam-instance-profile Name="s3_role_profile"
```
c. Creating the bucket

```
aws s3api create-bucket --bucket s3assgn --region eu-north-1 --create-bucket-configuration LocationConstraint=eu-north-1   
```
```
{
    "Location": "http://s3assgn.s3.amazonaws.com/"
}
```
<img width="837" alt="Screenshot 2023-05-17 at 5 48 35 PM" src="https://github.com/Rajkeshav12/AWS_Assignment/assets/123532501/608ee5b0-5248-4759-a78b-3e6d9075be14">

## Question 2

## put files in S3 bucket from lambda

### Creating Clients
```
import boto3
import json
from botocore.exceptions import ClientError
```

## Create custom role for AWS lambda which will only have put object access Creating policy for put object access
```
iam = boto3.client('iam')

policy_document = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject"
            ],
            "Resource": [
                "arn:aws:s3:::s3assgn/*"
            ]
        }
    ]
}

create_policy_response = iam.create_policy(
        PolicyName='lambdaS-s3-put-object-policy',
        PolicyDocument=json.dumps(policy_document)
)

policy_arn = create_policy_response['Policy']['Arn']


role_name = 'rajkarole'
create_role_response = iam.create_role(
    RoleName=role_name,
    AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    })
)
```
Attach the policy to the role

```
create_role_response = iam.attach_role_policy(
    RoleName=role_name,
    PolicyArn=policy_arn
)
```

b. Add role to generate and access Cloud watch logs

```
cloudwatch_logs_policy_document = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:GetLogEvents"
            ],
            "Resource": "*"
        }
    ]
}

cloudwatch_logs_policy_response = iam.create_policy(
    PolicyName='lambda-cloudwatch-policy-q2',
    PolicyDocument=json.dumps(cloudwatch_logs_policy_document)
)

cloudwatch_logs_policy_arn = cloudwatch_logs_policy_response['Policy']['Arn']
```

Attach the policy to the role

```
iam.attach_role_policy(
    RoleName=role_name ,
    PolicyArn=cloudwatch_logs_policy_arn
)
```
<img width="1097" alt="Screenshot 2023-05-17 at 6 17 06 PM" src="https://github.com/Rajkeshav12/AWS_Assignment/assets/123532501/f75aad7c-ae54-4481-9c31-31698799b046">

c. Create a new Lambda function using the above role

Created a lambda function in which, written a python script in such a way that it generates json in given format and saves that file in the specified bucket.

<img width="1325" alt="Screenshot 2023-05-17 at 6 20 32 PM" src="https://github.com/Rajkeshav12/AWS_Assignment/assets/123532501/17a02e2f-2b3f-4bf1-82ea-dba8201ca665">

d. Schedule the job to run every minute. Stop execution after 3 runs

Written a cloudwatch rule, in such a way that it runs only once per minute and had attached this rule to the written lambda function.

To stop exection after three runs I initilized a counter variable in which we increases upon after every execution and once the count reaches three, the executions stops by setting its concurrency to 0. The below is the lamba fuction which does the above said things.

```
import boto3
import datetime, time
import json

s3 = boto3.resource('s3')

bucket_name = 's3assgn'
key_name = 'transaction{}.json'

cw_logs = boto3.client('logs')
log_group = 'lambda_logs'
log_stream = 'lambda_stream'
counter=0
def set_concurrency_limit(function_name):
    lambda_client = boto3.client('lambda')
    response = lambda_client.put_function_concurrency(
        FunctionName=function_name,
        ReservedConcurrentExecutions=0
    )
    print(response)
    
def lambda_handler(event, context):
    global counter
    counter+=1
    try:
        # Generate JSON in the given format
        transaction_id = 12345
        payment_mode = "card/netbanking/upi"
        Amount = 200.0
        customer_id = 101
        Timestamp = str(datetime.datetime.now())
        transaction_data = {
            "transaction_id": transaction_id,
            "payment_mode": payment_mode,
            "Amount": Amount,
            "customer_id": customer_id,
            "Timestamp": Timestamp
        }
        
        # Save JSON file in S3 bucket
        json_data = json.dumps(transaction_data)
        file_name = key_name.format(Timestamp.replace(" ", "_"))
        s3.Bucket(bucket_name).Object(file_name).put(Body=json_data)
        
        # Log the S3 object creation event
        log_message = f"Object created in S3 bucket {bucket_name}: {file_name}"
        cw_logs.put_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            logEvents=[{
                'timestamp': int(round(time.time() * 1000)),
                'message': log_message
            }]
        )
        
        # Stop execution after 3 runs
        print(context)
        if counter==1:
            print('First execution')
        elif counter==2:
            print('Second execution')
        elif counter==3:
            print('Third execution')
            print('Stopping execution')
            set_concurrency_limit('rajlambdafunction')
    except Exception as e:
        print(e)
 ```

e. Check if cloud watch logs are generated.


<img width="880" alt="Screenshot 2023-05-17 at 6 33 15 PM" src="https://github.com/Rajkeshav12/AWS_Assignment/assets/123532501/5927672b-bb50-4a13-a388-e8a86751bd20">

<img width="923" alt="Screenshot 2023-05-17 at 6 33 58 PM" src="https://github.com/Rajkeshav12/AWS_Assignment/assets/123532501/80c3a33c-8bc8-416c-b660-55aaf261cfea">


## Question 3

### API gateway - Lambda integration

a. Modify lambda function to accept parameters

The below is the fucntion which after modification accepts the parameters and returns the succes meesage and filename.

```
import boto3
import datetime
import json

s3 = boto3.resource('s3')
bucket_name = 's3assgn'
key_name = 'file{}.json'

def lambda_handler(event, context):
    try:
        # Parse input data
        body = event['body']
        timestamp = str(datetime.datetime.now())
        body["timestamp"] = timestamp
        
        # Save JSON file in S3 bucket
        json_data = json.dumps(body)
        file_name = key_name.format(timestamp.replace(" ", "_"))
        s3.Object(bucket_name, file_name).put(Body=json_data)

        # Log the S3 object creation event
        print(f"Object created in S3 bucket {bucket_name}: {file_name}")

        return {
            "file_name": file_name,
            "status": "success"
        }

    except Exception as e:
        print(e)
        return {
            "status": e
        }
  ```
  
  b. Create a POST API from API Gateway, pass parameters as request body to Lambda job. Return the filename and status code as a response.
To create a post API to feed to lambda job these steps were followed

### Steps-

1. Open the API Gateway console and locate the "Create API" button. Click on it.
2. From the available options, choose "REST API" and proceed by clicking "Build".
3. Select "New API" and assign a name to API. Once done, click "Create API".
4. To create a new resource under your API, click "Create Resource".
5. Provide a name for the resource and create it by clicking "Create Resource".
6. Click "Create Method" and choose "POST" from the dropdown menu.
7. From the options presented, select "Lambda Function" and ensure that the "Use Lambda Proxy integration" box is checked.
8. In the "Lambda Function" field, enter the name of your Lambda function. Save the changes by clicking "Save".
9. Access the integration request settings and add a mapping template of "application/json".
10. Insert the provided code snippet into the mapping template.
11. Deploy the API

```
#set($inputRoot = $input.path('$'))
{
    "body": $input.json('$')
}
```

<img width="956" alt="Screenshot 2023-05-17 at 6 42 39 PM" src="https://github.com/Rajkeshav12/AWS_Assignment/assets/123532501/bb33cc4b-8b09-4d87-98cf-badeddfee469">


<img width="895" alt="Screenshot 2023-05-17 at 6 44 22 PM" src="https://github.com/Rajkeshav12/AWS_Assignment/assets/123532501/b5a3e225-8860-4346-9b48-0fe82e0cb119">


c. Consume API from the local machine and pass unique data to lambda.

```
rajkeshavkumarjha@AS-MAC-0350 desktop % curl -X POST -H "Content-Type: application/json" -d '{"transaction_id": 234234, "payment_mode": "cash", "amount": 2000.0, "customer_id": 106}'   https://fng8k9w9se.execute-api.eu-north-1.amazonaws.com/rajstage/rajresource
{"file_name": "file2023-05-17_11:17:25.155634.json", "status": "success"}% 
```

Verification for log file

<img width="869" alt="Screenshot 2023-05-17 at 6 47 11 PM" src="https://github.com/Rajkeshav12/AWS_Assignment/assets/123532501/527f4e66-5b6e-4ee1-8e6b-2ddc2972f95d">

