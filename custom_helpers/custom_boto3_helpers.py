import boto3

def get_papaya_aws_credentials():
  sts_client = boto3.client('sts')
  assumed_role_object=sts_client.assume_role(
    RoleArn="<your-secret-role-name>",
    RoleSessionName="AssumeRoleSession1")
  return assumed_role_object['Credentials']

def get_stored_secret(assumed_role_obj, sec_id):
    client = boto3.client(
        "secretsmanager",
        region_name="<your-aws-region>",
        aws_access_key_id=assumed_role_obj["AccessKeyId"],
        aws_secret_access_key=assumed_role_obj["SecretAccessKey"],
        aws_session_token=assumed_role_obj["SessionToken"],
    )
    return client.get_secret_value(SecretId=sec_id)