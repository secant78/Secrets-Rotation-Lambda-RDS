"""
Assignment 11: Secrets Rotation with Lambda and RDS -- infrastructure setup.

Creates (idempotently):
  1.  Security groups        -- Lambda SG (outbound only) + RDS SG (3306 from Lambda SG)
  2.  RDS DB subnet group    -- all default-VPC subnets
  3.  RDS MySQL instance     -- db.t3.micro, MySQL 8.0, no public access
  4.  Secrets Manager secret -- initial credentials JSON
  5.  Rotation Lambda role   -- SecretsManager, RDS describe, Logs, VPC ENI
  6.  App Lambda role        -- SecretsManager GetSecretValue, Logs, VPC ENI
  7.  Rotation Lambda        -- packaged with pymysql, VPC-enabled
  8.  App Lambda             -- packaged with pymysql, VPC-enabled
  9.  SM invoke permission   -- allows Secrets Manager to call rotation Lambda
 10.  Rotation schedule      -- 7-day automatic rotation (also triggers immediately)
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import time
import zipfile

import boto3
from botocore.exceptions import ClientError

import config

ec2      = boto3.client("ec2",            region_name=config.REGION)
iam      = boto3.client("iam")
rds      = boto3.client("rds",            region_name=config.REGION)
sm       = boto3.client("secretsmanager", region_name=config.REGION)
lambda_  = boto3.client("lambda",         region_name=config.REGION)
sts      = boto3.client("sts")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _account_id():
    return sts.get_caller_identity()["Account"]


def _tag(name):
    return [
        {"Key": "Name",    "Value": name},
        {"Key": "Project", "Value": "SecretsRotation-Assignment11"},
    ]


def _wait(seconds, msg=""):
    print(f"  Waiting {seconds}s{': ' + msg if msg else ''}...")
    time.sleep(seconds)


def _get_default_vpc_and_subnets():
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
    vpc_id = vpcs["Vpcs"][0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )
    subnet_ids = [s["SubnetId"] for s in subnets["Subnets"]]
    return vpc_id, subnet_ids


def _zip_lambda_with_pymysql(handler_filename: str) -> bytes:
    """Package a Lambda handler + pymysql into a zip and return raw bytes."""
    buf = io.BytesIO()
    with tempfile.TemporaryDirectory() as pkg_dir:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "pymysql",
             "--target", pkg_dir, "--quiet"],
        )
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            handler_path = os.path.join(
                os.path.dirname(__file__), "lambda", handler_filename
            )
            zf.write(handler_path, handler_filename)
            for root, _dirs, files in os.walk(pkg_dir):
                for file in files:
                    abs_path = os.path.join(root, file)
                    rel_path = os.path.relpath(abs_path, pkg_dir)
                    zf.write(abs_path, rel_path)
    buf.seek(0)
    return buf.read()


# ---------------------------------------------------------------------------
# Step 1: Security groups
# ---------------------------------------------------------------------------

def create_security_groups():
    print("\n[1/10] Security groups...")
    vpc_id, _ = _get_default_vpc_and_subnets()

    # Lambda SG
    lambda_sg_id = None
    try:
        resp = ec2.create_security_group(
            GroupName=config.LAMBDA_SG_NAME,
            Description="Lambda SG for secrets rotation - outbound only",
            VpcId=vpc_id,
            TagSpecifications=[{"ResourceType": "security-group", "Tags": _tag(config.LAMBDA_SG_NAME)}],
        )
        lambda_sg_id = resp["GroupId"]
        print(f"  Created Lambda SG: {lambda_sg_id}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidGroup.Duplicate":
            filters = [{"Name": "group-name", "Values": [config.LAMBDA_SG_NAME]},
                       {"Name": "vpc-id",      "Values": [vpc_id]}]
            lambda_sg_id = ec2.describe_security_groups(Filters=filters)["SecurityGroups"][0]["GroupId"]
            print(f"  Lambda SG already exists: {lambda_sg_id}")
        else:
            raise

    # RDS SG
    rds_sg_id = None
    try:
        resp = ec2.create_security_group(
            GroupName=config.RDS_SG_NAME,
            Description="RDS SG for secrets rotation - MySQL from Lambda SG",
            VpcId=vpc_id,
            TagSpecifications=[{"ResourceType": "security-group", "Tags": _tag(config.RDS_SG_NAME)}],
        )
        rds_sg_id = resp["GroupId"]
        print(f"  Created RDS SG: {rds_sg_id}")
        # Add inbound rule: TCP 3306 from Lambda SG
        ec2.authorize_security_group_ingress(
            GroupId=rds_sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort":   config.DB_PORT,
                "ToPort":     config.DB_PORT,
                "UserIdGroupPairs": [{"GroupId": lambda_sg_id}],
            }],
        )
        print(f"  Authorized MySQL (3306) from Lambda SG on RDS SG")
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidGroup.Duplicate":
            filters = [{"Name": "group-name", "Values": [config.RDS_SG_NAME]},
                       {"Name": "vpc-id",      "Values": [vpc_id]}]
            rds_sg_id = ec2.describe_security_groups(Filters=filters)["SecurityGroups"][0]["GroupId"]
            print(f"  RDS SG already exists: {rds_sg_id}")
        else:
            raise

    return lambda_sg_id, rds_sg_id


# ---------------------------------------------------------------------------
# Step 2: DB subnet group
# ---------------------------------------------------------------------------

def create_db_subnet_group(subnet_ids):
    print("\n[2/10] DB subnet group...")
    try:
        rds.create_db_subnet_group(
            DBSubnetGroupName=config.DB_SUBNET_GROUP_NAME,
            DBSubnetGroupDescription="Subnet group for secrets rotation RDS instance",
            SubnetIds=subnet_ids,
            Tags=_tag(config.DB_SUBNET_GROUP_NAME),
        )
        print(f"  Created DB subnet group: {config.DB_SUBNET_GROUP_NAME}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBSubnetGroupAlreadyExistsFault":
            print(f"  DB subnet group already exists: {config.DB_SUBNET_GROUP_NAME}")
        else:
            raise


# ---------------------------------------------------------------------------
# Step 3: RDS MySQL instance
# ---------------------------------------------------------------------------

def create_rds_instance(rds_sg_id):
    print("\n[3/10] RDS MySQL instance (this takes 5-15 minutes)...")

    # Check if already exists
    try:
        resp = rds.describe_db_instances(DBInstanceIdentifier=config.DB_INSTANCE_ID)
        status = resp["DBInstances"][0]["DBInstanceStatus"]
        endpoint = resp["DBInstances"][0].get("Endpoint", {}).get("Address")
        if status == "available" and endpoint:
            print(f"  RDS instance already available: {endpoint}")
            return endpoint
        print(f"  RDS instance exists (status={status}), waiting for available...")
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBInstanceNotFoundFault":
            rds.create_db_instance(
                DBInstanceIdentifier=config.DB_INSTANCE_ID,
                DBInstanceClass=config.DB_INSTANCE_CLASS,
                Engine=config.DB_ENGINE,
                EngineVersion=config.DB_ENGINE_VERSION,
                MasterUsername=config.DB_MASTER_USERNAME,
                MasterUserPassword=config.DB_MASTER_PASSWORD,
                DBName=config.DB_NAME,
                DBSubnetGroupName=config.DB_SUBNET_GROUP_NAME,
                VpcSecurityGroupIds=[rds_sg_id],
                PubliclyAccessible=False,
                MultiAZ=False,
                StorageType="gp2",
                AllocatedStorage=20,
                BackupRetentionPeriod=0,
                DeletionProtection=False,
                Tags=_tag(config.DB_INSTANCE_ID),
            )
            print(f"  Creating RDS instance: {config.DB_INSTANCE_ID}")
        else:
            raise

    # Poll until available (up to 20 minutes)
    for attempt in range(1, 41):
        time.sleep(30)
        resp   = rds.describe_db_instances(DBInstanceIdentifier=config.DB_INSTANCE_ID)
        inst   = resp["DBInstances"][0]
        status = inst["DBInstanceStatus"]
        print(f"  [{attempt * 30}s] Status: {status}")
        if status == "available":
            endpoint = inst["Endpoint"]["Address"]
            print(f"  RDS instance available: {endpoint}")
            return endpoint

    raise RuntimeError("RDS instance did not become available within 20 minutes")


# ---------------------------------------------------------------------------
# Step 4: Secrets Manager secret
# ---------------------------------------------------------------------------

def create_secret(db_endpoint):
    print("\n[4/10] Secrets Manager secret...")
    secret_value = json.dumps({
        "username": config.DB_MASTER_USERNAME,
        "password": config.DB_MASTER_PASSWORD,
        "host":     db_endpoint,
        "port":     config.DB_PORT,
        "dbname":   config.DB_NAME,
    })
    try:
        resp = sm.create_secret(
            Name=config.SECRET_NAME,
            SecretString=secret_value,
            Tags=_tag(config.SECRET_NAME),
        )
        arn = resp["ARN"]
        print(f"  Created secret: {arn}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceExistsException":
            arn = sm.describe_secret(SecretId=config.SECRET_NAME)["ARN"]
            # Update host endpoint in case RDS was recreated
            sm.put_secret_value(SecretId=config.SECRET_NAME, SecretString=secret_value)
            print(f"  Secret already exists, updated endpoint: {arn}")
        else:
            raise
    return arn


# ---------------------------------------------------------------------------
# Step 5: Rotation Lambda IAM role
# ---------------------------------------------------------------------------

def create_rotation_lambda_role():
    print("\n[5/10] Rotation Lambda IAM role...")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action":    "sts:AssumeRole",
        }],
    })
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid":    "SecretsManager",
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:UpdateSecretVersionStage",
                    "secretsmanager:GetRandomPassword",
                ],
                "Resource": "*",
            },
            {
                "Sid":      "RDS",
                "Effect":   "Allow",
                "Action":   ["rds:DescribeDBInstances"],
                "Resource": "*",
            },
            {
                "Sid":    "Logs",
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
            {
                "Sid":    "VPC",
                "Effect": "Allow",
                "Action": [
                    "ec2:CreateNetworkInterface",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:DeleteNetworkInterface",
                    "ec2:AssignPrivateIpAddresses",
                    "ec2:UnassignPrivateIpAddresses",
                ],
                "Resource": "*",
            },
        ],
    })

    role_arn = None
    for attempt in range(1, 13):
        try:
            resp     = iam.create_role(
                RoleName=config.ROTATION_LAMBDA_ROLE,
                AssumeRolePolicyDocument=trust,
                Description="Rotation Lambda execution role - SecretsManager + RDS + VPC",
            )
            role_arn = resp["Role"]["Arn"]
            print(f"  Created role: {role_arn}")
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityAlreadyExists":
                role_arn = iam.get_role(RoleName=config.ROTATION_LAMBDA_ROLE)["Role"]["Arn"]
                print(f"  Role already exists: {role_arn}")
                break
            elif "cannot be assumed" in str(e):
                print(f"  IAM propagation (attempt {attempt}/12), waiting 5s...")
                time.sleep(5)
            else:
                raise

    iam.put_role_policy(
        RoleName=config.ROTATION_LAMBDA_ROLE,
        PolicyName="RotationLambdaPolicy",
        PolicyDocument=policy,
    )
    print("  Inline policy attached.")
    return role_arn


# ---------------------------------------------------------------------------
# Step 6: App Lambda IAM role
# ---------------------------------------------------------------------------

def create_app_lambda_role():
    print("\n[6/10] App Lambda IAM role...")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action":    "sts:AssumeRole",
        }],
    })
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid":    "SecretsManager",
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                ],
                "Resource": "*",
            },
            {
                "Sid":    "Logs",
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
            {
                "Sid":    "VPC",
                "Effect": "Allow",
                "Action": [
                    "ec2:CreateNetworkInterface",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:DeleteNetworkInterface",
                    "ec2:AssignPrivateIpAddresses",
                    "ec2:UnassignPrivateIpAddresses",
                ],
                "Resource": "*",
            },
        ],
    })

    role_arn = None
    for attempt in range(1, 13):
        try:
            resp     = iam.create_role(
                RoleName=config.APP_LAMBDA_ROLE,
                AssumeRolePolicyDocument=trust,
                Description="App Lambda execution role - SecretsManager read + VPC",
            )
            role_arn = resp["Role"]["Arn"]
            print(f"  Created role: {role_arn}")
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityAlreadyExists":
                role_arn = iam.get_role(RoleName=config.APP_LAMBDA_ROLE)["Role"]["Arn"]
                print(f"  Role already exists: {role_arn}")
                break
            elif "cannot be assumed" in str(e):
                print(f"  IAM propagation (attempt {attempt}/12), waiting 5s...")
                time.sleep(5)
            else:
                raise

    iam.put_role_policy(
        RoleName=config.APP_LAMBDA_ROLE,
        PolicyName="AppLambdaPolicy",
        PolicyDocument=policy,
    )
    print("  Inline policy attached.")
    return role_arn


# ---------------------------------------------------------------------------
# Step 7: Rotation Lambda
# ---------------------------------------------------------------------------

def create_rotation_lambda(role_arn, subnet_ids, lambda_sg_id):
    print("\n[7/10] Rotation Lambda...")
    print("  Packaging rotation_handler.py + pymysql...")
    code = _zip_lambda_with_pymysql("rotation_handler.py")

    vpc_config = {"SubnetIds": subnet_ids, "SecurityGroupIds": [lambda_sg_id]}

    for attempt in range(1, 13):
        try:
            resp   = lambda_.create_function(
                FunctionName=config.ROTATION_LAMBDA_NAME,
                Runtime="python3.12",
                Role=role_arn,
                Handler="rotation_handler.lambda_handler",
                Code={"ZipFile": code},
                Timeout=config.LAMBDA_TIMEOUT,
                MemorySize=config.LAMBDA_MEMORY,
                VpcConfig=vpc_config,
                Description="Secrets Manager rotation handler for RDS MySQL",
            )
            fn_arn = resp["FunctionArn"]
            print(f"  Created: {fn_arn}")
            return fn_arn
        except lambda_.exceptions.InvalidParameterValueException as e:
            if "cannot be assumed" in str(e):
                print(f"  IAM role not ready (attempt {attempt}/12), waiting 5s...")
                time.sleep(5)
            else:
                raise
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceConflictException":
                lambda_.update_function_code(
                    FunctionName=config.ROTATION_LAMBDA_NAME, ZipFile=code
                )
                lambda_.get_waiter("function_updated").wait(
                    FunctionName=config.ROTATION_LAMBDA_NAME
                )
                lambda_.update_function_configuration(
                    FunctionName=config.ROTATION_LAMBDA_NAME,
                    Role=role_arn,
                    Timeout=config.LAMBDA_TIMEOUT,
                    MemorySize=config.LAMBDA_MEMORY,
                    VpcConfig=vpc_config,
                )
                fn_arn = lambda_.get_function_configuration(
                    FunctionName=config.ROTATION_LAMBDA_NAME
                )["FunctionArn"]
                print(f"  Updated existing function: {fn_arn}")
                return fn_arn
            else:
                raise

    raise RuntimeError("Rotation Lambda creation failed: IAM role never became assumable")


# ---------------------------------------------------------------------------
# Step 8: App Lambda
# ---------------------------------------------------------------------------

def create_app_lambda(role_arn, subnet_ids, lambda_sg_id):
    print("\n[8/10] App Lambda...")
    print("  Packaging app_handler.py + pymysql...")
    code = _zip_lambda_with_pymysql("app_handler.py")

    vpc_config = {"SubnetIds": subnet_ids, "SecurityGroupIds": [lambda_sg_id]}
    env_vars   = {"Variables": {"SECRET_NAME": config.SECRET_NAME}}

    for attempt in range(1, 13):
        try:
            resp   = lambda_.create_function(
                FunctionName=config.APP_LAMBDA_NAME,
                Runtime="python3.12",
                Role=role_arn,
                Handler="app_handler.lambda_handler",
                Code={"ZipFile": code},
                Timeout=config.LAMBDA_TIMEOUT,
                MemorySize=config.LAMBDA_MEMORY,
                VpcConfig=vpc_config,
                Environment=env_vars,
                Description="Application Lambda that reads secret and connects to RDS",
            )
            fn_arn = resp["FunctionArn"]
            print(f"  Created: {fn_arn}")
            return fn_arn
        except lambda_.exceptions.InvalidParameterValueException as e:
            if "cannot be assumed" in str(e):
                print(f"  IAM role not ready (attempt {attempt}/12), waiting 5s...")
                time.sleep(5)
            else:
                raise
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceConflictException":
                lambda_.update_function_code(
                    FunctionName=config.APP_LAMBDA_NAME, ZipFile=code
                )
                lambda_.get_waiter("function_updated").wait(
                    FunctionName=config.APP_LAMBDA_NAME
                )
                lambda_.update_function_configuration(
                    FunctionName=config.APP_LAMBDA_NAME,
                    Role=role_arn,
                    Timeout=config.LAMBDA_TIMEOUT,
                    MemorySize=config.LAMBDA_MEMORY,
                    VpcConfig=vpc_config,
                    Environment=env_vars,
                )
                fn_arn = lambda_.get_function_configuration(
                    FunctionName=config.APP_LAMBDA_NAME
                )["FunctionArn"]
                print(f"  Updated existing function: {fn_arn}")
                return fn_arn
            else:
                raise

    raise RuntimeError("App Lambda creation failed: IAM role never became assumable")


# ---------------------------------------------------------------------------
# Step 9: Grant Secrets Manager permission to invoke rotation Lambda
# ---------------------------------------------------------------------------

def grant_secretsmanager_rotation_permission(rotation_fn_arn):
    print("\n[9/10] Granting Secrets Manager invoke permission...")
    try:
        lambda_.add_permission(
            FunctionName=config.ROTATION_LAMBDA_NAME,
            StatementId="SecretsManagerInvoke",
            Action="lambda:InvokeFunction",
            Principal="secretsmanager.amazonaws.com",
        )
        print("  Permission granted.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceConflictException":
            print("  Permission already exists.")
        else:
            raise


# ---------------------------------------------------------------------------
# Step 10: Configure automatic rotation
# ---------------------------------------------------------------------------

def configure_rotation(secret_arn, rotation_fn_arn):
    print("\n[10/10] Configuring rotation schedule (7 days)...")
    sm.rotate_secret(
        SecretId=secret_arn,
        RotationLambdaARN=rotation_fn_arn,
        RotationRules={"AutomaticallyAfterDays": config.ROTATION_DAYS},
    )
    print(f"  Rotation configured. First rotation triggered immediately.")
    print(f"  Note: wait ~60s for the initial rotation to complete before running tests.")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("Assignment 11: Secrets Rotation with Lambda and RDS")
    print("=" * 60)

    vpc_id, subnet_ids = _get_default_vpc_and_subnets()
    print(f"\nVPC: {vpc_id}  |  Subnets: {subnet_ids}")

    lambda_sg_id, rds_sg_id = create_security_groups()
    create_db_subnet_group(subnet_ids)
    db_endpoint      = create_rds_instance(rds_sg_id)
    secret_arn       = create_secret(db_endpoint)

    rotation_role_arn = create_rotation_lambda_role()
    app_role_arn      = create_app_lambda_role()

    _wait(15, "IAM role propagation")

    rotation_fn_arn = create_rotation_lambda(rotation_role_arn, subnet_ids, lambda_sg_id)
    app_fn_arn      = create_app_lambda(app_role_arn, subnet_ids, lambda_sg_id)

    grant_secretsmanager_rotation_permission(rotation_fn_arn)
    configure_rotation(secret_arn, rotation_fn_arn)

    print("\n" + "=" * 60)
    print("DEPLOYMENT COMPLETE")
    print("=" * 60)
    print(f"\nRDS Endpoint      : {db_endpoint}")
    print(f"Secret Name       : {config.SECRET_NAME}")
    print(f"Rotation Lambda   : {config.ROTATION_LAMBDA_NAME}")
    print(f"App Lambda        : {config.APP_LAMBDA_NAME}")
    print(f"\nMonitor rotation:")
    print(f"  aws logs tail /aws/lambda/{config.ROTATION_LAMBDA_NAME} --follow --region {config.REGION}")


if __name__ == "__main__":
    main()
