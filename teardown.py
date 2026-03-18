"""
Assignment 11: Teardown -- deletes all resources in reverse creation order.
Safe to run multiple times; missing resources are silently skipped.
"""

import time

import boto3
from botocore.exceptions import ClientError

import config

ec2     = boto3.client("ec2",            region_name=config.REGION)
iam     = boto3.client("iam")
rds     = boto3.client("rds",            region_name=config.REGION)
sm      = boto3.client("secretsmanager", region_name=config.REGION)
lambda_ = boto3.client("lambda",         region_name=config.REGION)
logs    = boto3.client("logs",           region_name=config.REGION)


def _swallow(fn, *args, codes=(
    "NoSuchEntity",
    "NoSuchEntityException",
    "ResourceNotFoundException",
    "DBInstanceNotFoundFault",
    "DBSubnetGroupNotFoundFault",
    "InvalidGroup.NotFound",
    "ResourceNotFound",
    "InvalidParameterException",
), **kwargs):
    """Call fn; silently ignore ClientErrors whose code is in codes."""
    try:
        return fn(*args, **kwargs)
    except ClientError as e:
        if e.response["Error"]["Code"] in codes:
            return None
        raise


# ---------------------------------------------------------------------------
# Step 1: Cancel rotation (prevent mid-teardown Lambda invocations)
# ---------------------------------------------------------------------------

def cancel_rotation():
    print("[1/8] Cancelling rotation schedule...")
    _swallow(sm.cancel_rotate_secret, SecretId=config.SECRET_NAME)
    print("  Done.")


# ---------------------------------------------------------------------------
# Step 2: Delete Lambda functions
# ---------------------------------------------------------------------------

def delete_lambdas():
    print("[2/8] Deleting Lambda functions...")
    for name in [config.ROTATION_LAMBDA_NAME, config.APP_LAMBDA_NAME]:
        _swallow(lambda_.delete_function, FunctionName=name)
        print(f"  Deleted (or not found): {name}")


# ---------------------------------------------------------------------------
# Step 3: Delete Lambda IAM roles
# ---------------------------------------------------------------------------

def _delete_role(role_name):
    # Delete inline policies first
    try:
        policies = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        for p in policies:
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NoSuchEntity", "NoSuchEntityException"):
            raise
    # Detach managed policies
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        for p in attached:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NoSuchEntity", "NoSuchEntityException"):
            raise
    _swallow(iam.delete_role, RoleName=role_name)
    print(f"  Deleted (or not found): {role_name}")


def delete_lambda_roles():
    print("[3/8] Deleting Lambda IAM roles...")
    _delete_role(config.ROTATION_LAMBDA_ROLE)
    _delete_role(config.APP_LAMBDA_ROLE)


# ---------------------------------------------------------------------------
# Step 4: Delete secret (force-delete to avoid 7-day recovery window)
# ---------------------------------------------------------------------------

def delete_secret():
    print("[4/8] Deleting Secrets Manager secret...")
    _swallow(
        sm.delete_secret,
        SecretId=config.SECRET_NAME,
        ForceDeleteWithoutRecovery=True,
    )
    print(f"  Deleted (or not found): {config.SECRET_NAME}")


# ---------------------------------------------------------------------------
# Step 5: Delete RDS instance (poll until gone)
# ---------------------------------------------------------------------------

def delete_rds_instance():
    print("[5/8] Deleting RDS instance (may take ~10 minutes)...")
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=config.DB_INSTANCE_ID,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
        )
        print(f"  Deletion initiated: {config.DB_INSTANCE_ID}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBInstanceNotFoundFault":
            print(f"  Not found: {config.DB_INSTANCE_ID}")
            return
        elif e.response["Error"]["Code"] == "InvalidDBInstanceStateFault":
            # Already being deleted
            print(f"  Already deleting: {config.DB_INSTANCE_ID}")
        else:
            raise

    # Poll until the instance is gone
    for attempt in range(1, 41):
        time.sleep(30)
        try:
            resp   = rds.describe_db_instances(DBInstanceIdentifier=config.DB_INSTANCE_ID)
            status = resp["DBInstances"][0]["DBInstanceStatus"]
            print(f"  [{attempt * 30}s] Status: {status}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBInstanceNotFoundFault":
                print(f"  RDS instance deleted.")
                return
            raise

    print("  WARNING: RDS instance did not finish deleting in 20 minutes")


# ---------------------------------------------------------------------------
# Step 6: Delete DB subnet group (must be after RDS is gone)
# ---------------------------------------------------------------------------

def delete_db_subnet_group():
    print("[6/8] Deleting DB subnet group...")
    _swallow(
        rds.delete_db_subnet_group,
        DBSubnetGroupName=config.DB_SUBNET_GROUP_NAME,
    )
    print(f"  Deleted (or not found): {config.DB_SUBNET_GROUP_NAME}")


# ---------------------------------------------------------------------------
# Step 7: Delete security groups
# ---------------------------------------------------------------------------

def delete_security_groups():
    print("[7/8] Deleting security groups...")

    # Give ENIs time to detach after RDS deletion
    print("  Waiting 30s for network interfaces to detach...")
    time.sleep(30)

    vpc_id = None
    try:
        vpcs   = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
        vpc_id = vpcs["Vpcs"][0]["VpcId"]
    except Exception:
        pass

    def _get_sg_id(name):
        if not vpc_id:
            return None
        try:
            sgs = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": [name]},
                         {"Name": "vpc-id",     "Values": [vpc_id]}]
            )["SecurityGroups"]
            return sgs[0]["GroupId"] if sgs else None
        except Exception:
            return None

    rds_sg_id    = _get_sg_id(config.RDS_SG_NAME)
    lambda_sg_id = _get_sg_id(config.LAMBDA_SG_NAME)

    # Revoke inbound rule on RDS SG that references Lambda SG (required before SG deletion)
    if rds_sg_id and lambda_sg_id:
        _swallow(
            ec2.revoke_security_group_ingress,
            GroupId=rds_sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort":   config.DB_PORT,
                "ToPort":     config.DB_PORT,
                "UserIdGroupPairs": [{"GroupId": lambda_sg_id}],
            }],
        )

    # Delete RDS SG first (it had the inbound rule referencing Lambda SG)
    if rds_sg_id:
        _swallow(ec2.delete_security_group, GroupId=rds_sg_id)
        print(f"  Deleted RDS SG: {rds_sg_id}")
    else:
        print(f"  RDS SG not found: {config.RDS_SG_NAME}")

    if lambda_sg_id:
        _swallow(ec2.delete_security_group, GroupId=lambda_sg_id)
        print(f"  Deleted Lambda SG: {lambda_sg_id}")
    else:
        print(f"  Lambda SG not found: {config.LAMBDA_SG_NAME}")


# ---------------------------------------------------------------------------
# Step 8: Delete CloudWatch log groups
# ---------------------------------------------------------------------------

def delete_log_groups():
    print("[8/8] Deleting CloudWatch log groups...")
    for name in [config.ROTATION_LAMBDA_NAME, config.APP_LAMBDA_NAME]:
        log_group = f"/aws/lambda/{name}"
        _swallow(logs.delete_log_group, logGroupName=log_group)
        print(f"  Deleted (or not found): {log_group}")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("Assignment 11: Teardown")
    print("=" * 60)
    print()

    cancel_rotation()
    delete_lambdas()
    delete_lambda_roles()
    delete_secret()
    delete_rds_instance()
    delete_db_subnet_group()
    delete_security_groups()
    delete_log_groups()

    print()
    print("=" * 60)
    print("TEARDOWN COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
