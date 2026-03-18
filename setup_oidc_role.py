"""
One-time setup: create the GitHub Actions OIDC provider and IAM role.

Run this locally ONCE before using the GitHub Actions workflows:
    python setup_oidc_role.py

Copy the printed role ARN into your GitHub repository secret: AWS_ROLE_ARN
"""

import json
import boto3
from botocore.exceptions import ClientError

GITHUB_REPO = "secant78/Secrets-Rotation-Lambda-RDS"
OIDC_URL    = "token.actions.githubusercontent.com"
ROLE_NAME   = "GitHubActions-SecretsRotation-Role"
THUMBPRINT  = "6938fd4d98bab03faadb97b34396831e3780aea1"

POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid":      "EC2Permissions",
            "Effect":   "Allow",
            "Action":   ["ec2:*"],
            "Resource": "*",
        },
        {
            "Sid":      "RDSPermissions",
            "Effect":   "Allow",
            "Action":   ["rds:*"],
            "Resource": "*",
        },
        {
            "Sid":      "SecretsManagerPermissions",
            "Effect":   "Allow",
            "Action":   ["secretsmanager:*"],
            "Resource": "*",
        },
        {
            "Sid":      "LambdaPermissions",
            "Effect":   "Allow",
            "Action":   ["lambda:*"],
            "Resource": "*",
        },
        {
            "Sid":    "IAMPermissions",
            "Effect": "Allow",
            "Action": [
                "iam:CreateRole",
                "iam:DeleteRole",
                "iam:GetRole",
                "iam:UpdateRole",
                "iam:PutRolePolicy",
                "iam:GetRolePolicy",
                "iam:DeleteRolePolicy",
                "iam:AttachRolePolicy",
                "iam:DetachRolePolicy",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies",
                "iam:PassRole",
                "iam:TagRole",
            ],
            "Resource": "*",
        },
        {
            "Sid":      "CloudWatchLogsPermissions",
            "Effect":   "Allow",
            "Action":   ["logs:*"],
            "Resource": "*",
        },
        {
            "Sid":      "STSPermissions",
            "Effect":   "Allow",
            "Action":   ["sts:GetCallerIdentity"],
            "Resource": "*",
        },
    ],
}


def get_account_id(sts):
    return sts.get_caller_identity()["Account"]


def ensure_oidc_provider(iam, account_id):
    provider_arn = f"arn:aws:iam::{account_id}:oidc-provider/{OIDC_URL}"
    try:
        iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
        print(f"OIDC provider already exists: {provider_arn}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntityException":
            iam.create_open_id_connect_provider(
                Url=f"https://{OIDC_URL}",
                ClientIDList=["sts.amazonaws.com"],
                ThumbprintList=[THUMBPRINT],
            )
            print(f"Created OIDC provider: {provider_arn}")
        else:
            raise
    return provider_arn


def ensure_iam_role(iam, provider_arn):
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"Federated": provider_arn},
            "Action":    "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {f"{OIDC_URL}:aud": "sts.amazonaws.com"},
                "StringLike":   {f"{OIDC_URL}:sub": f"repo:{GITHUB_REPO}:*"},
            },
        }],
    }

    try:
        resp     = iam.create_role(
            RoleName=ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="GitHub Actions role for Secrets Rotation assignment",
        )
        role_arn = resp["Role"]["Arn"]
        print(f"Created IAM role: {role_arn}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            role_arn = iam.get_role(RoleName=ROLE_NAME)["Role"]["Arn"]
            print(f"IAM role already exists: {role_arn}")
            iam.update_assume_role_policy(
                RoleName=ROLE_NAME,
                PolicyDocument=json.dumps(trust),
            )
        else:
            raise

    iam.put_role_policy(
        RoleName=ROLE_NAME,
        PolicyName="GitHubActionsSecretsRotationPolicy",
        PolicyDocument=json.dumps(POLICY),
    )
    print("Inline policy attached.")
    return role_arn


def main():
    iam = boto3.client("iam")
    sts = boto3.client("sts")

    account_id   = get_account_id(sts)
    print(f"AWS Account: {account_id}")

    provider_arn = ensure_oidc_provider(iam, account_id)
    role_arn     = ensure_iam_role(iam, provider_arn)

    print("\n" + "=" * 60)
    print("SETUP COMPLETE")
    print("=" * 60)
    print(f"\nAdd this to your GitHub repository secrets:")
    print(f"  Secret name : AWS_ROLE_ARN")
    print(f"  Secret value: {role_arn}")
    print("\nGitHub -> Settings -> Secrets and variables -> Actions -> New repository secret")


if __name__ == "__main__":
    main()
