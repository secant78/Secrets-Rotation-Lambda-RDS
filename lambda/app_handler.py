"""
Assignment 11: Application Lambda

Reads database credentials from Secrets Manager and connects to RDS.
Simulates a real application that relies on the managed secret.
"""

import json
import logging
import os

import boto3
import pymysql

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sm = boto3.client("secretsmanager")

SECRET_NAME = os.environ.get("SECRET_NAME", "rds-secrets-rotation-sean")


def lambda_handler(event, context):
    logger.info("app_handler invoked")

    # Fetch current credentials from Secrets Manager
    resp  = sm.get_secret_value(SecretId=SECRET_NAME)
    creds = json.loads(resp["SecretString"])

    logger.info("Retrieved secret. Host=%s User=%s", creds["host"], creds["username"])

    # Connect to RDS and run verification queries
    conn = pymysql.connect(
        host=creds["host"],
        port=int(creds.get("port", 3306)),
        user=creds["username"],
        password=creds["password"],
        database=creds["dbname"],
        connect_timeout=10,
    )
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT VERSION()")
            mysql_version = cursor.fetchone()[0]

            cursor.execute("SELECT CURRENT_USER()")
            current_user = cursor.fetchone()[0]

        result = {
            "status":        "SUCCESS",
            "mysql_version": mysql_version,
            "current_user":  current_user,
            "host":          creds["host"],
            "username":      creds["username"],
        }
        logger.info("Connection successful: %s", json.dumps(result))
        return result
    finally:
        conn.close()
