"""
Assignment 11: Secrets Manager Rotation Lambda

Implements single-user rotation for an RDS MySQL database.
AWS Secrets Manager calls this Lambda four times per rotation cycle:

  1. createSecret  - generate new password, store as AWSPENDING version
  2. setSecret     - apply the new password to the database
  3. testSecret    - verify new credentials connect successfully
  4. finishSecret  - promote AWSPENDING to AWSCURRENT

Each step is idempotent: safe to retry if a previous attempt failed partway through.
"""

import json
import logging
import secrets
import string

import boto3
import pymysql

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sm = boto3.client("secretsmanager")

PASSWORD_CHARS  = string.ascii_letters + string.digits + "!#$%^&*()-_=+[]{}|;:,.<>?"
PASSWORD_LENGTH = 32


# ── Helpers ──────────────────────────────────────────────────────────────────

def generate_password() -> str:
    return "".join(secrets.choice(PASSWORD_CHARS) for _ in range(PASSWORD_LENGTH))


def get_secret_dict(secret_id: str, stage: str, token: str = None) -> dict:
    kwargs = {"SecretId": secret_id, "VersionStage": stage}
    if token:
        kwargs["VersionId"] = token
    resp = sm.get_secret_value(**kwargs)
    return json.loads(resp["SecretString"])


def get_connection(creds: dict):
    return pymysql.connect(
        host=creds["host"],
        port=int(creds.get("port", 3306)),
        user=creds["username"],
        password=creds["password"],
        database=creds["dbname"],
        connect_timeout=10,
    )


# ── Step 1: createSecret ─────────────────────────────────────────────────────

def create_secret(secret_id: str, token: str) -> None:
    logger.info("createSecret: %s", secret_id)

    # Idempotency: if AWSPENDING already exists for this token, nothing to do
    try:
        sm.get_secret_value(SecretId=secret_id, VersionId=token, VersionStage="AWSPENDING")
        logger.info("AWSPENDING already exists for this token - skipping")
        return
    except sm.exceptions.ResourceNotFoundException:
        pass

    current = get_secret_dict(secret_id, "AWSCURRENT")
    pending = dict(current)
    pending["password"] = generate_password()

    sm.put_secret_value(
        SecretId=secret_id,
        ClientRequestToken=token,
        SecretString=json.dumps(pending),
        VersionStages=["AWSPENDING"],
    )
    logger.info("Stored new password as AWSPENDING")


# ── Step 2: setSecret ────────────────────────────────────────────────────────

def set_secret(secret_id: str, token: str) -> None:
    logger.info("setSecret: %s", secret_id)

    pending = get_secret_dict(secret_id, "AWSPENDING", token)

    # Idempotency: if AWSPENDING creds already work, the DB was already updated
    try:
        conn = get_connection(pending)
        conn.close()
        logger.info("AWSPENDING credentials already work - setSecret already applied")
        return
    except Exception:
        pass

    current = get_secret_dict(secret_id, "AWSCURRENT")
    conn = get_connection(current)
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "ALTER USER %s@'%%' IDENTIFIED BY %s",
                (pending["username"], pending["password"]),
            )
            cursor.execute("FLUSH PRIVILEGES")
        conn.commit()
        logger.info("Password updated in MySQL for user '%s'", pending["username"])
    finally:
        conn.close()


# ── Step 3: testSecret ───────────────────────────────────────────────────────

def test_secret(secret_id: str, token: str) -> None:
    logger.info("testSecret: %s", secret_id)

    pending = get_secret_dict(secret_id, "AWSPENDING", token)
    conn = get_connection(pending)
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            assert result[0] == 1, "SELECT 1 returned unexpected result"
        logger.info("testSecret PASSED: new credentials connect successfully")
    finally:
        conn.close()


# ── Step 4: finishSecret ─────────────────────────────────────────────────────

def finish_secret(secret_id: str, token: str) -> None:
    logger.info("finishSecret: %s", secret_id)

    metadata = sm.describe_secret(SecretId=secret_id)
    versions = metadata.get("VersionIdsToStages", {})

    # Idempotency: if this token is already AWSCURRENT, nothing to do
    if "AWSCURRENT" in versions.get(token, []):
        logger.info("Token is already AWSCURRENT - skipping")
        return

    # Find the current version to demote
    current_version = next(
        (vid for vid, stages in versions.items() if "AWSCURRENT" in stages),
        None,
    )

    sm.update_secret_version_stage(
        SecretId=secret_id,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    logger.info("Promoted %s to AWSCURRENT, demoted %s to AWSPREVIOUS", token, current_version)


# ── Entry point ──────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    logger.info("Rotation event: %s", json.dumps(event))

    step      = event["Step"]
    secret_id = event["SecretId"]
    token     = event["ClientRequestToken"]

    metadata = sm.describe_secret(SecretId=secret_id)

    if not metadata.get("RotationEnabled"):
        raise ValueError(f"Secret {secret_id} is not configured for rotation")

    versions = metadata.get("VersionIdsToStages", {})
    if token not in versions:
        raise ValueError(f"Token {token} not found in secret versions")
    if "AWSCURRENT" in versions[token]:
        logger.info("Token is already AWSCURRENT - nothing to do")
        return
    if "AWSPENDING" not in versions[token]:
        raise ValueError(f"Token {token} is not in AWSPENDING stage")

    dispatch = {
        "createSecret": create_secret,
        "setSecret":    set_secret,
        "testSecret":   test_secret,
        "finishSecret": finish_secret,
    }

    handler = dispatch.get(step)
    if not handler:
        raise ValueError(f"Unknown rotation step: {step}")

    handler(secret_id, token)
