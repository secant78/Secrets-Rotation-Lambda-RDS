"""
Assignment 11: Secrets Rotation with Lambda and RDS
Configuration constants shared across all scripts.
"""

REGION = "us-east-1"
SUFFIX = "sean"

# ── RDS ───────────────────────────────────────────────────────────────────────
DB_INSTANCE_ID       = f"secrets-rotation-db-{SUFFIX}"
DB_INSTANCE_CLASS    = "db.t3.micro"
DB_ENGINE            = "mysql"
DB_ENGINE_VERSION    = "8.0"
DB_NAME              = "mydb"
DB_MASTER_USERNAME   = "admin"
DB_MASTER_PASSWORD   = "InitialPassword123!"   # replaced by Secrets Manager on first rotation
DB_SUBNET_GROUP_NAME = f"secrets-rotation-subnetgrp-{SUFFIX}"
DB_PORT              = 3306

# ── Security Groups ───────────────────────────────────────────────────────────
RDS_SG_NAME          = f"rds-sg-{SUFFIX}"
LAMBDA_SG_NAME       = f"lambda-sg-{SUFFIX}"

# ── Secrets Manager ───────────────────────────────────────────────────────────
SECRET_NAME          = f"rds-secrets-rotation-{SUFFIX}"
ROTATION_DAYS        = 7

# ── Lambda ────────────────────────────────────────────────────────────────────
ROTATION_LAMBDA_NAME = f"rotation-handler-{SUFFIX}"
APP_LAMBDA_NAME      = f"app-handler-{SUFFIX}"
ROTATION_LAMBDA_ROLE = f"rotation-lambda-role-{SUFFIX}"
APP_LAMBDA_ROLE      = f"app-lambda-role-{SUFFIX}"
LAMBDA_TIMEOUT       = 60
LAMBDA_MEMORY        = 256
