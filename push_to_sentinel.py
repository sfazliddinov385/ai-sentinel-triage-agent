"""
push_to_sentinel.py - Upload the scenario logs into Microsoft Sentinel custom
tables (SigninLogs_CL, AuditLogs_CL) via the Azure Monitor Logs Ingestion API.

SIMPLE SETUP - put these 4 files in ONE folder:
    push_to_sentinel.py   (this file)
    signin_logs.json
    audit_logs.json
    .env                  (the config file with your 7 values)

Your .env file should contain (no quotes, no spaces around =):
    AZURE_TENANT_ID=...
    AZURE_CLIENT_ID=...
    AZURE_CLIENT_SECRET=...
    DCR_IMMUTABLE=dcr-0591a91615ba4e3c8fdf1e8df344065c
    DCE_ENDPOINT=https://dce-sentinel-lab-126o.eastus-1.ingest.monitor.azure.com
    STREAM_SIGNIN=Custom-SigninLogs_CL
    STREAM_AUDIT=Custom-AuditLogs_CL

Then in a terminal, from inside that folder:
    pip install azure-monitor-ingestion azure-identity
    python push_to_sentinel.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_env():
    cfg = dict(os.environ)
    env_path = os.path.join(HERE, ".env")
    if os.path.exists(env_path):
        for line in open(env_path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg


def main():
    try:
        from azure.identity import ClientSecretCredential
        from azure.monitor.ingestion import LogsIngestionClient
    except ImportError:
        print("Missing libraries. Run:")
        print("    pip install azure-monitor-ingestion azure-identity")
        sys.exit(1)

    cfg = load_env()
    required = ["DCE_ENDPOINT", "DCR_IMMUTABLE", "STREAM_SIGNIN", "STREAM_AUDIT",
                "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        print("Missing values in .env:", ", ".join(missing))
        print("Make sure a .env file sits next to this script with all 7 values.")
        sys.exit(1)

    signin_path = os.path.join(HERE, "signin_logs.json")
    audit_path = os.path.join(HERE, "audit_logs.json")
    for p in (signin_path, audit_path):
        if not os.path.exists(p):
            print(f"Missing data file: {p}")
            print("Put signin_logs.json and audit_logs.json in the same folder as this script.")
            sys.exit(1)

    credential = ClientSecretCredential(
        tenant_id=cfg["AZURE_TENANT_ID"],
        client_id=cfg["AZURE_CLIENT_ID"],
        client_secret=cfg["AZURE_CLIENT_SECRET"],
    )
    client = LogsIngestionClient(endpoint=cfg["DCE_ENDPOINT"], credential=credential)

    signin = json.load(open(signin_path))
    audit = json.load(open(audit_path))

    print(f"Uploading {len(signin)} sign-in records to {cfg['STREAM_SIGNIN']} ...")
    client.upload(rule_id=cfg["DCR_IMMUTABLE"], stream_name=cfg["STREAM_SIGNIN"], logs=signin)

    print(f"Uploading {len(audit)} audit records to {cfg['STREAM_AUDIT']} ...")
    client.upload(rule_id=cfg["DCR_IMMUTABLE"], stream_name=cfg["STREAM_AUDIT"], logs=audit)

    print("\nDone. Data appears in Sentinel within about 5 minutes.")
    print("Verify in the Logs (KQL) editor with:")
    print("    SigninLogs_CL | take 10")
    print("    AuditLogs_CL | take 10")


if __name__ == "__main__":
    main()
