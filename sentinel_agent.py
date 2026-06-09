"""
sentinel_agent.py - AI investigation agent that queries LIVE Microsoft Sentinel.

Instead of reading local JSON, the agent's KQL runs against the real Sentinel
workspace via the Azure Monitor Query API. The agent decides which queries to
write based on what it finds - a real agentic investigation against a live SIEM.

SETUP - put this file in a folder with a .env containing:
    AZURE_TENANT_ID=...
    AZURE_CLIENT_ID=...
    AZURE_CLIENT_SECRET=...
    WORKSPACE_ID=7e8398b9-5cfc-4c84-b7dc-6482f6676835
    ANTHROPIC_API_KEY=sk-ant-...     (omit to run in mock mode)

The app (AZURE_CLIENT_ID) needs the 'Log Analytics Reader' role on the workspace.

Install:
    pip install azure-monitor-query azure-identity anthropic

Run:
    python sentinel_agent.py            # live AI if ANTHROPIC_API_KEY set, else mock
    python sentinel_agent.py --mock     # force mock (still queries real Sentinel)
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_env():
    cfg = dict(os.environ)
    p = os.path.join(HERE, ".env")
    if os.path.exists(p):
        for line in open(p):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg


CFG = load_env()


def get_kql_client():
    from azure.identity import ClientSecretCredential
    from azure.monitor.query import LogsQueryClient

    cred = ClientSecretCredential(
        tenant_id=CFG["AZURE_TENANT_ID"],
        client_id=CFG["AZURE_CLIENT_ID"],
        client_secret=CFG["AZURE_CLIENT_SECRET"],
    )
    return LogsQueryClient(cred)


def run_kql(query):
    """Execute KQL against the LIVE Sentinel workspace and return rows as dicts."""
    from azure.monitor.query import LogsQueryStatus
    from datetime import timedelta

    client = get_kql_client()
    try:
        resp = client.query_workspace(
            workspace_id=CFG["WORKSPACE_ID"],
            query=query,
            timespan=timedelta(days=7),
        )
        if resp.status == LogsQueryStatus.SUCCESS:
            tables = resp.tables
        else:
            tables = resp.partial_data
        rows = []
        for t in tables:
            cols = [c for c in t.columns]
            for r in t.rows:
                rows.append({cols[i]: r[i] for i in range(len(cols))})
        return rows
    except Exception as e:
        return {"error": str(e)}


# ---- threat intel (local enrichment) -----------------------------------------
IP_INTEL = {
    "102.89.34.180": {"verdict": "malicious", "categories": ["anonymizer", "account_takeover"]},
    "73.118.45.9": {"verdict": "benign", "categories": ["residential_isp"]},
    "70.114.200.5": {"verdict": "benign", "categories": ["residential_isp"]},
    "98.42.17.66": {"verdict": "benign", "categories": ["mobile_carrier"]},
    "65.52.108.33": {"verdict": "benign", "categories": ["corporate"]},
}


def check_ip_intel(ip):
    return IP_INTEL.get(ip, {"verdict": "unknown", "categories": []})


TOOL_SCHEMAS = [
    {
        "name": "run_kql_query",
        "description": (
            "Run a KQL query against the live Microsoft Sentinel workspace and get rows back. "
            "Tables: SigninLogs_CL (TimeGenerated, UserPrincipalName, IPAddress, Location, "
            "ResultType, ResultDescription, MfaResult, ConditionalAccessStatus, RiskLevelDuringSignIn, "
            "RiskState, UserAgent, DeviceDetail) and AuditLogs_CL (TimeGenerated, OperationName, "
            "UserPrincipalName, InitiatedByIP, Result, TargetResource, ModifiedProperties). "
            "Example: SigninLogs_CL | where RiskLevelDuringSignIn == \"high\" | sort by TimeGenerated asc"
        ),
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "KQL query to run"}},
            "required": ["query"],
        },
    },
    {
        "name": "check_ip_intel",
        "description": "Check an IP address reputation. Returns malicious / benign / unknown.",
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string"}},
            "required": ["ip"],
        },
    },
]

DISPATCH = {"run_kql_query": lambda query: run_kql(query),
            "check_ip_intel": lambda ip: check_ip_intel(ip)}

SYSTEM_PROMPT = """You are a Tier 1 SOC analyst agent investigating a Microsoft Sentinel \
environment. You investigate by writing KQL against the live workspace.

Investigate whether there has been an account compromise. Steps:
1. Query SigninLogs_CL for high-risk sign-ins to find suspicious activity.
2. For any suspicious IP, check threat intel.
3. If you find a compromised account, query AuditLogs_CL for that user to find \
post-compromise actions (inbox rules, forwarding, consents).
4. Correlate into a timeline and decide: is this a real incident or noise?

Base every conclusion on rows you actually retrieved.

When your investigation is complete, your FINAL message must contain ONLY a JSON \
object and nothing else - no preamble, no explanation before or after, no markdown \
code fences. Just the raw JSON object, starting with { and ending with }:
{
  "verdict": "true_positive" | "false_positive" | "needs_investigation",
  "confidence": 0-100,
  "severity": "low" | "medium" | "high" | "critical",
  "summary": "one-sentence headline",
  "reasoning": "why, citing specific evidence",
  "kql_used": ["the KQL queries you ran"],
  "timeline": ["ordered events with timestamps"],
  "recommended_actions": ["concrete next steps"]
}"""


def _extract_json(text):
    """Pull the JSON object out of the model's final message, tolerating any
    surrounding text or code fences."""
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    return {"verdict": "needs_investigation", "confidence": 0, "severity": "unknown",
            "summary": "Could not parse model output.", "reasoning": "",
            "raw": text}


def investigate_live():
    import anthropic

    client = anthropic.Anthropic(api_key=CFG.get("ANTHROPIC_API_KEY"))
    messages = [{"role": "user", "content":
                 "Investigate this Sentinel workspace for any account compromise in the last 7 days."}]

    for _ in range(15):
        resp = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS,
            messages=messages,
        )
        if resp.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": resp.content})
            results = []
            for block in resp.content:
                if block.type == "tool_use":
                    out = DISPATCH[block.name](**block.input)
                    n = len(out) if isinstance(out, list) else 1
                    print(f"    {block.name}({block.input}) -> {n} result(s)")
                    results.append({"type": "tool_result", "tool_use_id": block.id,
                                    "content": json.dumps(out, default=str)})
            messages.append({"role": "user", "content": results})
            continue
        text = "".join(b.text for b in resp.content if b.type == "text")
        return _extract_json(text)
    return {"verdict": "needs_investigation", "confidence": 0, "severity": "unknown",
            "summary": "step limit reached", "reasoning": ""}


def investigate_mock():
    """Queries REAL Sentinel but uses scripted reasoning (no Claude API needed)."""
    print("[agent] querying live Sentinel (mock reasoning)\n")
    kql1 = ('SigninLogs_CL | where RiskLevelDuringSignIn == "high" '
            '| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultDescription, MfaResult '
            '| sort by TimeGenerated asc')
    print(f"    KQL> {kql1}")
    risky = run_kql(kql1)
    if isinstance(risky, dict) and risky.get("error"):
        return {"verdict": "needs_investigation", "confidence": 0, "severity": "unknown",
                "summary": "query failed", "reasoning": risky["error"]}
    print(f"    -> {len(risky)} high-risk sign-ins")

    ips = sorted({r["IPAddress"] for r in risky}) if risky else []
    mal = [ip for ip in ips if check_ip_intel(ip)["verdict"] == "malicious"]
    for ip in ips:
        print(f"    intel> {ip} -> {check_ip_intel(ip)['verdict']}")

    user = risky[0]["UserPrincipalName"] if risky else None
    kql2 = f'AuditLogs_CL | where UserPrincipalName == "{user}" | sort by TimeGenerated asc'
    print(f"    KQL> {kql2}")
    audit = run_kql(kql2)
    audit_n = len(audit) if isinstance(audit, list) else 0
    print(f"    -> {audit_n} audit actions")

    return {
        "verdict": "true_positive" if mal else "needs_investigation",
        "confidence": 96 if mal else 40,
        "severity": "critical" if mal else "medium",
        "summary": f"Account takeover of {user} from malicious IP {mal[0] if mal else '?'} "
                   f"with {audit_n} post-compromise audit action(s).",
        "reasoning": f"Live Sentinel query returned {len(risky)} high-risk sign-ins for {user}, "
                     f"including activity from {mal[0] if mal else 'an unknown IP'} (flagged malicious). "
                     f"AuditLogs showed {audit_n} subsequent control-plane action(s) consistent with BEC.",
        "kql_used": [kql1, kql2],
        "timeline": [f"{r['TimeGenerated']}  {r['ResultDescription']} from {r['IPAddress']}" for r in risky],
        "recommended_actions": [
            f"Disable {user} and revoke sessions", "Block the malicious IP",
            "Remove malicious inbox rules / forwarding", "Engage IR for BEC scoping"],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true")
    args = ap.parse_args()

    for k in ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "WORKSPACE_ID"]:
        if not CFG.get(k):
            print(f"Missing {k} in .env"); sys.exit(1)

    use_live = not args.mock and CFG.get("ANTHROPIC_API_KEY")
    print(f"[agent] investigating live Sentinel workspace ({'live AI' if use_live else 'mock'} mode)\n")

    report = investigate_live() if use_live else investigate_mock()

    print("\n" + "=" * 68)
    print(f"  VERDICT: {report.get('verdict', 'unknown').upper()}  "
          f"(confidence {report.get('confidence')}%, severity {report.get('severity')})")
    print(f"  {report.get('summary')}")
    if report.get("reasoning"):
        print(f"\n  REASONING: {report.get('reasoning')}")
    if report.get("timeline"):
        print("\n  TIMELINE:")
        for t in report["timeline"]:
            print(f"    - {t}")
    if report.get("kql_used"):
        print("\n  KQL RUN AGAINST LIVE SENTINEL:")
        for q in report["kql_used"]:
            print(f"    {q}")
    if report.get("recommended_actions"):
        print("\n  RECOMMENDED ACTIONS:")
        for a in report["recommended_actions"]:
            print(f"    - {a}")
    print("=" * 68)

    with open(os.path.join(HERE, "live_investigation.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)
    print("\n[agent] report saved to live_investigation.json")


if __name__ == "__main__":
    main()