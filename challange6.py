#!/usr/bin/env python3
"""
KriptoStream Automated Storage Hygiene (Retention) — Lab 6 Automation
=========================================================================

Automates:
  Task 1: Define the cleanup scope (krypto-data-cleanup-dev policy,
          Docker package type, scoped to the project + dev-local repos)
  Task 2: Configure retention rules — a time-based rule (age) and a
          "Keep Last N Versions" safety-net rule
  Task 3: Trigger a Dry Run and poll until it completes
  Task 4: Download + inspect the dry-run CSV report, then activate the
          policy with a daily 2 AM cron schedule

REQUIREMENTS
------------
  pip install requests --break-system-packages

CONFIGURATION (environment variables)
--------------------------------------
  JFROG_URL            e.g. https://trialyo541m.jfrog.io
  JFROG_ADMIN_TOKEN     an admin-scoped Access/Identity token

SCHEMA NOTE
-----------
The core create/update payload below (key, description, cronExp,
projectKey, itemType, enabled, skipTrashcan, searchCriteria with repos/
packageTypes/includedProjects/createdBeforeInDays/keepLastNVersions) is
taken directly from JFrog's own REST API reference for
"Update a Package-Level Cleanup Policy" and matches the field names used
by JFrog's official Terraform/Pulumi providers for this same resource —
so it's on firmer ground than some of the schemas we had to reverse-
engineer earlier in this project.

The dry-run trigger and report-download endpoints are less consistently
documented across versions. If those specific calls 400/404, the fastest
fix (same approach that worked for Xray Watches/Policies in Lab 4) is:
trigger the dry run once by hand in Administration > Artifactory Settings
> Retention Policies > Cleanup, then open your browser's Network tab to
capture the real request/response shape and adjust the script accordingly.
"""

import os
import sys
import json
import time
import requests

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

JFROG_URL = os.environ.get("JFROG_URL", "").rstrip("/")
ADMIN_TOKEN = os.environ.get("JFROG_ADMIN_TOKEN", "")

if not JFROG_URL or not ADMIN_TOKEN:
    print("ERROR: Please set JFROG_URL and JFROG_ADMIN_TOKEN environment variables.")
    sys.exit(1)

PROJECT_KEY = "krypto-data"
POLICY_KEY = f"{PROJECT_KEY}-cleanup-dev"
TARGET_REPO = f"{PROJECT_KEY}-docker-dev-local"

TIME_RULE_DAYS = 30          # Task 2: time-based rule — packages older than 30 days
KEEP_LAST_N = 5              # Task 2: version keep rule — safety net
DAILY_2AM_CRON = "0 0 2 * * ?"   # Quartz format, per lab spec

session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {ADMIN_TOKEN}",
    "Content-Type": "application/json",
})


def log(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def check(resp, ok_codes=(200, 201, 204)):
    ok = resp.status_code in ok_codes
    tag = "OK" if ok else "FAIL"
    print(f"    -> {tag} ({resp.status_code}) {resp.request.method} {resp.request.url}")
    if not ok:
        try:
            print(f"       {resp.json()}")
        except Exception:
            print(f"       {resp.text[:400]}")
    return ok


# --------------------------------------------------------------------------
# Task 1 & 2: Create the Cleanup Policy (scope + rules together)
# --------------------------------------------------------------------------

def create_cleanup_policy():
    log(f"Task 1/2: Creating cleanup policy '{POLICY_KEY}'")
    # NOTE: like every other Artifactory *config* resource in this project
    # (repos, users, groups), cleanup policies use idempotent PUT directly
    # to the resource path — not POST to a collection endpoint. The docs
    # sidebar lists this as "Create...post" but that 405 confirms PUT is
    # what the server actually accepts.
    url = f"{JFROG_URL}/artifactory/api/cleanup/packages/policies/{POLICY_KEY}"
    payload = {
        "key": POLICY_KEY,
        "description": "DLTC-01 storage hygiene: cleans up krypto-data dev "
                        "Docker artifacts older than 30 days, always keeping "
                        "the 5 most recent versions as a safety net.",
        "projectKey": PROJECT_KEY,
        "itemType": "package",
        # Policies must be created disabled — activation happens via a
        # separate call after the dry run is reviewed (Task 4).
        "enabled": False,
        "skipTrashcan": True,  # per the lab's "Why This Matters" guidance
        "searchCriteria": {
            "repos": [TARGET_REPO],
            "packageTypes": ["Docker"],
            "includedProjects": [PROJECT_KEY],
            # Task 2, Rule 1: Time-Based Rule
            "createdBeforeInDays": TIME_RULE_DAYS,
            # Task 2, Rule 2: Version Keep Rule (the safety net) — the N
            # most recent versions are always excluded from cleanup, even
            # if they're older than createdBeforeInDays.
            "keepLastNVersions": KEEP_LAST_N,
        },
    }
    resp = session.put(url, data=json.dumps(payload))
    if resp.status_code == 400 and "already exist" in resp.text.lower():
        warn(f"Policy {POLICY_KEY} already exists, continuing.")
        return True
    ok = check(resp, ok_codes=(200, 201))
    if not ok:
        warn("If this fails on schema, create the policy by hand in "
             "Administration > Artifactory Settings > Retention Policies > "
             "Cleanup > + Create Policy, matching the lab spec, then GET it "
             f"back to see the exact accepted shape: "
             f"GET {url}")
    return ok


def verify_scope_precision():
    """Validation checklist item 1: confirm the policy targets *-dev-local
    and explicitly does NOT match *-prod-local."""
    log("Validating scope precision (targets dev-local, not prod-local)")
    url = f"{JFROG_URL}/artifactory/api/cleanup/packages/policies/{POLICY_KEY}"
    resp = session.get(url)
    if not check(resp):
        return False
    data = resp.json()
    repos = data.get("searchCriteria", {}).get("repos", [])
    print(f"    Targeted repos: {repos}")
    targets_dev = TARGET_REPO in repos
    targets_prod = any("prod-local" in r for r in repos)
    if targets_dev and not targets_prod:
        log("    -> OK: scoped to dev-local only, prod-local excluded")
        return True
    warn("    -> Scope looks wrong — double check the repos list above")
    return False


# --------------------------------------------------------------------------
# Task 3: Dry Run
# --------------------------------------------------------------------------

def trigger_dry_run():
    log(f"Task 3: Triggering a Dry Run for '{POLICY_KEY}'")
    url = f"{JFROG_URL}/artifactory/api/cleanup/packages/policies/{POLICY_KEY}/run"
    payload = {"dryRun": True}
    resp = session.put(url, data=json.dumps(payload))
    if not check(resp, ok_codes=(200, 201, 202)):
        warn("If this endpoint doesn't match your platform version, trigger "
             "the dry run by hand instead: Administration > Artifactory "
             "Settings > Retention Policies > Cleanup > locate the policy > "
             "••• > Perform a Dry Run — then use "
             "get_latest_run()/download_report() below to fetch the result.")
        return None
    data = resp.json()
    trigger_id = data.get("triggerId") or data.get("trigger_id") or data.get("id")
    log(f"    -> Dry run triggered, trigger ID: {trigger_id}")
    return trigger_id


def wait_for_dry_run_complete(trigger_id, timeout=300, interval=10):
    if not trigger_id:
        warn("No trigger ID to poll — check the dry run status manually in the UI.")
        return None
    log(f"Waiting for dry run to complete (up to {timeout}s)...")
    url = f"{JFROG_URL}/artifactory/api/cleanup/policies/runs/{trigger_id}"
    waited = 0
    while waited < timeout:
        resp = session.get(url)
        if resp.status_code == 200:
            data = resp.json()
            status = data.get("status", "").lower()
            print(f"    status: {status} ({waited}s elapsed)")
            if "complete" in status:
                log("    -> Dry run complete.")
                return data
            if "fail" in status or "error" in status:
                warn(f"    Dry run failed: {data}")
                return None
        time.sleep(interval)
        waited += interval
    warn("    Timed out waiting for dry run completion.")
    return None


# --------------------------------------------------------------------------
# Task 4: Download Report + Activate
# --------------------------------------------------------------------------

def download_report(trigger_id, out_path=None):
    log(f"Task 4: Downloading dry-run report for trigger {trigger_id}")
    out_path = out_path or f"{POLICY_KEY}-dryrun-report.zip"
    url = f"{JFROG_URL}/artifactory/api/cleanup/policies/runs/{trigger_id}/report"
    resp = session.get(url)
    if resp.status_code != 200:
        check(resp)
        warn("If this 404s, download the report manually from Administration "
             "> Artifactory Settings > Retention Policies > Cleanup > Runs "
             "tab > locate the run > Download icon.")
        return None
    with open(out_path, "wb") as f:
        f.write(resp.content)
    log(f"    -> Saved {out_path} ({len(resp.content)} bytes)")
    return out_path


def inspect_report_for_prod_leakage(zip_path):
    """Validation checklist item 3: confirm the CSV only lists dev-local
    artifacts and NO prod-local artifacts before activation."""
    import zipfile
    import csv
    import io

    log(f"Inspecting {zip_path} for any accidental prod-local matches")
    try:
        with zipfile.ZipFile(zip_path) as z:
            csv_names = [n for n in z.namelist() if n.endswith(".csv")]
            if not csv_names:
                warn("    No CSV found inside the report zip.")
                return False
            with z.open(csv_names[0]) as f:
                content = f.read().decode("utf-8", errors="replace")
    except Exception as e:
        warn(f"    Could not open report zip: {e}")
        return False

    reader = csv.reader(io.StringIO(content))
    rows = list(reader)
    print(f"    Report has {len(rows)} lines")
    prod_hits = [row for row in rows if any("prod-local" in cell for cell in row)]
    if prod_hits:
        warn(f"    -> DANGER: {len(prod_hits)} row(s) reference prod-local! "
             "Do NOT activate this policy until the scope is fixed.")
        for row in prod_hits[:5]:
            print(f"        {row}")
        return False
    log("    -> OK: no prod-local artifacts found in the dry-run report.")
    return True


def activate_policy():
    log(f"Task 4: Activating '{POLICY_KEY}' with daily 2 AM cron schedule")
    url = f"{JFROG_URL}/artifactory/api/cleanup/packages/policies/{POLICY_KEY}"
    payload = {
        "key": POLICY_KEY,
        "cronExp": DAILY_2AM_CRON,
        "enabled": True,
    }
    resp = session.put(url, data=json.dumps(payload))
    return check(resp, ok_codes=(200, 201, 204))


def verify_activation():
    """Validation checklist item 4: confirm Active switch is ON and a
    cron expression is set."""
    log("Validating activation (Active=ON, cron set)")
    url = f"{JFROG_URL}/artifactory/api/cleanup/packages/policies/{POLICY_KEY}"
    resp = session.get(url)
    if not check(resp):
        return False
    data = resp.json()
    enabled = data.get("enabled")
    cron = data.get("cronExp")
    print(f"    enabled={enabled}, cronExp={cron}")
    return bool(enabled) and bool(cron)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    create_cleanup_policy()
    verify_scope_precision()

    trigger_id = trigger_dry_run()
    run_data = wait_for_dry_run_complete(trigger_id)

    report_path = None
    if trigger_id:
        report_path = download_report(trigger_id)

    safe_to_activate = True
    if report_path:
        safe_to_activate = inspect_report_for_prod_leakage(report_path)
    else:
        warn("No report downloaded automatically — manually verify the dry "
             "run CSV before activating (see guidance above).")
        safe_to_activate = False

    if safe_to_activate:
        activate_policy()
        verify_activation()
    else:
        warn("Skipping activation — resolve the scope/report issue first, "
             "then re-run (policy creation is idempotent, so this script "
             "can be safely re-run after fixing the report/scope issue).")

    log("Lab 6 automation complete. Screenshot the policy showing Active "
        "status + cron schedule, and keep the dry-run CSV as your report "
        "deliverable.")


if __name__ == "__main__":
    main()
