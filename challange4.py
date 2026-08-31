#!/usr/bin/env python3
"""
KriptoStream Security Gate (Xray) — Lab 4 Automation
========================================================

Automates:
  Task 1: Create the Security Policy (DLTC-01 / krypto-data-security-block)
  Task 2: Create the project-scoped Watch (krypto-data-dev-watch)
  Task 3: Pull/tag/push a known-vulnerable image (busybox:1.30) and
          trigger an Xray scan against the watch
  Task 4: Verify the download is actually blocked, and pull the
          Watch Violations report

REQUIREMENTS
------------
  - Docker installed and running
  - JFrog CLI (`jf`) installed and configured with a server ID that has
    push/pull access to your instance (needed for `jf docker scan`)
  - pip install requests --break-system-packages

CONFIGURATION (environment variables)
--------------------------------------
  JFROG_URL            e.g. https://trialyo541m.jfrog.io
  JFROG_ADMIN_TOKEN     an admin-scoped Access/Identity token
  JF_CLI_SERVER_ID      the server ID configured via `jf c add` to use for
                         `jf docker scan` (e.g. "trial-admin")
  NOTIFY_EMAIL           optional — email for the policy's Notify action

HONEST CAVEAT
-------------
Xray's Policy V2 and Watch V2 REST schemas have shifted across platform
versions and aren't fully, consistently documented publicly. The payloads
below are built from JFrog's own published examples and are a solid
starting point, but if either POST fails with a schema error, the fastest
fix is: create that one resource by hand in the UI, then GET it back via
the same endpoint to see your instance's exact accepted shape — the same
approach that resolved the OIDC identity mapping schema in Lab 3.
"""

import os
import sys
import json
import subprocess
import requests

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

JFROG_URL = os.environ.get("JFROG_URL", "").rstrip("/")
ADMIN_TOKEN = os.environ.get("JFROG_ADMIN_TOKEN", "")
JF_CLI_SERVER_ID = os.environ.get("JF_CLI_SERVER_ID", "")
NOTIFY_EMAIL = os.environ.get("NOTIFY_EMAIL", "")

if not JFROG_URL or not ADMIN_TOKEN:
    print("ERROR: Please set JFROG_URL and JFROG_ADMIN_TOKEN environment variables.")
    sys.exit(1)

PROJECT_KEY = "krypto-data"
PROJECT_NAME = "KRIPTO-STREAM-DATA"
POLICY_NAME = f"{PROJECT_KEY}-security-block"
RULE_NAME = "Block-High-Critical"
WATCH_NAME = f"{PROJECT_KEY}-dev-watch"
DEV_DOCKER_REPO = f"{PROJECT_KEY}-docker-dev-local"
BUILD_NAME = "krypto-build"
BUILD_NAME_PATTERN = "krypto-build.*"

VULNERABLE_IMAGE = os.environ.get("VULN_IMAGE", "alpine")
VULNERABLE_TAG = os.environ.get("VULN_TAG", "3.7")

REGISTRY_HOST = JFROG_URL.replace("https://", "").replace("http://", "")
TARGET_REF = f"{REGISTRY_HOST}/{DEV_DOCKER_REPO}/{VULNERABLE_IMAGE}:{VULNERABLE_TAG}"

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


def run(cmd, check_rc=False):
    print(f"    $ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip())
    if check_rc and result.returncode != 0:
        warn(f"Command failed with exit code {result.returncode}")
    return result


# --------------------------------------------------------------------------
# Task 0: Make sure the dev-local Docker repo exists
# --------------------------------------------------------------------------

def create_dev_docker_repo():
    log(f"Task 0 (prereq): Ensuring {DEV_DOCKER_REPO} exists")
    url = f"{JFROG_URL}/artifactory/api/repositories/{DEV_DOCKER_REPO}"
    payload = {
        "key": DEV_DOCKER_REPO,
        "rclass": "local",
        "packageType": "docker",
        "projectKey": PROJECT_KEY,
        "environments": ["DEV"],
        "dockerApiVersion": "V2",
        "description": "Dev-local Docker repo, gated by the security Watch in Lab 4",
    }
    resp = session.put(url, data=json.dumps(payload))
    if resp.status_code == 400 and "already exist" in resp.text.lower():
        warn(f"{DEV_DOCKER_REPO} already exists, continuing.")
        return True
    return check(resp)


# --------------------------------------------------------------------------
# Task 1: Security Policy (DLTC-01)
# --------------------------------------------------------------------------

def create_security_policy():
    log(f"Task 1: Creating security policy '{POLICY_NAME}'")
    url = f"{JFROG_URL}/xray/api/v2/policies"
    payload = {
        "name": POLICY_NAME,
        "type": "security",
        "description": "DLTC-01: Block High/Critical severity vulnerabilities "
                        "at download time and fail the CI build.",
        "rules": [
            {
                "name": RULE_NAME,
                "priority": 1,
                "criteria": {
                    "min_severity": "High"
                },
                "actions": {
                    "block_download": {
                        "unscanned": True,
                        "active": True
                    },
                    "fail_build": True,
                    "mails": [NOTIFY_EMAIL] if NOTIFY_EMAIL else [],
                    "block_release_bundle_distribution": False,
                    "custom_severity": ""
                }
            }
        ]
    }
    resp = session.post(url, data=json.dumps(payload))
    if resp.status_code == 400 and "already exist" in resp.text.lower():
        warn(f"Policy {POLICY_NAME} already exists, continuing.")
        return True
    ok = check(resp, ok_codes=(200, 201))
    if not ok:
        warn("If this fails on schema, create the policy by hand in Xray > "
             "Watches & Policies > Policies > + Create Policy, matching the "
             "settings in the lab spec, then GET it back to see the exact "
             f"accepted shape: GET {url}/{POLICY_NAME}")
    return ok


def verify_policy_min_severity():
    """Validation checklist item 1: confirm min severity is really High."""
    log("Validating policy min_severity == High")
    url = f"{JFROG_URL}/xray/api/v2/policies/{POLICY_NAME}"
    resp = session.get(url)
    if not check(resp):
        return False
    data = resp.json()
    rules = data.get("rules", [])
    for rule in rules:
        sev = rule.get("criteria", {}).get("min_severity")
        print(f"    Rule '{rule.get('name')}': min_severity = {sev}")
        if sev and sev.lower() == "high":
            return True
    warn("    Could not confirm min_severity == High from the policy definition.")
    return False


# --------------------------------------------------------------------------
# Task 2: Watch (project-scoped enforcement)
# --------------------------------------------------------------------------

def create_watch(include_build_resource=True):
    log(f"Task 2: Creating watch '{WATCH_NAME}' scoped to project {PROJECT_KEY}")
    url = f"{JFROG_URL}/xray/api/v2/watches"
    resources = [
        {
            "type": "repository",
            "name": DEV_DOCKER_REPO,
            "bin_mgr_id": "default"
        }
    ]
    if include_build_resource:
        resources.append({
            "type": "build",
            "name": BUILD_NAME,  # literal registered build name — Xray
                                  # validates this against its indexed
                                  # builds list, NOT the regex pattern
            "bin_mgr_id": "default",
            "ant_patterns": [BUILD_NAME_PATTERN]  # the regex belongs here
        })
    payload = {
        "general_data": {
            "name": WATCH_NAME,
            "description": "Enforces DLTC-01 on dev-local Docker repo and krypto-build* builds",
            "active": True
        },
        "project_resources": {
            "resources": resources
        },
        "assigned_policies": [
            {
                "name": POLICY_NAME,
                "type": "security"
            }
        ],
        # Restricts the watch itself to only ever be able to reference
        # resources inside this project (isolation from other teams' repos).
        "project_key": PROJECT_KEY,
    }
    if NOTIFY_EMAIL:
        payload["watch_recipients"] = [NOTIFY_EMAIL]

    resp = session.post(url, data=json.dumps(payload))
    if resp.status_code == 400 and "already exist" in resp.text.lower():
        warn(f"Watch {WATCH_NAME} already exists, continuing.")
        return True
    if resp.status_code == 400 and "doesn't exist" in resp.text.lower() and include_build_resource:
        warn("Build resource rejected (not indexed in Xray yet) — retrying "
             "with just the repository resource so the gate test isn't "
             "blocked. Add the build resource back once it's indexed "
             "(Xray > Administration > Indexing > Builds).")
        return create_watch(include_build_resource=False)
    ok = check(resp, ok_codes=(200, 201))
    if not ok:
        warn("If this fails on schema (very possible — Watch v2's project "
             "scoping field name varies by version), create it by hand in "
             "Xray > Watches & Policies > Watches > + New Watch, matching "
             "the lab spec (Scope: Project > KRIPTO-STREAM-DATA), then GET "
             f"it back to see the exact shape: GET {url}/{WATCH_NAME}")
    return ok


def verify_watch_project_scope():
    """Validation checklist item 2: confirm project isolation."""
    log("Validating watch is scoped to the project")
    url = f"{JFROG_URL}/xray/api/v2/watches/{WATCH_NAME}"
    resp = session.get(url)
    if not check(resp):
        return False
    data = resp.json()
    project_key = data.get("project_key") or data.get("projectKey")
    print(f"    Watch project_key: {project_key}")
    return project_key == PROJECT_KEY


# --------------------------------------------------------------------------
# Task 3: Trigger the Gate — push the vulnerable image + scan
# --------------------------------------------------------------------------

def push_vulnerable_image():
    log(f"Task 3: Pulling and pushing known-vulnerable image {VULNERABLE_IMAGE}:{VULNERABLE_TAG}")
    source_ref = f"{VULNERABLE_IMAGE}:{VULNERABLE_TAG}"

    run(["docker", "pull", source_ref], check_rc=True)
    run(["docker", "tag", source_ref, TARGET_REF], check_rc=True)
    push = run(["docker", "push", TARGET_REF], check_rc=True)
    return push.returncode == 0


def trigger_scan_with_watch():
    log(f"Task 3: Triggering an Xray scan against watch '{WATCH_NAME}'")
    if not JF_CLI_SERVER_ID:
        warn("JF_CLI_SERVER_ID not set — skipping automated `jf docker scan`. "
             f"Run manually:\n"
             f"    jf docker scan {TARGET_REF} --watches={WATCH_NAME}")
        return None
    cmd = ["jf", "docker", "scan", TARGET_REF, f"--watches={WATCH_NAME}",
           "--server-id", JF_CLI_SERVER_ID]
    result = run(cmd)
    # A non-zero exit here is EXPECTED and GOOD if the policy's fail_build
    # action fired — that's the gate working, not a script bug.
    if result.returncode != 0:
        log("    -> Non-zero exit is expected here if the gate fired "
            "(fail_build action). Check the output above for violation details.")
    return result


# --------------------------------------------------------------------------
# Task 4: Verify the Block
# --------------------------------------------------------------------------

def wait_for_scan_to_register(image=None, tag=None, timeout=240, interval=20):
    """Poll Xray's artifact summary until the scan has actually registered
    server-side. This is different from (and more reliable than) the CLI's
    'scan completed' message, which reflects a client-side check that may
    not be what the download-blocking policy actually evaluates against."""
    image = image or VULNERABLE_IMAGE
    tag = tag or VULNERABLE_TAG
    path = f"{DEV_DOCKER_REPO}/{image}/{tag}/manifest.json"
    log(f"Waiting for Xray to finish indexing/scanning {path} "
        f"(up to {timeout}s)...")
    url = f"{JFROG_URL}/xray/api/v1/summary/artifact"
    waited = 0
    while waited < timeout:
        resp = session.post(url, data=json.dumps({"checksums": [], "paths": [path]}))
        if resp.status_code == 200:
            data = resp.json()
            if data.get("artifacts"):
                log(f"    -> Scan registered after {waited}s.")
                artifact = data["artifacts"][0]
                issues = artifact.get("issues", [])
                print(f"    -> {len(issues)} issue(s)/CVE(s) found on this artifact")
                for issue in issues[:10]:
                    print(f"        - [{issue.get('severity')}] {issue.get('cve') or issue.get('summary','')}")
                return True
        print(f"    ...not yet indexed ({waited}s elapsed)")
        import time as _time
        _time.sleep(interval)
        waited += interval
    warn(f"    Timed out after {timeout}s waiting for the scan to register. "
         "Try triggering a manual reindex: POST /xray/api/v1/index "
         f'{{"repos": ["{DEV_DOCKER_REPO}"]}}')
    return False


def verify_pull_is_blocked():
    log("Task 4: Verifying the pull is blocked (this SHOULD fail)")
    run(["docker", "rmi", TARGET_REF], check_rc=False)
    result = run(["docker", "pull", TARGET_REF], check_rc=False)

    blocked_markers = ["DENIED", "download blocking policy", "not downloaded"]
    output = (result.stdout or "") + (result.stderr or "")
    blocked = result.returncode != 0 and any(m in output for m in blocked_markers)

    if blocked:
        log("    -> CONFIRMED BLOCKED: pull failed with the expected Xray "
            "download-blocking-policy error.")
    elif result.returncode != 0:
        warn("    -> Pull failed, but not with the expected Xray block "
             "message — check the output above; this may be an unrelated "
             "error (auth, network, image not found) rather than the gate "
             "actually working.")
    else:
        warn("    -> Pull SUCCEEDED — the gate did NOT block the download. "
             "Check that: (1) the image was actually scanned "
             "(Xray status not 'Pending'/'Not Scanned'), (2) the watch is "
             "correctly assigned to the policy, and (3) the repo is indexed "
             "for Xray scanning (Administration > Xray Settings > Indexed "
             "Resources).")
    return blocked


def get_watch_violations():
    log(f"Fetching Watch Violations for '{WATCH_NAME}'")
    url = f"{JFROG_URL}/xray/api/v1/violations"
    payload = {
        "filters": {
            "watch_name": WATCH_NAME
        },
        "pagination": {
            "order_by": "created",
            "direction": "desc",
            "limit": 50,
            "offset": 0
        }
    }
    resp = session.post(url, data=json.dumps(payload))
    if not check(resp):
        warn("If this 400s, try GET /xray/api/v1/violations with query "
             "params instead, or view Xray > Watches & Policies > "
             "Violations in the UI directly and filter by watch name.")
        return []
    data = resp.json()
    violations = data.get("violations", data.get("data", []))
    log(f"    -> {len(violations)} violation(s) found")
    for v in violations[:10]:
        cve = v.get("cve") or v.get("summary", "")
        sev = v.get("severity")
        print(f"        - [{sev}] {cve}")
    return violations


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    create_dev_docker_repo()
    create_security_policy()
    verify_policy_min_severity()
    create_watch()
    verify_watch_project_scope()

    if push_vulnerable_image():
        trigger_scan_with_watch()
        wait_for_scan_to_register()
        verify_pull_is_blocked()
        get_watch_violations()

    log("Lab 4 automation complete. Screenshot the Watch page (policy + "
        "targeted repos) and the terminal output showing the blocked pull "
        "for your deliverables.")


if __name__ == "__main__":
    main()
