#!/usr/bin/env python3
"""
KriptoStream JFrog Governance Lab — Automation Script
=======================================================

Automates Lab 1: Project Governance & Identity Modeling on a JFrog Platform
instance (self-hosted or JFrog Cloud), covering:

  Task 1: Project creation + admin privileges
  Task 2: Local / Remote / Virtual repository strategy
  Task 3 & 4: Governance-compliant group + dummy user creation
  Task 5: Mapping groups to Project Roles
  Task 6: Custom role without "Delete Build" (Build Info immutability)
  Validation: Push test, Destruction test, Promote test, Touch test

REQUIREMENTS
------------
  pip install requests --break-system-packages

CONFIGURATION
-------------
Set these environment variables before running (recommended over hardcoding):

  JFROG_URL            e.g. https://mycompany.jfrog.io
  JFROG_ADMIN_TOKEN    an admin-scoped Access/Identity token
  DUMMY_USER_PASSWORD  password to assign to the 3 simulated users
                        (must meet your platform's password policy)

Run:
  python3 challange1.py

The script is idempotent-ish: it checks for existing resources where the API
allows and skips/reports rather than hard-failing, so it can be re-run.

NOTE ON THE VALIDATION TESTS
-----------------------------
The "Push", "Destruction", "Promote" and "Touch" tests in the lab are
per-user permission tests. To actually exercise them as each user (rather
than as admin), each dummy user needs their own identity token or basic
auth credentials. This script:
  1. Creates the users with the password from DUMMY_USER_PASSWORD.
  2. Generates a scoped access token for each user via the admin token
     (JFrog Access API supports "impersonation"-style token creation for
     admins), then uses that token to run the test as that user.
If your platform disables token creation for other users, the script will
fall back to basic-auth (username/password) for the per-user calls.
"""

import os
import sys
import json
import base64
import requests

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

JFROG_URL = os.environ.get("JFROG_URL", "").rstrip("/")
ADMIN_TOKEN = os.environ.get("JFROG_ADMIN_TOKEN", "")
DUMMY_PASSWORD = os.environ.get("DUMMY_USER_PASSWORD", "")

if not JFROG_URL or not ADMIN_TOKEN:
    print("ERROR: Please set JFROG_URL and JFROG_ADMIN_TOKEN environment variables.")
    sys.exit(1)

if not DUMMY_PASSWORD:
    print("ERROR: Please set DUMMY_USER_PASSWORD environment variable "
          "(used for alice-dev, bob-rel, charlie-view).")
    sys.exit(1)

PROJECT_KEY = "krypto-data"          # <= 12 chars, lowercase
PROJECT_NAME = "KRIPTO-STREAM-DATA"

REPO_DEV = f"{PROJECT_KEY}-npm-dev-local"
REPO_STAGING = f"{PROJECT_KEY}-npm-staging-local"
REPO_PROD = f"{PROJECT_KEY}-npm-prod-local"
REPO_REMOTE = f"{PROJECT_KEY}-npm-registrynpmjs-remote"
REPO_VIRTUAL = f"{PROJECT_KEY}-npm-dev"

GROUP_DEV = f"{PROJECT_KEY}-Developer"
GROUP_REL = f"{PROJECT_KEY}-ReleaseManager"
GROUP_VIEW = f"{PROJECT_KEY}-Viewer"

CUSTOM_DEV_ROLE = f"{PROJECT_KEY}-CustomDev"

USERS = {
    "alice-dev": {"group": GROUP_DEV, "email": "alice-dev@kriptostream.local"},
    "bob-rel": {"group": GROUP_REL, "email": "bob-rel@kriptostream.local"},
    "charlie-view": {"group": GROUP_VIEW, "email": "charlie-view@kriptostream.local"},
}

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
    """Print a compact status line and return True/False for success."""
    ok = resp.status_code in ok_codes
    tag = "OK" if ok else "FAIL"
    print(f"    -> {tag} ({resp.status_code}) {resp.request.method} {resp.request.url}")
    if not ok:
        try:
            print(f"       {resp.json()}")
        except Exception:
            print(f"       {resp.text[:300]}")
    return ok


# --------------------------------------------------------------------------
# Task 1: Project Creation & Quota Management
# --------------------------------------------------------------------------

def create_project():
    log(f"Task 1: Creating project '{PROJECT_NAME}' (key: {PROJECT_KEY})")
    url = f"{JFROG_URL}/access/api/v1/projects"
    payload = {
        "project_key": PROJECT_KEY,
        "display_name": PROJECT_NAME,
        "admin_privileges": {
            "manage_members": True,
            "manage_resources": True,
            "index_resources": True,
        },
    }
    resp = session.post(url, data=json.dumps(payload))
    if resp.status_code == 400 and "already exist" in resp.text.lower():
        warn(f"Project {PROJECT_KEY} already exists, continuing.")
        return True
    return check(resp, ok_codes=(200, 201))


# --------------------------------------------------------------------------
# Task 2: Repository Strategy (local / remote / virtual)
# --------------------------------------------------------------------------

def create_local_repo(repo_key, environment="DEV"):
    log(f"Creating local repo: {repo_key}")
    url = f"{JFROG_URL}/artifactory/api/repositories/{repo_key}"
    payload = {
        "key": repo_key,
        "rclass": "local",
        "packageType": "npm",
        "projectKey": PROJECT_KEY,
        "environments": [environment],
        "description": f"{repo_key} — managed by KriptoStream governance lab",
    }
    resp = session.put(url, data=json.dumps(payload))
    return check(resp)


def create_remote_repo():
    log(f"Creating remote repo: {REPO_REMOTE}")
    url = f"{JFROG_URL}/artifactory/api/repositories/{REPO_REMOTE}"
    payload = {
        "key": REPO_REMOTE,
        "rclass": "remote",
        "packageType": "npm",
        "url": "https://registry.npmjs.org",
        "projectKey": PROJECT_KEY,
        "description": "Proxy to npmjs.org",
    }
    resp = session.put(url, data=json.dumps(payload))
    return check(resp)


def create_virtual_repo():
    log(f"Creating virtual repo: {REPO_VIRTUAL}")
    url = f"{JFROG_URL}/artifactory/api/repositories/{REPO_VIRTUAL}"
    payload = {
        "key": REPO_VIRTUAL,
        "rclass": "virtual",
        "packageType": "npm",
        "projectKey": PROJECT_KEY,
        "repositories": [REPO_DEV, REPO_REMOTE],
        "defaultDeploymentRepo": REPO_DEV,
        "description": "Virtual repo abstracting dev-local + npmjs remote",
    }
    resp = session.put(url, data=json.dumps(payload))
    return check(resp)


def verify_virtual_repo_resolution():
    log("Resolution Check: verifying virtual repo contains expected members")
    url = f"{JFROG_URL}/artifactory/api/repositories/{REPO_VIRTUAL}"
    resp = session.get(url)
    if resp.status_code != 200:
        return check(resp)
    data = resp.json()
    members = set(data.get("repositories", []))
    expected = {REPO_DEV, REPO_REMOTE}
    if expected.issubset(members):
        log(f"    -> OK: virtual repo contains {sorted(expected)}")
        return True
    warn(f"    -> Virtual repo members {members} do not match expected {expected}")
    return False


def setup_repositories():
    log("Task 2: Implementing repository strategy")
    create_local_repo(REPO_DEV, "DEV")
    create_local_repo(REPO_STAGING, "DEV")
    create_local_repo(REPO_PROD, "PROD")
    create_remote_repo()
    create_virtual_repo()
    verify_virtual_repo_resolution()


# --------------------------------------------------------------------------
# Task 3 & 4: Groups + Dummy Users
# --------------------------------------------------------------------------

def create_group(group_name, description=""):
    log(f"Creating group: {group_name}")
    url = f"{JFROG_URL}/artifactory/api/security/groups/{group_name}"
    payload = {"name": group_name, "description": description, "autoJoin": False}
    resp = session.put(url, data=json.dumps(payload))
    return check(resp)


def create_user(username, email, group):
    log(f"Creating user: {username} (group: {group})")
    url = f"{JFROG_URL}/artifactory/api/security/users/{username}"
    payload = {
        "email": email,
        "password": DUMMY_PASSWORD,
        "groups": [group],
        "admin": False,
        "profileUpdatable": True,
        "disableUIAccess": False,
    }
    resp = session.put(url, data=json.dumps(payload))
    return check(resp)


def setup_groups_and_users():
    log("Task 3/4: Governance-compliant groups + dummy users")
    create_group(GROUP_DEV, "Developers — build & push to dev-local")
    create_group(GROUP_REL, "Release Managers — promote release bundles")
    create_group(GROUP_VIEW, "Viewers — read-only access")

    for username, meta in USERS.items():
        create_user(username, meta["email"], meta["group"])


# --------------------------------------------------------------------------
# Task 5: Project Role Assignment (group -> project role mapping)
# --------------------------------------------------------------------------

def assign_group_to_project_role(group_name, role_name):
    log(f"Mapping group '{group_name}' -> role '{role_name}' in project {PROJECT_KEY}")
    url = f"{JFROG_URL}/access/api/v1/projects/{PROJECT_KEY}/groups/{group_name}"
    payload = {"name": group_name, "roles": [role_name]}
    resp = session.put(url, data=json.dumps(payload))
    return check(resp)


def assign_project_roles():
    log("Task 5: Mapping groups to Project Roles")
    assign_group_to_project_role(GROUP_DEV, "Developer")
    assign_group_to_project_role(GROUP_REL, "Release Manager")
    assign_group_to_project_role(GROUP_VIEW, "Viewer")


# --------------------------------------------------------------------------
# Task 6: Custom role without "Delete Build" (Build Info immutability)
# --------------------------------------------------------------------------

def inspect_default_developer_role():
    log("Task 6: Inspecting default 'Developer' role actions")
    url = f"{JFROG_URL}/access/api/v1/projects/{PROJECT_KEY}/roles/Developer"
    resp = session.get(url)
    if resp.status_code != 200:
        warn("Could not fetch default Developer role definition (may be a built-in "
             "role not exposed via this endpoint on your platform version).")
        check(resp)
        return None
    data = resp.json()
    log(f"    Default Developer actions: {data.get('actions')}")
    return data


def create_custom_dev_role_without_delete_build():
    log(f"Creating custom role '{CUSTOM_DEV_ROLE}' (Developer minus 'DELETE_BUILD')")
    url = f"{JFROG_URL}/access/api/v1/projects/{PROJECT_KEY}/roles"
    # Mirrors standard Developer actions but omits DELETE_BUILD so Build Info
    # metadata cannot be wiped, preserving DLT compliance / audit trail.
    payload = {
        "name": CUSTOM_DEV_ROLE,
        "type": "CUSTOM",
        "environments": ["DEV", "PROD"],
        "actions": [
            "READ_REPOSITORY",
            "ANNOTATE_REPOSITORY",
            "DEPLOY_CACHE_REPOSITORY",
            "DELETE_OVERWRITE_REPOSITORY",
            "MANAGE_XRAY_MD_REPOSITORY",
            "READ_RELEASE_BUNDLE",
            "ANNOTATE_RELEASE_BUNDLE",
            "CREATE_RELEASE_BUNDLE",
            "DISTRIBUTE_RELEASE_BUNDLE",
            "DELETE_RELEASE_BUNDLE",
            "READ_BUILD",
            "ANNOTATE_BUILD",
            "DEPLOY_BUILD",
            # "DELETE_BUILD" intentionally OMITTED to enforce Build Info immutability
            "READ_SOURCES_PIPELINE",
            "TRIGGER_PIPELINE",
            "READ_INTEGRATIONS_PIPELINE",
            "READ_POOLS_PIPELINE",
        ],
    }
    resp = session.post(url, data=json.dumps(payload))
    if resp.status_code == 400 and "already exist" in resp.text.lower():
        warn(f"Role {CUSTOM_DEV_ROLE} already exists, continuing.")
        return True
    return check(resp, ok_codes=(200, 201))


def rebind_alice_to_custom_role():
    """Swap alice-dev's group mapping from stock 'Developer' to the custom
    role that lacks DELETE_BUILD, satisfying the immutability requirement."""
    log(f"Re-mapping '{GROUP_DEV}' to custom role '{CUSTOM_DEV_ROLE}'")
    return assign_group_to_project_role(GROUP_DEV, CUSTOM_DEV_ROLE)


def enforce_build_immutability():
    log("Task 6: Build Info immutability enforcement")
    inspect_default_developer_role()
    create_custom_dev_role_without_delete_build()
    rebind_alice_to_custom_role()


# --------------------------------------------------------------------------
# Per-user token helper (for the validation tests)
# --------------------------------------------------------------------------

def get_user_token(username):
    """Attempt to mint a scoped access token acting as `username`, using the
    admin token. Falls back to basic auth if token creation is restricted."""
    url = f"{JFROG_URL}/access/api/v1/tokens"
    payload = {
        "subject": f"jfac@01/users/{username}",  # generic subject form; adjust to your instance's realm if needed
        "expires_in": 3600,
        "scope": f"applied-permissions/user",
    }
    resp = session.post(url, data=json.dumps(payload))
    if resp.status_code in (200, 201):
        return resp.json().get("access_token")
    warn(f"Could not mint token for {username} ({resp.status_code}); "
         f"falling back to basic auth with the dummy password.")
    return None


def user_session(username):
    token = get_user_token(username)
    s = requests.Session()
    if token:
        s.headers.update({"Authorization": f"Bearer {token}"})
    else:
        basic = base64.b64encode(f"{username}:{DUMMY_PASSWORD}".encode()).decode()
        s.headers.update({"Authorization": f"Basic {basic}"})
    return s


# --------------------------------------------------------------------------
# Validation Checklist
# --------------------------------------------------------------------------

def test_push_as_alice():
    log('Validation: "Push" Test (Alice) — expect 200/201')
    s = user_session("alice-dev")
    url = f"{JFROG_URL}/artifactory/{REPO_DEV}/dummy/1.0.0/dummy-1.0.0.txt"
    resp = s.put(url, data=b"dummy artifact content for lab validation")
    return check(resp, ok_codes=(200, 201))


def test_delete_build_as_alice(build_name="dummy-build", build_number="1"):
    log('Validation: "Destruction" Test (Alice) — expect 403 Forbidden')
    s = user_session("alice-dev")
    url = (f"{JFROG_URL}/artifactory/api/build/{build_name}"
           f"?buildNumbers={build_number}&project={PROJECT_KEY}")
    resp = s.delete(url)
    if resp.status_code == 403:
        log("    -> OK: delete-build correctly forbidden (403)")
        return True
    warn(f"    -> Unexpected status {resp.status_code}; immutability may not be enforced")
    return False


def test_promote_release_bundle(username, expect_success):
    verb = "SUCCESS" if expect_success else "FAILURE"
    log(f'Validation: "Promote" Test ({username}) — expect {verb}')
    s = user_session(username)
    url = f"{JFROG_URL}/lifecycle/api/v2/promotion/records/dummy-bundle/1.0.0"
    payload = {
        "project_key": PROJECT_KEY,
        "target_env": "PROD",
        "included_repository_keys": [REPO_STAGING],
    }
    resp = s.post(url, data=json.dumps(payload), headers={"Content-Type": "application/json"})
    success = resp.status_code in (200, 201)
    if success == expect_success:
        log(f"    -> OK: got {'success' if success else 'failure'} as expected")
        return True
    warn(f"    -> Unexpected result: status {resp.status_code}")
    return False


def test_touch_as_charlie():
    log('Validation: "Touch" Test (Charlie) — expect 403 Forbidden')
    s = user_session("charlie-view")
    url = f"{JFROG_URL}/artifactory/{REPO_DEV}/dummy/1.0.0/charlie-should-fail.txt"
    resp = s.put(url, data=b"charlie should not be able to upload this")
    if resp.status_code == 403:
        log("    -> OK: upload correctly forbidden (403)")
        return True
    warn(f"    -> Unexpected status {resp.status_code}")
    return False


def run_validation_checklist():
    log("Running Validation Checklist")
    results = {
        "resolution_check": verify_virtual_repo_resolution(),
        "push_alice": test_push_as_alice(),
        "destruction_alice": test_delete_build_as_alice(),
        "promote_alice_should_fail": test_promote_release_bundle("alice-dev", expect_success=False),
        "promote_bob_should_succeed": test_promote_release_bundle("bob-rel", expect_success=True),
        "touch_charlie": test_touch_as_charlie(),
    }
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    for name, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL':5s} - {name}")
    print("=" * 60)
    return results


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    create_project()
    setup_repositories()
    setup_groups_and_users()
    assign_project_roles()
    enforce_build_immutability()
    run_validation_checklist()
    log("Lab automation complete. Take screenshots of the Artifactory UI "
        "(Virtual Repo config, user permission logs) for your deliverables.")


if __name__ == "__main__":
    main()
