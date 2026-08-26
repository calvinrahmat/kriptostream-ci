#!/usr/bin/env python3
"""
KriptoStream Passwordless CI/CD & Build Traceability — Lab 3 Automation
=========================================================================

This lab is mostly about configuring trust relationships (OIDC) and running
a CI pipeline (GitHub Actions), which by nature live partly outside a single
Python script. This script automates everything that CAN be driven via the
JFrog REST API, and generates the GitHub Actions workflow file for you:

  Task 1: OIDC Provider + Identity Mapping (Platform/Project Admin)
  Task 2: Generates the .github/workflows/jfrog-oidc.yml workflow file
  Task 3: Verifies the resulting build/manifest after you run the workflow
  Task 4/5: Triggers an Xray Vulnerabilities Report scoped to the project,
            polls for completion, and downloads PDF + CSV exports
  Task 6: Triggers an SBOM export (CycloneDX/SPDX) for the build and
          validates a dependency is present in it
  Task 7: Runs the CVE -> component -> impacted-artifact search chain
          via the real Xray Search APIs

WHAT THIS SCRIPT CANNOT DO
----------------------------
  - It cannot trigger the GitHub Actions workflow itself (Task 3's "trigger
    manually" step) — that happens in the GitHub UI/CLI (`gh workflow run`),
    since only GitHub can mint the OIDC id-token for the handshake.
  - Task 8 (contextual analysis / marking a violation "Ignored") is a
    judgment call best made in the Xray UI, though this script includes a
    helper to fetch contextual-analysis status for reference.

REQUIREMENTS
------------
  pip install requests --break-system-packages

CONFIGURATION (environment variables)
--------------------------------------
  JFROG_URL            e.g. https://trialyo541m.jfrog.io
  JFROG_ADMIN_TOKEN     an admin-scoped Access/Identity token
  GITHUB_ORG            your GitHub org/user, e.g. "calvin-nugroho"
  GITHUB_REPO           your GitHub repo name, e.g. "kriptostream-ci"
"""

import os
import sys
import json
import time
import argparse
import requests

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

JFROG_URL = os.environ.get("JFROG_URL", "").rstrip("/")
ADMIN_TOKEN = os.environ.get("JFROG_ADMIN_TOKEN", "")
GITHUB_ORG = os.environ.get("GITHUB_ORG", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "")

if not JFROG_URL or not ADMIN_TOKEN:
    print("ERROR: Please set JFROG_URL and JFROG_ADMIN_TOKEN environment variables.")
    sys.exit(1)

if not GITHUB_ORG or not GITHUB_REPO:
    print("ERROR: Please set GITHUB_ORG and GITHUB_REPO environment variables "
          "(used in the OIDC identity mapping claim and generated workflow).")
    sys.exit(1)

PROJECT_KEY = "krypto-data"
PROJECT_NAME = "KRIPTO-STREAM-DATA"
OIDC_PROVIDER_NAME = f"{PROJECT_KEY}-github-oidc"
IDENTITY_MAPPING_NAME = f"{PROJECT_KEY}-gh-mapping"
TARGET_REPO = f"{PROJECT_KEY}-npm-dev-local"
BUILD_NAME = "krypto-build"

REGISTRY_HOST = JFROG_URL.replace("https://", "").replace("http://", "")

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
# Task 1: OIDC Provider Configuration + Identity Mapping
# --------------------------------------------------------------------------

def create_oidc_provider():
    log(f"Task 1: Creating OIDC provider '{OIDC_PROVIDER_NAME}'")
    url = f"{JFROG_URL}/access/api/v1/oidc"
    payload = {
        "name": OIDC_PROVIDER_NAME,
        "issuer_url": "https://token.actions.githubusercontent.com",
        "provider_type": "GitHub",
        "audience": OIDC_PROVIDER_NAME,
        "organization": GITHUB_ORG,  # must be a real GitHub org/username
        "description": "Trust anchor for KriptoStream GitHub Actions CI/CD",
    }
    resp = session.post(url, data=json.dumps(payload))
    if resp.status_code == 400 and "already exist" in resp.text.lower():
        warn(f"OIDC provider {OIDC_PROVIDER_NAME} already exists, continuing.")
        return True
    return check(resp)


def create_identity_mapping():
    log(f"Task 1: Creating identity mapping '{IDENTITY_MAPPING_NAME}' "
        f"(project-scoped, Developer role)")
    url = f"{JFROG_URL}/access/api/v1/oidc/{OIDC_PROVIDER_NAME}/identity_mappings"
    # Restricts the mapping to your specific GitHub repo via the claim, and
    # scopes the resulting token to the Developer role in this project only.
    # CONFIRMED SCHEMA (verified against a live instance 2026-08):
    #   - field name is "claims" (a nested JSON object), NOT "claims_json"
    #     (the "claims_json" name comes from Terraform's HCL->JSON mapping,
    #     not the raw REST API)
    #   - project-role scoping is embedded directly in the token_spec.scope
    #     string: applied-permissions/roles:<project_key>:"Role1","Role2"
    #   - username is required alongside a role scope
    payload = {
        "name": IDENTITY_MAPPING_NAME,
        "priority": 1,
        "claims": {
            "repository": f"{GITHUB_ORG}/{GITHUB_REPO}"
        },
        "token_spec": {
            "username": f"{PROJECT_KEY}-gh-ci",
            "scope": f'applied-permissions/roles:{PROJECT_KEY}:"Developer"',
            "audience": "*@*",
            "expires_in": 600,  # 10 minutes, per lab spec
        },
    }
    resp = session.post(url, data=json.dumps(payload))
    if resp.status_code == 400 and "already exist" in resp.text.lower():
        warn(f"Identity mapping {IDENTITY_MAPPING_NAME} already exists, continuing.")
        return True
    return check(resp, ok_codes=(200, 201))


def setup_oidc_trust():
    create_oidc_provider()
    create_identity_mapping()


# --------------------------------------------------------------------------
# Task 2: Generate the GitHub Actions Workflow
# --------------------------------------------------------------------------

WORKFLOW_TEMPLATE = """\
name: JFrog OIDC Passwordless Publish

on:
  workflow_dispatch: {{}}

permissions:
  id-token: write   # required for the GitHub OIDC handshake
  contents: read

jobs:
  publish-and-trace:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup JFrog CLI (OIDC — no static credentials)
        uses: jfrog/setup-jfrog-cli@v4
        env:
          JF_URL: {jfrog_url}
        with:
          oidc-provider-name: {oidc_provider_name}

      - name: Create dummy DLT manifest artifact
        run: echo "KriptoStream DLT manifest - $(date -u)" > dlt-manifest.txt

      - name: Upload artifact to dev-local repo
        run: |
          jf rt upload dlt-manifest.txt {target_repo}/dlt-manifest/1.0.0/dlt-manifest.txt \\
            --build-name={build_name} --build-number=${{{{ github.run_number }}}} \\
            --project={project_key}

      - name: Collect environment variables for Build Info
        run: |
          jf rt build-collect-env {build_name} ${{{{ github.run_number }}}} \\
            --project={project_key}

      - name: Collect Git metadata for Build Info (VCS traceability)
        run: |
          jf rt build-add-git {build_name} ${{{{ github.run_number }}}} \\
            --project={project_key}

      - name: Publish Build Info to Artifactory
        run: |
          jf rt build-publish {build_name} ${{{{ github.run_number }}}} \\
            --project={project_key}
"""


def generate_github_actions_workflow(output_path=".github/workflows/jfrog-oidc.yml"):
    log(f"Task 2: Generating GitHub Actions workflow at {output_path}")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    content = WORKFLOW_TEMPLATE.format(
        jfrog_url=JFROG_URL,
        oidc_provider_name=OIDC_PROVIDER_NAME,
        target_repo=TARGET_REPO,
        build_name=BUILD_NAME,
        project_key=PROJECT_KEY,
    )
    with open(output_path, "w") as f:
        f.write(content)
    log(f"    -> Written. Commit this file to {GITHUB_ORG}/{GITHUB_REPO} at "
        f"the same path, then trigger it manually:")
    log(f"       gh workflow run jfrog-oidc.yml --repo {GITHUB_ORG}/{GITHUB_REPO}")
    return output_path


# --------------------------------------------------------------------------
# Task 3: Verification (after the workflow has run)
# --------------------------------------------------------------------------

def verify_manifest_uploaded():
    log(f"Task 3: Verifying dlt-manifest.txt exists in {TARGET_REPO}")
    url = f"{JFROG_URL}/artifactory/api/storage/{TARGET_REPO}/dlt-manifest/1.0.0/dlt-manifest.txt"
    resp = session.get(url)
    return check(resp)


def verify_build_info(build_number):
    log(f"Task 3: Fetching Build Info for {BUILD_NAME}#{build_number}")
    url = (f"{JFROG_URL}/artifactory/api/build/{BUILD_NAME}"
           f"?buildNumber={build_number}&project={PROJECT_KEY}")
    resp = session.get(url)
    if not check(resp):
        return False
    data = resp.json().get("buildInfo", {})
    vcs = data.get("vcs", [])
    env_props = {k: v for k, v in data.get("properties", {}).items()
                 if k.startswith("buildInfo.env.")}
    if vcs:
        log(f"    -> VCS populated: {vcs}")
    else:
        warn("    -> VCS section is empty — check that 'jf rt build-add-git' "
             "ran inside a real git checkout in the workflow.")
    if env_props:
        log(f"    -> Environment tab populated with {len(env_props)} variable(s)")
    else:
        warn("    -> No environment properties found — check 'jf rt build-collect-env' ran.")
    return bool(vcs) and bool(env_props)


# --------------------------------------------------------------------------
# Task 4/5: Xray Vulnerabilities Report (PDF + CSV export)
# --------------------------------------------------------------------------

def create_vulnerabilities_report(has_fix_only=True):
    log("Task 4/5: Creating Xray Vulnerabilities Report scoped to the project")
    # Project scoping is a QUERY PARAMETER on this endpoint (projectKey),
    # not a body field — this is the documented behavior for Xray 3.21.2+.
    url = f"{JFROG_URL}/xray/api/v1/reports/vulnerabilities?projectKey={PROJECT_KEY}"
    payload = {
        "name": f"{PROJECT_KEY}-exec-vuln-report",
        "resources": {
            "repositories": [
                {"name": f"{PROJECT_KEY}-npm-dev-local"},
                {"name": f"{PROJECT_KEY}-npm-staging-local"},
                {"name": f"{PROJECT_KEY}-npm-prod-local"},
                {"name": f"{PROJECT_KEY}-docker-prod-local"},
            ]
        },
    }
    if has_fix_only:
        payload["filters"] = {"has_remediation": True}
    resp = session.post(url, data=json.dumps(payload))
    if not check(resp, ok_codes=(200, 201)):
        warn("If this still 400s, the 'resources' shape is worth double "
             "checking live: open Xray > Reports > Create Report in the UI, "
             "fill the same scope by hand, open your browser's Network tab, "
             "and copy the exact request body it sends — Xray's report "
             "schema has shifted across versions and the UI always sends "
             "the version your instance actually expects.")
        return None
    report_id = resp.json().get("report_id") or resp.json().get("id")
    log(f"    -> Report ID: {report_id}")
    return report_id


def wait_for_report(report_id, timeout=180, interval=5):
    log(f"Polling report {report_id} for completion...")
    url = f"{JFROG_URL}/xray/api/v1/reports/{report_id}/status"
    waited = 0
    while waited < timeout:
        resp = session.get(url)
        if resp.status_code == 200:
            status = resp.json().get("status", "").lower()
            print(f"    status: {status} ({waited}s elapsed)")
            if status in ("completed", "done", "ready"):
                return True
            if status in ("failed", "error"):
                warn(f"    Report generation failed: {resp.json()}")
                return False
        time.sleep(interval)
        waited += interval
    warn("    Timed out waiting for report to complete.")
    return False


def export_report(report_id, fmt, out_path):
    log(f"Exporting report {report_id} as {fmt.upper()} -> {out_path}")
    url = f"{JFROG_URL}/xray/api/v1/reports/export/{report_id}?format={fmt}"
    resp = session.get(url)
    if resp.status_code != 200:
        check(resp)
        return False
    with open(out_path, "wb") as f:
        f.write(resp.content)
    log(f"    -> Saved {out_path} ({len(resp.content)} bytes)")
    return True


def generate_and_export_vulnerability_report():
    report_id = create_vulnerabilities_report(has_fix_only=True)
    if not report_id:
        return False
    if not wait_for_report(report_id):
        return False
    ok_pdf = export_report(report_id, "pdf", f"{PROJECT_KEY}-vuln-report.pdf")
    ok_csv = export_report(report_id, "csv", f"{PROJECT_KEY}-vuln-report.csv")
    return ok_pdf and ok_csv


# --------------------------------------------------------------------------
# Task 6: SBOM Export (CycloneDX / SPDX)
# --------------------------------------------------------------------------

def export_sbom(component_version, fmt="cyclonedx", out_path=None):
    """Attempts a build-scoped SBOM export.

    NOTE: `/xray/api/v1/component/exportDetails` is for a single indexed
    ARTIFACT/component (package name + type + version Xray has already
    scanned) — it is NOT the same as exporting an SBOM for an entire BUILD.
    The lab's Task 6 explicitly asks for the build-scoped export (Scan List
    > Builds > your build > Export scan data > SBOM tab), which uses a
    build-name/build-number pair, not a generic component identity.

    If this still 404s with "Component is not found", the most reliable
    path is the UI itself: open that same Export screen, choose the format,
    click Generate, and use your browser's Network tab (or "Copy as cURL")
    to capture the exact request it fires — Xray's build/SBOM export
    endpoint isn't consistently documented across versions, so the UI is
    the ground truth for your specific instance.
    """
    log(f"Task 6: Exporting SBOM for build {BUILD_NAME}#{component_version} ({fmt})")
    out_path = out_path or f"{BUILD_NAME}-sbom.{fmt}.json"
    url = f"{JFROG_URL}/xray/api/v1/sbom/export"
    payload = {
        "build_name": BUILD_NAME,
        "build_number": component_version,
        "project_key": PROJECT_KEY,
        "spec_version": "1.4" if fmt == "cyclonedx" else "2.3",
        "sbom_format": fmt,
    }
    resp = session.post(url, data=json.dumps(payload))
    if not check(resp, ok_codes=(200, 201)):
        warn("Build-scoped SBOM export endpoint may differ on your platform "
             "version — see the docstring above for how to capture the exact "
             "request from the UI's Network tab instead.")
        return None
    with open(out_path, "wb") as f:
        f.write(resp.content)
    log(f"    -> Saved {out_path}")
    return out_path


def validate_sbom_contains(sbom_path, expected_dependency="lodash"):
    log(f"Validating SBOM contains expected dependency: {expected_dependency}")
    try:
        with open(sbom_path) as f:
            content = f.read()
    except FileNotFoundError:
        warn(f"    SBOM file not found: {sbom_path}")
        return False
    found = expected_dependency.lower() in content.lower()
    print(f"    -> {'FOUND' if found else 'NOT FOUND'}: '{expected_dependency}' in {sbom_path}")
    return found


# --------------------------------------------------------------------------
# Task 7: API-Based Impact Analysis ("Zero-Day" Search)
# --------------------------------------------------------------------------

def search_components_by_cve(cve_id):
    """Step 1: Find which components are affected by a given CVE."""
    log(f"Task 7 (Find Components): Searching components affected by {cve_id}")
    url = f"{JFROG_URL}/xray/api/v1/component/searchByCves"
    payload = {"cve_ids": [cve_id]}
    resp = session.post(url, data=json.dumps(payload))
    if not check(resp):
        return []
    data = resp.json()
    # The endpoint can return either a bare list or {"data": [...]}
    # depending on platform version — handle both.
    if isinstance(data, list):
        components = data
    elif isinstance(data, dict):
        components = data.get("data", [])
    else:
        components = []
    log(f"    -> {len(components)} component(s) found")
    return components


def search_impacted_resources(cve_id=None, name=None, pkg_type=None, version=None, limit=1000):
    """Step 2: Find the specific artifacts (Docker images/ZIPs/etc.) containing
    the affected component. Uses the real Xray v2 Search API:
      GET /xray/api/v2/search/impactedResources
    Mode 1 (by vulnerability) needs `cve_id`.
    Mode 2/3 (by package) need `name` + `pkg_type`, with optional `version`.
    """
    log("Task 7 (Find Artifacts): Running impactedResources search")
    url = f"{JFROG_URL}/xray/api/v2/search/impactedResources"
    params = {"limit": limit}
    if cve_id:
        params["vulnerability"] = cve_id
    if name:
        params["name"] = name
    if pkg_type:
        params["type"] = pkg_type
    if version:
        params["version"] = version

    resp = session.get(url, params=params)
    if not check(resp):
        return []
    data = resp.json()
    resources = data.get("resources", data.get("artifacts", []))
    log(f"    -> {len(resources)} impacted resource(s) found")
    for r in resources[:10]:
        print(f"        - {json.dumps(r)[:200]}")
    return resources


def run_zero_day_search(cve_id="CVE-2025-22871"):
    components = search_components_by_cve(cve_id)
    resources = search_impacted_resources(cve_id=cve_id)
    return bool(components) or bool(resources)


# --------------------------------------------------------------------------
# Task 8: Contextual Analysis (reference helper only)
# --------------------------------------------------------------------------

def get_contextual_analysis(component_id, cve_id, artifact_path):
    log(f"Task 8: Fetching contextual analysis for {cve_id} on {component_id}")
    url = f"{JFROG_URL}/xray/api/v1/cve_applicability"
    payload = {
        "component_id": component_id,
        "vulnerability_id": cve_id,
        "path": artifact_path,
    }
    resp = session.post(url, data=json.dumps(payload))
    if resp.status_code == 204:
        warn("    -> No applicability data available for this component/CVE.")
        return None
    if not check(resp):
        return None
    return resp.json()


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="KriptoStream OIDC/CI/Xray lab automation")
    parser.add_argument("--build-number", help="Build number to verify (Task 3), "
                         "e.g. the GitHub Actions run number")
    parser.add_argument("--cve", default="CVE-2025-22871",
                         help="CVE ID to use for the Task 7 zero-day search")
    parser.add_argument("--sbom-version", default="1",
                         help="Build/component version to export the SBOM for")
    parser.add_argument("--skip-oidc-setup", action="store_true")
    parser.add_argument("--skip-report", action="store_true")
    parser.add_argument("--skip-sbom", action="store_true")
    args = parser.parse_args()

    if not args.skip_oidc_setup:
        setup_oidc_trust()
        generate_github_actions_workflow()
        log("Now commit + push the generated workflow file, then trigger it "
            "manually in GitHub Actions before continuing to verification.")

    if args.build_number:
        verify_manifest_uploaded()
        verify_build_info(args.build_number)

    if not args.skip_report:
        generate_and_export_vulnerability_report()

    if not args.skip_sbom:
        sbom_path = export_sbom(args.sbom_version, fmt="cyclonedx")
        if sbom_path:
            validate_sbom_contains(sbom_path, expected_dependency="lodash")

    run_zero_day_search(args.cve)

    log("Lab 3 automation complete. Screenshot the Builds tab (VCS + "
        "Environment populated) and the GitHub Actions run log for your "
        "deliverables.")


if __name__ == "__main__":
    main()
