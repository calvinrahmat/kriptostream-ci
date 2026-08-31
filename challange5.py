#!/usr/bin/env python3
"""
KriptoStream Shift-Left Security with Frogbot & SBOM — Lab 5 Automation
===========================================================================

Automates:
  Task 1: Sets the three required GitHub Actions repository secrets
          (JF_URL, JF_ACCESS_TOKEN, JF_GIT_TOKEN) via the GitHub API
  Task 2: Generates the Frogbot PR-scan workflow from scratch, wired to
          your Lab 1/4 project scope and watch
  Task 3: Creates a branch, introduces the known-vulnerable
          lodash@4.17.11 dependency, commits, pushes, and opens the PR
  Task 4: Polls the PR for the Frogbot bot comment and the check run
          status, and reports whether the gate actually fired

REQUIREMENTS
------------
  pip install requests pynacl --break-system-packages
  (pynacl is required to encrypt secrets for the GitHub API — GitHub
  requires libsodium sealed-box encryption, not plaintext, even over HTTPS)

  git installed and configured for push access to your repo
  A GitHub Personal Access Token with 'repo' and 'workflow' scopes

CONFIGURATION (environment variables)
--------------------------------------
  JFROG_URL             e.g. https://trialyo541m.jfrog.io
  JFROG_ADMIN_TOKEN      an Xray/Artifactory access token — this becomes
                          the JF_ACCESS_TOKEN secret Frogbot uses
  GITHUB_ORG             e.g. calvinrahmat
  GITHUB_REPO            e.g. kriptostream-ci
  GITHUB_PAT              a GitHub Personal Access Token with repo/workflow
                          scopes — used both to call the GitHub API AND
                          becomes the JF_GIT_TOKEN secret Frogbot uses to
                          post PR comments
  REPO_LOCAL_PATH         local path to your cloned repo (default: cwd)
"""

import os
import sys
import json
import base64
import subprocess
import requests

try:
    from nacl import encoding, public
except ImportError:
    print("ERROR: pynacl is required. Install with: "
          "pip install pynacl --break-system-packages")
    sys.exit(1)

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

JFROG_URL = os.environ.get("JFROG_URL", "").rstrip("/")
JFROG_ADMIN_TOKEN = os.environ.get("JFROG_ADMIN_TOKEN", "")
GITHUB_ORG = os.environ.get("GITHUB_ORG", "")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "")
GITHUB_PAT = os.environ.get("GITHUB_PAT", "")
REPO_LOCAL_PATH = os.environ.get("REPO_LOCAL_PATH", os.getcwd())

for name, val in [("JFROG_URL", JFROG_URL), ("JFROG_ADMIN_TOKEN", JFROG_ADMIN_TOKEN),
                   ("GITHUB_ORG", GITHUB_ORG), ("GITHUB_REPO", GITHUB_REPO),
                   ("GITHUB_PAT", GITHUB_PAT)]:
    if not val:
        print(f"ERROR: Please set {name} environment variable.")
        sys.exit(1)

PROJECT_KEY = "krypto-data"
WATCH_NAME = f"{PROJECT_KEY}-dev-watch"
BRANCH_NAME = "feature/add-vulnerable-dlt-lib"
VULNERABLE_PACKAGE = "lodash"
VULNERABLE_VERSION = "4.17.11"

gh_session = requests.Session()
gh_session.headers.update({
    "Authorization": f"Bearer {GITHUB_PAT}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
})

GH_API = f"https://api.github.com/repos/{GITHUB_ORG}/{GITHUB_REPO}"


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


def run(cmd, cwd=None, check_rc=True):
    print(f"    $ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd or REPO_LOCAL_PATH, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip())
    if check_rc and result.returncode != 0:
        warn(f"Command failed with exit code {result.returncode}")
    return result


# --------------------------------------------------------------------------
# Task 1: Repository Secrets
# --------------------------------------------------------------------------

def get_repo_public_key():
    log("Fetching repo's public key for secret encryption")
    resp = gh_session.get(f"{GH_API}/actions/secrets/public-key")
    if not check(resp):
        return None
    return resp.json()


def encrypt_secret(public_key_b64, secret_value):
    """GitHub requires secrets encrypted with libsodium sealed box, using
    the repo's public key. Plaintext over HTTPS is NOT accepted."""
    public_key = public.PublicKey(public_key_b64.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")


def set_secret(name, value, key_info):
    log(f"Setting repository secret: {name}")
    encrypted_value = encrypt_secret(key_info["key"], value)
    url = f"{GH_API}/actions/secrets/{name}"
    payload = {
        "encrypted_value": encrypted_value,
        "key_id": key_info["key_id"],
    }
    resp = gh_session.put(url, data=json.dumps(payload))
    return check(resp, ok_codes=(201, 204))


def configure_secrets():
    log("Task 1: Configuring GitHub repository secrets for Frogbot")
    key_info = get_repo_public_key()
    if not key_info:
        warn("Could not fetch public key — set secrets manually instead: "
             f"github.com/{GITHUB_ORG}/{GITHUB_REPO}/settings/secrets/actions")
        return False

    set_secret("JF_URL", JFROG_URL, key_info)
    set_secret("JF_ACCESS_TOKEN", JFROG_ADMIN_TOKEN, key_info)
    set_secret("JF_GIT_TOKEN", GITHUB_PAT, key_info)
    log("    -> Note: JF_GIT_TOKEN reuses GITHUB_PAT here for convenience. "
        "For production use, mint a separate, narrowly-scoped PAT dedicated "
        "to Frogbot rather than reusing your admin/automation token.")
    return True


# --------------------------------------------------------------------------
# Task 2: Generate the Frogbot Workflow
# --------------------------------------------------------------------------

FROGBOT_WORKFLOW = """\
name: "Frogbot Scan Pull Request (KriptoStream)"

on:
  pull_request:
    types: [opened, synchronize]

permissions:
  pull-requests: write
  contents: read

jobs:
  scan-pull-request:
    runs-on: ubuntu-latest
    env:
      JF_URL: ${{{{ secrets.JF_URL }}}}
      JF_ACCESS_TOKEN: ${{{{ secrets.JF_ACCESS_TOKEN }}}}
      JF_GIT_TOKEN: ${{{{ secrets.JF_GIT_TOKEN }}}}
      # Links this scan to the project-scoped governance gate from Lab 1/4:
      # any High/Critical violation matched by this watch's policy fails
      # the check and blocks merge, enforcing DLTC-01 at PR review time.
      JF_WATCHES: "{watch_name}"
      JF_FAIL: "true"
    steps:
      - name: Frogbot Scan
        uses: jfrog/frogbot@v2
"""


def generate_frogbot_workflow(output_path=".github/workflows/frogbot-scan-pr.yml"):
    log(f"Task 2: Generating Frogbot workflow at {output_path}")
    full_path = os.path.join(REPO_LOCAL_PATH, output_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    content = FROGBOT_WORKFLOW.format(watch_name=WATCH_NAME)
    with open(full_path, "w") as f:
        f.write(content)
    log(f"    -> Written to {full_path}")
    return full_path


# --------------------------------------------------------------------------
# Task 3: Simulate a Vulnerable Contribution
# --------------------------------------------------------------------------

def ensure_package_json():
    """Create a minimal package.json if the repo doesn't have one yet —
    Frogbot needs a real manifest file to scan."""
    path = os.path.join(REPO_LOCAL_PATH, "package.json")
    if os.path.exists(path):
        return path
    log("No package.json found — creating a minimal one")
    minimal = {
        "name": "kriptostream-ci",
        "version": "1.0.0",
        "description": "KriptoStream CI/CD governance demo",
        "dependencies": {}
    }
    with open(path, "w") as f:
        json.dump(minimal, f, indent=2)
    return path


def add_vulnerable_dependency():
    log(f"Task 3: Adding known-vulnerable dependency "
        f"{VULNERABLE_PACKAGE}@{VULNERABLE_VERSION}")
    path = ensure_package_json()
    with open(path) as f:
        data = json.load(f)
    data.setdefault("dependencies", {})[VULNERABLE_PACKAGE] = VULNERABLE_VERSION
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    log(f"    -> {path} now pins {VULNERABLE_PACKAGE}@{VULNERABLE_VERSION}")
    return path


def create_branch_commit_push_pr():
    log(f"Creating branch '{BRANCH_NAME}', committing, and pushing")
    run(["git", "checkout", "-b", BRANCH_NAME], check_rc=False)
    add_vulnerable_dependency()
    run(["git", "add", "package.json"])
    run(["git", "commit", "-m",
         f"Add {VULNERABLE_PACKAGE}@{VULNERABLE_VERSION} (simulated vulnerable dependency)"])
    push = run(["git", "push", "-u", "origin", BRANCH_NAME], check_rc=False)
    if push.returncode != 0:
        warn("Push failed — if the branch already exists remotely, this "
             "may be a re-run; check manually with `git status`.")

    log("Opening the Pull Request via GitHub API")
    default_branch = get_default_branch()
    payload = {
        "title": "Add vulnerable DLT library dependency (Lab 5 simulation)",
        "head": BRANCH_NAME,
        "base": default_branch,
        "body": "Simulated vulnerable contribution for KriptoStream Lab 5 "
                "— introduces lodash@4.17.11 to trigger the Frogbot "
                "shift-left security gate.",
    }
    resp = gh_session.post(f"{GH_API}/pulls", data=json.dumps(payload))
    if resp.status_code == 422 and "already exists" in resp.text.lower():
        warn("A PR for this branch may already be open — fetching it instead.")
        return find_existing_pr()
    if not check(resp, ok_codes=(201,)):
        return None
    pr = resp.json()
    log(f"    -> PR #{pr['number']} opened: {pr['html_url']}")
    return pr


def get_default_branch():
    resp = gh_session.get(GH_API)
    if resp.status_code == 200:
        return resp.json().get("default_branch", "main")
    return "main"


def find_existing_pr():
    resp = gh_session.get(f"{GH_API}/pulls", params={"head": f"{GITHUB_ORG}:{BRANCH_NAME}", "state": "open"})
    if resp.status_code == 200 and resp.json():
        pr = resp.json()[0]
        log(f"    -> Found existing PR #{pr['number']}: {pr['html_url']}")
        return pr
    return None


# --------------------------------------------------------------------------
# Task 4: Verify the Feedback Loop
# --------------------------------------------------------------------------

def poll_for_frogbot_comment(pr_number, timeout=300, interval=15):
    log(f"Task 4: Polling PR #{pr_number} for the Frogbot comment "
        f"(up to {timeout}s)")
    url = f"{GH_API}/issues/{pr_number}/comments"
    waited = 0
    import time as _time
    while waited < timeout:
        resp = gh_session.get(url)
        if resp.status_code == 200:
            comments = resp.json()
            for c in comments:
                body = c.get("body", "")
                user = c.get("user", {}).get("login", "")
                if "vulnerable dependencies" in body.lower() and "bot" in user.lower():
                    log(f"    -> Found Frogbot comment from {user} "
                        f"after {waited}s")
                    print(f"    Comment URL: {c.get('html_url')}")
                    return c
        print(f"    ...not yet posted ({waited}s elapsed)")
        _time.sleep(interval)
        waited += interval
    warn("    Timed out waiting for the Frogbot comment. Check the Actions "
         "tab directly for the workflow run status/logs.")
    return None


def check_pr_status(pr_number):
    log(f"Checking PR #{pr_number} check-run / gate status")
    resp = gh_session.get(f"{GH_API}/commits/{BRANCH_NAME}/check-runs")
    if not check(resp):
        return None
    runs = resp.json().get("check_runs", [])
    for run_info in runs:
        name = run_info.get("name", "")
        conclusion = run_info.get("conclusion")
        status = run_info.get("status")
        print(f"    Check '{name}': status={status}, conclusion={conclusion}")
    return runs


def verify_feedback_loop(pr):
    if not pr:
        warn("No PR to verify against.")
        return False
    pr_number = pr["number"]
    comment = poll_for_frogbot_comment(pr_number)
    check_pr_status(pr_number)
    return comment is not None


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    configure_secrets()
    generate_frogbot_workflow()

    log("Commit + push the generated workflow file to your default branch "
        "FIRST (Frogbot workflows must exist on the base branch to run on "
        "PRs), before opening the vulnerable-dependency PR.")
    log(f"    cd {REPO_LOCAL_PATH} && git add .github/workflows/frogbot-scan-pr.yml "
        f"&& git commit -m 'Add Frogbot PR scan workflow' && git push")

    proceed = input("\nHave you committed and pushed the workflow to the "
                     "default branch? [y/N]: ").strip().lower()
    if proceed != "y":
        log("Stopping here — re-run this script after pushing the workflow "
            "to proceed with Task 3/4.")
        return

    pr = create_branch_commit_push_pr()
    verify_feedback_loop(pr)

    log("Lab 5 automation complete. Screenshot the Frogbot PR comment "
        "showing the 'Vulnerable Dependencies' table for your deliverable.")


if __name__ == "__main__":
    main()
