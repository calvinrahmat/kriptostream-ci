#!/usr/bin/env python3
"""
KriptoStream Legacy Artifact Migration — Lab 2 Automation
============================================================

Automates the "Lift and Shift" Docker migration:

  Task 1: Create the target Docker repo (krypto-data-docker-prod-local)
  Task 2: Pull / retag / push a single image manually (demonstrated via a
          single-image helper function you can also run by hand)
  Task 3: Bulk-migrate the full legacy image list via scripting
  Validation: tag listing, manifest readability, delete-then-repull test

REQUIREMENTS
------------
  - Docker installed and running locally (the script shells out to the
    `docker` CLI — Docker's Python SDK does not give a meaningfully
    simpler path for plain pull/tag/push/login flows).
  - pip install requests --break-system-packages

CONFIGURATION (environment variables)
--------------------------------------
  JFROG_URL            e.g. https://trialyo541m.jfrog.io   (no trailing slash)
  JFROG_ADMIN_TOKEN    an admin-scoped Access/Identity token (for repo
                        creation + manifest/tag verification via REST API)
  JFROG_DOCKER_USER    username used for `docker login`
  JFROG_DOCKER_PASS    password or identity token used for `docker login`

NOTE ON THE DOCKER REGISTRY HOSTNAME
--------------------------------------
This script assumes the "Repository Path Method" for Docker registries,
which is the default on JFrog Cloud (SaaS) instances:

    docker login <instance>.jfrog.io
    docker tag  <image>:<tag> <instance>.jfrog.io/<repo-key>/<image>:<tag>
    docker push <instance>.jfrog.io/<repo-key>/<image>:<tag>

If your instance instead uses the "Subdomain Method" (common on some
self-hosted setups, e.g. <repo-key>.mycompany.com), set
REGISTRY_HOST_OVERRIDE below or pass --registry-host on the CLI.
"""

import os
import sys
import json
import argparse
import subprocess
import requests

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

JFROG_URL = os.environ.get("JFROG_URL", "").rstrip("/")
ADMIN_TOKEN = os.environ.get("JFROG_ADMIN_TOKEN", "")
DOCKER_USER = os.environ.get("JFROG_DOCKER_USER", "")
DOCKER_PASS = os.environ.get("JFROG_DOCKER_PASS", "")

if not JFROG_URL or not ADMIN_TOKEN:
    print("ERROR: Please set JFROG_URL and JFROG_ADMIN_TOKEN environment variables.")
    sys.exit(1)

if not DOCKER_USER or not DOCKER_PASS:
    print("ERROR: Please set JFROG_DOCKER_USER and JFROG_DOCKER_PASS environment "
          "variables (used for `docker login`).")
    sys.exit(1)

PROJECT_KEY = "krypto-data"
REPO_KEY = f"{PROJECT_KEY}-docker-prod-local"

# Derived from JFROG_URL, e.g. "trialyo541m.jfrog.io"
REGISTRY_HOST_OVERRIDE = os.environ.get("REGISTRY_HOST", "")
REGISTRY_HOST = REGISTRY_HOST_OVERRIDE or JFROG_URL.replace("https://", "").replace("http://", "")

# The legacy image list from the lab spec
LEGACY_IMAGES = [
    ("busybox", "1.34.1"),
    ("busybox", "1.35.0"),
    ("alpine", "3.18"),
    ("alpine", "3.19"),
]

session = requests.Session()
session.headers.update({
    "Authorization": f"Bearer {ADMIN_TOKEN}",
    "Content-Type": "application/json",
})


def log(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")


def run(cmd, check=True):
    """Run a shell command, streaming output, and return the CompletedProcess."""
    print(f"    $ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip())
    if check and result.returncode != 0:
        warn(f"Command failed with exit code {result.returncode}")
    return result


def check(resp, ok_codes=(200, 201, 204)):
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
# Task 1: Target Repository Configuration
# --------------------------------------------------------------------------

def create_docker_repo():
    log(f"Task 1: Creating Docker repository '{REPO_KEY}'")
    url = f"{JFROG_URL}/artifactory/api/repositories/{REPO_KEY}"
    payload = {
        "key": REPO_KEY,
        "rclass": "local",
        "packageType": "docker",
        "projectKey": PROJECT_KEY,
        "environments": ["PROD"],
        "dockerApiVersion": "V2",
        "description": (
            "Lift-and-shift home for legacy DLT registry images. "
            "Stable, historical releases — do not treat as a dev/staging repo."
        ),
    }
    resp = session.put(url, data=json.dumps(payload))
    if resp.status_code == 400 and "already exist" in resp.text.lower():
        warn(f"Repo {REPO_KEY} already exists, continuing.")
        return True
    return check(resp)


# --------------------------------------------------------------------------
# Docker login
# --------------------------------------------------------------------------

def docker_login():
    log(f"Logging in to registry host: {REGISTRY_HOST}")
    result = subprocess.run(
        ["docker", "login", REGISTRY_HOST, "-u", DOCKER_USER, "--password-stdin"],
        input=DOCKER_PASS,
        capture_output=True,
        text=True,
    )
    print(result.stdout.rstrip())
    if result.returncode != 0:
        print(result.stderr.rstrip())
        warn("Docker login failed — check JFROG_DOCKER_USER/JFROG_DOCKER_PASS "
             "and that REGISTRY_HOST is reachable/correct for your instance.")
        return False
    log("Docker login succeeded.")
    return True


# --------------------------------------------------------------------------
# Task 2: Migration Workflow (single image — pull / tag / push)
# --------------------------------------------------------------------------

def migrate_single_image(image, tag):
    """Pull the legacy image, retag it for the target repo, and push it.
    This is the manual "Lift and Shift" step from Task 2, factored out so
    Task 3's bulk loop can reuse it per-image."""
    source_ref = f"{image}:{tag}"
    target_ref = f"{REGISTRY_HOST}/{REPO_KEY}/{image}:{tag}"

    log(f"Migrating {source_ref} -> {target_ref}")

    pull = run(["docker", "pull", source_ref])
    if pull.returncode != 0:
        warn(f"Failed to pull {source_ref}, skipping.")
        return False

    retag = run(["docker", "tag", source_ref, target_ref])
    if retag.returncode != 0:
        warn(f"Failed to retag {source_ref}, skipping.")
        return False

    push = run(["docker", "push", target_ref])
    if push.returncode != 0:
        warn(f"Failed to push {target_ref}.")
        return False

    log(f"    -> Migrated: {target_ref}")
    return True


# --------------------------------------------------------------------------
# Task 3: Bulk Migration Simulation
# --------------------------------------------------------------------------

def bulk_migrate(images=LEGACY_IMAGES):
    log(f"Task 3: Bulk-migrating {len(images)} legacy images")
    results = {}
    for image, tag in images:
        ok = migrate_single_image(image, tag)
        results[f"{image}:{tag}"] = ok
    return results


# --------------------------------------------------------------------------
# Validation Checklist
# --------------------------------------------------------------------------

def list_tags(image):
    """Task validation #1: confirm the image + tag are present in the repo."""
    url = f"{JFROG_URL}/artifactory/api/docker/{REPO_KEY}/v2/{image}/tags/list"
    resp = session.get(url)
    if resp.status_code != 200:
        check(resp)
        return []
    return resp.json().get("tags", [])


def verify_artifacts_present():
    log("Validation 1: Artifact Verification — checking tags exist in the repo")
    all_ok = True
    seen = {}
    for image, tag in LEGACY_IMAGES:
        if image not in seen:
            seen[image] = list_tags(image)
        tags = seen[image]
        present = tag in tags
        print(f"    {'OK' if present else 'MISSING'}: {image}:{tag} "
              f"(repo tags for {image}: {tags})")
        all_ok = all_ok and present
    return all_ok


def verify_manifest_readable():
    log("Validation 2: Metadata Check — fetching manifest JSON for each image")
    all_ok = True
    for image, tag in LEGACY_IMAGES:
        url = f"{JFROG_URL}/artifactory/api/docker/{REPO_KEY}/v2/{image}/manifests/{tag}"
        resp = session.get(url, headers={
            "Accept": "application/vnd.docker.distribution.manifest.v2+json"
        })
        ok = resp.status_code == 200
        print(f"    {'OK' if ok else 'FAIL'}: manifest for {image}:{tag} "
              f"(status {resp.status_code})")
        if ok:
            try:
                manifest = resp.json()
                layer_count = len(manifest.get("layers", manifest.get("fsLayers", [])))
                print(f"        -> readable JSON, {layer_count} layer(s) referenced")
            except Exception:
                warn("        -> response was 200 but not parseable JSON")
                ok = False
        all_ok = all_ok and ok
    return all_ok


def verify_pull_after_local_delete(image="alpine", tag="3.19"):
    """Task validation #3: delete locally, then pull from Artifactory to
    confirm the migrated copy is actually retrievable end-to-end."""
    target_ref = f"{REGISTRY_HOST}/{REPO_KEY}/{image}:{tag}"
    log(f"Validation 3: Pull Verification — using {target_ref}")

    log("    Removing local image copy (docker rmi)")
    run(["docker", "rmi", target_ref], check=False)
    # Also remove the original source-tagged copy if present, so we know the
    # pull below can ONLY have come from Artifactory, not local cache.
    run(["docker", "rmi", f"{image}:{tag}"], check=False)

    log("    Pulling from Artifactory")
    pull = run(["docker", "pull", target_ref])
    ok = pull.returncode == 0
    print(f"    -> {'OK: pull succeeded from Artifactory' if ok else 'FAIL: pull did not succeed'}")
    return ok


def run_validation_checklist():
    log("Running Validation Checklist")
    results = {
        "artifact_verification": verify_artifacts_present(),
        "manifest_readable": verify_manifest_readable(),
        "pull_after_delete": verify_pull_after_local_delete(),
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
    parser = argparse.ArgumentParser(description="KriptoStream Docker migration lab automation")
    parser.add_argument("--registry-host", help="Override the Docker registry hostname "
                         "(defaults to the host portion of JFROG_URL)")
    parser.add_argument("--skip-migration", action="store_true",
                         help="Skip pull/tag/push and only run validation "
                              "(useful for re-checking an already-migrated repo)")
    args = parser.parse_args()

    global REGISTRY_HOST
    if args.registry_host:
        REGISTRY_HOST = args.registry_host

    create_docker_repo()

    if not args.skip_migration:
        if not docker_login():
            sys.exit(1)
        bulk_migrate()

    run_validation_checklist()

    log("Migration automation complete. Grab UI screenshots of the Artifact "
        "Tree View under krypto-data-docker-prod-local for your deliverables.")


if __name__ == "__main__":
    main()
