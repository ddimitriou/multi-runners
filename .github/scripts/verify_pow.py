#!/usr/bin/env python3
"""
PoW-Hook Server-Side Verifier (GitHub Actions)

Verifies the Ed25519/RSA SSH signature (tree_hash|session_id|status) on every
commit in a push or pull_request against the committer's registered GitHub SSH
keys, and optionally cross-references the server-side attestation artifact.
"""
import sys
import os
import subprocess
import base64
import json
import time
import urllib.request
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


def run(cmd):
    return subprocess.check_output(cmd, shell=True).decode().strip()


# ---------------------------------------------------------------------------
# GitHub SSH Key Verification
# ---------------------------------------------------------------------------

def _api_base():
    return os.environ.get("POW_GITHUB_API_URL", "https://api.github.com").rstrip("/")


def get_github_username_for_commit(repo, commit_sha, gh_token):
    """Resolve the GitHub username of the commit's author via the Commits API."""
    url = f"{_api_base()}/repos/{repo}/commits/{commit_sha}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {gh_token}",
        "Accept": "application/vnd.github.v3+json",
    })
    try:
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read().decode())
        return data.get("author", {}).get("login")
    except Exception as e:
        print(f"   ⚠️  Could not resolve GitHub username for {commit_sha}: {e}")
        return None


def get_github_ssh_keys(username, gh_token):
    """Fetch the SSH public keys registered on a GitHub user's account."""
    url = f"{_api_base()}/users/{username}/keys"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {gh_token}",
        "Accept": "application/vnd.github.v3+json",
    })
    try:
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read().decode())
        return [k["key"] for k in data]
    except Exception as e:
        print(f"   ⚠️  Could not fetch SSH keys for {username}: {e}")
        return []


def verify_with_github_keys(sig_raw, payload_bytes, username, gh_token):
    """
    Try to verify sig_raw/payload_bytes against every SSH key registered
    on GitHub for username.  Supports RSA (PKCS1v15/SHA-256) and Ed25519.
    Returns True if any key matches.
    """
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey, ECDSA

    ssh_keys = get_github_ssh_keys(username, gh_token)
    if not ssh_keys:
        return False

    for key_str in ssh_keys:
        try:
            pub_key = serialization.load_ssh_public_key(key_str.encode())
            if isinstance(pub_key, RSAPublicKey):
                pub_key.verify(sig_raw, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
            elif isinstance(pub_key, (Ed25519PublicKey, Ed448PublicKey)):
                pub_key.verify(sig_raw, payload_bytes)
            elif isinstance(pub_key, EllipticCurvePublicKey):
                pub_key.verify(sig_raw, payload_bytes, ECDSA(hashes.SHA256()))
            else:
                continue
            return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# Attestation Artifact Lookup
# ---------------------------------------------------------------------------

def check_attestation_artifact(repo, session_id, expected_hash, gh_token, retries=3, delay=5):
    """
    Query GitHub's Artifacts API to confirm a PASSED attestation artifact
    exists for the given session_id.  Returns True if found.
    """
    if not gh_token or not repo:
        return None  # Cannot check — treat as inconclusive

    artifact_name = f"pow-attestation-{session_id}-{expected_hash}-PASSED"
    url = f"{_api_base()}/repos/{repo}/actions/artifacts?name={artifact_name}"

    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={
                "Authorization": f"Bearer {gh_token}",
                "Accept": "application/vnd.github.v3+json",
            })
            resp = urllib.request.urlopen(req)
            data = json.loads(resp.read().decode())
            if data.get("total_count", 0) > 0:
                print(f"   📜 Attestation artifact found: {artifact_name}")
                return True
        except Exception:
            pass

        if attempt < retries - 1:
            print(f"   ⏳ Waiting {delay}s for attestation artifact (attempt {attempt+2}/{retries})…")
            time.sleep(delay)

    print(f"   ⚠️  Attestation artifact NOT found: {artifact_name}")
    return False


# ---------------------------------------------------------------------------
# Verifier Modules
# ---------------------------------------------------------------------------

def resolve_commit_range():
    """Determine the range of commits to verify based on the GitHub event."""
    event_name = os.environ.get("GITHUB_EVENT_NAME")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        # Local fallback
        return run("git rev-parse HEAD~1"), run("git rev-parse HEAD"), "main", {}

    with open(event_path) as f:
        event = json.load(f)

    if event_name == "pull_request":
        base_sha = event["pull_request"]["base"]["sha"]
        head_sha = event["pull_request"]["head"]["sha"]
        ref_name = event["pull_request"]["head"]["ref"]
    else:
        base_sha = event.get("before")
        head_sha = event.get("after")
        ref_name = os.environ.get("GITHUB_REF", "").replace("refs/heads/", "")

        if not base_sha or base_sha == "0" * 40:
            try:
                base_sha = run(f"git merge-base origin/main {head_sha}") if head_sha else "HEAD~1"
            except Exception:
                base_sha = "HEAD~1"
        if not head_sha:
            head_sha = "HEAD"

    return base_sha, head_sha, ref_name, event


def verify_single_commit(commit, repo, gh_token, expected_hash):
    """Verify the PoW signature and attestation for a single commit."""
    print(f"\n🔍 Verifying commit {commit}…")

    pow_checks_b64 = run(f'git log -1 --format="%(trailers:key=PoW-Checks,valueonly)" {commit}')
    tree_hash = run(f"git log -1 --format=%T {commit}")

    if not pow_checks_b64:
        print(f"❌ Commit {commit} missing required PoW-Checks trailer.")
        return False

    try:
        bundle_json = base64.b64decode(pow_checks_b64).decode()
        bundle = json.loads(bundle_json)
        token = bundle["token"]
        session = bundle["session"]
        status = bundle["status"]
        cmd_hash = bundle["checks_hash"]
    except Exception:
        print(f"❌ Commit {commit} PoW-Checks trailer is not valid base64 JSON.")
        return False

    if cmd_hash != expected_hash:
        print(f"❌ Commit {commit} used incorrect POW_CHECKS_CMD (hash mismatch).")
        return False

    sign_payload = f"{cmd_hash}|{tree_hash}|{session}|{status}"
    try:
        sig_raw = base64.b64decode(token)
    except Exception:
        print(f"❌ Commit {commit} token is not valid base64.")
        return False

    username = get_github_username_for_commit(repo, commit, gh_token)
    if not username:
        print(f"❌ Cannot resolve GitHub username for commit {commit}.")
        return False

    if not verify_with_github_keys(sig_raw, sign_payload.encode(), username, gh_token):
        print(f"❌ No matching GitHub SSH key for commit {commit} (user: {username}).")
        return False

    print(f"   ✅ Signature verified via GitHub SSH keys of {username}.")

    if check_attestation_artifact(repo, session, expected_hash, gh_token) is False:
        print(f"❌ No server-side attestation found for session {session}.")
        return False

    return True


def teardown_pr(repo_name, ref_name, gh_token, admins):
    """Close linked PRs and notify admins."""
    try:
        owner = repo_name.split("/")[0]
        prs_url = f"{_api_base()}/repos/{repo_name}/pulls?head={owner}:{ref_name}&state=open"
        req_prs = urllib.request.Request(prs_url, headers={
            "Authorization": f"Bearer {gh_token}",
            "Accept": "application/vnd.github.v3+json",
        })
        resp = urllib.request.urlopen(req_prs)
        open_prs = json.loads(resp.read().decode())

        tag = f"{admins} " if admins else ""
        support_link = "https://support.github.com/contact/general"
        msg = (
            f"🚨 **Proof-of-Work Validation Failed**\n\n"
            f"{tag}This Pull Request received a commit containing an unverified or fraudulent "
            f"cryptographic signature.\n\n"
            f"_The PR has been automatically closed and the compromised branch pushed over._\n\n"
            f"**Manual Action Required:** GitHub does not provide an API to hard-delete Pull Requests. "
            f"To completely scrub the unverified commit history from the repository index, an administrator must "
            f"open a ticket with GitHub Support requesting the total deletion of this PR.\n"
            f"👉 [Submit a Support Ticket]({support_link})"
        )

        for pr in open_prs:
            pr_num = pr["number"]
            c_url = f"{_api_base()}/repos/{repo_name}/issues/{pr_num}/comments"
            urllib.request.urlopen(urllib.request.Request(c_url, data=json.dumps({"body": msg}).encode(), headers={
                "Authorization": f"Bearer {gh_token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json",
            }))
            p_url = f"{_api_base()}/repos/{repo_name}/pulls/{pr_num}"
            urllib.request.urlopen(urllib.request.Request(p_url, data=json.dumps({"state": "closed"}).encode(), headers={
                "Authorization": f"Bearer {gh_token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json",
            }, method="PATCH"))
            print(f"✅ Closed PR #{pr_num} and posted instructions to admins.")
    except Exception as e:
        print(f"⚠️  PR API teardown error: {e}")


def perform_server_side_check(expected_cmd):
    """Execute the server-side quality check command."""
    print(f"\n⚙️ Executing server-side check: {expected_cmd}")
    extra_header = None
    key = "http.https://github.com/.extraheader"
    try:
        extra_header = subprocess.check_output(["git", "config", "--local", "--get", key]).decode().strip()
        subprocess.check_call(["git", "config", "--local", "--unset", key])
    except subprocess.CalledProcessError:
        pass

    try:
        subprocess.check_call(expected_cmd, shell=True)
        print("✅ Server-side check passed.")
        return True
    except subprocess.CalledProcessError:
        print("❌ Server-side check failed. A zero-trust validation error occurred.")
        return False
    finally:
        if extra_header:
            subprocess.check_call(["git", "config", "--local", key, extra_header])


def handle_rejection(ref_name, last_valid, gh_token, event):
    """Revert the push and clean up PRs if necessary."""
    print("\n-------------------------------------------------------")
    print("REJECTED: One or more commits failed validation.")
    print(f"WARNING: Obliterating invalid commits from branch {ref_name}")
    print("-------------------------------------------------------")

    if gh_token:
        repo_name = os.environ.get("GITHUB_REPOSITORY") or event.get("repository", {}).get("full_name")
        admins = os.environ.get("POW_ADMIN_HANDLES", "")
        teardown_pr(repo_name, ref_name, gh_token, admins)

    run("git config --global user.name github-actions[bot]")
    run("git config --global user.email github-actions[bot]@users.noreply.github.com")
    run(f"git push --force origin {last_valid}:refs/heads/{ref_name}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Main Logic
# ---------------------------------------------------------------------------

def main():
    if os.environ.get("POW_ENFORCE", "").strip().lower() != "true":
        print("⚠️  POW_ENFORCE is not \"true\" — validation is disabled.")
        sys.exit(0)

    gh_token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    expected_cmd = os.environ.get("POW_CHECKS_CMD", "none")
    expected_hash = hashlib.sha256(expected_cmd.encode()).hexdigest()

    base_sha, head_sha, ref_name, event = resolve_commit_range()
    commits_str = ""
    try:
        commits_str = run(f"git log {base_sha}..{head_sha} --format=%H")
    except Exception:
        pass

    if not commits_str:
        print("No new commits to verify.")
        sys.exit(0)

    commits = commits_str.splitlines()
    commits.reverse()
    missing = 0
    last_valid = base_sha

    for commit in commits:
        if not verify_single_commit(commit, repo, gh_token, expected_hash):
            missing += 1
            break
        last_valid = commit

    if missing == 0 and expected_cmd and expected_cmd != "none":
        if not perform_server_side_check(expected_cmd):
            missing += 1
            last_valid = base_sha

    if missing > 0:
        handle_rejection(ref_name, last_valid, gh_token, event)

    print("\n🎉 All commits have valid Proof-of-Work tokens and server attestations!")


if __name__ == "__main__":
    main()
