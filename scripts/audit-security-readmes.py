#!/usr/bin/env python3
"""Audit public cybersecurity README files for structure, safety, SEO, links, and secrets."""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

OWNER = "TehseenTech"
REPOSITORIES = {
    "manus-skills": {
        "kind": "workflow system",
        "required_terms": ["workflow", "validation"],
        "required_markers": ["Safe use note", "human review"],
    },
    "digital-evidence-preservation": {
        "kind": "digital forensics resource",
        "required_terms": ["digital evidence", "chain of custody"],
        "required_markers": ["Privacy and repository safety", "Disclaimer"],
    },
    "online-fraud-scam-response": {
        "kind": "incident-response resource",
        "required_terms": ["fraud", "phishing", "evidence"],
        "required_markers": ["Privacy and repository safety", "Disclaimer"],
    },
    "hacked-account-recovery": {
        "kind": "account-security resource",
        "required_terms": ["recovery", "multi-factor authentication"],
        "required_markers": ["Privacy and repository safety", "Disclaimer"],
    },
    "identity-sim-misuse-response": {
        "kind": "mobile-security resource",
        "required_terms": ["SIM", "identity", "evidence"],
        "required_markers": ["Privacy and repository safety", "Disclaimer"],
    },
    "Cdr-dashboard-by-Tehseen-raza": {
        "kind": "data-analysis dashboard",
        "required_terms": ["Streamlit", "authorized", "limitations"],
        "required_markers": ["Responsible use", "Data handling and limitations"],
    },
}


def get(url: str, token: str | None = None) -> tuple[int, bytes, str]:
    headers = {"User-Agent": "TehseenTech-readme-audit/1.0", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read(), response.headers.get("content-type", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), ""
    except Exception as exc:
        return 0, str(exc).encode(), ""


def github_api(path: str, token: str | None) -> dict:
    status, body, _ = get(f"https://api.github.com/{path.lstrip('/')}", token)
    if status != 200:
        raise RuntimeError(f"GitHub API returned {status} for {path}")
    return json.loads(body.decode("utf-8"))


def extract_links(markdown: str) -> list[str]:
    links = re.findall(r"https?://[^)\s<>\"]+", markdown)
    return sorted(set(link.rstrip(".,`" ) for link in links))


def audit(repo: str, config: dict, token: str | None) -> tuple[dict, list[str]]:
    findings: list[str] = []
    api = github_api(f"repos/{OWNER}/{repo}/readme", token)
    import base64
    markdown = base64.b64decode(api["content"]).decode("utf-8", errors="replace")
    lines = markdown.splitlines()
    h1 = [line for line in lines if re.match(r"^#\s+", line)]
    if len(h1) != 1:
        findings.append(f"SEO structure: expected exactly one H1 heading, found {len(h1)}.")
    if len(markdown) < 300:
        findings.append("SEO/content: README is very short; add purpose, usage, limitations, and scope.")
    first_content = next((line.strip() for line in lines if line.strip() and not line.startswith("#") and not line.startswith("<")), "")
    if len(first_content) < 40:
        findings.append("SEO/content: the opening description is too short to explain the project clearly.")
    lower = markdown.lower()
    for term in config["required_terms"]:
        if term.lower() not in lower:
            findings.append(f"SEO/topic coverage: missing expected term `{term}` for {config['kind']}.")
    for marker in config["required_markers"]:
        if marker.lower() not in lower:
            findings.append(f"Safety/documentation: missing `{marker}` section or phrase.")
    secret_patterns = {
        "GitHub token": r"gh[pousr]_[A-Za-z0-9_]{20,}",
        "private key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        "AWS access key": r"AKIA[0-9A-Z]{16}",
    }
    for label, pattern in secret_patterns.items():
        if re.search(pattern, markdown):
            findings.append(f"Security: possible {label} pattern found; review immediately.")
    link_results = []
    unverified_links = []
    for link in extract_links(markdown):
        status, _, _ = get(link, token if "api.github.com" in link else None)
        if status in {403, 406, 429}:
            unverified_links.append({"url": link, "status": status})
        elif status < 200 or status >= 400:
            findings.append(f"Link check: `{link}` returned HTTP {status or 'error'}.")
            link_results.append({"url": link, "status": status or "error"})
    return {"repo": repo, "sha": api.get("sha", "unknown"), "links_checked": len(extract_links(markdown)), "link_failures": link_results, "unverified_links": unverified_links}, findings


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN")
    all_findings: list[tuple[str, str]] = []
    results: list[dict] = []
    for repo, config in REPOSITORIES.items():
        try:
            result, findings = audit(repo, config, token)
            results.append(result)
            all_findings.extend((repo, finding) for finding in findings)
        except Exception as exc:
            all_findings.append((repo, f"Audit error: {exc}"))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print("# Cybersecurity README audit\n")
    print(f"Generated: {now}\n")
    print("This report is deterministic and advisory. It does not rewrite README files automatically.\n")
    print("## Repository checks\n")
    for result in results:
        print(f"- `{result['repo']}` — checked {result['links_checked']} links; latest README blob `{result['sha'][:12]}`")
    unverified = [(result["repo"], item) for result in results for item in result["unverified_links"]]
    if unverified:
        print("\n## Links requiring manual confirmation\n")
        print("Some official sites block automated requests; these links were not called broken:")
        for repo, item in unverified:
            print(f"- **{repo}:** `{item['url']}` returned HTTP {item['status']} to the automated checker.")
    print("\n## Findings\n")
    if not all_findings:
        print("No findings. The featured README set passed the configured structure, safety, SEO-term, link, and secret-pattern checks.")
    else:
        for repo, finding in all_findings:
            print(f"- **{repo}:** {finding}")
    print("\n## Review policy\n")
    print("README changes should be made through a reviewed pull request. Do not publish credentials, victim data, case evidence, or unauthorized datasets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
