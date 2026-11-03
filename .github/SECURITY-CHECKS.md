# Security checks

Installed and maintained by the `security-base` skill in
[Represent-Studio/skills](https://github.com/Represent-Studio/skills/tree/main/security-base).
Don't edit these files by hand in one repo. Change the skill, then reinstall everywhere.

| Check | Runs on | Blocks merge? | What it does |
|---|---|---|---|
| **Malware scan** | every PR, every push, daily | Yes (required check) | Deterministic scan for the Nov 2026 malware and its variants: auto-run hooks, loaders, CI tricks, exfiltration. Fails on any force-push. [MALWARE-SCAN.md](MALWARE-SCAN.md) |
| **AI security review** | every PR | Yes (required check) | A model reviews the change for malicious code and vulnerabilities. Fails closed. [AI-SECURITY-REVIEW.md](AI-SECURITY-REVIEW.md) |
| **zizmor** | PRs that change workflows | No (advisory) | GitHub Actions security, from the zizmor project |
| **Semgrep** | every PR | No (advisory) | Code vulnerabilities from the Semgrep community rules; reports only what the PR adds |

## If a check is red

1. **Don't open the branch in an editor, and don't run npm, node or Python in it.**
2. Read the findings in the run summary.
3. If it's real: don't merge, tell Renat and Mykhailo, and follow the incident steps in the security-base skill.
4. If it's a false alarm: see "If the check fails" in MALWARE-SCAN.md, or push a fix and let the AI review re-run.
   Exemptions in `malware-scan-allow.txt` need a second person's review.

## Never

- Disable, skip or weaken these workflows or scripts to get a PR merged.
- Add an exemption without pinning it to the file's content (`@blob`).
- Force-push a shared branch.
