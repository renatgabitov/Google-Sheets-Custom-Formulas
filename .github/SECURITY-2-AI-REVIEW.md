# Security 2 - AI review

Every pull request gets a security review from an AI model through
[OpenRouter](https://openrouter.ai). It posts one comment on the PR and updates
it on each new push. Findings also show up as annotations on the changed lines.

It looks for two things: **malicious or sabotaged code** (hidden auto-run hooks,
obfuscated code, credential theft, backdoors, risky new dependencies, CI changes
that expose secrets) and **exploitable vulnerabilities** (injection, XSS, SSRF, auth
mistakes, hard-coded secrets).

## It's a merge gate

The check **fails**, so the PR can't merge once it's a required check, when:

- a finding is **high or critical** (change the level with the `AI_REVIEW_FAIL_ON` variable), or
- the review **couldn't be completed**: no key or model configured, OpenRouter down,
  an unreadable answer, a PR too large to review in full, or a PR from a fork.

It fails closed on purpose. An attacker shouldn't be able to slip a change through
by breaking the reviewer.

If it blocks something you're sure is fine, fix the finding or push again (the model
reviews again). As a last resort, an organization admin can bypass the rule on that one PR.

It pairs with the **Security 1 - Malware check** (SECURITY-1-MALWARE-CHECK.md). That one is deterministic and
can't be talked out of a finding. This one understands logic, such as a backdoor written as
ordinary code, which no pattern can catch. Require both.

## Setup (once, for the whole organization)

1. **OpenRouter:** create an API key just for this, with a credit limit.
2. **GitHub → Represent-Studio → Settings → Secrets and variables → Actions:**
   - **Secrets** tab → New organization secret → name `OPENROUTER_API_KEY`, paste
     the key, Repository access → selected repositories.
   - **Variables** tab → New organization variable → name `OPENROUTER_MODEL`, value
     a model id from [openrouter.ai/models](https://openrouter.ai/models)
     (for example `anthropic/...` or `openai/...`), same repository access.
3. **Make it required:** Repository → Settings → Rules → the ruleset for `main` →
   Require status checks to pass → add **Security 2 - AI review** (next to **Security 1 - Malware check**).

A repository that gets this workflow but not the secret will block every PR, by design.

## Switching models or gate level

- **Model:** change the `OPENROUTER_MODEL` variable. It takes effect on the next PR push.
  A repository variable with the same name overrides the organization one.
- **Gate level:** variable `AI_REVIEW_FAIL_ON` = `critical`, `high` (default), `medium` or
  `low`. Use `off` to make the review advisory only.

## What it sees

- The PR's changes with surrounding context. Large files are split into parts, never cut.
  Up to 8 model calls per run (about 1 MB of diff); a bigger PR fails as "too large to
  review in full". Split it.
- Lockfiles, build output and binary files aren't sent to the model; the Malware check
  checks those.
- It runs the reviewer script from the base branch, so a PR can't change the reviewer
  that reviews it.
- Permissions: read the code, comment on the PR. It can't push, merge or change settings.
- Cost: one to eight model calls per PR push. Watch usage in OpenRouter.

## Run it locally (no key needed for a dry run)

```bash
python3 -I .github/scripts/ai_security_review.py --base origin/main --head HEAD --dry-run
```
