# Frequently Asked Questions (FAQ)

Quick answers to common questions about Vulnera's features, capabilities, and usage.

## Quota & Rate Limiting

### How much does analysis cost in tokens?

Each operation consumes tokens from your daily quota:

| Operation           | Cost     |
| ------------------- | -------- |
| Basic analysis      | 3 tokens |
| LLM explanation     | 6 tokens |
| Code fix generation | 6 tokens |
| LLM query           | 6 tokens |

**Example:** A full analysis (3) + 2 LLM features (12) = 15 tokens total.

**Reference:** [Quota & Pricing Guide](../user-guide/quota-pricing.md)

### What's the difference between API key tier and organization tier?

| Tier            | Daily Limit | Use Case                 |
| --------------- | ----------- | ------------------------ |
| Unauthenticated | 10 tokens   | Testing, no auth         |
| API Key         | 40 tokens   | Single integration       |
| Organization    | 48 tokens   | Team usage, shared quota |

**Team quota pools together**: If an org has 5 members, all members share the 48-token daily limit (no per-member quota).

### Can I increase my quota?

**Yes.** Options:

1. **Organization tier** — Upgrade to shared team quota (100 tokens/day)
2. **Premium plan** — Contact vulnera for higher limits
3. **On-premise** — Deploy Vulnera privately with unlimited quota

### What happens when I exceed my quota?

You receive a `429 Too Many Requests` error:

Quota resets at 00:00 UTC every day.

---

## Offline Capabilities

### What can Vulnera analyze offline (without internet)?

| Module       | Offline | Notes                                   |
| ------------ | ------- | --------------------------------------- |
| SAST         | ✅ Yes  | AST pattern matching (Python, JS, Rust) |
| Secrets      | ✅ Yes  | ML pattern recognition + entropy        |
| API          | ✅ Yes  | OpenAPI schema analysis                 |
| Dependencies | ❌ No   | Requires CVE database                   |
| LLM          | ❌ No   | Requires Pangu API                      |

**CLI offline scan:**

```bash
vulnera analyze --source ./my-project --modules sast,secrets,api
# No internet required
```

### Can I use Vulnera without an internet connection?

**Partial.** The CLI can run offline scans for SAST, Secrets, and API analysis. Dependency scanning requires internet (to fetch CVE data from registries).

---

## Analysis Accuracy & False Positives

### Why do I have false positives in secret detection?

Common causes:

1. **Test/example secrets** — Hardcoded in docs or tests
   - **Fix:** Mark as `.vulnera-ignore` or use entropy baseline filters

2. **Placeholder values** — Keys like `YOUR_API_KEY_HERE`
   - **Fix:** Entropy score filters exclude most placeholders

3. **High-entropy strings** — Random tokens in logs
   - **Fix:** Configure entropy thresholds per secret type

**False positive rate:** <5% for high-confidence secrets (AWS keys, private certs)

**Reference:** [Secrets Detection](../analysis/secrets-detection.md)

### How accurate is SAST analysis?

**Detection rates:**

| Vulnerability              | Confidence | False Positives |
| -------------------------- | ---------- | --------------- |
| SQL Injection              | 95-98%     | <3%             |
| Cross-Site Scripting (XSS) | 93-97%     | <4%             |
| Command Injection          | 92-95%     | <5%             |
| Hardcoded Secrets          | 98%+       | <2%             |

**Limitation:** Cannot detect business logic flaws or complex multi-step attacks .

### Why didn't Vulnera detect a vulnerability I know exists?

Possible reasons:

1. **Dynamic code patterns** — Code generated at runtime
   - SAST analyzes static AST; runtime patterns require dynamic analysis "next step In roadmap"

2. **Complex data flow** — Multi-step taint chains
   - Default taint depth is 3 hops; increase with `--taint-depth=5`

3. **Custom sanitizers** — User-defined security functions not recognized
   - Configure in `.vulnera.toml` under `sast.custom_sanitizers`

4. **False negative filtering** — Some detections suppressed to reduce noise
   - Enable with `--analysis-depth=full`

**Reference:** [SAST Analysis](../analysis/sast.md)

---

## ML vs. LLM

### What's the difference between ML models and LLM features?

| Aspect            | ML Models (Detection)                  | LLM Features (Explanation)    |
| ----------------- | -------------------------------------- | ----------------------------- |
| **Purpose**       | Find vulnerabilities                   | Explain & fix vulnerabilities |
| **Technology**    | Pattern matching, AST parsing, entropy | Huawei Cloud Pangu LLM        |
| **Speed**         | <1 second                              | 3-10 seconds                  |
| **Offline**       | ✅ Yes                                 | ❌ No                         |
| **Cost**          | 3 tokens                               | 6 tokens                      |
| **Deterministic** | ✅ Same input = same output            | ❌ May vary slightly          |

### Are ML models proprietary?

**Detection models** (SAST, Secrets, API) are **rule-based and open-source**:

- SAST: tree-sitter AST patterns (GitHub open-source)
- Secrets: Entropy + regex patterns (public ML fingerprints)
- API: OpenAPI schema validation (OWASP standards)

**LLM explanations** use Huawei Cloud.

### Can I use Vulnera without LLM features?

**Yes.** All detection modules work offline:

```bash
vulnera analyze --source . --modules sast,secrets,api,dependencies
# No LLM explanations, but full analysis completed
```

LLM is optional for:

- Explanations (`vulnera explain-finding <id>`)
- Code fixes (`vulnera generate-fix <id>`)
- Natural language queries (`vulnera query "How do I...?"`)

---

## Customization

### Can I customize SAST rules?

**Yes, three ways:**

1. **Update existing rules:**

   ```toml
   # .vulnera.toml
   [sast]
   rule_overrides = {
     "SQL_INJECTION" = { severity = "high", enabled = true }
   }
   ```

2. **Add custom rules:**

   ```python
   # .vulnera/custom_rules.py
   @sast_rule("CUSTOM_XSS")
   def check_unescaped_output(node):
       """Check for unescaped user input in HTML templates"""
       # Custom pattern matching logic
   ```

3. **Disable noisy rules:**

   ```toml
   [sast.disabled_rules]
   "LOW_ENTROPY_STRING" = true
   "COMMENTED_SECRET" = true
   ```

**Reference:** [SAST Analysis](../analysis/sast.md)

### Can I filter out certain secret types?

**Yes:**

```toml
# .vulnera.toml
[secrets]
ignored_patterns = [
  "GITHUB_TOKEN_PLACEHOLDER",  # Exact string match
  "^test_.*",                   # Regex patterns
]

# Or ignore by file
ignored_files = [
  "docs/examples.md",
  "tests/fixtures/**"
]
```

**Command line:**

```bash
vulnera analyze . --secrets-ignore-patterns="test_,example_"
```

---

## Integration

### How do I integrate Vulnera into GitHub Actions?

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  vulnera:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: vulnera-dev/vulnera-action@v1
        with:
          api-key: ${{ secrets.VULNERA_API_KEY }}
          analysis-depth: standard
          fail-on-severity: high
```

**Reference:** [DevSecOps Quick Start](../getting-started/personas/devsecops-quickstart.md)

### Can I scan S3 buckets?

**Yes:**

```bash
vulnera analyze --source s3://my-bucket/project \
  --aws-credentials-from-env
```

**Requirements:**

- AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY environment variables
- S3 bucket must have read access

**Reference:** [Cloud Engineer Quick Start](../getting-started/personas/cloud-engineer-quickstart.md)

### Does Vulnera support enterprise deployments?

**Yes, three options:**

1. **SaaS (api.vulnera.studio)** — Fully managed
2. **Self-hosted Docker** — On your infrastructure
3. **Kubernetes helm chart** — Enterprise clusters

**Reference:** [Architecture - Deployment Models](./architecture.md#deployment-models)

---

## Performance

### How long does analysis take?

**Typical times (standard depth):**

| Source                | Size      | Time      |
| --------------------- | --------- | --------- |
| Small repo (5K LOC)   | <1 MB     | 2-5 sec   |
| Medium repo (50K LOC) | 5-10 MB   | 10-30 sec |
| Large repo (800K LOC) | 50-100 MB | 1-5 min   |

**Optimization:**

```bash
# Faster (minimal depth)
vulnera analyze . --analysis-depth=minimal  # 2-3 sec

# Slower (full depth)
vulnera analyze . --analysis-depth=full     # +2-3x time
```

### Can I parallelize scanning?

**Yes:**

```bash
# Scan 10 repos in parallel
for repo in repo1 repo2 ... repo10; do
  vulnera analyze $repo --source-type=git &
done
wait
```

**Concurrency limits:**

- CLI: Unlimited (your machine)
- API: 50 concurrent jobs per organization
- Jobs queued beyond limit; respects rate limit

---

## Organization & Teams

### How do I share results with my team?

1. **Create organization:**

   ```bash
   vulnera org create "My Team"
   ```

2. **Invite members:**

   ```bash
   vulnera org members add teammate@company.com --role=analyst
   ```

3. **Run scan under organization:**

   ```bash
   vulnera analyze . --org-id=<org-id>
   # Results visible to all org members
   ```

**Reference:** [DevSecOps Quick Start](../getting-started/personas/devsecops-quickstart.md)

### What are organization roles?

| Role           | Permissions                                                 |
| -------------- | ----------------------------------------------------------- |
| **Owner**      | Create/delete org, manage all settings, view all results    |
| **Admin** \*   | Invite members, configure scanning policies, view analytics |
| **Analyst** \* | Run scans, view results, generate reports                   |
| **Viewer**     | View results only, read-only access                         |

---

## Troubleshooting

### Vulnera says "API Key not found" but I set VULNERA_API_KEY

**Check:**

```bash
echo $VULNERA_API_KEY  # Verify variable is set
vulnera auth status   # Check authentication
```

**Possible causes:**

- API key is revoked
- API key doesn't have required organization access
- Environment variable not exported (use `export VULNERA_API_KEY=...`)

### Analysis returns empty results but I expect findings

**Check:**

1. **Verify modules are enabled:**

   ```bash
   vulnera analyze . --modules=all --verbose
   # Should list sast, secrets, api, dependencies
   ```

2. **Lower analysis depth:**

   ```bash
   vulnera analyze . --analysis-depth=full  # More aggressive
   ```

3. **Check file filter:**

   ```bash
   vulnera analyze . --include-files="**/*.py,**/*.js"
   ```

### LLM explanations are slow or timing out

**Solutions:**

1. Increase timeout: `vulnera config set llm.timeout=60`
2. Use organization tier for higher concurrency
3. Request explanations asynchronously: `vulnera explain --async`

---

## Dashboard & Web Platform

### What is vulnera.studio?

**Vulnera Studio** ([vulnera.studio](https://vulnera.studio)) is the central web dashboard for managing vulnerability analysis, team collaboration, and security insights. It provides:

- **Personal Dashboard** — View your scans and findings
- **Organization Management** — Team collaboration with shared quotas
- **API Key Management** — Generate keys for CLI and API access
- **Integrations** — Connect GitHub, GitLab, Slack, webhooks
- **Analytics & Reporting** — Track team metrics and generate compliance reports
- **Billing Management** — Upgrade plans and manage subscriptions

**Access:** Visit [https://vulnera.studio](https://vulnera.studio) and sign in with your email.

**Reference:** [Dashboard Guide](../user-guide/dashboard/guide.md)

### How do I create an organization?

**Step-by-step:**

1. Log in to [vulnera.studio](https://vulnera.studio)
2. Click **+ New Organization** in sidebar
3. Enter organization name, description, and logo (optional)
4. Select plan tier (Free, Pro, Enterprise)
5. Click **Create** — you're now the owner

**What you get:**

- Shared quota pool (e.g., 48 tokens/month for Free, 1000 for Pro)
- Team member management (invite/remove members)
- Centralized reporting and analytics
- Organization API keys for CI/CD

**Reference:** [Organization Management](../user-guide/dashboard/organization-management.md)

### How do I invite team members?

**Invite members to your organization:**

1. Go to **Settings → Members**
2. Click **Invite Member**
3. Enter email address(es) and select role:
   - **Admin** — Manage team, integrations, settings
   - **Member** — Create scans, resolve findings
   - **Viewer** — Read-only access (good for executives)
4. Click **Send Invitations**
5. Members receive email with join link

**Roles & Permissions:**

- **Owner** — Full access, billing, delete organization
- **Admin** — Members, settings, integrations (no billing)
- **Member** — Create/view scans, resolve findings
- **Viewer** — Read-only access to scans and reports

**Reference:** [Team Collaboration](../user-guide/dashboard/team-collaboration.md)

### How do I generate an API key for the CLI?

**Generate API key:**

1. Log in to [vulnera.studio](https://vulnera.studio)
2. Go to **Settings → API Keys**
3. Click **Generate New Key**
4. Name the key (e.g., "GitHub Actions", "Local Dev")
5. Set expiration (Never, 30 days, 90 days, 1 year)
6. Click **Create** and **copy immediately** (not shown again)
7. Store securely in your credential manager or CI/CD secrets

**Use in CLI:**

```bash
vulnera auth login --api-key YOUR_API_KEY
```

**Use in GitHub Actions:**

```yaml
- name: Scan with Vulnera
  env:
    VULNERA_API_KEY: ${{ secrets.VULNERA_API_KEY }}
  run: vulnera analyze . --all-modules
```

**Security:** Rotate API keys every 90 days. Revoke unused keys immediately.

### What's the difference between personal and organization API keys?

| Aspect           | Personal Key                 | Organization Key                                 |
| ---------------- | ---------------------------- | ------------------------------------------------ |
| **Quota**        | 40 tokens/day (your own)     | Shared org quota (48/day for Free, 1000 for Pro) |
| **Access**       | Your scans only              | All org members' scans                           |
| **Team**         | Individual                   | Shared across team                               |
| **Use case**     | Local dev, personal projects | CI/CD, team automation                           |
| **Generated in** | Settings → API Keys          | Organization → Settings → API Keys               |

**Best practice:** Use organization keys for CI/CD pipelines; personal keys for local testing.

### How do I upgrade my organization's plan?

**Upgrade plan:**

1. Go to [vulnera.studio](https://vulnera.studio) → **Settings → Billing**
2. Current plan and quota displayed
3. Click **Change Plan** or **Upgrade**
4. Select new tier (Pro, Enterprise) or add custom tokens
5. Update payment method if needed
6. Click **Confirm Upgrade**

**Plan options:**

- **Free** — 48 tokens/month, 5 members, basic integrations
- **Pro** — 1000 tokens/month, unlimited members, advanced integrations
- **Enterprise** — Custom tokens, SSO/SAML, custom domains, priority support

**Downgrade:** Available mid-cycle; changes take effect at next billing date.

**Reference:** [Quota & Pricing](../user-guide/quota-pricing.md)

### How do I connect GitHub for automatic scanning?

**GitHub Integration setup:**

1. Go to [vulnera.studio](https://vulnera.studio) → **Settings → Integrations → GitHub**
2. Click **Connect GitHub**
3. Authorize Vulnera GitHub App (select repos or all repos)
4. Enable auto-scan triggers:
   - On push to main/develop
   - On all pull requests
   - Scheduled daily scan
5. Save — scans now run automatically

**What happens:**

- PRs show Vulnera status checks
- Comments added to PRs with findings
- Merge blocked if critical issues found (configurable)
- Results uploaded to GitHub code scanning

**Reference:** [Dashboard Guide - GitHub Integration](../user-guide/dashboard/guide.md#github-integration)

### How do I set up Slack notifications?

**Enable Slack integration:**

1. Go to [vulnera.studio](https://vulnera.studio) → **Settings → Integrations → Slack**
2. Click **Connect Slack Workspace**
3. Authorize Vulnera app in Slack
4. Select notification channel
5. Configure notification types:
   - Critical findings (immediate)
   - Daily digest
   - Weekly summary
   - Quota alerts
6. Save

**Example Slack message:**

```
🚨 Critical Vulnerability Found
Repo: acme/backend
Finding: SQL Injection in /api/users.py
CVSS: 9.2
→ View Details [Link]
```

**Reference:** [Dashboard Guide - Slack Integration](../user-guide/dashboard/guide.md#slack-integration)

### How do I view team analytics and usage?

**Organization Analytics:**

1. Go to [vulnera.studio](https://vulnera.studio) → **Organization → Analytics**
2. View dashboard:
   - Total quota used vs. remaining
   - Per-member breakdown (token consumption)
   - Module usage (pie chart: Dependencies, SAST, Secrets, API)
   - 6-month usage trend
   - Top analyzed projects

**Export report:**

1. Click **Export**
2. Choose format: CSV, JSON, or PDF
3. Download for spreadsheets or stakeholder reporting

**Reference:** [Dashboard Guide - Quota Management](../user-guide/dashboard/guide.md#quota-management--analytics)

### Can I generate compliance reports from the dashboard?

**Yes, multiple report types:**

1. Go to [vulnera.studio](https://vulnera.studio) → **Reports → Compliance Reports**
2. Select framework:
   - SOC2 Type II
   - ISO 27001
   - GDPR
   - HIPAA (Enterprise)
   - PCI DSS (Enterprise)
3. Select date range
4. Click **Generate** → PDF/HTML download
5. Share with auditors or stakeholders

**Report contents:**

- Security metrics summary
- Audit log excerpts
- Member access records
- Vulnerability remediation status
- Data handling compliance statements

**Reference:** [Dashboard Guide - Reporting & Export](../user-guide/dashboard/guide.md#reporting--export)

### How do I remove a team member?

**Remove member from organization:**

1. Go to [vulnera.studio](https://vulnera.studio) → **Settings → Members**
2. Find member in list
3. Click **Remove** (⋯ menu)
4. Confirm removal — member loses access immediately

**What happens:**

- Member can no longer see organization scans
- Their scans remain in history (for audit)
- Their API keys are revoked
- Activity logged in audit trail

**Reinvite later:** Can re-invite removed members anytime

**Reference:** [Organization Management - Removing Members](../user-guide/dashboard/organization-management.md#removing-members)

---

## Security & Privacy

### Is my code scanned securely?

**Data handling:**

| Data           | Storage                                 | Retention              |
| -------------- | --------------------------------------- | ---------------------- |
| Code artifacts | Encrypted in transit, encrypted at rest | 30 days (deleted)      |
| Findings       | Database (encrypted)                    | Until you delete       |
| API keys       | Hashed in database                      | Until revoked          |
| User data      | GDPR compliant                          | Until account deletion |

**Reference:** [Architecture - Security Model](./architecture.md#security-model)

### Can I see Vulnera's source code?

**Partial:**

- **Open-source**: SAST rules, Secrets patterns, CLI utilities
- **Proprietary**: LLM integration, API backend, rate limiting logic
- **Reference**: [GitHub open-source modules](https://github.com/vulnera-dev/vulnera/tree/main/vulnera-sast)

### Is on-premise deployment available?

**NO.** Vulnera doesn't supports self-hosted deployment with plan to support in future.

Contact Vulnera for enterprise licenses.

---

## Cost & Licensing

### Is there a free tier?

**Yes:**

| Tier         | Features                                          | Cost         |
| ------------ | ------------------------------------------------- | ------------ |
| Community    | SAST, Secrets, API (offline)                      | Free         |
| Developer    | +Dependency scanning, LLM (limited 40 tokens/day) | Free/API key |
| Organization | Team collaboration, 100 tokens/day, analytics     | $99/month    |
| Enterprise   | Unlimited, SLA                                    | Custom       |

**Reference:** [Quota & Pricing](../user-guide/quota-pricing.md)

### What if I exceed my quota?

**Billing options:**

1. **Auto-upgrade** — Automatically upgrade org to higher tier at month-end
2. **Per-use billing** — Pay $0.10/token over quota (prepay)
3. **Reserved quota** — Pre-purchase token packages at 20% discount

Set preferences in organization settings > Billing.

---

## Getting Help

**Resources:**

- **Documentation:** [Full guide](../README.md)
- **Community:** [GitHub Discussions](https://github.com/vulnera-dev/vulnera/discussions)
- **Web:** [vulnera.studio](https://vulnera.studio)
- **Enterprise SLA:** Contact vulnera sales for support plans.

**For bugs:** [GitHub Issues](https://github.com/vulnera-dev/vulnera/issues)

---

## Quick Links

- [Getting Started](../getting-started/README.md)
- [Dashboard Guide](../user-guide/dashboard/guide.md)
- [Organization Management](../user-guide/dashboard/organization-management.md)
- [Team Collaboration](../user-guide/dashboard/team-collaboration.md)
- [CLI Guide](../CLI_GUIDE.md)
- [API Reference](./api-spec.md)
- [Quota & Pricing](../user-guide/quota-pricing.md)
- [LLM Features](../user-guide/llm-features.md)
