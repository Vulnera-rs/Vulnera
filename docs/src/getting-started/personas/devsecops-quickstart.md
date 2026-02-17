# DevSecOps Quick Start (10 Minutes)

**For:** Security team leads and DevSecOps engineers managing organization-wide vulnerability scanning.

**Goal:** Set up team-based security scanning with shared quotas, analytics, and multi-project orchestration.

## Step 1: Create Organization

```bash
vulnera organizations create \
  --name "Engineering Security Team" \
  --description "Security scanning for all projects"
```

**Output:**

```
Organization created: org-abc123
Shared daily quota: 48 tokens (vs 40 for single user)
Admin URL: https://vulnera.studio/orgs/org-abc123/settings
```

## Step 2: Invite Team Members

```bash
# Invite security engineer
vulnera organizations add-member \
  --org org-abc123 \
  --email alice@company.com \
  --role admin

# Invite developer with view-only access
vulnera organizations add-member \
  --org org-abc123 \
  --email bob@company.com \
  --role viewer
```

### Roles

| Role        | Capabilities                                          |
| ----------- | ----------------------------------------------------- |
| **Owner**   | Create/delete org, manage members, billing, analytics |
| **Admin**   | Run scans, manage members, view analytics             |
| **Analyst** | Run scans, view results, comment on findings          |
| **Viewer**  | View-only access to results and analytics             |

## Step 3: Setup Continuous Scanning

### GitHub Organization Integration

```bash
# Store Vulnera API key as GitHub secret
# Go to Settings → Secrets and variables → Actions → New repository secret
# Name: VULNERA_API_KEY
# Value: (get from vulnera dashboard)
```

Create `.github/workflows/vulnera-scan.yml`:

```yaml
name: Vulnera Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 2 * * *" # Daily at 2 AM

jobs:
  vulnera:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Download Vulnera CLI
        run: |
          curl -L https://github.com/Vulnera-rs/Vulnera/releases/latest/download/vulnera-linux-x86_64 -o vulnera
          chmod +x vulnera

      - name: Run Full Security Analysis
        env:
          VULNERA_API_KEY: ${{ secrets.VULNERA_API_KEY }}
        run: |
          ./vulnera analyze . \
            --all-modules \
            --format json \
            --output vulnera-report.json

      - name: Report Results
        run: |
          ./vulnera report vulnera-report.json \
            --format github \
            --post-to-pr
```

## Step 4: View Organization Analytics

```bash
# Get team usage summary
vulnera organizations analytics dashboard --org org-abc123

# Get historical usage (last 3 months)
vulnera organizations analytics usage --org org-abc123 --months 3
```

**Sample output:**

```
Organization: Engineering Security Team
Period: December 2024

Daily Usage Trend:
  Dec 1:  ▄ 28 tokens (70%)
  Dec 2:  █ 47 tokens (98%) ← Peak
  Dec 3:  ▂ 12 tokens (30%)
  Avg:    ▃ 31 tokens (65%)

Per-Member Breakdown:
  Alice (alice@company.com): 156 tokens (52%)
  Bob (bob@company.com):     89 tokens (30%)
  Charlie (charlie@...):      54 tokens (18%)

Recommendations:
  - High usage on Dec 2. Consider optimizing batch operations.
  - LLM features used 45% of quota. See quota-pricing.md for cost details.
```

## Step 5: Create Shared Scanning Policies

### Severity Filters

```bash
# Define which issues to alert on
vulnera organizations policy create \
  --org org-abc123 \
  --name "Production Policy" \
  --min-severity critical,high \
  --affected-projects "*-prod"
```

### Exemptions

```bash
# Exclude known false positives
vulnera organizations policy exempt \
  --org org-abc123 \
  --finding-id SAST-SQL-001 \
  --reason "Legacy code, deprecated but functional" \
  --expires 2025-06-30
```

## Step 6: Setup Notifications

### Slack Integration

```bash
# Get Vulnera webhook URL from dashboard
vulnera organizations integrations connect slack \
  --org org-abc123 \
  --webhook-url https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### Notification Rules

```bash
# Alert on any critical finding
vulnera organizations notifications create \
  --org org-abc123 \
  --name "Critical Alerts" \
  --condition "severity == critical" \
  --channel slack

# Weekly summary
vulnera organizations notifications create \
  --org org-abc123 \
  --name "Weekly Summary" \
  --condition "summary" \
  --frequency weekly \
  --channel email
```

## Step 7: Scan Multiple Repositories

```bash
# Create scanning profile
vulnera organizations profile create \
  --org org-abc123 \
  --name "Standard Scan" \
  --modules "sast,secrets,deps,api" \
  --severity-threshold "high"

# Scan repositories
vulnera scan-repos \
  --org org-abc123 \
  --profile "Standard Scan" \
  --repos "my-org/repo-1,my-org/repo-2,my-org/repo-3"
```

## Step 8: Monitor and Report

### Dashboard View

```bash
# Open web dashboard
open https://vulnera.studio/orgs/org-abc123/dashboard
```

Shows:

- Real-time scan status
- Vulnerability trends
- Team member activity
- Quota usage
- Historical comparisons

### Export Reports

```bash
# Export findings to compliance format
vulnera organizations report export \
  --org org-abc123 \
  --format sarif \
  --period "last-month" \
  --output compliance-report.sarif

# Email to stakeholders
vulnera organizations report email \
  --org org-abc123 \
  --recipients security-team@company.com \
  --include-recommendations
```

## Quota Management for Teams

### Shared Quota Model

```
Organization Daily Quota: 48 tokens

Typical usage:
  Monday (high activity):    45 tokens
  Tuesday (low activity):     8 tokens
  Wednesday-Friday (average): 20 tokens each

Weekly pattern: Usually peaks Monday, dips on weekends
Recommendation: Schedule large scans Monday morning
```

### Cost Optimization

```bash
# Only scan high/critical severity to save quota
vulnera analyze . --severity high

# Batch LLM explanations (costs 6 tokens total vs 6 per finding)
vulnera analyze . --batch-llm-enrich

# Use organizational discount (48 tokens vs 40 individual)
# 20% savings per team member
```

## Integration Examples

### Jira Integration

Auto-create Jira tickets for high-severity findings:

```bash
vulnera organizations integrations connect jira \
  --org org-abc123 \
  --jira-url https://company.atlassian.net \
  --api-token YOUR_TOKEN \
  --auto-create-issues \
  --severity-threshold high
```

### Datadog/New Relic APM

Send security metrics to monitoring:

```bash
vulnera organizations integrations connect datadog \
  --org org-abc123 \
  --api-key YOUR_DATADOG_KEY \
  --send-metrics \
  --metric-tags "team:security,env:prod"
```

## Common Workflows

### Scan on Every Push

```bash
# GitHub Actions workflow (see Step 3)
# Results appear as GitHub check
# PR comments show new findings
# Auto-block PRs with critical issues (optional)
```

### Scan on Merge Request

```bash
# GitLab CI pipeline
# Results in MR discussion
# Approve/block based on findings
```

### Weekly Security Reports

```bash
# Cron job to generate reports
0 9 * * 1 vulnera report generate --org org-abc123 --email security@company.com
```

## Monitoring & Alerting

```bash
# Setup alert for quota approaching limit
vulnera organizations alerts create \
  --org org-abc123 \
  --alert "quota_threshold" \
  --threshold 90 \
  --action "email-admin"

# Alert on policy violations
vulnera organizations alerts create \
  --org org-abc123 \
  --alert "policy_violation" \
  --action "slack-notification"
```

## Next Steps

1. **Understand quota costs** → [Quota & Pricing](../../user-guide/quota-pricing.md)
2. **Create custom analysis policies** → [Policy Configuration](../../user-guide/configuration.md)

---

**Need help?** Contact support or join our security community [Discord](https://discord.gg/vulnera).
