# Vulnera Dashboard Guide

Welcome to the **Vulnera Web Dashboard** — your central hub for vulnerability analysis, team collaboration, and security insights. This guide covers all dashboard features available at [vulnera.studio](https://vulnera.studio).

## Getting Started with the Dashboard

### First Login

1. Navigate to [vulnera.studio](https://vulnera.studio)
2. Click **Sign Up** or **Sign In**
3. Authenticate with your email and password (or OAuth provider if available)
4. Verify your email address via the confirmation link

### Dashboard Welcome Tour

After your first login, you'll see:

- **Personal Dashboard** — Your recent scans, quota usage, and quick actions
- **Navigation Sidebar** — Access to all features
- **Profile Menu** — Account settings, preferences, logout

## Core Dashboard Features

### 1. Personal Vulnerability Dashboard

Your personal hub displays:

- **Recent Scans** — Latest vulnerability analysis results
- **Quick Stats** — Total findings, critical/high severity issues, trend indicators
- **Action Items** — Unreviewed findings requiring attention
- **Quota Usage** — Current monthly analysis tokens consumed vs. allocated
- **Recent Projects** — Quick links to frequently scanned repositories

**Tips:**
- Use filters to drill down by severity, module type, or status
- Star important findings for quick reference
- Export scan results as PDF or JSON

### 2. Organization Management

#### Creating an Organization

Organizations enable team collaboration with shared quotas and centralized reporting.

**To create an organization:**

1. Click **+ New Organization** in the sidebar (or from the dashboard)
2. Enter organization name, description, and optional logo
3. Select a plan tier (Free, Pro, Enterprise)
4. Confirm — you're now the organization admin

**Organization settings include:**

- **General** — Name, description, logo, contact email
- **Members** — Add/remove team members, assign roles
- **Billing** — Subscription, payment method, invoices
- **API Keys** — Generate keys for CLI and API access
- **Integrations** — Connect Slack, GitHub, GitLab, Azure DevOps
- **Security** — SAML/SSO setup (Enterprise), audit logs
- **Webhooks** — Configure event notifications

#### Organization Roles & Permissions

| Role | Permissions |
|------|-------------|
| **Owner** | Full access, billing, member management, delete org |
| **Admin** | Members, settings, API keys, integrations, but not billing |
| **Member** | View scans, create jobs, use shared quota |
| **Viewer** | Read-only access to scans and findings |

### 3. Team Member Management

#### Inviting Team Members

1. Go to **Settings → Members**
2. Click **Invite Member**
3. Enter email address and select role (Admin, Member, Viewer)
4. Send invitation — member receives email with join link
5. Member accepts and gains access to organization

#### Managing Member Access

- **Change Role** — Click member, update role, save
- **Remove Member** — Click ⋯ → Remove (they lose access immediately)
- **Resend Invitation** — If member hasn't joined within 7 days
- **Activity Log** — View member actions and scan history

**Best Practices:**
- Assign **Viewer** role to non-technical stakeholders
- Use **Member** for developers and security team
- Restrict **Admin** role to team leads
- Audit member list quarterly

### 4. API Key Management

API keys enable CLI authentication and programmatic API access.

#### Generating an API Key

1. Go to **Settings → API Keys**
2. Click **Generate New Key**
3. Name the key (e.g., "GitHub Actions CI", "Local Dev")
4. Set expiration (Never, 30 days, 90 days, 1 year)
5. Click **Create** and copy the key immediately (not shown again)
6. Store securely in your credential manager or CI/CD secrets

#### Using API Keys

**In CLI:**
```bash
vulnera auth login --api-key YOUR_API_KEY
```

**In CI/CD (GitHub Actions):**
```yaml
- name: Scan with Vulnera
  env:
    VULNERA_API_KEY: ${{ secrets.VULNERA_API_KEY }}
  run: vulnera analyze . --all-modules
```

**In programmatic API calls:**
```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  https://api.vulnera.studio/api/v1/analyze/job
```

#### Key Security

- ⚠️ **Never commit keys** to version control
- ⏱️ **Rotate keys regularly** (recommended: every 90 days)
- 🗑️ **Revoke unused keys** immediately from the dashboard
- 📋 **Audit key usage** in the activity log
- 🔒 **Store in secure vaults** (1Password, HashiCorp Vault, GitHub Secrets)

### 5. Quota Management & Analytics

#### Understanding Quotas

Vulnera uses a **token-based quota system**:

- **Personal Account** — 40 tokens/month (default)
- **Organization (Free Plan)** — 48 tokens/month shared
- **Organization (Pro)** — 1000 tokens/month
- **Organization (Enterprise)** — Custom allocation

**Tokens consumed by analysis:**
- Dependency scan: 1 token (base) + 0.5 per package manager
- SAST scan: 1 token per file (up to 10 files)
- Secret scan: 0.5 tokens
- API security scan: 0.5 tokens

#### Viewing Usage Analytics

**Personal Dashboard:**
```
Settings → Usage → Personal Monthly Stats
```

Shows:
- Tokens consumed this month
- Usage by module type (pie chart)
- Scans completed / failed
- Top analyzed projects

**Organization Dashboard (Admin only):**
```
Settings → Analytics → Organization Dashboard
```

Shows:
- Team quota consumption (shared bar)
- Per-member breakdown
- Module usage trends
- Cost projection (if on paid plan)

**Export Usage Reports:**

Click **Export** to download:
- CSV for spreadsheets
- JSON for integrations
- PDF for stakeholder reports

#### Quota Alerts

Configure notifications for quota milestones:

1. Go to **Settings → Notifications**
2. Enable **Quota Alerts** at 50%, 75%, 90%, 100%
3. Choose notification method (Email, Slack, In-app)

### 6. Scan History & Results

#### Viewing All Scans

**Personal:**
```
Dashboard → Recent Scans (or Settings → Scan History)
```

**Organization:**
```
Organization → Scans → All Scans
```

#### Scan Details Page

Each scan shows:

- **Overview** — Project source, date, duration, status
- **Findings** — Vulnerabilities grouped by severity
- **Module Results** — Dependency, SAST, Secrets, API analysis
- **AI Insights** — Explanations and recommended fixes (if LLM enabled)
- **Timeline** — Job execution logs
- **Export** — Download as JSON, SARIF, PDF

#### Filtering & Searching

Filter by:
- **Severity** — Critical, High, Medium, Low, Info
- **Status** — Open, Resolved, Ignored, False Positive
- **Module** — Dependencies, SAST, Secrets, API
- **Date Range** — Last 7 days, 30 days, custom
- **Source** — Repository, S3 bucket, local upload

### 7. Integrations & Webhooks

#### Slack Integration

Connect your organization's Slack workspace for notifications:

1. Go to **Settings → Integrations → Slack**
2. Click **Connect Slack Workspace**
3. Authorize Vulnera app (one-time)
4. Select channel for notifications
5. Configure notification triggers:
   - New critical/high findings
   - Daily digest
   - Quota threshold alerts

**Example Slack message:**
```
🚨 Critical Vulnerability Found
Repo: acme/backend
Finding: SQL Injection in /api/users.py
CVSS: 9.2
→ View Details [Link]
```

#### GitHub Integration

Link GitHub repositories for automatic scanning:

1. Go to **Settings → Integrations → GitHub**
2. Click **Connect GitHub**
3. Authorize Vulnera app (select repos to access)
4. Enable automatic scanning:
   - On push to main/develop
   - On pull requests
   - Scheduled daily scan

**GitHub Checks Integration:**
- Vulnera comments on PRs with findings
- Blocks merge if critical issues found (optional)
- Shows SARIF upload for code scanning

#### GitLab CI Integration

Configure in your `.gitlab-ci.yml`:

```yaml
vulnera-scan:
  image: vulnera:latest
  script:
    - vulnera auth login --api-key $VULNERA_API_KEY
    - vulnera analyze . --all-modules --format sarif > vulnera.sarif
  artifacts:
    reports:
      sast: vulnera.sarif
```

#### Webhook Management

Custom webhooks for external systems:

1. Go to **Settings → Webhooks**
2. Click **Add Webhook**
3. Enter webhook URL
4. Select events:
   - `scan.completed` — On analysis finish
   - `finding.created` — New vulnerability detected
   - `finding.resolved` — Manually marked resolved
5. Test webhook, enable, save

**Webhook payload example:**
```json
{
  "event": "scan.completed",
  "scan_id": "scan-12345",
  "project": "acme/backend",
  "findings_count": 5,
  "critical_count": 2,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### 8. Reporting & Export

#### Generate Reports

1. Go to **Reports** (sidebar) or **Organization → Reports**
2. Click **New Report**
3. Select:
   - Report type (Executive Summary, Detailed, Compliance)
   - Date range
   - Modules to include
   - Recipients (email, download)
4. Click **Generate** → PDF/HTML download

#### Report Types

- **Executive Summary** — High-level metrics for stakeholders
- **Detailed Technical** — Full findings, CVSS scores, remediation
- **Compliance** — GDPR/SOC2/ISO27001 aligned format
- **Scheduled Reports** — Set recurring (weekly, monthly) auto-generation

#### SARIF Export

Export findings in SARIF format for CI/CD integrations:

1. Open scan → Click **Export**
2. Select **SARIF** format
3. Use in GitHub/GitLab code scanning dashboards

## Security & Best Practices

### Account Security

- ✅ **Enable 2FA** — Go to Settings → Security → Two-Factor Authentication
- ✅ **Review Sessions** — Settings → Active Sessions, log out unused devices
- ✅ **Audit Log** — Organization → Settings → Audit Log (admin only)
- ✅ **Regular Backups** — Export API keys, integrations config periodically

### Organization Security

- ✅ **Principle of Least Privilege** — Assign minimal required roles
- ✅ **Key Rotation** — Rotate API keys every 90 days
- ✅ **SSO/SAML** — Enable for Enterprise (single sign-on)
- ✅ **Member Review** — Quarterly audit of team access
- ✅ **Webhook Verification** — Validate webhook signatures server-side

### Compliance & Audit

Track security activities:
- **Audit Log** → All member actions, API calls, configuration changes
- **Access Reports** → Who accessed what and when
- **Data Export** → Download all org data for compliance
- **Retention Policy** → Configure how long to store scan results

## Troubleshooting

### Common Issues

**Q: API key not working in CLI**
```bash
A: 1. Verify key hasn't expired (Settings → API Keys)
   2. Check key is correct: vulnera auth status
   3. Regenerate if needed: vulnera auth login --api-key NEW_KEY
```

**Q: Quota exhausted mid-month**
```bash
A: 1. Upgrade plan (Settings → Billing)
   2. Review usage (Analytics → Dashboard)
   3. Optimize scans (exclude non-critical paths)
   4. Contact support for emergency tokens (Enterprise)
```

**Q: Team member can't see organization scans**
```bash
A: 1. Verify member role is not "Viewer" (Settings → Members)
   2. Check member email verified
   3. Have member log out and log back in
   4. Clear browser cache
```

**Q: Slack integration not sending notifications**
```bash
A: 1. Verify channel name correct (Settings → Integrations → Slack)
   2. Check Slack workspace hasn't revoked app permissions
   3. Test webhook (Settings → Webhooks → Test)
   4. Review notification triggers are enabled
```

**Q: GitHub PR checks not appearing**
```bash
A: 1. Verify GitHub app installed on repo (Settings → Integrations → GitHub)
   2. Check branch protection doesn't block Vulnera status
   3. Enable "Auto-scan PRs" (Settings → Integrations → GitHub)
   4. Verify API key has org access (not personal only)
```

## Advanced Features

### SSO & SAML (Enterprise)

Configure single sign-on for enterprise organizations:

1. **Settings → Security → SSO**
2. Select provider (Okta, Azure AD, Google Workspace)
3. Download metadata or enter IdP details
4. Test login → Users auto-provisioned on first SSO login

### Custom Domains (Enterprise)

Host dashboard on your subdomain:

1. **Settings → Custom Domain → Configure**
2. Add `your-domain.vulnera.studio` CNAME record
3. Request SSL certificate issuance
4. Dashboard available at `https://your-domain.vulnera.studio`

### Role-Based Access Control (RBAC)

Create custom roles with granular permissions (Enterprise):

1. **Settings → Roles → New Role**
2. Define permissions:
   - `scan:create` — Create new scans
   - `scan:view` — View scan results
   - `finding:resolve` — Mark findings resolved
   - `settings:manage` — Modify org settings
3. Assign users to custom role

## Next Steps

- **Connect Your First Repository** — Set up GitHub integration for automated scans
- **Invite Your Team** — Add members and start collaborative vulnerability tracking
- **Generate API Key** — Integrate with your CI/CD pipeline
- **Configure Integrations** — Set up Slack, webhooks for automated notifications
- **Explore Reports** — Generate your first compliance or executive summary report

For API-level access, see the [API Reference](../api-reference.md).
For CLI-based workflows, see [CLI Reference](../../getting-started/personas/developer-quickstart.md).

---

**Need help?** Email [support@vulnera.studio](mailto:support@vulnera.studio) or visit our [FAQ](../reference/faq.md).
```

Now let me create the organization management guide:
