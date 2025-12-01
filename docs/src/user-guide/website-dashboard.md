# Vulnera Dashboard Guide

> Master the web-based vulnerability management platform at **[vulnera.studio](https://vulnera.studio)**

## Overview

The Vulnera Dashboard is a full-featured web application for managing vulnerability scans, organizing teams, tracking analytics, and integrating with CI/CD pipelines. Whether you're a solo developer or managing an enterprise security program, the dashboard provides intuitive controls and real-time insights.

**Access:** [https://vulnera.studio](https://vulnera.studio)

---

## Getting Started with the Dashboard

### Creating Your Account

1. Navigate to **[vulnera.studio](https://vulnera.studio)**
2. Click **Sign Up**
3. Enter your email and create a secure password
4. Verify your email address
5. You're ready to go!

### First Login Walkthrough

After logging in, you'll see:

- **Dashboard Home** — Your personal vulnerability overview
- **Recent Scans** — Latest analysis jobs and their results
- **Quick Stats** — Monthly quota usage and key metrics
- **Navigation Sidebar** — Access to all features

---

## Key Dashboard Features

### 🏠 Personal Dashboard

View your scan activity at a glance:

- **Total Vulnerabilities Found** — Critical, high, medium, low breakdown
- **Recent Scans** — Latest 10 jobs with status and timestamps
- **Monthly Quota Usage** — Tokens consumed vs. your plan limit
- **Quick Actions** — Start a new scan, generate API key, view documentation

**Path:** `Dashboard` (default landing page after login)

---

### 🔐 API Key Management

Generate and manage API keys for CLI and programmatic access.

#### Generate a New API Key

1. Click **Settings** → **API Keys**
2. Click **Generate New Key**
3. Choose a name (e.g., "CI/CD Pipeline", "Local Dev Machine")
4. Select expiration (30/90/365 days or never)
5. Click **Generate**
6. **Copy immediately** — you won't see it again!

#### Use the API Key

```bash
# CLI authentication
vulnera auth login --api-key YOUR_API_KEY

# Or set as environment variable
export VULNERA_API_KEY=YOUR_API_KEY

# HTTP requests
curl https://api.vulnera.studio/api/v1/health \
  -H "Authorization: Bearer YOUR_API_KEY"
```

#### Manage Existing Keys

In **Settings → API Keys**, you can:

- ✅ View key age and last used timestamp
- ✅ Rotate keys (invalidate old, generate new)
- ✅ Set custom expiration dates
- ✅ Revoke keys immediately
- ✅ View key usage statistics

**Security Best Practice:** Rotate API keys every 90 days. Use environment-specific keys (separate key for CI/CD, local development, staging).

---

### 👥 Organization Management

Scale security across teams with shared quotas and role-based access.

#### Create an Organization

1. Click **Organizations** (top navigation)
2. Click **Create New Organization**
3. Enter organization name and optional description
4. Choose plan tier (Free, Professional, Enterprise)
5. Click **Create**

You're now the **Organization Owner**.

#### Organization Settings

**Path:** `Organizations → [Your Org] → Settings`

Manage:

- **Organization Name & Description**
- **Shared Daily Quota** — Pool resources across team members
- **Member Management** — Add/remove users, assign roles
- **Billing & Subscription** — Payment method, invoices, plan upgrades
- **Integrations** — Connect Slack, GitHub, GitLab, Azure DevOps
- **Webhook Configuration** — Custom notifications and automations

---

### 👤 Team Member Management

#### Invite Team Members

1. Go to **Organizations → [Your Org] → Members**
2. Click **Invite Member**
3. Enter email address and select role:
   - **Owner** — Full access, billing control, org deletion
   - **Admin** — Member management, integration setup, analytics
   - **Developer** — Run scans, view results, manage personal keys
   - **Viewer** — Read-only access to org dashboard and results

4. Click **Send Invite**

The invited user will receive an email. Once they accept, they're part of the team and share the organization quota.

#### Manage Member Roles

1. Go to **Members**
2. Click on a member
3. Change role or click **Remove** to revoke access

---

### 📊 Organization Analytics & Quotas

Track usage across your team in real-time.

#### Quota Dashboard

**Path:** `Organizations → [Your Org] → Analytics → Quota`

View:

- **Daily Quota Remaining** — Tokens available today
- **Monthly Usage Trend** — Graph showing consumption over 30 days
- **Cost Breakdown** — Token usage by module (Deps, SAST, Secrets, API)
- **Member Contribution** — Quota used per team member
- **Quota Alerts** — Warnings at 75%, 90%, 100% consumption

#### Scan History & Reports

**Path:** `Organizations → [Your Org] → Scans`

Access all scans run by organization members:

- Filter by date range, status, module type
- View detailed results (findings, severity distribution)
- Export reports (CSV, JSON, SARIF format)
- Generate compliance reports (if Enterprise plan)

#### Team Performance Metrics

**Path:** `Organizations → [Your Org] → Analytics → Performance`

See:

- **Scans Run This Month** — Total count
- **Vulnerabilities Found** — By severity
- **Mean Time to Resolution** — How fast team fixes issues
- **Module Usage Distribution** — Which analysis modules are most used
- **Top Finding Types** — Most common vulnerabilities discovered

---

### 🔗 CI/CD Integrations

Connect Vulnera to your development workflow.

#### GitHub Integration

1. Go to **Organizations → [Your Org] → Integrations**
2. Click **GitHub**
3. Authorize Vulnera to access your GitHub account
4. Select repositories to enable scanning
5. Configure webhook events (push, PR, scheduled)

Once enabled:

- Automatic scans trigger on PRs and pushes
- Results appear as GitHub checks/status
- Comments on PRs with findings and fixes

#### GitLab Integration

Similar workflow:

1. **Integrations → GitLab**
2. Generate a GitLab personal access token
3. Paste into Vulnera configuration
4. Enable repositories and webhook triggers

#### Azure DevOps

1. **Integrations → Azure DevOps**
2. Configure organization URL and PAT (Personal Access Token)
3. Select project and pipelines
4. Results sync to Azure Pipelines

#### Slack Notifications

1. **Integrations → Slack**
2. Click **Add to Slack** (OAuth flow)
3. Select channel for vulnerability alerts
4. Configure notification rules:
   - Notify on critical findings only
   - Notify on all findings
   - Daily digest
   - Weekly summary

---

### ⚙️ Settings & Preferences

#### Account Settings

**Path:** `Settings → Account`

- Change email address
- Update password
- Enable two-factor authentication (2FA)
- View login history and active sessions
- Manage connected devices

#### Notification Preferences

**Path:** `Settings → Notifications`

Control where and when you receive alerts:

- ✅ Email notifications (on/off)
- ✅ Slack integration (channel, frequency)
- ✅ Webhook URLs (custom integrations)
- ✅ Alert severity threshold (critical only, or all)

#### Privacy & Data

**Path:** `Settings → Privacy`

- View data retention policies
- Download your personal data
- Delete account (irreversible)

---

## Common Dashboard Workflows

### Workflow 1: Set Up Your First Organization (Team Lead)

```
1. Sign up at https://vulnera.studio
2. Go to Organizations → Create New Organization
3. Name it "My Company Security"
4. Go to Members → Invite Team
5. Add developers with "Developer" role
6. Go to Integrations → Connect Slack
7. All team members now share quota and get notifications
```

### Workflow 2: Get API Key for CI/CD Pipeline

```
1. Log in to https://vulnera.studio
2. Settings → API Keys → Generate New Key
3. Name it "GitHub Actions CI"
4. Copy the key
5. Add to GitHub repo → Settings → Secrets and variables → Actions
6. Use in workflow:
   - Set env variable: VULNERA_API_KEY
   - Run: vulnera auth login --api-key $VULNERA_API_KEY
   - Run: vulnera analyze .
```

### Workflow 3: Track Team Vulnerability Progress

```
1. Go to Organizations → [Your Org]
2. Navigate to Analytics → Performance
3. Review monthly statistics
4. Click on "Most Common Findings" to identify patterns
5. Share report with team leadership
6. Adjust security policies based on trends
```

### Workflow 4: Configure GitHub PR Checks

```
1. Dashboard → Integrations → GitHub
2. Authorize and select repositories
3. Enable "Check on Pull Request"
4. Push to any branch → Vulnera auto-scans
5. Results appear in GitHub PR checks
6. Developers see findings before merge
```

---

## Dashboard FAQs

**Q: How do I reset my password?**  
A: Click **Forgot Password** on the login page. You'll receive a reset link via email (valid for 24 hours).

**Q: Can I have multiple API keys?**  
A: Yes! Generate separate keys for each use case (local dev, CI/CD, external integrations). Each can have different expiration dates.

**Q: What happens when I exceed my quota?**  
A: New scans will be queued until quota resets (usually daily or monthly depending on your plan). You'll receive warnings at 75% and 90% usage.

**Q: How do I change my organization's plan?**  
A: Go to **Organizations → [Your Org] → Settings → Billing**. Click **Upgrade Plan** or **Downgrade Plan** as needed. Changes take effect immediately.

**Q: Can I transfer my organization to someone else?**  
A: Yes. Go to **Settings → Transfer Organization Ownership**. The new owner must accept the transfer. You'll remain as an admin.

**Q: How are team quotas calculated?**  
A: **Organization Quota = Member Count × Per-User Quota**. For example, 5 developers on a "Professional" plan = 200 daily tokens (40 tokens per developer × 5).

---

## Dashboard Security

### API Key Best Practices

- ✅ Never commit API keys to version control
- ✅ Rotate keys every 90 days
- ✅ Use different keys for different environments
- ✅ Revoke keys immediately if compromised
- ✅ Monitor "Last Used" timestamp for unused keys

### Organization Access Control

- ✅ Assign minimal required roles (principle of least privilege)
- ✅ Remove members who leave the team
- ✅ Enable 2FA on your personal account
- ✅ Review login history regularly
- ✅ Use OAuth integrations (GitHub, GitLab) instead of storing credentials

### Data Privacy

Vulnera is AGPL v3 open source:

- ✅ Your code is scanned locally when using CLI
- ✅ Dashboard data is encrypted in transit (HTTPS)
- ✅ Database is encrypted at rest
- ✅ We don't share data with third parties
- ✅ See [Privacy Policy](https://vulnera.studio/privacy) for details

---

## Troubleshooting

### I can't log in

- Check your email and password
- Try **Forgot Password** to reset
- Check for typos in email address
- Try incognito/private browser mode (clears cookies)
- Ensure JavaScript is enabled in your browser

### My API key isn't working

- Verify the full key was copied (no truncation)
- Check key hasn't expired (view expiration in Settings)
- Ensure key is for the correct organization
- Try rotating the key (revoke old, generate new)

### Quota exceeded unexpectedly

- Review **Analytics → Quota** to see breakdown by module
- Check if integrations (GitHub, GitLab) are running auto-scans
- Review team member scan activity
- Consider upgrading plan

### Integrations not triggering

- Verify webhook is enabled in integrations settings
- Check logs in CI/CD platform (GitHub Actions, GitLab CI, etc.)
- Ensure API key has correct permissions
- Try re-authorizing the integration

---

## Next Steps

- **[CLI Reference](../guides/cli-reference.md)** — Use CLI alongside dashboard
- **[API Reference](../reference/api-reference.md)** — Programmatic access to dashboard data
- **[Configuration Guide](../guides/configuration.md)** — Customize dashboard behavior
- **[Support](https://vulnera.studio/support)** — Contact support team

---

**Ready to get started?** Visit **[vulnera.studio](https://vulnera.studio)** now!
