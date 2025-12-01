# Organization Management Guide

Organizations in Vulnera enable team collaboration with shared quotas, centralized reporting, and role-based access control. This guide covers everything you need to manage your organization effectively.

## Creating an Organization

### Step-by-Step Setup

1. **Navigate to Organization Creation**
   - Click **+ New Organization** in the sidebar
   - Or go to **Dashboard → Organizations → Create New**

2. **Fill in Organization Details**
   - **Organization Name** — Your company or team name (e.g., "Acme Security Team")
   - **Description** — Brief description of the organization's purpose
   - **Logo** — Optional: Upload organization logo (PNG, JPG, 512×512px recommended)
   - **Contact Email** — Primary contact for billing and notifications

3. **Select Plan Tier**
   - **Free** — 48 tokens/month, up to 5 members, basic integrations
   - **Pro** — 1000 tokens/month, unlimited members, advanced integrations
   - **Enterprise** — Custom tokens, SSO/SAML, custom domains, priority support

4. **Confirm Creation**
   - Review settings
   - Click **Create Organization**
   - You're automatically made Owner and Organization Admin

### Post-Creation Setup Checklist

- [ ] Upload organization logo
- [ ] Add organization description
- [ ] Set up billing (if on paid plan)
- [ ] Invite team members
- [ ] Generate API key
- [ ] Configure integrations
- [ ] Set notification preferences

## Organization Roles & Permissions

### Role Hierarchy

```
Owner
  ↓ (can delegate to)
Admin
  ↓ (can delegate to)
Member
Viewer (read-only)
```

### Detailed Permissions Matrix

| Permission | Owner | Admin | Member | Viewer |
|------------|-------|-------|--------|--------|
| **Scans** | | | | |
| Create scans | ✅ | ✅ | ✅ | ❌ |
| View scans | ✅ | ✅ | ✅ | ✅ |
| Delete scans | ✅ | ✅ | ❌ | ❌ |
| Export scan results | ✅ | ✅ | ✅ | ✅ |
| **Findings** | | | | |
| View findings | ✅ | ✅ | ✅ | ✅ |
| Resolve findings | ✅ | ✅ | ✅ | ❌ |
| Mark false positive | ✅ | ✅ | ✅ | ❌ |
| **Organization Settings** | | | | |
| View settings | ✅ | ✅ | ❌ | ❌ |
| Modify general info | ✅ | ✅ | ❌ | ❌ |
| Manage members | ✅ | ✅ | ❌ | ❌ |
| Manage API keys | ✅ | ✅ | ❌ | ❌ |
| **Billing & Subscriptions** | | | | |
| View billing | ✅ | ❌ | ❌ | ❌ |
| Manage billing | ✅ | ❌ | ❌ | ❌ |
| Upgrade plan | ✅ | ❌ | ❌ | ❌ |
| **Integrations** | | | | |
| View integrations | ✅ | ✅ | ❌ | ❌ |
| Configure integrations | ✅ | ✅ | ❌ | ❌ |
| Manage webhooks | ✅ | ✅ | ❌ | ❌ |
| **Audit & Compliance** | | | | |
| View audit logs | ✅ | ✅ | ❌ | ❌ |
| Export organization data | ✅ | ❌ | ❌ | ❌ |
| Delete organization | ✅ | ❌ | ❌ | ❌ |

### When to Use Each Role

- **Owner** — Organization founders, ultimate decision-makers, billing contact
  - Best for: 1-2 key decision-makers per organization
  - Caution: Rarely needed, keep minimal

- **Admin** — Team leads, security directors, technical leads
  - Best for: Day-to-day organization management
  - Responsibility: Member provisioning, integration setup

- **Member** — Developers, security engineers, DevOps engineers
  - Best for: Active security practitioners who scan code
  - Permissions: Run scans, view/resolve findings

- **Viewer** — Executives, managers, stakeholders (read-only)
  - Best for: Non-technical decision-makers who need visibility
  - Permissions: View scans, findings, reports (no modifications)

## Managing Team Members

### Inviting Members

**Method 1: Dashboard Invitation**

1. Go to **Settings → Members**
2. Click **Invite Member**
3. Enter email address(es) — comma-separated for bulk invite
4. Select role for each member:
   - Admin (for team leads)
   - Member (for developers)
   - Viewer (for stakeholders)
5. Click **Send Invitations**
6. Members receive email with join link (valid for 7 days)

**Method 2: Share Organization Link**

1. Go to **Settings → Members → Copy Share Link**
2. Share link with team (anyone with link can request access)
3. Requests appear in pending approval queue
4. Admin reviews and approves/denies

### Accepting an Invitation

Members receive email from `invite@vulnera.studio`:

1. Click **Join Organization** link
2. Sign in to Vulnera account (create if needed)
3. Click **Accept Invitation**
4. Redirect to organization dashboard
5. Immediately have access to shared quota and scans

### Member Status States

| Status | Description | Action |
|--------|-------------|--------|
| **Invited** | Email sent, awaiting acceptance | Can resend invite or cancel |
| **Active** | Member joined and has access | Can change role or remove |
| **Pending Approval** | Join request submitted (if approval required) | Admin can approve/deny |
| **Inactive** | Member inactive >30 days | Can reactivate or remove |
| **Removed** | Former member, no access | Can reinvite |

### Changing Member Roles

1. Go to **Settings → Members**
2. Find member in list
3. Click member row → **Edit**
4. Change role dropdown
5. Click **Save** — changes take effect immediately
6. Member receives notification of role change

### Removing Members

1. Go to **Settings → Members**
2. Click member → **Remove**
3. Confirm removal
4. Member loses all access immediately
5. Their scans remain in history (read-only for audit purposes)

**Note:** Removed members can be reinvited later.

### Viewing Member Activity

**Member Details Page:**

1. Go to **Settings → Members**
2. Click member name
3. View:
   - Email address, role, join date
   - Last active timestamp
   - Scans created by member
   - API keys generated by member
   - Activity timeline

**Organization Audit Log (Admin only):**

1. Go to **Settings → Audit Log**
2. Filter by member:
   - Action type (invited, removed, scan created, etc.)
   - Member email
   - Date range
3. Export as CSV for compliance

## Shared Quota Management

### Understanding Organization Quotas

When members scan within an organization, tokens are consumed from the **shared organization quota**, not individual quotas.

**Example:**
- Organization quota: 1000 tokens/month (Pro plan)
- Member A creates scan: uses 10 tokens from shared pool
- Member B creates scan: uses 15 tokens from shared pool
- Remaining: 975 tokens available to all members

### Quota Allocation Strategies

**Strategy 1: Fully Shared (Default)**
- All members share single quota pool
- Transparent: Anyone can see total usage
- Best for: Small, collaborative teams

**Strategy 2: Department Quotas (Enterprise)**
- Divide quota by team (e.g., 400 tokens/Backend team, 300/Frontend)
- Managed via API or contact sales
- Best for: Large organizations with multiple teams

**Strategy 3: Per-Member Budgets (Enterprise)**
- Set individual limits per member (e.g., 50 tokens/developer)
- Prevents single member from exhausting quota
- Best for: Organizations with varied usage patterns

### Monitoring Quota Usage

**Organization Dashboard:**

1. Go to **Organization → Analytics → Dashboard**
2. View:
   - Total tokens used this month
   - Tokens remaining
   - Usage trend graph (last 6 months)
   - Per-member breakdown table

**Usage Breakdown:**

```
Total: 850 / 1000 tokens used (85%)

By Module:
├── Dependency Analysis: 450 tokens (53%)
├── SAST: 300 tokens (35%)
├── Secrets: 75 tokens (9%)
└── API Security: 25 tokens (3%)

By Member:
├── alice@acme.com: 400 tokens (47%)
├── bob@acme.com: 300 tokens (35%)
└── charlie@acme.com: 150 tokens (18%)
```

### Setting Quota Alerts

Configure notifications when quota usage reaches thresholds:

1. Go to **Settings → Notifications → Quota Alerts**
2. Enable alerts at:
   - 50% usage
   - 75% usage
   - 90% usage
   - 100% (exhausted)
3. Choose notification method:
   - Email (sent to organization contact)
   - Slack (if integrated)
   - In-app notification
4. Save

### Upgrading Quota

**Option 1: Upgrade Plan**
- Free → Pro: +952 tokens (1000 total)
- Pro → Enterprise: Custom allocation
- Go to **Settings → Billing → Upgrade Plan**

**Option 2: Temporary Quota Boost (Enterprise)**
- Purchase additional tokens mid-month
- Contact [sales@vulnera.studio](mailto:sales@vulnera.studio)
- Available for 30 days, expires unused

## Organization Settings

### General Settings

**Organization Profile:**
- Organization name
- Description
- Logo (upload new or remove)
- Contact email
- Website URL (optional)

**Edit:** Settings → General → Edit Profile

### Security Settings

**Two-Factor Authentication (for members):**
- Require 2FA for all members (optional, Admin sets)
- Go to **Settings → Security → Require 2FA**

**Session Management:**
- Session timeout: 30 minutes (default)
- Custom timeout available (Enterprise)
- Go to **Settings → Security → Session Policy**

**IP Whitelisting (Enterprise):**
- Restrict access to specific IP ranges
- Useful for VPN-only access
- Go to **Settings → Security → IP Whitelist**

**SSO/SAML (Enterprise):**
- Single sign-on via Okta, Azure AD, Google Workspace
- Auto-provisioning of team members
- Go to **Settings → Security → SSO Configuration**

### Data & Privacy

**Data Retention Policy:**
- Set how long scan results are kept (30 days to 2 years)
- Default: 1 year
- Go to **Settings → Data → Retention Policy**

**Data Export:**
- Export all organization data (GDPR compliance)
- Includes scans, findings, member list, audit logs
- Go to **Settings → Data → Export Organization Data**

**Data Deletion:**
- Permanently delete organization and all data (irreversible)
- Requires Owner password confirmation
- Go to **Settings → Data → Delete Organization**

### Billing & Subscriptions

**View Subscription:**
1. Go to **Settings → Billing → Subscription**
2. View:
   - Current plan (Free/Pro/Enterprise)
   - Billing cycle (monthly/annual)
   - Next billing date
   - Annual savings (if on annual plan)

**Update Payment Method:**
1. Go to **Settings → Billing → Payment Method**
2. Click **Edit**
3. Update card details or select different card
4. Click **Save**

**Invoices & History:**
1. Go to **Settings → Billing → Invoices**
2. View all past invoices (searchable)
3. Download as PDF
4. Filter by date range

**Upgrade/Downgrade Plan:**
1. Go to **Settings → Billing → Change Plan**
2. Select new plan
3. Review pricing impact
4. Click **Confirm Upgrade/Downgrade**
5. Changes take effect immediately (or at next cycle)

## Integrations & Webhooks

### Slack Integration

**Setup:**
1. Go to **Settings → Integrations → Slack**
2. Click **Connect Slack Workspace**
3. Select Vulnera workspace and authorize
4. Select notification channel
5. Enable notification types:
   - Critical findings
   - Daily summary
   - Weekly report
   - Quota alerts

**Slack Notifications Example:**
```
🚨 Critical Vulnerability Detected
Repository: acme/backend
Finding: SQL Injection in POST /api/users
Severity: Critical (CVSS 9.2)
Module: SAST
👉 View Details
```

**Disable Slack:**
- Go to **Settings → Integrations → Slack**
- Click **Disconnect**

### GitHub Integration

**Setup:**
1. Go to **Settings → Integrations → GitHub**
2. Click **Connect GitHub**
3. Authorize Vulnera GitHub App
4. Select repositories to scan
5. Configure auto-scan triggers:
   - On push to main/develop
   - On all pull requests
   - Scheduled daily

**GitHub Features:**
- PR comments with findings
- Status checks (block merge if critical)
- SARIF upload to code scanning
- Auto-create issues for high-severity findings

**Manage Repositories:**
- Add new repos: Settings → Integrations → GitHub → **Add Repository**
- Remove repos: Settings → Integrations → GitHub → **Remove** (⋯)

### GitLab Integration

**Setup (via CI/CD):**

In `.gitlab-ci.yml`:
```yaml
vulnera-scan:
  image: vulnera:latest
  script:
    - vulnera auth login --api-key $VULNERA_API_KEY
    - vulnera analyze . --all-modules --format sarif > vulnera.sarif
  artifacts:
    reports:
      sast: vulnera.sarif
    paths:
      - vulnera.sarif
  allow_failure: true
```

### Webhooks

**Create Webhook:**
1. Go to **Settings → Webhooks → Add Webhook**
2. Enter webhook URL (must be HTTPS)
3. Select events:
   - `scan.started` — Analysis job started
   - `scan.completed` — Analysis finished
   - `finding.created` — New vulnerability detected
   - `finding.resolved` — Manually marked resolved
4. (Optional) Set webhook secret for signature verification
5. Click **Create**

**Test Webhook:**
1. Go to **Settings → Webhooks**
2. Find webhook in list
3. Click **Test** → sends sample payload to URL
4. View response status and body

**Webhook Payload:**
```json
{
  "event": "scan.completed",
  "scan_id": "scan-abc123def456",
  "organization_id": "org-xyz789",
  "project": {
    "name": "acme/backend",
    "source": "github",
    "url": "https://github.com/acme/backend"
  },
  "analysis_results": {
    "total_findings": 12,
    "critical": 2,
    "high": 5,
    "medium": 4,
    "low": 1
  },
  "modules_run": [
    "dependencies",
    "sast",
    "secrets"
  ],
  "timestamp": "2024-01-15T14:30:00Z",
  "duration_seconds": 245
}
```

**Webhook Security:**
- Always use HTTPS
- Verify webhook signature on your server
- Signature header: `X-Vulnera-Signature: sha256=<hash>`
- Implement timeout/retry logic

## Audit & Compliance

### Audit Log

Organization admins can view all member actions and configuration changes.

**Access Audit Log:**
1. Go to **Settings → Audit Log**
2. View entries (newest first):
   - Timestamp
   - Member email
   - Action (invited, scan created, key generated, etc.)
   - Resource affected
   - IP address

**Filter Audit Log:**
- By action type (Member activity, Configuration, Scan, Integration)
- By member email
- By date range
- By resource (scan ID, API key ID, etc.)

**Export Audit Log:**
1. Go to **Settings → Audit Log → Export**
2. Select date range
3. Choose format: CSV or JSON
4. Download file

**Audit Log Retention:**
- Free plan: 30 days
- Pro: 90 days
- Enterprise: 2 years (configurable)

### Compliance Reports

**Generate Compliance Report:**
1. Go to **Reports → Compliance Reports**
2. Select framework:
   - SOC2 Type II
   - ISO 27001
   - GDPR
   - HIPAA (Enterprise)
   - PCI DSS (Enterprise)
3. Select date range
4. Click **Generate**
5. Download as PDF

**Report Contents:**
- Organization access controls summary
- Member provisioning/deprovisioning records
- Security incident history
- Data handling practices
- Audit log excerpts

## Best Practices

### Organization Structure

**Small Teams (1-10 members):**
- 1 Owner
- 1-2 Admins
- Rest as Members/Viewers
- Shared quota sufficient

**Medium Teams (10-50 members):**
- 1 Owner
- 3-5 Admins (by department/team)
- Members/Viewers as needed
- Consider department quotas (Enterprise)

**Large Organizations (50+ members):**
- 1 Owner
- 10+ Admins (by team/geography)
- Hierarchical teams (Enterprise)
- Custom RBAC roles (Enterprise)
- SSO/SAML mandatory

### Member Lifecycle

**Onboarding:**
1. Invite new member with appropriate role
2. Have member review organization settings
3. Add to Slack channel notifications
4. Provide API key for CLI (if Member/Admin)
5. Confirm first scan works

**Offboarding:**
1. Remove member from organization
2. Revoke API keys (if any)
3. Review scans they created (for audit)
4. Export member's contributions (if needed)
5. Archive related configurations

### Security Practices

✅ **Do:**
- Assign minimal required role (principle of least privilege)
- Use Viewers for non-technical stakeholders
- Rotate API keys every 90 days
- Enable 2FA for all members (if available)
- Audit member list quarterly
- Review audit logs monthly
- Enable webhook signature verification

❌ **Don't:**
- Share API keys between members
- Grant Owner role to multiple people
- Use generic/shared email addresses
- Disable audit logging
- Leave unused integrations connected
- Ignore quota warnings

## Troubleshooting

**Q: Member invited but never received email**
```
A: 1. Check their spam folder
   2. Resend invite: Settings → Members → Resend
   3. Verify email address spelling
   4. Check if email is already registered (member may self-join)
```

**Q: Member can't see organization scans**
```
A: 1. Verify member role is not Viewer
   2. Confirm member accepted invitation
   3. Member should log out and log back in
   4. Clear browser cache
   5. Check audit log for removal records
```

**Q: API key not working for organization scans**
```
A: 1. Verify key belongs to org admin/member
   2. Check key hasn't expired (Settings → API Keys)
   3. Confirm key has org scope (not just personal)
   4. Regenerate if needed
   5. Verify member role allows scan creation
```

**Q: Quota exhausted early**
```
A: 1. Review usage (Analytics → Dashboard)
   2. Check for duplicate scans
   3. Optimize scan targets (exclude node_modules, etc.)
   4. Upgrade plan (Settings → Billing)
   5. Contact sales for temporary boost (Enterprise)
```

**Q: How to transfer organization ownership**
```
A: 1. Owner adds desired new owner as Admin
   2. New owner transfers via Settings → Transfer Ownership
   3. Current owner confirms transfer
   4. Former owner demoted to Admin automatically
```

## Next Steps

- **Set Up Integrations** — Connect Slack, GitHub for automated workflows
- **Configure Webhooks** — Feed findings to your ticketing system
- **Generate Your First Report** — Create compliance or executive summary report
- **Audit Organization** — Review member list and access quarterly

For team collaboration workflows, see [Team Collaboration Guide](team-collaboration.md).
For dashboard features, see [Dashboard Guide](guide.md).

---

**Need help?** Email [support@vulnera.studio](mailto:support@vulnera.studio) or visit our [FAQ](../reference/faq.md).
