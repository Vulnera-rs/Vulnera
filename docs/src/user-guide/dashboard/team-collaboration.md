# Team Collaboration Guide

Vulnera enables seamless collaboration across security teams, DevOps, and developers. This guide covers workflows for shared vulnerability analysis, coordinated remediation, and team-based security practices.

## Collaboration Workflows

### Shared Analysis Setup

**Scenario: Security team wants developers to run scans and review findings together**

1. **Create Organization**
   - Go to Dashboard → **+ New Organization**
   - Name: "Engineering Security"
   - Add organization description

2. **Invite Team Members**
   - Go to Settings → Members → **Invite Member**
   - Invite developers with **Member** role (can create scans, resolve findings)
   - Invite security lead with **Admin** role (manage integrations, settings)
   - Invite executives with **Viewer** role (read-only access to reports)

3. **Set Up Shared Quota**
   - Organization gets shared token pool (e.g., 1000 tokens/month for Pro)
   - All members draw from same pool
   - No individual limits unless configured (Enterprise)

4. **Enable Notifications**
   - Settings → Integrations → Slack
   - Connect team Slack workspace
   - Enable daily summary and critical finding alerts
   - All members get notifications in shared channel

### Scan Coordination

**Multi-stage scanning workflow:**

```
Developer creates scan
         ↓
Scan runs (uses shared quota)
         ↓
Results available to all members
         ↓
Security team reviews findings
         ↓
Developer addresses findings
         ↓
Findings marked resolved
         ↓
Historical record kept for audit
```

**Practical Example:**

1. **Developer Alice** runs scan on `/backend`:
   ```bash
   vulnera auth login --api-key $ORG_API_KEY  # (org key, not personal)
   vulnera analyze ./backend --all-modules
   ```

2. **Security lead Bob** reviews findings in dashboard:
   - Open scan → Filter by Critical/High severity
   - Add comments to findings
   - Mark false positives
   - Create Jira tickets for issues

3. **Developer Alice** gets Slack notification:
   - "New critical finding in backend scan"
   - She clicks link → opens dashboard
   - Sees Bob's comments and tickets
   - Fixes code locally

4. **Alice re-runs scan** after fix:
   - Same findings now show as "Resolved"
   - Historical comparison shows before/after

### Code Review Integration

**GitHub PR workflow with Vulnera:**

1. **Setup GitHub Integration** (Admin):
   - Settings → Integrations → GitHub
   - Authorize Vulnera app
   - Enable "Auto-scan PRs"

2. **Developer opens PR**:
   - GitHub automatically triggers Vulnera scan
   - Results appear as PR status check

3. **Security review**:
   - PR blocked if critical issues found
   - Vulnera comment on PR with findings
   - Link to full dashboard for details
   - Developer can request security review

4. **Resolution**:
   - Developer pushes fix commit
   - Vulnera automatically re-scans
   - If clean, PR check passes
   - Can now merge to main

**Example GitHub PR Comment:**
```
🚨 Vulnera Security Scan Found Issues

Critical (1):
- SQL Injection in /src/api/users.py:45
  CVSS: 9.2

High (2):
- Hardcoded API key in config.py:12
- Missing input validation in POST /api/data:78

View full report: [Dashboard Link]
Bot action: This PR is blocked until issues are resolved
```

## Finding Management

### Assigning Findings

**Assign to Team Member:**

1. Open scan → select finding
2. Click **Assign To**
3. Search member by email or name
4. Member gets notification:
   - Email: "You've been assigned a critical finding"
   - Slack: Link to finding with severity
   - In-app: Shows in "Assigned to Me" queue

**My Assignments View:**
- Dashboard → **My Assignments**
- Shows all findings assigned to current member
- Sort by severity, due date, project
- Quick filter: Unstarted, In Progress, Blocked

### Tracking Remediation

**Finding Status Lifecycle:**

```
Open (New)
    ↓
In Progress (assigned, work started)
    ↓
Resolved (fix implemented, verified)
OR
False Positive (not a real issue)
OR
Acknowledged (known issue, accepting risk)
```

**Updating Status:**

1. Open finding → **Status** dropdown
2. Select new status
3. Add comment (optional):
   - Explain why marked false positive
   - Link to fix PR or commit
   - Document risk acceptance

4. Members with access see update:
   - Slack notification: "@alice marked as Resolved"
   - Audit log records change
   - Dashboard updates in real-time

### Commenting & Discussion

**Collaborate on Finding:**

1. Open finding → scroll to **Discussion** section
2. Click **Add Comment**
3. Type message (Markdown supported)
4. @mention team members: `@bob` or `@security-team`
5. Submit → all mentioned members notified

**Example Finding Discussion:**
```
Alice: "This is a security issue in our OAuth implementation"

Bob: "Good catch. I'll check if this affects production"

Charlie: "@bob let's verify in staging first"

Security Lead: "Approved for resolution. PR: #4521"
```

**Threaded Discussions (Enterprise):**
- Reply to specific comments
- Resolve/pin important threads
- Export discussion for compliance

## Reporting & Analytics

### Team Analytics Dashboard

**Organization Analytics (Admin view):**

Go to **Settings → Analytics → Dashboard**

**View:**
- Team quota usage (bar chart: 850/1000 tokens used)
- Usage by member (table: Alice 400 tokens, Bob 300, etc.)
- Usage by module (pie: Dependencies 50%, SAST 35%, Secrets 15%)
- Trend (line graph: last 6 months)
- Busiest project, most findings by type

### Shared Reports

**Generate Report for Stakeholders:**

1. Go to **Reports → New Report**
2. Select report type:
   - **Executive Summary** — High-level metrics for leadership
   - **Detailed Technical** — Full findings for security team
   - **Compliance** — SOC2/ISO27001/GDPR aligned
   - **Department Summary** — Findings by team/project
3. Configure:
   - Date range (last 30 days, last quarter, custom)
   - Modules to include (dependencies, SAST, secrets, API)
   - Recipients (email, download, or both)
4. Click **Generate**
5. Share PDF/HTML with stakeholders

**Executive Summary Example:**
```
VULNERA SECURITY REPORT
January 2024

OVERVIEW
Total Vulnerabilities: 247
Critical: 12  |  High: 45  |  Medium: 120  |  Low: 70

TRENDS
↓ 15% fewer critical issues vs. last month
→ Secrets detection improved (5 leaked credentials caught)
↑ Dependencies increased (new packages added)

TEAM PERFORMANCE
Alice: 42 scans, 340 findings reviewed
Bob: 38 scans, 280 findings reviewed
Charlie: 25 scans, 180 findings reviewed

NEXT STEPS
1. Remediate 5 critical issues (ongoing)
2. Update 12 outdated dependencies (in progress)
3. Add 2 new team members for code review capacity
```

### Custom Dashboards (Enterprise)

Create personalized views:

1. Go to **Organization → Dashboards → Custom**
2. Select widgets:
   - Recent findings
   - Team quota gauge
   - Trend chart
   - Member activity
   - CI/CD integration status
3. Arrange layout, save as team dashboard
4. Share with team members

## Security Team Workflows

### Daily Security Review Routine

**Morning (15 min):**
1. Check Slack for critical findings overnight
2. Review **My Assignments** dashboard
3. Prioritize by severity and project criticality

**Mid-day (30 min):**
1. Comment on findings with remediation guidance
2. Assign new findings to developers
3. Update status on resolved items

**End-of-day (10 min):**
1. Generate daily summary report
2. Check team quota usage (alert if >75%)
3. Review newly integrated repositories

**Weekly (1 hour):**
1. All-hands meeting: review weekly findings summary
2. Discuss high-priority remediation blockers
3. Plan integrations/automation improvements

### Escalation Process

**When to escalate finding:**

1. **Critical + No Owner Assigned** → Assign to team lead immediately
2. **Finding unresolved 7+ days** → Escalate to manager
3. **Multiple critical findings in same code** → Schedule code review session
4. **Suspicious pattern** (e.g., many secrets) → Notify CISO

**Escalation in Dashboard:**

1. Open finding → **Mark Escalated**
2. Add reason:
   - High business impact
   - Unresponsive team
   - Need architecture review
3. Escalated findings show in red on analytics
4. Leadership dashboard shows escalations count

## Developer Workflows

### Running Scans as Developer

**Individual Contributor:**

```bash
# Authenticate with org API key
vulnera auth login --api-key $ORG_API_KEY

# Scan your code (uses org quota, not personal)
vulnera analyze ./src --all-modules --format json

# View results (or use dashboard)
vulnera analyze ./src --all-modules --format sarif | jq '.findings[] | {location, message, severity}'
```

**Pre-commit Scanning:**

1. Install hook:
   ```bash
   vulnera install-hook ./
   ```

2. Hook runs before commit, blocks if critical:
   ```bash
   $ git commit
   Vulnera scan in progress...
   2 critical findings detected. Commit blocked.
   Fix and retry: git commit
   ```

**CI/CD Integration:**

In `.github/workflows/security.yml`:
```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vulnera-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Vulnera scan
        env:
          VULNERA_API_KEY: ${{ secrets.VULNERA_API_KEY }}
        run: |
          curl -L https://releases.vulnera.studio/vulnera-linux-x86_64 -o vulnera
          chmod +x vulnera
          ./vulnera analyze . --all-modules --format sarif > vulnera.sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: vulnera.sarif
```

### Understanding & Fixing Findings

**When you get assigned a finding:**

1. **Notification** (Slack, email, dashboard)
   - Click link → opens finding details

2. **Understand the Issue**
   - Read vulnerability explanation
   - Look at affected code snippet
   - Review CVSS score and severity
   - Check provided remediation guidance

3. **Research if Needed**
   - Follow linked CVE/CWE
   - Check if it affects your use case
   - Ask security team for context (@bob in dashboard)

4. **Fix or Dismiss**
   - **If real issue:** Create fix branch, implement patch, commit
   - **If false positive:** Mark as such in dashboard with reason
   - **If acceptable risk:** Mark as "Acknowledged" (with manager approval)

5. **Verify**
   - Re-run scan locally: `vulnera analyze ./`
   - Finding should disappear or show as resolved
   - Create PR with fix
   - Vulnera auto-scans PR → shows as clean

6. **Mark Complete**
   - PR merged → Vulnera marks finding resolved
   - Or manually: Dashboard → Finding → Status → Resolved

**Example Finding Workflow:**
```
Finding: SQL Injection in /api/users.py:45
Severity: Critical
CVSS: 9.2

Developer reads:
"User input is concatenated directly into SQL query without parameterization"

Developer fixes:
```python
# Before
query = f"SELECT * FROM users WHERE id = {user_id}"

# After
query = "SELECT * FROM users WHERE id = $1"
db.execute(query, [user_id])
```

Developer re-scans → Finding gone → PR merged

Dashboard shows: "Resolved by commit abc123def"
```

## Cross-Team Collaboration

### Developer + Security Team

**Weekly Sync Meeting:**

1. **Agenda** (30 min):
   - Review critical findings from past week
   - Discuss blockers (unclear requirements, false positives)
   - Prioritize next week's work
   - Demo fixes and improvements

2. **Before Meeting**:
   - Security team prepares findings summary (generated report)
   - Developers review assigned items in dashboard
   - Both teams note questions

3. **After Meeting**:
   - Document decisions in dashboard comments
   - Update remediation timeline
   - Send summary email to stakeholders

### DevOps + Security Team

**Infrastructure Scanning:**

1. **DevOps** sets up cloud scanning:
   ```bash
   vulnera analyze s3://our-bucket --all-modules
   vulnera analyze github-repos --org acme-corp --all-modules
   ```

2. **Security reviews** infrastructure findings:
   - Cloud misconfigurations
   - Exposed credentials in configs
   - Vulnerable dependencies in infra code

3. **DevOps fixes** issues:
   - Updates IaC templates (Terraform, CloudFormation)
   - Re-scans to verify
   - Dashboards show infrastructure security posture

### Security Team + Leadership

**Monthly Executive Report:**

1. **Generate Compliance Report**:
   - Go to Reports → Compliance Reports → SOC2
   - Select past month
   - Download PDF

2. **Include in Board Deck**:
   - Overview of findings trend
   - Team remediation velocity
   - Risk metrics and KPIs
   - Budget/quota efficiency

3. **Dashboard Access for Leadership**:
   - Create Viewer accounts for executives
   - Give read-only access to reports
   - They can view trends without modifying findings

## Notifications & Alerts

### Configuring Team Notifications

**Central Configuration (Admin):**

1. Go to **Settings → Notifications**
2. Set for entire team:
   - Critical findings: Immediate Slack alert
   - High findings: Daily digest email
   - Quota alerts: At 75%, 90%, 100%
   - Member activity: Weekly summary

**Personal Preferences (Member):**

1. Go to **Profile → Notification Preferences**
2. Member can override:
   - Frequency (real-time, daily digest, weekly summary)
   - Channel (email, Slack, in-app, SMS)
   - Finding types (all, critical only, assigned only)

### Slack Channel Strategy

**Setup Channels:**

- `#vulnera-critical` — Real-time critical findings (mention team lead)
- `#vulnera-security` — All findings, daily summary (team discussion)
- `#vulnera-alerts` — Quota warnings, integration issues (ops only)
- `#vulnera-ci` — PR scan results, CI/CD integration logs (read-only bot)

**Slack Automation Example:**

```
@vulnera-bot configure
├── #vulnera-critical: severity >= critical
├── #vulnera-security: summary daily 9 AM
├── #vulnera-alerts: quota > 90%
└── #vulnera-ci: all GitHub PR scans
```

## Performance Metrics

### Key Metrics to Track

**Team Health:**
- **Remediation Rate** — % of findings fixed within SLA
- **Mean Time to Remediation (MTTR)** — Days from finding to resolved
- **False Positive Rate** — % of dismissed as not real issue
- **Scan Frequency** — Scans per week by team

**Security Posture:**
- **Critical Findings Trend** — Month-over-month comparison
- **Dependency Age** — Average age of dependencies
- **Secret Exposures** — Count of exposed credentials (should be zero)
- **Coverage** — % of repositories being scanned

**Quota Efficiency:**
- **Tokens/Finding** — Cost per vulnerability found
- **Scans/Token** — How many scans per token used
- **Team Quota Burndown** — Days until month-end quota exhausted

### Monthly Review Template

**Run this monthly:**

1. Export analytics report (Settings → Analytics → Export)
2. Calculate metrics above
3. Create 1-page summary:
   - Headline: metrics vs. last month
   - Key wins: critical issues resolved
   - Blockers: findings taking too long
   - Next month priorities
4. Share with team + leadership

## Best Practices

### Team Organization

✅ **Small Team (5 members):**
- 1 Security lead (Admin)
- 4 Developers (Members)
- Shared single quota pool
- Daily Slack updates

✅ **Medium Team (15 members):**
- 1-2 Security leads (Admin)
- 10-12 Developers (Member)
- 2-3 Managers (Viewer)
- Department-specific Slack channels

✅ **Large Organization (50+ members):**
- Hierarchical teams (Enterprise)
- Custom RBAC roles
- Department quotas
- Cross-team steering committee

### Communication Best Practices

✅ **Do:**
- Comment on findings with context (not just "fix this")
- Mention developers in Slack for urgent issues
- Have weekly syncs (async updates via dashboard)
- Document decisions in finding comments
- Celebrate resolved critical findings

❌ **Don't:**
- Assign findings without explanation
- Ignore escalated issues
- Let findings sit unreviewed >5 days
- Resolve without verification
- Skip audit log reviews

### Security Practices

✅ **Do:**
- Use organization API keys, not personal keys
- Rotate API keys quarterly
- Enable 2FA for all members
- Audit member list monthly
- Export compliance reports quarterly
- Review webhook logs

❌ **Don't:**
- Share API keys in chat/email
- Use shared email addresses
- Keep inactive members in org
- Disable audit logging
- Store findings in plaintext
- Ignore unreviewed scans

## Common Scenarios

### Scenario 1: Onboarding New Developer

1. Admin invites developer with **Member** role
2. Developer accepts invite
3. DevOps provides org API key
4. Developer authenticates: `vulnera auth login --api-key`
5. Developer runs first scan: `vulnera analyze ./`
6. Security team reviews findings, comments with guidance
7. Developer receives Slack notification, fixes issues
8. Next scan shows issues resolved

**Timeline:** 30 minutes total

### Scenario 2: Critical Finding in Production Code

1. Vulnera detects critical SQL injection in production branch
2. Slack alert goes to `#vulnera-critical` (pings team lead)
3. Security lead opens dashboard, verifies severity
4. Security lead assigns to Alice (code owner) with comment: "URGENT: Fix before merge"
5. Alice gets Slack notification, sees 9.2 CVSS score
6. Alice creates hotfix branch, implements parameterized query
7. Alice commits fix, GitHub auto-scans PR (Vulnera)
8. Dashboard shows finding now marked "Resolved"
9. Alice creates PR, security approves, code merged
10. Production release includes fix

**Timeline:** 2-4 hours

### Scenario 3: Monthly Compliance Reporting

1. Security lead runs report: Reports → Compliance → SOC2 → January
2. Report generated: PDF with audit log, member actions, findings summary
3. Security lead emails report to CISO, board
4. CISO reviews with dashboard (Viewer access)
5. Sends to auditor for compliance verification

**Timeline:** 10 minutes to generate, 1 hour to review

## Troubleshooting

**Q: Team member not seeing organization scans**
```
A: 1. Verify member accepted invitation (check email)
   2. Confirm member role is not Viewer
   3. Have member log out/log back in
   4. Clear browser cache
   5. Check if member was removed (Settings → Audit Log)
```

**Q: Findings not appearing in Slack**
```
A: 1. Verify Slack integration enabled (Settings → Integrations)
   2. Check notification triggers configured
   3. Verify Vulnera app still has channel permissions
   4. Test webhook: Settings → Webhooks → Test
   5. Check Slack app hasn't been uninstalled from workspace
```

**Q: Team member assigned findings but didn't respond**
```
A: 1. Verify notification settings (Settings → Notifications)
   2. Member may have disabled email notifications
   3. Send direct Slack message if urgent
   4. Escalate to manager if blocking
   5. Consider reassigning if no response in 3 days
```

**Q: How to handle team member leaving?**
```
A: 1. Remove member (Settings → Members → Remove)
   2. Revoke their API keys immediately
   3. Reassign their open findings to other members
   4. Export their scan history (for audit/compliance)
   5. Review audit log for any suspicious activity
```

## Next Steps

- **Set Up Slack** — Enable real-time alerts for your team
- **Create Weekly Sync** — Calendar recurring meeting to review findings
- **Generate First Report** — Monthly compliance or executive summary
- **Document Workflows** — Create team runbook for common scenarios

For dashboard features, see [Dashboard Guide](guide.md).
For organization setup, see [Organization Management](organization-management.md).

---

**Need help?** Email [support@vulnera.studio](mailto:support@vulnera.studio) or visit our [FAQ](../reference/faq.md).
