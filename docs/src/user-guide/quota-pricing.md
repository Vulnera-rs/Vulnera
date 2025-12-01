# Quota & Pricing

Understand how Vulnera's quota system works, cost weighting, and how to optimize your usage.

## Rate Limiting Overview

Vulnera uses a **token-based quota system** with different tiers based on authentication level.

### Quota Tiers

| Account Type            | Daily Quota            | Requests/Day | Burst Size  | Reset Time   |
| ----------------------- | ---------------------- | ------------ | ----------- | ------------ |
| **Unauthenticated**     | 10 tokens              | ~10 requests | 5 requests  | UTC midnight |
| **API Key**             | 40 tokens              | ~13 requests | 20 requests | UTC midnight |
| **Organization Member** | 48 tokens (+20% bonus) | ~16 requests | 20 requests | UTC midnight |

### What Each Operation Costs

```
GET request                    → 1 token
POST request (standard)        → 2 tokens
Analysis operation (deps)      → 3 tokens
LLM operation (explain/fix)    → 6 tokens
LLM batch enrichment          → 6 tokens per finding
```

## Cost Examples

### Scenario 1: Individual Developer (Unauthenticated)

```
Daily budget: 10 tokens

Option A: Multiple small analyses
- Dependency check: 3 tokens
- Secret scan: 3 tokens
- Code analysis: 3 tokens
- Total: 9 tokens (1 token left)

Option B: Single analysis with LLM enhancement
- Full analysis: 3 tokens
- Explanations for 2 findings: 12 tokens
- Total: 15 tokens → EXCEEDS QUOTA ❌

Recommendation: Authenticate to get 40 tokens/day
```

### Scenario 2: API Key (40 tokens/day)

```
Daily budget: 40 tokens

- Analyze project (SAST + secrets + API): 3 tokens
- Dependency scan: 3 tokens
- Get explanations for 3 findings: 18 tokens
- Generate code fix for 1 finding: 6 tokens
- Total: 30 tokens

Remaining: 10 tokens for 3-4 more requests ✅
```

### Scenario 3: Organization (48 tokens/day)

```
Organization with 5 security team members
Shared daily budget: 48 tokens

Per-person allocation (if evenly divided):
- Member 1: ~9 tokens
- Member 2: ~9 tokens
- Member 3: ~9 tokens
- Member 4: ~9 tokens
- Member 5: ~9 tokens
- Reserve: ~3 tokens

Each member can:
- 2 full analyses with LLM enhancement per day
- Or 3 analyses without LLM per day
```

## Understanding Token Cost Weights

### Why LLM Costs 2x Analysis?

- **Analysis operations** use pre-built ML models running locally
- **LLM operations** call Huawei Cloud Pangu API, which has cloud costs + latency

Pricing reflects actual infrastructure costs.

## How to Optimize Quota Usage

### Tip 1: Batch Operations

❌ **Inefficient: Individual LLM calls**

```bash
# Each call costs 6 tokens
for finding in "${findings[@]}"; do
  vulnera llm explain "$finding"  # 6 tokens × N findings
done
```

✅ **Efficient: Batch enrichment**

```bash
# Single API call costs 6 tokens for all findings
curl -X POST /api/v1/jobs/12345/enrich
```

**Savings:** 5 findings = 30 tokens (individual) vs 6 tokens (batch) = **24 tokens saved**

### Tip 2: Selective LLM Enhancement

❌ **Inefficient: Explain everything**

```bash
vulnera analyze /path/to/project --enhance-with-explanations
# May have 20 findings × 6 tokens = 120 tokens
```

✅ **Efficient: Only high-severity findings**

```bash
vulnera analyze /path/to/project \
  --severity high \
  --enhance-with-explanations
# Maybe 3 findings × 6 tokens = 18 tokens
```

### Tip 3: Use Offline-Only Analysis

❌ **Expensive: Full online analysis**

```bash
vulnera analyze --all-modules  # Costs 3+ tokens
```

✅ **Free (or cheap): Offline analysis**

```bash
vulnera analyze --skip-deps  # SAST + secrets + API = offline
# Still costs 3 tokens (POST) but no dependencies scanned
```

### Tip 4: Cache Results

Vulnera automatically caches analysis results for 24 hours.

```bash
# First call: 3 tokens
vulnera analyze /path/to/project

# Second call (same project, within 24h): Uses cache
vulnera analyze /path/to/project  # May cost 0-1 tokens if cached
```

### Tip 5: Organize Team Usage

For teams:

- Create organization (pool quota across members)
- Assign quotas per team member or project
- Monitor usage with analytics dashboard

## Monitoring Quota Usage

### CLI: Check Current Quota

```bash
vulnera quota
```

**Output:**

```
Quota Status
╔════════════════════════════════════════╗
║ Usage: ████████░░░░░░░░░░░░░░░░░░░░░░░║ 15/40
╚════════════════════════════════════════╝

Daily Limit: 40 tokens (API Key)
Used Today: 15 tokens
Remaining: 25 tokens

Breakdown by operation:
  Analysis: 6 tokens (2 analyses)
  LLM: 9 tokens (1 explanation + 1 fix)

Resets in: 8h 45m (UTC midnight)
Account: api-key-prod-xxxxx
```

### API: Get Quota Status

```bash
curl https://api.vulnera.studio/api/v1/quota \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Response:**

```json
{
  "daily_limit": 40,
  "used_today": 15,
  "remaining": 25,
  "tier": "api_key",
  "reset_at": "2025-01-01T00:00:00Z",
  "breakdown": {
    "analysis": 6,
    "llm": 9,
    "auth": 0
  }
}
```

### Dashboard: Organization Analytics

For organization members, view team usage:

```bash
vulnera organizations analytics usage --months 3
```

Shows:

- Daily quota usage trends
- Per-member breakdown
- Peak usage times
- Recommendations for optimization

## Upgrading Your Quota

### Option 1: Authenticate

Free → **40 tokens/day** (4x increase)

```bash
vulnera auth login
# Enter your API key
```

### Option 2: Create Organization

Single account → **48 tokens/day** (shared across team)

```bash
vulnera organizations create --name "My Team"
vulnera organizations add-member --email team@company.com
# Shared pool of 48 tokens/day
```

### Option 3: Custom Plan

For enterprise, contact sales for custom quota limits.

## What Happens at Quota Exceeded?

### Rate Limited (429 Error)

```bash
vulnera analyze /path/to/project
# Error: Rate limit exceeded. Remaining quota: 0 tokens
# Reset in: 14h 22m
```

### Workarounds

1. **Wait for reset** (UTC midnight)
2. **Use offline-only analysis** (SAST, secrets, API—no token cost for local files)
3. **Reduce LLM usage** (stop enhancing findings temporarily)
4. **Upgrade plan** (authenticate or create organization)

## Free Tier vs Paid

### Community Users

- **Cost:** Free
- **Daily quota:** 10 tokens
- **LLM features:** Available (but limited by quota)
- **Storage:** None (results deleted after 7 days)
- **Support:** Community Discord

### API Key Tier

- **Cost:** Free (always—no subscription required)
- **Daily quota:** 40 tokens (4x community)
- **LLM features:** Full access
- **Storage:** 30 days
- **Support:** Email support

### Organization Tier

- **Cost:** Contact sales
- **Daily quota:** 48-480 tokens (depends on team size)
- **LLM features:** Full access
- **Storage:** Unlimited (1 year retention)
- **Support:** Dedicated account manager
- **Features:** Team analytics, member management, audit logs

## FAQ

**Q: Can I request quota increase?**
A: Contact Vulnera with your use case.

**Q: Do I pay for failed analyses (if they hit errors)?**
A: No. Only completed requests consume quota.

**Q: Does caching reduce quota cost?**
A: Cached results may cost 0-1 tokens instead of 3. Depends on if the query exactly matches cache key.

**Q: What if I run out of quota mid-month?**
A: Quota resets at UTC midnight each day. You can use free offline analysis (SAST, secrets) while waiting.

**Q: How much does LLM cost compared to detection?**
A: LLM costs 2x analysis operations (6 vs 3 tokens). It calls cloud API, hence the cost.
