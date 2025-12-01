# AI-Powered Explanations & Fixes (LLM-Based)

Vulnera goes beyond vulnerability detection. Get instant, human-readable explanations and AI-generated code fixes using LLM-powered analysis.

## What Is LLM-Based Analysis?

LLM (Large Language Model) features use advanced AI—specifically **Huawei Cloud Pangu**—to provide:

- **Vulnerability Explanations** — Why a finding matters and what risks it poses
- **Code Fix Suggestions** — Concrete code snippets showing how to remediate the issue
- **Natural Language Queries** — Ask security questions in plain English
- **Context-Aware Insights** — AI understands your specific code, language, and framework

LLM features are **separate from core detection**. Detection modules (secrets, SAST, API, deps) are rule-based and work offline. LLM features enhance findings after analysis.

## Key Features

### 1. Vulnerability Explanations

**Get AI-powered explanations for every finding.**

```bash
# CLI example
vulnera analyze /path/to/project --format json | jq '.findings[] | .llm_explanation'
```

**Response (streaming):**

```
A SQL injection vulnerability occurs when user input is directly concatenated
into SQL queries without proper parameterization. An attacker can inject
malicious SQL code to bypass authentication, extract data, or modify the database.

To fix: Use parameterized queries or prepared statements with placeholder
values instead of string concatenation.
```

### 2. AI-Generated Code Fixes

**Get actionable remediation code.**

```bash
# CLI example with code context
vulnera analyze /path/to/project --enhance-with-fixes
```

**Response:**

```python
# Fixed code using proper escaping
from flask import escape
html = f"<div>{escape(user_input)}</div>"

# Or use Jinja2 templating (recommended)
# {{ user_input }} is automatically escaped in templates
```

### 3. Natural Language Queries

**Ask security questions in plain English.**

```bash
vulnera llm query "How do I securely store API keys in my Node.js application?"
```

**Response:**

```
Based on your analysis results:

1. Outdated Express.js (3.x) - Use 4.18+ for security patches
2. Unvalidated user input in route handlers - Add input validation middleware
3. Hardcoded API keys in .env - Use environment-based configuration instead

For detailed remediation steps, run: vulnera llm fix --issue [issue_id]
```

## Cost & Quota Considerations

LLM requests consume **6x quota tokens** compared to standard analysis (3x tokens).

### Rate Limiting & Costs

| Account Tier        | Daily Limit                  | LLM Requests/Day | Cost per Request     |
| ------------------- | ---------------------------- | ---------------- | -------------------- |
| Unauthenticated     | 10 requests/day              | Limited          | 6 tokens per request |
| API Key             | 40 requests/day              | ~6-7 requests    | 6 tokens per request |
| Organization Member | 48 requests/day (+20% bonus) | ~8 requests      | 6 tokens per request |

with organization accounts, team members share a combined quota.
with plan to expand limits in future as we expand our infrastructure.

### Cost Weighting Explained

- **Detection (GET)**: 1 token
- **Analysis (POST)**: 3 tokens
- **LLM Operations (explain/fix/query)**: 6 tokens
- **LLM Enrichment (batch explanations)**: 6 tokens per finding

**Example: API Cost**

```
Analyzing a project with 5 findings:
- Dependency analysis: 3 tokens
- SAST analysis: 3 tokens
- Secret detection: 3 tokens
- 5 LLM explanations: 5 × 6 = 30 tokens
- Total: 39 tokens (one large request)

With 40 token/day API key quota, this consumes ~97% of daily limit.
```

### Quota Estimation

**For individual developers:**

- Run analysis: 3 tokens
- Get explanations: 6 tokens per finding (avg 3-5 findings) = 18-30 tokens
- Occasional code fixes: 6 tokens
- **Daily budget: ~40-50 tokens = good for 1-2 full analyses with LLM enhancement**

**For teams:**

- Create organization for shared quota (4x-8x multiplier)
- Team members share daily budget
- Quota resets at UTC midnight

## Using LLM Features

### CLI: Enhance Findings with Explanations

```bash
# Get explanations for all findings
vulnera analyze /path/to/project --enhance-with-explanations

# Or pipe to jq for specific findings
vulnera analyze /path/to/project --format json \
  | jq '.findings[0] | @json' \
  | vulnera llm explain
```

## Enabling/Disabling LLM Features

### Environment Variables

```bash
# Enable LLM
export VULNERA_LLM_ENABLED=true
export VULNERA_LLM_PROVIDER=huawei-pangu
export VULNERA_LLM_API_KEY=your_key_here

# Use in CLI
vulnera analyze /path/to/project --enhance-with-explanations
```

## Best Practices

### 1. Use LLM for High-Severity Findings

```bash
# Only enhance critical/high severity findings to save quota
vulnera analyze /path/to/project \
  --enhance-with-fixes \
  --severity high
```

### 2. Batch Enrich Results

Instead of individual LLM calls, enrich entire job results.

### 3. Cache Explanations

Vulnera caches LLM explanations for duplicate findings. Same vulnerability ID = cached response.

### 4. Use Natural Language Queries for Discovery

```bash
# Ask about vulnerabilities you don't understand
vulnera llm query "What is YAML injection and why is it dangerous?"
```

## Comparison: Detection vs LLM Features

| Aspect       | Detection Modules           | LLM Features                  |
| ------------ | --------------------------- | ----------------------------- |
| **Method**   | Rule-based, ML models       | LLM (Huawei Pangu)            |
| **Offline**  | ✅ Yes (SAST, secrets, API) | ❌ Requires network           |
| **Cost**     | 3 tokens                    | 6 tokens                      |
| **Use Case** | Find vulnerabilities        | Understand & remediate        |
| **Speed**    | Instant                     | 1-5 seconds                   |
| **Accuracy** | High (rules + patterns)     | Context-aware, conversational |

## Troubleshooting

**Q: LLM requests are slow**
A: LLM processing takes 1-5 seconds. For bulk analysis, use batch enrichment API instead of individual requests.

**Q: Getting quota exceeded errors with LLM enabled**
A: LLM costs 6x regular analysis. Reduce LLM usage or upgrade your plan. See [Quota & Pricing](quota-pricing.md).

**Q: LLM explanations seem generic**
A: Provide code context in your request. More context = better explanations. See examples above.

**Q: Can I use LLM offline?**
A: No—LLM features require network. Use offline-only analysis modules (SAST, secrets, API) for local scanning.

## Next Steps

- [Configure LLM settings](configuration.md) for your environment
- [Understand quota & costs](quota-pricing.md)
- [Explore natural language queries](llm-queries.md)
- [Learn about code fix generation](llm-code-fixes.md)
