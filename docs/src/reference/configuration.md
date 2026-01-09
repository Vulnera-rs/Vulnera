# Configuration Reference

This page documents all configuration options for Vulnera.

## Environment Variables

All configuration can be set via environment variables with the `VULNERA__` prefix using double underscores for nesting.

---

## Core Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `VULNERA__AUTH__JWT_SECRET` | JWT signing secret (32+ chars) | Required |
| `VULNERA__SERVER__ADDRESS` | Server bind address | `0.0.0.0:3000` |
| `VULNERA__SERVER__ENABLE_DOCS` | Enable Swagger UI | `true` |

---

## LLM Configuration

Vulnera supports multiple LLM providers for AI-powered features.

### Provider Selection

| Variable | Description | Default |
|----------|-------------|---------|
| `VULNERA__LLM__PROVIDER` | Active provider: `google_ai`, `openai`, `azure` | `google_ai` |
| `VULNERA__LLM__DEFAULT_MODEL` | Model name for generation | `gemini-2.0-flash` |
| `VULNERA__LLM__TEMPERATURE` | Generation temperature (0.0-1.0) | `0.3` |
| `VULNERA__LLM__MAX_TOKENS` | Maximum tokens to generate | `2048` |
| `VULNERA__LLM__TIMEOUT_SECONDS` | Request timeout | `60` |
| `VULNERA__LLM__ENABLE_STREAMING` | Enable streaming responses | `true` |

### Google AI (Gemini)

| Variable | Description |
|----------|-------------|
| `GOOGLE_AI_KEY` | API key from [aistudio.google.com](https://aistudio.google.com/app/apikey) |
| `VULNERA__LLM__GOOGLE_AI__BASE_URL` | Custom API endpoint |

**Recommended models:** `gemini-2.0-flash`, `gemini-1.5-pro`

### OpenAI

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | API key from [platform.openai.com](https://platform.openai.com/api-keys) |
| `VULNERA__LLM__OPENAI__BASE_URL` | Custom endpoint (for Ollama, vLLM, etc.) |
| `VULNERA__LLM__OPENAI__ORGANIZATION_ID` | Organization ID |

**Recommended models:** `gpt-4`, `gpt-4-turbo`, `gpt-3.5-turbo`

### Azure OpenAI

| Variable | Description |
|----------|-------------|
| `AZURE_OPENAI_KEY` | Azure API key |
| `VULNERA__LLM__AZURE__ENDPOINT` | Azure resource endpoint |
| `VULNERA__LLM__AZURE__DEPLOYMENT` | Deployment name |
| `VULNERA__LLM__AZURE__API_VERSION` | API version (default: `2024-02-15-preview`) |

### Resilience Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `VULNERA__LLM__RESILIENCE__ENABLED` | Enable circuit breaker + retry | `true` |
| `VULNERA__LLM__RESILIENCE__MAX_RETRIES` | Max retry attempts | `3` |
| `VULNERA__LLM__RESILIENCE__INITIAL_BACKOFF_MS` | Initial backoff delay | `500` |
| `VULNERA__LLM__RESILIENCE__MAX_BACKOFF_MS` | Maximum backoff delay | `30000` |
| `VULNERA__LLM__RESILIENCE__CIRCUIT_BREAKER_THRESHOLD` | Failures before circuit opens | `5` |
| `VULNERA__LLM__RESILIENCE__CIRCUIT_BREAKER_TIMEOUT_SECS` | Seconds before circuit recovery | `60` |

### Enrichment Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `VULNERA__LLM__ENRICHMENT__MAX_FINDINGS_TO_ENRICH` | Max findings to enrich | `10` |
| `VULNERA__LLM__ENRICHMENT__MAX_CONCURRENT_ENRICHMENTS` | Concurrent enrichment calls | `3` |
| `VULNERA__LLM__ENRICHMENT__INCLUDE_CODE_CONTEXT` | Include code in prompts | `true` |
| `VULNERA__LLM__ENRICHMENT__MAX_CODE_CONTEXT_CHARS` | Max code snippet length | `2000` |

---

## Sandbox Configuration

The sandbox provides secure isolation for SAST and secrets detection modules.

| Variable | Description | Default |
|----------|-------------|---------|
| `VULNERA__SANDBOX__ENABLED` | Enable sandboxing | `true` |
| `VULNERA__SANDBOX__BACKEND` | Sandbox backend (see below) | `auto` |
| `VULNERA__SANDBOX__EXECUTION_TIMEOUT_SECS` | Execution timeout | `30` |
| `VULNERA__SANDBOX__MEMORY_LIMIT_MB` | Memory limit (process backend) | `256` |

### Sandbox Backends

| Backend | Description | Requirements |
|---------|-------------|--------------|
| `auto` | Auto-detect best backend | Recommended |
| `landlock` | Kernel-level isolation | Linux 5.13+ |
| `process` | Fork-based isolation | Any Linux |
| `none` | Disable sandboxing | Not recommended |

**Landlock** provides near-zero overhead security using Linux kernel capabilities. Falls back to **process** on older kernels.

---

## Cache Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `VULNERA__CACHE__DRAGONFLY_URL` | Redis/Dragonfly URL | Optional |
| `VULNERA__CACHE__DEFAULT_TTL_SECS` | Default cache TTL | `3600` |

---

## Example Configuration

### Minimal (Development)

```bash
DATABASE_URL='postgresql://localhost/vulnera'
VULNERA__AUTH__JWT_SECRET='dev-secret-key-at-least-32-chars!'
GOOGLE_AI_KEY='your-api-key'
```

### Production

```bash
DATABASE_URL='postgresql://user:pass@db.example.com:5432/vulnera'
VULNERA__AUTH__JWT_SECRET='production-secret-minimum-32-chars!'
VULNERA__CACHE__DRAGONFLY_URL='redis://cache.example.com:6379'

# LLM
VULNERA__LLM__PROVIDER='google_ai'
GOOGLE_AI_KEY='your-production-key'
VULNERA__LLM__RESILIENCE__ENABLED=true

# Sandbox
VULNERA__SANDBOX__ENABLED=true
VULNERA__SANDBOX__BACKEND='auto'

# Server
VULNERA__SERVER__ENABLE_DOCS=false
VULNERA__SERVER__CORS_ORIGINS='https://vulnera.studio'
```
