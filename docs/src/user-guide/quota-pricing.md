# Quota & Pricing

This document explains how **local CLI quotas** and **server rate limits** work, and how they differ.

---

## Two Separate Systems

### 1) CLI Local Quota (Per Machine)

The CLI enforces a **local daily request limit** and persists usage on the machine.

**Limits (CLI):**

- **Unauthenticated:** 10 requests/day
- **Authenticated (API key):** 40 requests/day

**Where this lives:**

- Stored locally by the CLI (per machine)
- Reset at **UTC midnight**
- You can check status with `vulnera quota`

**Commands:**

```/dev/null/commands.txt#L1-3
vulnera auth status
vulnera quota
vulnera quota sync
```

**Notes:**

- The CLI quota is a local guardrail and can be **synced with server state** if the server is reachable.
- Offline mode uses local quota only.

---

### 2) Server Rate Limits (API)

The server enforces **tiered rate limits** and **token costs per request**. This is authoritative for hosted/self-hosted API usage.

**Default tiers (from `config/default.toml`):**

- **API key**: 100 req/min, 2000 req/hour, burst 20
- **Authenticated (cookie)**: 60 req/min, 1000 req/hour, burst 10
- **Anonymous**: 10 req/min, 100 req/hour, burst 5
- **Org bonus**: +20% to tier limits

**Token cost weights (per request):**

- `GET` = 1
- `POST`/`PUT`/`DELETE` = 2
- **Analysis** = 3
- **LLM** = 6

These costs apply to the **server-side rate limiter**, not the CLI local tracker.

---

## Practical Examples

### CLI (Local)

- `vulnera analyze .` → consumes 1 local request
- `vulnera deps .` → consumes 1 local request + server usage

### Server (API)

- `POST /api/v1/analyze/job` → cost `analysis = 3`
- `POST /api/v1/llm/explain` → cost `llm = 6`
- `GET /api/v1/quota` → cost `get = 1`

---

## How to Check Usage

### CLI (Local)

```/dev/null/commands.txt#L1-1
vulnera quota
```

### Server (API)

```/dev/null/commands.txt#L1-2
curl https://api.vulnera.studio/api/v1/quota \
  -H "X-API-Key: <your_api_key>"
```

---

## Configuration (Server)

Server limits live in `config/default.toml`:

- `server.rate_limit.tiers.*` for rate tiers
- `server.rate_limit.costs.*` for request cost weights
- `server.rate_limit.tiers.org_bonus_percent`

Override with environment variables using the `VULNERA__` prefix.

---

## Guidance

- **Use the CLI locally** for offline modules (SAST, Secrets, API).
- **Use server-backed analysis** for dependency scanning and LLM features.
- **Batch LLM enrichment** to reduce total cost.

---

## Troubleshooting

**Local CLI says quota exceeded**

- Wait for UTC reset or authenticate for 40/day
- Use `vulnera auth login` and `vulnera quota`

**Server returns 429**

- You’ve exceeded the configured server tier limits
- Reduce request volume or increase limits in server config

---
