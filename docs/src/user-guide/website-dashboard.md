# Web Dashboard (API-First Guidance)

Vulnera is API-first and does **not** ship a bundled web UI in this repository. If you need a dashboard, use the API endpoints below to build your own UI or integrate with existing tools.

---

## Core API Endpoints

### Health & Docs

- `GET /health` — service health
- `GET /metrics` — metrics endpoint
- `GET /docs` — Swagger UI (if enabled)
- `GET /api-docs/openapi.json` — OpenAPI spec

### Jobs & Analysis

- `POST /api/v1/analyze/job` — create analysis job
- `GET /api/v1/jobs/{id}` — get job status/result

### Organizations

- `POST /api/v1/organizations` — create organization
- `GET /api/v1/organizations` — list organizations
- `GET /api/v1/organizations/{id}` — organization details
- `PUT /api/v1/organizations/{id}` — update organization
- `DELETE /api/v1/organizations/{id}` — delete organization
- `GET /api/v1/organizations/{id}/members` — list members
- `POST /api/v1/organizations/{id}/members` — invite member
- `DELETE /api/v1/organizations/{id}/members/{user_id}` — remove member
- `POST /api/v1/organizations/{id}/leave` — leave organization
- `POST /api/v1/organizations/{id}/transfer` — transfer ownership

### Analytics & Quota

- `GET /api/v1/organizations/{id}/analytics/dashboard` — org dashboard stats
- `GET /api/v1/organizations/{id}/analytics/usage` — org usage
- `GET /api/v1/organizations/{id}/analytics/quota` — org quota
- `GET /api/v1/me/analytics/dashboard` — personal dashboard stats
- `GET /api/v1/me/analytics/usage` — personal usage
- `GET /api/v1/quota` — quota usage

### LLM Features (Optional)

- `POST /api/v1/llm/explain`
- `POST /api/v1/llm/fix`
- `POST /api/v1/llm/query`
- `POST /api/v1/jobs/{job_id}/enrich`

---

## Authentication & Security

- Cookie auth uses JWT + CSRF.
- API key auth uses `X-API-Key` header.
- CORS must be configured for your UI origin.
- Swagger UI can be disabled in production via config.

---

## Building Your Own Dashboard

A minimal dashboard typically includes:

1. **Organization selector**
2. **Recent jobs list** (`/organizations/{id}/analytics/dashboard`)
3. **Findings view** (from job detail: `/jobs/{id}`)
4. **Quota widget** (`/organizations/{id}/analytics/quota` or `/api/v1/quota`)
5. **Usage charts** (`/organizations/{id}/analytics/usage`)

---

## Configuration Reference

See:

- [Configuration Reference](../reference/configuration.md)
- [System Architecture](../reference/architecture.md)

---

## Next Steps

- [LLM Features](llm-features.md)
- [Quota & Pricing](quota-pricing.md)
- [Organization Management](dashboard/organization-management.md)
