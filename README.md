<div align="center">

# Vulnera

**High-Performance Vulnerability Analysis Platform**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.82%2B-orange.svg)](https://www.rust-lang.org/tools/install)
[![Rust](https://img.shields.io/badge/Rust-1.82+-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg?logo=docker)](https://hub.docker.com/)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.0-green.svg?logo=openapi-initiative)](https://swagger.io/)

*Multi-ecosystem vulnerability analysis with dependency scanning, SAST, secrets detection, and API security auditing*

[Quick Start](#-quick-start) • [Documentation](https://k5602.github.io/Vulnera/) • [API Reference](http://localhost:3000/docs)

</div>

---

## Architecture

```mermaid
flowchart TB
    subgraph Clients["Client Layer"]
        CLI["CLI Tool"]
        API["HTTP API"]
        EXT["IDE Extensions"]
    end

    subgraph Orchestrator["Orchestration"]
        ORCH["Module Registry"]
        SEL["Rule-Based Selector"]
        JOB["Job Queue"]
    end

    subgraph Modules["Analysis Modules"]
        DEPS["🔍 Dependencies"]
        SAST["🛡️ SAST"]
        SEC["🔑 Secrets"]
        APIS["📋 API Security"]
    end

    subgraph Data["Data Sources"]
        OSV["OSV"]
        NVD["NVD"]
        GHSA["GHSA"]
    end

    CLI & API & EXT --> ORCH
    ORCH --> SEL --> JOB
    JOB --> DEPS & SAST & SEC & APIS
    DEPS --> OSV & NVD & GHSA
```

## ✨ Features

| Module | Capabilities |
|--------|-------------|
| **Dependency Analysis** | npm, PyPI, Maven, Cargo, Go, Composer, Ruby, NuGet — CVE aggregation from OSV/NVD/GHSA |
| **SAST** | Python, JavaScript, Rust static analysis with AST parsing and custom rules |
| **Secrets Detection** | Regex + entropy-based detection for AWS, Azure, GCP, API keys, tokens |
| **API Security** | OpenAPI 3.x analysis for auth, validation, and security misconfigurations |

**Core Platform:**

- 🚀 **Async Rust** — Tokio-powered concurrent processing
- 🏗️ **DDD Architecture** — Clean separation of domain, application, infrastructure layers
- 🔐 **Auth** — JWT tokens + API keys with PostgreSQL-backed management
- ⚡ **Smart Caching** — Dragonfly DB with configurable TTL
- 📖 **OpenAPI** — Auto-generated Swagger UI documentation

---

## 🚀 Quick Start

### Prerequisites

- Rust 1.82+ • PostgreSQL 12+ • SQLx CLI

### Install & Run

```bash
git clone https://github.com/k5602/Vulnera.git && cd Vulnera
export DATABASE_URL='postgresql://user:pass@localhost:5432/vulnera'
sqlx migrate run --source migrations
cargo run
```

**Docker:**

```bash
docker build -t vulnera .
docker run -p 3000:3000 -e DATABASE_URL='postgresql://...' vulnera
```

**Verify:** `curl http://localhost:3000/health` • **API Docs:** <http://localhost:3000/docs>

---

## 📖 Documentation

| Guide | Description |
|-------|-------------|
| [Quick Start](https://k5602.github.io/Vulnera/getting-started/quick-start.html) | Installation and first scan |
| [CLI Reference](https://k5602.github.io/Vulnera/guide/cli-reference.html) | Command-line usage |
| [Configuration](https://k5602.github.io/Vulnera/guide/configuration.html) | Environment variables and TOML config |
| [Authentication](https://k5602.github.io/Vulnera/guide/authentication.html) | JWT and API key setup |
| [Analysis Modules](https://k5602.github.io/Vulnera/modules/overview.html) | Module-specific documentation |
| [Architecture](https://k5602.github.io/Vulnera/architecture/overview.html) | System design and DDD patterns |
| [CI/CD Integration](https://k5602.github.io/Vulnera/integration/cicd.html) | GitHub Actions, GitLab CI, Azure DevOps |

---

## ⚙️ Configuration

```bash
# Required
DATABASE_URL='postgresql://user:pass@localhost:5432/vulnera'
VULNERA__AUTH__JWT_SECRET='minimum-32-character-secret-key'

# Optional (recommended)
VULNERA__CACHE__DRAGONFLY_URL='redis://127.0.0.1:6379'
VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=8
```

Config files: `config/development.toml`, `config/production.toml`

---

## 🔐 Authentication

```bash
# Register (sets HttpOnly cookies)
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -c cookies.txt \
  -d '{"email": "user@example.com", "password": "SecurePass123"}'

# Extract CSRF token from response, then make protected requests
curl -X POST http://localhost:3000/api/v1/analyze/job \
  -b cookies.txt \
  -H "X-CSRF-Token: <csrf_token>" \
  -H "Content-Type: application/json" \
  -d '{"source": {"type": "directory", "path": "."}}'  
```

---

## 🛠️ Development

```bash
# Setup
make -C scripts/build_workflow install-deps

# Test
cargo nextest run --workspace

# CI checks
make -C scripts/build_workflow quick-check
```

### Project Structure

```
vulnera-core/         # Domain models, config, shared infrastructure
vulnera-orchestrator/ # HTTP API, job orchestration, controllers
vulnera-deps/         # Dependency analysis module
vulnera-sast/         # Static analysis module
vulnera-secrets/      # Secrets detection module
vulnera-api/          # OpenAPI security analysis module
vulnera-llm/          # LLM-powered explanations
```

---

## 🚢 Deployment

### Production Checklist

- [ ] Strong JWT secret (32+ characters)
- [ ] Disable docs: `VULNERA__SERVER__ENABLE_DOCS=false`
- [ ] Configure CORS origins
- [ ] Enable HTTPS
- [ ] Set up monitoring (OpenTelemetry)

### Azure Architecture

```
Azure Front Door → API Management → App Service/Container Apps
                                         ↓
                   PostgreSQL ← Vulnera → Key Vault
                                         ↓
                                   Dragonfly Cache
```

---

## 👥 Team

| Name | Role |
|------|------|
| **Khaled Mahmoud** | Project Lead, Backend Developer |
| **Abd El-Rahman Mossad** | Frontend, LSP Server Maintainer|
| **Amr Medhat** | Cloud Engineer |
| **Gasser Mohammed** | Frontend Engineer |

---

## 📜 License

[AGPL v3.0](LICENSE) — see [LICENSE](./LICENSE) for details.

---

<div align="center">

**[Documentation](https://k5602.github.io/Vulnera/)** • **[API Reference](http://localhost:3000/docs)** • **[Contributing](CONTRIBUTING.md)** • **[Changelog](CHANGELOG.md)**
