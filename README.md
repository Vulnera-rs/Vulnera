<div align="center">

# Vulnera

**High-Performance Vulnerability Analysis Platform**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.82%2B-orange.svg)](https://www.rust-lang.org/tools/install)
[![Rust](https://img.shields.io/badge/Rust-1.82+-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg?logo=docker)](https://hub.docker.com/)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.0-green.svg?logo=openapi-initiative)](https://swagger.io/)

_Multi-ecosystem vulnerability analysis with dependency scanning, SAST, secrets detection, and API security auditing_

[Quick Start](#-quick-start) • [Web Dashboard](https://vulnera.studio) • [Documentation](https://k5602.github.io/Vulnera/)

</div>

---

## 🌐 Web Dashboard & Team Collaboration

**[Vulnera Studio](https://vulnera.studio)** — Central web platform for team collaboration, security insights, and reporting:

| Feature                     | Description                                                                        |
| --------------------------- | ---------------------------------------------------------------------------------- |
| **Organization Management** | Create teams, manage members with role-based access (Owner, Admin, Member, Viewer) |
| **Shared Quota Pools**      | Team members share token allocations; no per-user limits                           |
| **API Key Management**      | Generate and rotate keys for CLI and CI/CD integration                             |
| **Integrations**            | Connect GitHub, GitLab, Slack, webhooks for automated workflows                    |
| **Team Analytics**          | Track usage by member, module, and project; export reports                         |
| **Compliance Reports**      | Generate SOC2, ISO27001, GDPR, HIPAA-aligned reports                               |
| **Audit Logs**              | Full history of member actions, configuration changes, and scans                   |
| **Webhooks**                | Real-time notifications for scan events and findings                               |

**Get started:** Visit [vulnera.studio](https://vulnera.studio) → Sign up → Create organization → Invite team.

---

## Architecture

</text>

<old_text line=73>
| [Quick Start](https://k5602.github.io/Vulnera/getting-started/quick-start.html) | Installation and first scan |
| [CLI Reference](https://k5602.github.io/Vulnera/guide/cli-reference.html) | Command-line usage |
| [Configuration](https://k5602.github.io/Vulnera/guide/configuration.html) | Environment variables and TOML config |
| [Authentication](https://k5602.github.io/Vulnera/guide/authentication.html) | JWT and API key setup |
| [Analysis Modules](https://k5602.github.io/Vulnera/modules/overview.html) | Module-specific documentation |
| [Architecture](https://k5602.github.io/Vulnera/architecture/overview.html) | System design and DDD patterns |
| [CI/CD Integration](https://k5602.github.io/Vulnera/integration/cicd.html) | GitHub Actions, GitLab CI, Azure DevOps |

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

| Module                  | Capabilities                                                                                     |
| ----------------------- | ------------------------------------------------------------------------------------------------ |
| **Dependency Analysis** | npm, PyPI, Maven, Cargo, Go, Composer, Ruby, NuGet — CVE aggregation from OSV/NVD/GHSA/CISA /KEV |
| **SAST**                | Python, JavaScript, Rust static analysis with AST parsing and custom rules                       |
| **Secrets Detection**   | ML + entropy-based detection for AWS, Azure, GCP, API keys, tokens                            |
| **API Security**        | OpenAPI 3.x analysis for auth, validation, and security misconfigurations                        |

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

**Verify:** `curl http://localhost:3000/health` • **API Docs:** <http://localhost:3000/docs>

---

## 📖 Documentation

| Guide                                                                           | Description                             |
| ------------------------------------------------------------------------------- | --------------------------------------- |
| [Quick Start](https://k5602.github.io/Vulnera/getting-started/quick-start.html) | Installation and first scan             |
| [CLI Reference](https://k5602.github.io/Vulnera/guide/cli-reference.html)       | Command-line usage                      |
| [Configuration](https://k5602.github.io/Vulnera/guide/configuration.html)       | Environment variables and TOML config   |
| [Authentication](https://k5602.github.io/Vulnera/guide/authentication.html)     | JWT and API key setup                   |
| [Analysis Modules](https://k5602.github.io/Vulnera/modules/overview.html)       | Module-specific documentation           |
| [Architecture](https://k5602.github.io/Vulnera/architecture/overview.html)      | System design and DDD patterns          |
| [CI/CD Integration](https://k5602.github.io/Vulnera/integration/cicd.html)      | GitHub Actions, GitLab CI, Azure DevOps |

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

## 🌍 Web Platform Access

**No setup required:**

```bash
# Option 1: Use web dashboard 
# 1. Visit https://vulnera.studio
# 2. Sign up → Create organization
# 3. Get API key from Settings → API Keys
# 4. Use key with CLI or CI/CD

vulnera auth login --api-key YOUR_API_KEY
vulnera analyze .
```

**For teams:**

```bash
# Organization admin creates team via web dashboard
# 1. https://vulnera.studio → Create Organization
# 2. Settings → Members → Invite team members
# 3. Share organization API key for CI/CD
# 4. All members share token quota, view shared scans
```

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

## 👥 Team & Community

| Name                     | Role                            |
| ------------------------ | ------------------------------- |
| **Khaled Mahmoud**       | Project Lead, Backend Developer |
| **Abd El-Rahman Mossad** | Frontend, LSP Server Maintainer |
| **Amr Medhat**           | Cloud Engineer                  |
| **Gasser Mohammed**      | Frontend Engineer               |

**Resources:**

- **Web Dashboard:** [vulnera.studio](https://vulnera.studio) — Full-featured team collaboration platform
- **Documentation:** [k5602.github.io/Vulnera](https://k5602.github.io/Vulnera/) — Complete guides and tutorials
- **GitHub:** [k5602/Vulnera](https://github.com/k5602/Vulnera) — Source code and issues
- **Community:** [GitHub Discussions](https://github.com/k5602/Vulnera/discussions) — Q&A and feedback

---

## 📜 License

[AGPL v3.0](LICENSE) — see [LICENSE](./LICENSE) for details.

---

<div align="center">

**[Web Dashboard](https://vulnera.studio)** • **[Documentation](https://k5602.github.io/Vulnera/)** • **[API Reference](http://localhost:3000/docs)** • **[Contributing](CONTRIBUTING.md)** • **[Changelog](CHANGELOG.md)**

</div>
