<div align="center">

# Vulnera

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![MSRV: 1.92](https://img.shields.io/badge/MSRV-1.92-orange.svg)](https://www.rust-lang.org/)
[![version](https://img.shields.io/badge/version-0.5.1-green.svg)](CHANGELOG.md)
[![Docs](https://img.shields.io/badge/docs-online-blue)](https://Vulnera-rs.github.io/Vulnera/)

**Security at the speed of Rust. Sandboxed by the kernel.**

[Quick Start](#quick-start) · [Documentation](https://Vulnera-rs.github.io/Vulnera/) · [Philosophy](PHILOSOPHY.md) · [Changelog](CHANGELOG.md)

</div>

---

## Why Vulnera?

Most security scanners are built on memory-unsafe foundations and require you to trust opaque SaaS services with your source code. Vulnera is different.

We built a **self-hosted, API-first security platform** that runs in your infrastructure, uses Linux kernel sandboxing (not containers), and gives you auditable rules-not black-box scores.

### Three Pillars

| Fastest | Safest | Transparent |
|---------|--------|-------------|
| 🚀 **Rust-native performance** - No GC pauses, lock-free caching | 🛡️ **Landlock kernel sandboxing** - Not containers. The actual Linux kernel. | 📖 **Auditable rules** - TOML rule packs you can read and modify |
| **<10s** for medium projects | **<1µs** sandbox startup overhead | Tree-sitter queries, not black boxes |

While other scanners sandbox with containers, Vulnera uses Linux Landlock LSM-the same kernel technology that powers Chrome's sandbox. Faster, safer, and not bypassable by container escapes.

### Security for the AI Coding Era

The rise of **"vibe coding"** - where developers and non-developers rely heavily on AI to rapidly generate software - has introduced widespread systemic security risks. This method prioritizes speed over rigorous engineering, resulting in code that is frequently **syntactically correct but logically insecure**.

**Common AI-generated security flaws Vulnera detects:**

| AI Hallucination | How Vulnera Catches It |
|------------------|------------------------|
| **Hard-coded API keys** in generated boilerplate | Secrets detection with entropy analysis + live verification |
| **SQL injection** in AI-generated database queries | SAST taint tracking from user input to query execution |
| **Missing authentication** in scaffolded endpoints | API security analyzers for auth gaps |
| **Vulnerable dependencies** in generated `requirements.txt` | CVE scanning across 9 ecosystems |
| **XSS vulnerabilities** in auto-generated frontend code | Inter-procedural data flow analysis |

**The stakes:** Software vulnerabilities have caused over $380 million in losses in industrial control systems alone. 90% of vulnerabilities stem from poor design and insecure coding practices - exactly what AI-generated code exacerbates.

**Vulnera's approach:** Fast, integrated security analysis that catches AI-generated vulnerabilities at the speed of AI-generated code.

---

### Built for the Full Development Lifecycle

**Pre-Production First** - Vulnera is designed to catch vulnerabilities before they reach production:

| Phase | How Vulnera Fits |
|-------|------------------|
| **IDE/CLI** | Real-time analysis via LSP as you write code |
| **Pre-commit** | `vulnera config hooks install` blocks secrets before commit |
| **CI/CD** | GitHub Actions integration fails builds on critical findings |
| **Staging** | Full analysis before production deployment |

**Post-Production** - For running systems:
- Dependency CVE monitoring for deployed applications
- API security regression testing against production OpenAPI specs
- Secrets rotation detection in configuration repositories

Our philosophy: **Shift Left, Monitor Right.** Catch vulnerabilities during development when they're cheapest to fix, but maintain visibility into production security posture.

---

## What It Does

Four community modules for comprehensive security analysis:

| Module | What It Finds | Languages / Formats |
|--------|--------------|---------------------|
| **SAST** | SQL injection, XSS, command injection, path traversal | Python, JavaScript/TypeScript, Rust, Go, C, C++ |
| **Secrets** | API keys, database passwords, private certificates | All text files |
| **Dependencies** | Known CVEs in your dependencies | npm, PyPI, Cargo, Maven, Gradle, Go, Ruby, PHP, NuGet |
| **API Security** | Authentication flaws, data exposure, misconfigurations | OpenAPI 3.0/3.1 specs |

**Key differentiators:**
- ✅ **Self-hosted by default** - Your code never leaves your infrastructure
- ✅ **100% offline capable** - SAST, Secrets, API analysis require zero network calls
- ✅ **Inter-procedural taint tracking** - Follows data flow across function boundaries
- ✅ **Live secret verification** - Confirms if detected AWS/GitHub tokens are actually valid
- ✅ **Incremental scanning** - Only re-analyzes changed files via content hashing

---

## Architecture

Vulnera is an **API-first platform** with multiple interfaces:

```
┌─────────────────────────────────────────────────────────────┐
│                      Vulnera Server                          │
│              (Axum REST API + Job Orchestrator)              │
├─────────────────────────────────────────────────────────────┤
│  SAST  │ Secrets │ Dependencies │ API Security │  LLM      │
│ Engine │ Engine  │   Engine     │   Engine     │ Explain   │
└─────────────────────────────────────────────────────────────┘
         │              Sandboxing (Landlock/Seccomp)
         ▼
┌─────────────────────────────────────────────────────────────┐
│                      Client Interfaces                       │
├──────────────┬──────────────┬──────────────┬────────────────┤
│   Web UI     │  REST API    │  IDE Ext     │     CLI        │
│  (Browser)   │  (Direct)    │(Zed/VS Code) │  (Terminal)    │
│              │              │              │                │
│  Dashboard   │  Any HTTP    │   LSP        │   vulnera      │
│  Analytics   │  client      │   Server     │   analyze      │
│  API Docs    │  curl/HTTPie │              │                │
└──────────────┴──────────────┴──────────────┴────────────────┘
```

**The server is the core product.** :
- **Web UI** - Dashboard, analytics, organization management
- **CLI** - Command-line client for local/offline workflows
- **REST API** - Direct HTTP API access from our web dashboard with our self hosted LLMs for you own use.
- **IDE Extensions** - Zed and VS Code via LSP (Language Server Protocol)

---

## Quick Start

### Option 1: Self-Hosted Server (Recommended for Teams)

Deploy the full platform in your infrastructure:

```bash
git clone --recursive https://github.com/Vulnera-rs/Vulnera.git
cd Vulnera

# Setup database
export DATABASE_URL='postgresql://user:pass@localhost:5432/vulnera'
sqlx migrate run

# Configure
cat > .env <<'EOF'
DATABASE_URL=postgresql://user:pass@localhost:5432/vulnera
VULNERA__AUTH__JWT_SECRET=$(openssl rand -hex 32)
EOF

# Run server
cargo run
```

**Access points:**
- Web UI: http://localhost:3000
- API Docs: http://localhost:3000/docs (Swagger UI)
- API Endpoint: http://localhost:3000/api/v1

### Option 2: CLI Client (Offline-First)

Use the CLI for local scanning without running a server:

```bash
cargo install vulnera-cli

# Offline scan - no server, no internet required
vulnera analyze .

# Or connect to your self-hosted server for team features
vulnera auth login --server http://localhost:3000
vulnera analyze . --remote
```

### Option 3: Docker (Quick Evaluation)

```bash
docker run --rm -v $(pwd):/scan vulnera/cli:latest analyze /scan
```

### Option 4: IDE Integration

Install IDE extensions for real-time analysis:

- **Zed:** Install `vulnera` extension from the extension store
- **VS Code:** Install from marketplace (connects to LSP server)

Configure extension to connect to your Vulnera server for team-wide analysis.

---

## Interfaces

### Web UI

Browser-based dashboard for team collaboration:

- **Project overview** - Security posture across all repositories
- **Finding details** - Drill into vulnerabilities with remediation guidance
- **Analytics** - Trending, MTTR metrics, security scorecards
- **Organization management** - RBAC, team quotas, webhook configurations
- **Policy configuration** - Org-level scanning policies
- **LLMs** - Explain findings, generate custom rules, triage with AI assistance with credits from your API quota

Access at `http://your-server:3000` after starting the server.

### REST API

Direct HTTP API for custom integrations:

```bash
# Submit analysis job
curl -X POST http://localhost:3000/api/v1/analysis \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "source_url": "https://github.com/org/repo",
    "modules": ["sast", "secrets", "deps"]
  }'

# Get findings
curl http://localhost:3000/api/v1/findings/$JOB_ID \
  -H "Authorization: Bearer $API_KEY"
```

Full API documentation available at `/docs` when server is running.

**API Keys:** Generate access tokens from the Web UI (Settings → API Keys) or programmatically via the auth endpoint.

### IDE Extensions

Real-time analysis in your editor:

| Editor | Extension | Connection |
|--------|-----------|------------|
| Zed | Built-in LSP | Connects to Vulnera server |
| VS Code | Vulnera extension | Connects to LSP adapter |

Features:
- Inline diagnostics as you type
- Quick fixes for vulnerabilities
- Dependency vulnerability highlighting
- Secret detection in real-time

### CLI Client

Command-line interface for local workflows and CI/CD:

```bash
# Scan with specific modules
vulnera analyze . --modules sast,secrets

# Watch mode - auto-scan on file changes
vulnera sast . --watch

# Pre-commit hook integration
vulnera config hooks install

# Export results
vulnera analyze . --format sarif --output report.sarif

# Check quota (when connected to server)
vulnera quota
```

The CLI works in two modes:
1. **Offline mode** - Runs analysis engines locally, no server required
2. **Connected mode** - Authenticates with your Vulnera server for team features

---

## Open Core: Community vs Enterprise

| Feature | Community (AGPL-3.0) | Enterprise (Licensed) |
|---------|------------------------|------------------------|
| **Server** | Full self-hosted server with web UI | Vulnera Studio (managed SaaS) |
| **Analysis Modules** | SAST, Secrets, Dependencies, API Security | DAST, IaC, CSPM, Fuzz, SBOM, License Compliance |
| **API Access** | Complete REST API | Same API |
| **IDE Extensions** | Full functionality | Same extensions |
| **CLI** | Full offline + connected capability | Same CLI |
| **Rules** | All built-in rules + custom TOML packs | Advanced rule packs, AI-assisted rule creation |
| **Workflows** | GitHub Actions, pre-commit hooks | Enterprise SSO (SAML/OIDC), Jira/Slack integration, auto-PR generation |
| **Analytics** | Basic dashboard | Advanced security analytics, compliance reporting |
| **Support** | Community (GitHub Issues) | SLA with dedicated support |

**Our philosophy:** The security platform is open source. Team workflow features and managed hosting are licensed.

---

## How It Works

### SAST Engine
- **Tree-sitter parsing** - Native AST generation for 6+ languages
- **OXC frontend** - Optional fast parser for JavaScript/TypeScript
- **Symbol table** - Scope-aware variable tracking with shadowing detection
- **Taint analysis** - Source-to-sink data flow tracking across function calls
- **Lock-free caching** - moka-based query cache with 512-entry default

### Secrets Detection
Three-pass pipeline for accuracy:
1. **Pattern/entropy matching** - 40+ regex rules + Shannon entropy scoring
2. **AST analysis** - Context-aware validation using tree-sitter
3. **Semantic validation** - Language-specific heuristics to filter test files, placeholders

### Sandboxing
Multi-backend architecture:
- **Landlock** (Linux 5.13+) - Kernel-enforced filesystem/network restrictions
- **Seccomp** (Older Linux) - Syscall filtering with process isolation
- **WASM** (Non-Linux) - WebAssembly-based portable sandbox (in development)

### Dependency Analysis
Cross-ecosystem vulnerability scanning:
- **9 package ecosystems** - npm, PyPI, Cargo, Maven, Gradle, Go, Ruby, PHP, NuGet
- **Multi-source intelligence** - OSV, NVD, GHSA, CISA KEV, EPSS, OSS Index
- **Smart caching** - Dragonfly/Redis with zstd compression and 24h TTL
- **Version resolution** - Semantic versioning with constraint satisfaction algorithms
- **Transitive resolution** - Full dependency graph analysis (work in progress for manifest-only projects)

### API Security
OpenAPI specification analysis:
- **9 security analyzers** - Authentication, authorization, data exposure, input validation, OAuth, security headers, misconfiguration, design, resource restriction
- **Automatic spec discovery** - Finds openapi.yaml, swagger.json, and variants
- **Schema reference resolution** - Follows $ref pointers across components
- **Contract integrity scoring** - Validates spec completeness and consistency

---

## Documentation

- [Getting Started](docs/src/getting-started/personas/developer-quickstart.md) - Developer quick start
- [API Reference](docs/src/reference/architecture.md) - REST API docs (via `/docs` endpoint or Web UI)
- [Configuration](docs/src/reference/configuration.md) - Environment variables and config files
- [FAQ](docs/src/reference/faq.md) - Common questions
- [Philosophy](PHILOSOPHY.md) - Core principles and design decisions
- [Roadmap](ROADMAP.md) - Future development plans

---

## Contributing

We welcome contributions, especially in:

- **SAST rules** - New tree-sitter queries in `vulnera-sast/rules/*.toml`
- **Lockfile parsers** - Completing transitive resolution for `go.sum`, `Gemfile.lock`, `composer.lock`
- **False positive reduction** - Improving entropy thresholds and semantic validators
- **IDE extensions** - Zed/VS Code extension improvements

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. All contributors must sign the [CLA](CLA.md).

### Development Setup

```bash
# Install git hooks
lefthook install

# Run CI checks locally
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
cargo nextest run --workspace
```

---

## Security

Vulnerabilities in Vulnera itself should be reported privately. See [SECURITY.md](SECURITY.md).

---

## License

Vulnera uses an open-core model:

**Community Edition** (AGPL-3.0-or-later):
- `vulnera-server` - Full web UI, REST API, job orchestration
- `vulnera-core` - Domain models and shared infrastructure
- `vulnera-sast` - Static analysis engine
- `vulnera-secrets` - Secret detection
- `vulnera-deps` - Dependency analysis
- `vulnera-api` - OpenAPI security analysis
- `vulnera-llm` - LLM provider abstractions
- `vulnera-sandbox` - Sandboxing backends
- `vulnera-orchestrator` - Job orchestration
- `vulnera-cli` - Command-line client
- `vulnera-adapter` - LSP server for IDE extensions

**Enterprise Features** (Proprietary - requires license):
- DAST module (dynamic application security testing)
- IaC security module (Terraform, Kubernetes, Dockerfile)
- CSPM (cloud security posture management)
- Fuzz testing module
- SBOM generation
- License compliance scanning
- Malicious package detection
- Vulnera Studio SaaS platform

See each repository's LICENSE file for details.
