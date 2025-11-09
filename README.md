# Vulnera Rust – High-Performance Vulnerability Analysis API

[![CI](https://github.com/k5602/Vulnera/actions/workflows/main-azure-web.yml/badge.svg?branch=main)](https://github.com/k5602/Vulnera/actions/workflows/main-azure-web.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.82%2B-orange.svg)](https://www.rust-lang.org/tools/install)

Vulnera is a fast, scalable, multi-ecosystem vulnerability analysis toolkit and testing platform built in Rust. It provides comprehensive security analysis capabilities including dependency vulnerability scanning, static code analysis (SAST), secrets detection, and API security auditing.

The platform aggregates vulnerability data from multiple authoritative sources (OSV, NVD, and GitHub Security Advisories) to provide accurate and up-to-date security intelligence. With its unified orchestrator architecture, Vulnera can perform multi-module analysis in a single request, automatically detecting and analyzing projects across different ecosystems and languages.

Designed for cloud-native workflows, Vulnera leverages async Rust, domain-driven design, and smart caching for reliability and speed. It exposes a robust HTTP API with comprehensive OpenAPI documentation, making it easy to integrate into CI/CD pipelines, development tools, and security automation workflows.

---

## Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Documentation](#-documentation)
- [Architecture](#-architecture)
- [Analysis Modules](#-analysis-modules)
- [Configuration](#-configuration)
- [Authentication](#-authentication)
- [Development](#-development)
- [Deployment](#-deployment)
- [Performance Tuning](#-performance-tuning)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Features

### Comprehensive Analysis Modules

- **Dependency Analysis:** Multi-ecosystem support (npm, PyPI, Maven/Gradle, Cargo, Go, Packagist, Ruby, .NET)
- **SAST (Static Application Security Testing):** Static code analysis for Python, JavaScript, and Rust
- **Secrets Detection:** Regex-based and entropy-based detection of exposed credentials and API keys
- **API Security:** OpenAPI 3.x specification analysis for security vulnerabilities

### Core Capabilities

- **Aggregated Vulnerability Data:** Combines OSV, NVD, and GitHub Security Advisories
- **Unified Orchestration:** Modular architecture with orchestrator pattern for multi-module analysis
- **Authentication & Authorization:** JWT tokens and API keys with PostgreSQL-backed user management
- **Async & Concurrent:** Built with Tokio for high throughput and bounded concurrency
- **Smart Caching:** Dragonfly DB-based, TTL-configurable cache for reduced API calls
- **Safe Version Recommendations:** Upgrade impact classification (major/minor/patch) with prerelease exclusion toggle
- **Domain-Driven Design:** Clean separation of domain, application, infrastructure, and presentation layers
- **OpenAPI Documentation:** Auto-generated Swagger UI for easy API exploration
- **Secure by Default:** Input validation, rate limiting, secure API handling, bcrypt password hashing
- **Container Ready:** Docker and Kubernetes support for production deployments

---

## ⚡ Quick Start

### Prerequisites

- **Rust 1.82+**
- **PostgreSQL 12+** (or Docker)
- **SQLx CLI** (for migrations)
- **Dragonfly DB** (optional, recommended for caching)

### Installation

**From Source:**

```bash
git clone https://github.com/k5602/Vulnera.git
cd Vulnera
export DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'
sqlx migrate run --source migrations
cargo build --release
cargo run
```

**Using Docker:**

```bash
DOCKER_BUILDKIT=1 docker build -t vulnera-rust .
docker run -p 3000:3000 \
  -e DATABASE_URL='postgresql://user:password@host:5432/vulnera' \
  vulnera-rust
```

**For detailed setup instructions, see the [Quick Start Guide](docs/QUICK_START.md).**

### Verify Installation

```bash
curl http://localhost:3000/health
```

Access API documentation at: <http://localhost:3000/docs>

---

## 📚 Documentation

### Getting Started

- **[Quick Start Guide](docs/QUICK_START.md)** - Get up and running quickly
- **[Database Setup](docs/SQLX_SETUP.md)** - PostgreSQL and migration setup
- **[API Testing Guide](docs/API_TESTING.md)** - Comprehensive API testing examples

### Examples

- **[API Usage Examples](docs/examples/api-usage.md)** - API endpoint usage examples
- **[Authentication Examples](docs/examples/authentication.md)** - JWT and API key authentication
- **[Configuration Examples](docs/examples/configuration.md)** - Complete configuration reference
- **[Analysis Modules Examples](docs/examples/analysis-modules.md)** - Module-specific usage examples

### Architecture

- **[Architecture Diagrams](docs/)** - System architecture and design
- **[Roadmap](docs/roadmap.md)** - Future features and development plans

---

## 🏗️ Architecture

Vulnera is built with **Domain-Driven Design (DDD)** and a layered architecture:

- **Domain Layer:** Pure business logic, entities, value objects
- **Application Layer:** Use cases, orchestration, error mapping
- **Infrastructure Layer:** API clients, parsers, caching, repositories
- **Presentation Layer:** HTTP API, DTOs, OpenAPI, middleware

### Modular Architecture & Orchestrator Pattern

Vulnera employs a modular architecture with an orchestrator pattern that enables unified analysis across multiple security analysis modules:

- **Module Registry:** Centralized registry manages all analysis modules
- **Rule-Based Selection:** Automatically selects modules based on source type and analysis depth
- **Unified API:** Single endpoint (`/api/v1/analyze/job`) for comprehensive analysis
- **Parallel Execution:** Modules execute in parallel for optimal performance

**For detailed architecture information, see the [Architecture Documentation](docs/).**

### Caching

Vulnera uses **Dragonfly DB** as the default cache backend, providing high-performance, Redis-compatible caching with:

- TTL-configurable cache entries
- Optional compression for large entries
- Built-in persistence and replication support

**Setup Dragonfly DB:**

```bash
docker run -d --name dragonfly -p 6379:6379 docker.dragonflydb.io/dragonflydb/dragonfly
```

---

## 🔍 Analysis Modules

Vulnera provides four specialized analysis modules that can work independently or together through the unified orchestrator. Each module is designed to detect specific types of security issues and can be configured to match your security requirements.

### Dependency Analysis Module

The Dependency Analysis Module scans dependency manifests across multiple package ecosystems to identify known vulnerabilities in your project's dependencies. It provides comprehensive vulnerability intelligence by aggregating data from OSV, NVD, and GitHub Security Advisories.

**Supported Ecosystems:**

- **Python:** `requirements.txt`, `Pipfile`, `pyproject.toml` (Pipenv, Poetry, pip)
- **Node.js:** `package.json`, `package-lock.json`, `yarn.lock` (npm, Yarn)
- **Java:** `pom.xml`, `build.gradle` (Maven, Gradle)
- **Rust:** `Cargo.toml`, `Cargo.lock` (Cargo)
- **Go:** `go.mod`, `go.sum` (Go modules)
- **PHP:** `composer.json`, `composer.lock` (Composer)
- **Ruby:** `Gemfile`, `Gemfile.lock` (Bundler)
- **.NET (NuGet):** `packages.config`, `*.csproj` (PackageReference), `*.props`/`*.targets` (central management)

**Key Features:**

- **Concurrent Processing:** Analyzes multiple packages in parallel for faster results
- **Safe Version Recommendations:** Provides upgrade suggestions with impact classification (major/minor/patch)
- **Registry Integration:** Resolves versions from official package registries
- **CVE Aggregation:** Combines vulnerability data from multiple sources for comprehensive coverage
- **Version Constraint Analysis:** Understands complex version constraints and provides actionable recommendations

### SAST (Static Application Security Testing) Module

The SAST Module performs static code analysis to detect security vulnerabilities directly in your source code. It uses Abstract Syntax Tree (AST) parsing to understand code structure and identify security anti-patterns, dangerous function calls, and common vulnerability patterns.

**Supported Languages:**

- **Python:** AST parsing via `tree-sitter-python` for comprehensive Python code analysis
- **JavaScript/TypeScript:** AST parsing via `tree-sitter-javascript` for modern JavaScript and TypeScript projects
- **Rust:** AST parsing via `syn` crate (proc-macro-based) for Rust source code analysis

**Key Features:**

- **Configurable Rule Repository:** Load custom security rules from TOML or JSON files
- **Default Rule Set:** Built-in rules for common vulnerabilities including:
  - SQL injection vulnerabilities
  - Command injection risks
  - Unsafe deserialization patterns
  - Hardcoded credentials and secrets
  - Insecure cryptographic operations
- **Pattern-Based Detection:** Multiple matcher types for flexible rule definition:
  - AST node type matching
  - Function call name matching
  - Regular expression pattern matching
- **Automatic Confidence Scoring:** Calculates confidence levels (High/Medium/Low) based on pattern specificity
- **Severity Classification:** Categorizes findings as Critical, High, Medium, Low, or Info
- **Configurable Scanning:** Customizable scan depth and exclude patterns for large codebases

### Secrets Detection Module

The Secrets Detection Module identifies exposed secrets, credentials, API keys, and other sensitive information that may have been accidentally committed to your codebase or repository. It uses multiple detection methods to catch secrets that might be missed by simple pattern matching.

**Detection Methods:**

- **Regex-Based Pattern Matching:** Pattern matching for known secret formats with high precision
- **Entropy-Based Statistical Analysis:** Detects high-entropy strings that are likely to be secrets:
  - Base64 strings (configurable threshold, default: 4.5)
  - Hexadecimal strings (configurable threshold, default: 3.0)
- **Git History Scanning:** Optional analysis of commit history to find secrets that were removed but remain in git history

**Supported Secret Types:**

- **Cloud Credentials:** AWS access keys, secret keys, session tokens; Azure credentials; GCP service account keys
- **API Keys:** Generic API keys, Stripe keys, Twilio tokens, SendGrid keys, and more
- **Authentication Tokens:** OAuth tokens, JWT tokens, bearer tokens
- **Database Credentials:** Connection strings, database passwords, MongoDB URIs
- **Private Keys:** SSH keys, RSA keys, EC keys, PGP private keys
- **Version Control Tokens:** GitHub tokens, GitLab tokens, Bitbucket tokens
- **High-Entropy Strings:** Base64-encoded secrets, hexadecimal secrets, random tokens

**Key Features:**

- **Configurable Entropy Thresholds:** Adjust sensitivity for different environments
- **Baseline File Support:** Track known secrets to reduce false positives
- **File Size Limits:** Configurable limits to handle large files efficiently
- **Comprehensive Exclude Patterns:** Automatically exclude build artifacts, dependencies, and generated files
- **Git History Analysis:** Optional deep scanning of commit history with configurable depth and date ranges

### API Security Module

The API Security Module analyzes OpenAPI 3.x specifications to identify security vulnerabilities and misconfigurations in API designs. It helps ensure your APIs follow security best practices before deployment.

**Analysis Categories:**

- **Authentication:** Detects missing or weak authentication mechanisms, JWT expiration issues, insecure token storage
- **Authorization:** Identifies missing authorization checks, overly permissive access controls, RBAC gaps
- **Input Validation:** Finds missing request validation, SQL injection risks, file upload size limits, XSS vulnerabilities
- **Data Exposure:** Detects sensitive data in URLs/headers, missing encryption, improper PII handling
- **Security Headers:** Identifies missing security headers, insecure CORS configuration, missing CSP headers
- **API Design:** Analyzes versioning issues, error handling, information disclosure, pagination security
- **OAuth/OIDC:** Detects insecure OAuth flows, missing token validation, redirect URI issues, scope problems

**Key Features:**

- **OpenAPI 3.x Support:** Full support for OpenAPI 3.0 and 3.1 specifications via `oas3` crate
- **Configurable Analyzers:** Enable or disable specific analyzers based on your needs
- **Severity Overrides:** Customize severity levels for specific vulnerability types
- **Path Exclusion:** Exclude specific API paths from analysis
- **Strict Mode:** Enable more aggressive security checks for high-security environments
- **Comprehensive Reporting:** Detailed findings with remediation suggestions

**For detailed module documentation and examples, see [Analysis Modules Examples](docs/examples/analysis-modules.md).**

---

## ⚙️ Configuration

Vulnera can be configured via TOML files in `config/` and environment variables (prefix `VULNERA__`).

### Essential Configuration

```bash
# Database (required)
DATABASE_URL='postgresql://user:password@localhost:5432/vulnera'

# Authentication (required for production)
VULNERA__AUTH__JWT_SECRET='your-secret-minimum-32-characters'

# Cache (optional, recommended)
VULNERA__CACHE__DRAGONFLY_URL="redis://127.0.0.1:6379"
```

### Configuration Profiles

- `development` - Development settings (default)
- `production` - Production settings

Set via `ENV` environment variable.

**For complete configuration options, see [Configuration Examples](docs/examples/configuration.md).**

---

## 🔐 Authentication

Vulnera supports two authentication methods:

1. **JWT Bearer Tokens** - For interactive sessions (default 24 hours)
2. **API Keys** - For service integrations and CI/CD pipelines

**For authentication examples and setup, see [Authentication Examples](docs/examples/authentication.md).**

### Quick Authentication Example

```bash
# Register
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePassword123"}'

# Use token
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"ecosystem": "npm", "content": "express@4.17.1"}'
```

---

## 🧑‍💻 Development

### Setup

```bash
make -C scripts/build_workflow install-deps
pre-commit install
```

### Testing

```bash
# Run all tests
cargo test

# Run parser tests only
cargo test parsers

# Run CI checks
make -C scripts/build_workflow ci-check
```

### Project Structure

```text
vulnera/
├── vulnera-core/      # Core domain and infrastructure
├── vulnera-deps/      # Dependency analysis module
├── vulnera-sast/      # SAST analysis module
├── vulnera-secrets/   # Secrets detection module
├── vulnera-api/       # API security module
├── vulnera-orchestrator/  # Orchestration and API layer
├── config/            # Configuration files
├── migrations/        # Database migrations
└── docs/              # Documentation
```

**For contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).**

---

## 🚀 Deployment

### Docker

```bash
docker build -t vulnera-rust .
docker run -p 3000:3000 \
  -e DATABASE_URL='postgresql://user:password@host:5432/vulnera' \
  vulnera-rust
```

### Production Considerations

- Use strong JWT secrets (minimum 32 characters)
- Disable API docs in production (`VULNERA__SERVER__ENABLE_DOCS=false`)
- Restrict CORS origins
- Use API keys for service integrations
- Enable HTTPS and security headers
- Configure proper database connection pooling
- Set up monitoring and logging

### Azure Cloud Architecture

Vulnera is designed for cloud-native deployment on Microsoft Azure:

- **Edge:** Azure Front Door for global entry, TLS, and WAF
- **Identity:** Entra Managed Identities for workload identity
- **API Gateway:** Azure API Management for routing and throttling
- **Compute:** Azure App Service or Azure Container Apps
- **Storage:** Azure Container Registry for images
- **Secrets:** Azure Key Vault for API keys and configuration
- **Observability:** Application Insights + Azure Monitor

![Azure Architecture](./docs/Azure_Arch.png)

---

## ⚡ Performance Tuning

Control concurrent package processing and caching for optimal performance:

```bash
# Default: 3 packages in parallel
VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=3

# For larger systems
VULNERA__ANALYSIS__MAX_CONCURRENT_PACKAGES=8

# Configure cache TTL to reduce API calls
VULNERA__CACHE__TTL_HOURS=24
```

**For more performance tuning options, see [Configuration Examples](docs/examples/configuration.md).**

---

## 🐞 Troubleshooting

### Common Issues

- **Build errors:** Update Rust, install system dependencies (`pkg-config`, `libssl-dev`)
- **API rate limits:** Provide API keys for OSV/NVD/GHSA
- **Cache issues:** Check Dragonfly DB connection and adjust TTL
- **Database connection:** Verify PostgreSQL is running and `DATABASE_URL` is correct

### Debug Mode

```bash
VULNERA__LOGGING__LEVEL=debug cargo run
```

**For more troubleshooting help, see the [Quick Start Guide](docs/QUICK_START.md#troubleshooting).**

---

## 🦀 Why Rust?

- **Performance:** Compiled and memory-safe, enabling faster analysis than interpreted languages
- **Concurrency:** Tokio async runtime allows true parallelism and efficient IO
- **Reliability:** Strict type system and error handling prevent runtime bugs
- **Security:** Eliminates entire classes of memory safety vulnerabilities
- **Scalability:** Async and concurrency model scales to thousands of requests with minimal resources

---

## 👥 Team

- Khaled Mahmoud — Project Manager, Main Developer, Rust Backend Developer
- Abd El-Rahman Mossad — Frontend Developer - Extension, LSP Server Developer and Maintainer
- Amr Medhat — Cloud Engineer
- Gasser Mohammed — Frontend Developer

---

## 📝 License

Affero GPL v3.0 or later — see [LICENSE](./LICENSE).

---

## 🌐 Related Projects

- **[Vulnera Frontend](https://github.com/k5602/Vulnera-Frontend)** - Official web UI

---

## 📜 Changelog

See [CHANGELOG.md](CHANGELOG.md) for the latest updates and version history.

---

## 🗺️ Roadmap

See [docs/roadmap.md](docs/roadmap.md) for planned features and development roadmap.

---

## 🔐 Security Policy

- **Responsible disclosure:** Use GitHub Security Advisories for private coordination
- **Secret management:** Prefer Entra Managed Identities and Key Vault on Azure
- **Response time:** Within 72 hours

---

## 🔁 Versioning

- **Semantic Versioning (SemVer):** MAJOR.MINOR.PATCH
- Release notes published in GitHub Releases
- Breaking changes highlighted in release notes

---

## 📖 Additional Resources

- [API Documentation](http://localhost:3000/docs) - Interactive Swagger UI
- [OpenAPI Specification](http://localhost:3000/docs/openapi.json) - Machine-readable API spec
- [Code of Conduct](CODE_OF_CONDUCT.md) - Community guidelines
- [Contributing Guide](CONTRIBUTING.md) - How to contribute
