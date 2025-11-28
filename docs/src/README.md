# Vulnera

> High-Performance Vulnerability Analysis Platform

**Vulnera** is a fast, scalable, multi-ecosystem vulnerability analysis toolkit and testing platform built in Rust. It provides comprehensive security analysis capabilities including:

- **Dependency Vulnerability Scanning** — Multi-ecosystem support (npm, PyPI, Maven, Cargo, Go, and more)
- **Static Analysis (SAST)** — AST-based code analysis for Python, JavaScript, and Rust
- **Secrets Detection** — Regex and entropy-based credential detection
- **API Security Auditing** — OpenAPI 3.x specification analysis

## Why Vulnera?

Built with **Rust** for superior performance, Vulnera delivers 50-80% faster analysis than competitors while maintaining memory safety guarantees. The platform aggregates vulnerability data from multiple authoritative sources (OSV, NVD, GitHub Security Advisories) to provide accurate, up-to-date security intelligence.

## Key Features

| Feature | Description |
|---------|-------------|
| **Unified Orchestration** | Single API endpoint for comprehensive multi-module analysis |
| **8+ Ecosystems** | npm, PyPI, Maven/Gradle, Cargo, Go, Packagist, Ruby, .NET |
| **Real-time Feedback** | Fast enough for pre-commit hooks and CI/CD pipelines |
| **Cloud-Native** | Docker and Kubernetes ready, Azure-optimized deployment |
| **API-First** | Comprehensive OpenAPI documentation with Swagger UI |

## Getting Started

New to Vulnera? Start with the [Quick Start Guide](getting-started/quick-start.md) to get up and running in minutes.

```bash
# Clone and build
git clone https://github.com/k5602/Vulnera.git
cd Vulnera
cargo build --release

# Run the server
cargo run
```

## Documentation Overview

This documentation is organized into the following sections:

- **Getting Started** — Installation, database setup, and initial configuration
- **User Guide** — CLI reference, API testing, configuration, and authentication
- **Analysis Modules** — Detailed documentation for each security analysis module
- **Architecture** — System design, domain-driven architecture, and future roadmap
- **Integration** — IDE extensions, CI/CD pipelines, and third-party integrations
- **Business & Operations** — Business model and operational documentation

## Quick Links

- [API Documentation](http://localhost:3000/docs) — Interactive Swagger UI
- [GitHub Repository](https://github.com/k5602/Vulnera) — Source code and issues
- [Changelog](https://github.com/k5602/Vulnera/blob/main/CHANGELOG.md) — Version history

## License

Vulnera is licensed under the [GNU Affero General Public License v3.0](https://github.com/k5602/Vulnera/blob/main/LICENSE).
