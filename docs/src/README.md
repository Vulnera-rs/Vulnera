# Vulnera — AI-Assisted Vulnerability Analysis Platform

> Lightning-fast, comprehensive security analysis. Powered by Rust performance and AI-enhanced insights.

**Vulnera** is your unified security partner—combining ultrafast vulnerability scanning with AI-powered explanations and code fixes. Stop managing fragmented point solutions. Get smarter security insights in seconds.

**Get Started:** Visit **[vulnera.studio](https://vulnera.studio)** to create your free account and start scanning in seconds.

## What Vulnera Does

### 🔍 AI-Assisted Security Analysis

Detect vulnerabilities across your entire codebase with intelligent analysis modules:

- **AI-Assisted Secret Detection** — Powered by ML-based pattern recognition and entropy analysis to catch exposed credentials before they leak
- **AI-Assisted Code Analysis** — AST-powered static analysis for Python, JavaScript, and Rust to find security flaws in source code
- **Dependency Vulnerability Scanning** — Coverage across 8+ ecosystems (npm, PyPI, Maven, Cargo, Go, Ruby, .NET, Packagist)
- **AI-Assisted API Security Analysis** — OpenAPI specification analysis to identify authentication, authorization, and data exposure issues

### 🤖 AI-Powered Explanations & Code Fixes

Beyond detection—understand and remediate:

- **Vulnerability Explanations** — Get human-readable explanations of every security issue (powered by LLM)
- **AI-Generated Code Fixes** — Receive actionable code snippets with remediation guidance (powered by LLM)
- **Natural Language Queries** — Ask security questions in plain English, get instant answers (powered by LLM)

### ⚡ Performance You'll Notice

- **50-80% faster** than competitors (Rust-based)
- **Real-time feedback** — Pre-commit hooks, instant CI/CD results
- **Offline-first analysis** — Local scanning without server dependency (SAST, secrets, API analysis)

## Who Is Vulnera For?

**Individual Developers** → Catch vulnerabilities before commits (use CLI or web dashboard)
**Security Teams** → Unified platform for multi-team oversight with team collaboration
**DevOps/Cloud Engineers** → Scan repositories and S3 buckets at scale with shared quotas
**Tool Integrators** → Embed security analysis in IDEs and CI/CD systems via API

## Quick Start by Role

Choose your path:

| Role                              | Web Dashboard                                                         | CLI / Local                                                                         |
| --------------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| **Individual Developer**          | [Web + Local](https://vulnera.studio)                                 | [Developer Quick Start](getting-started/personas/developer-quickstart.md)           |
| **Security Team Lead**            | [Team Collaboration](user-guide/dashboard/team-collaboration.md)      | [DevSecOps Quick Start](getting-started/personas/devsecops-quickstart.md)           |
| **Cloud/Infrastructure Engineer** | [Organization Setup](user-guide/dashboard/organization-management.md) | [Cloud Engineer Quick Start](getting-started/personas/cloud-engineer-quickstart.md) |

## Why Choose Vulnera?

| Benefit                      | Impact                                                          |
| ---------------------------- | --------------------------------------------------------------- |
| **Unified Platform**         | Replace 4+ separate tools with one integrated solution          |
| **AI-Enhanced Insights**     | Get explanations and fixes automatically—not just raw CVE lists |
| **Multi-Ecosystem Coverage** | 8+ package managers in one place                                |
| **Offline First**            | Scan locally without network dependency                         |
| **Developer-Friendly**       | Integrates seamlessly into workflows (CLI, API, IDE extensions) |
| **Memory Safe**              | Built in Rust for reliability and security                      |
| **Open Source**              | AGPL v3.0—full transparency, community-driven                   |

## Key Capabilities at a Glance

- ✅ **Offline vulnerability scanning** (SAST, secrets, API)
- ✅ **Multi-ecosystem dependency analysis** (npm, PyPI, Maven, Cargo, Go, Ruby, .NET, Packagist)
- ✅ **AI-powered remediation** (code fixes + explanations)
- ✅ **Team collaboration** (organizations, member management, shared quotas)
- ✅ **Real-time CI/CD integration** (GitHub, GitLab, Azure Pipelines)
- ✅ **Cloud-native** (S3 bucket scanning, repository analysis)
- ✅ **API-first design** (comprehensive REST + WebSocket support)

## Documentation Structure

### Getting Started

- **[Web Dashboard Guide](user-guide/dashboard/guide.md)** — Features, settings, integrations
- **[Organization Management](user-guide/dashboard/organization-management.md)** — Create teams, manage members, shared quotas
- **[Team Collaboration](user-guide/dashboard/team-collaboration.md)** — Workflows for security teams and developers

### For Users

- **[Analysis Capabilities](analysis/overview.md)** — Learn what each analysis module does
- **[AI-Powered Features](user-guide/llm-features.md)** — Explanations, code fixes, and natural language queries
- **[Quota & Pricing](user-guide/quota-pricing.md)** — Understand rate limits and cost weighting

### For Integrators & DevOps

- **[API Reference](user-guide/api-reference.md)** — Complete endpoint documentation
- **[CI/CD Integration](getting-started/personas/devsecops-quickstart.md)** — GitHub Actions, GitLab CI, Azure DevOps

## Get Started Now

### Option 1: Web Dashboard (Recommended for Teams)

**Fastest path for team setup:**

1. Visit **[vulnera.studio](https://vulnera.studio)**
2. Sign up with email
3. Create organization (or skip for personal use)
4. Invite team members (optional)
5. Generate API key from Settings
6. Use key with CLI for scanning

```bash
# Get API key from https://vulnera.studio/settings/api-keys
vulnera auth login --api-key YOUR_API_KEY

# Scan your project (uses team quota)
vulnera analyze /path/to/your/project --all-modules
```

### Option 2: CLI Only (No Account Needed)

**Run offline scans without authentication:**

```bash
# Install from pre-built binary
curl -L https://github.com/k5602/Vulnera/releases/latest/download/vulnera-linux-x86_64 -o vulnera
chmod +x vulnera

# Run offline analysis (SAST, Secrets, API - no auth needed)
./vulnera analyze /path/to/your/project --modules sast,secrets,api

# See AI-powered explanations for findings
./vulnera analyze /path/to/your/project --format json | jq '.findings[] | .llm_explanation'
```

**Note:** Full dependency scanning requires authentication with API key from [vulnera.studio](https://vulnera.studio).

## Why Choose vulnera.studio?

| Feature                | Benefit                                                         |
| ---------------------- | --------------------------------------------------------------- |
| **Web Dashboard**      | Beautiful UI for viewing scans, findings, and trends            |
| **Team Collaboration** | Invite members, share quota, assign findings, comment on issues |
| **Integrations**       | Connect GitHub, GitLab, Slack for automated workflows           |
| **Analytics**          | Track team metrics, generate compliance reports                 |
| **API Keys**           | Secure CI/CD integration with role-based access                 |
| **Webhooks**           | Real-time notifications to your tools                           |
| **Free Tier**          | 48 tokens/month shared quota, perfect for small teams           |
| **Enterprise**         | SSO/SAML, custom domains, priority support for large orgs       |
