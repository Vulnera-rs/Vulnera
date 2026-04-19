# vulnera-deps

Dependency analysis and vulnerability scanning for multiple package ecosystems.

## Purpose

Cross-ecosystem dependency resolution and CVE detection:

- **Lockfile parsing** - package-lock.json, Cargo.lock, poetry.lock, etc.
- **Vulnerability lookup** - GHSA, NVD, OSV, CISA KEV, EPSS, OSS Index
- **Version resolution** - Semantic versioning and constraint satisfaction
- **Transitive resolution** - Full dependency graph analysis

## Supported Ecosystems

| Ecosystem | Manifests | Lockfiles |
|-----------|-----------|-----------|
| npm/Node | package.json | package-lock.json, yarn.lock, pnpm-lock.yaml |
| Python | requirements.txt, Pipfile, pyproject.toml | poetry.lock, Pipfile.lock |
| Rust | Cargo.toml | Cargo.lock |
| Java | pom.xml, build.gradle | - |
| Go | go.mod | go.sum |
| Ruby | Gemfile | Gemfile.lock |
| PHP | composer.json | composer.lock |
| .NET | *.csproj | - |

## Key Features

- Multi-source vulnerability intelligence with caching
- Version range intersection for accurate vulnerability matching
- Git commit range matching for vulnerabilities affecting specific commits
- CWE filtering and normalization
- Workspace-aware analysis for monorepos

## Usage

Typically used via the orchestrator or CLI:

```bash
vulnera deps .  # CLI usage
```

## License

AGPL-3.0-or-later. See [LICENSE](../LICENSE) for details.
