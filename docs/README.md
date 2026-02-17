# Vulnera Workspace Docs Index

This page is the onboarding index for contributors working in the monorepo.

## Workspace Hook (Single Source)

- Pre-commit hook config: `/.pre-commit-config.yaml`
- Native git hook script: `/.githooks/pre-commit`

Use this once at the workspace root:

```bash
chmod +x .githooks/pre-commit
git config core.hooksPath .githooks
```

## Crate Overview

- Root server workspace: `/` (this repo)
- Adapter (LSP): `/adapter`
- Advisors: `/advisors`
- CLI: `/vulnera-cli`
- Core: `/vulnera-core`
- Orchestrator: `/vulnera-orchestrator`
- Dependencies module: `/vulnera-deps`
- SAST module: `/vulnera-sast`
- Secrets module: `/vulnera-secrets`
- API module: `/vulnera-api`
- LLM module: `/vulnera-llm`
- Sandbox module: `/vulnera-sandbox`

## Crate Docs / Changelog Links

### Root Workspace
- README: `/README.md`
- Changelog: `/CHANGELOG.md`
- Book/docs source: `/docs/src`

### Adapter
- README: `/adapter/README.md`

### Advisors
- README: `/advisors/README.md`
- Docs: `/advisors/docs/README.md`
- Changelog: `/advisors/CHANGELOG.md`

### CLI
- README: `/vulnera-cli/README.md`
- Docs index: `/vulnera-cli/docs/README.md`
- Changelog: `/vulnera-cli/CHANGELOG.md`

### SAST
- README: `/vulnera-sast/README.md`

## Contributor Quick Path

1. Start at `/README.md` and this file (`/docs/README.md`).
2. Set root git hooks once.
3. Use crate-local README/docs for module-specific workflows.
4. Track changes in `/CHANGELOG.md` (root) and crate-specific changelogs where applicable.
