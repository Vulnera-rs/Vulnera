# Vulnera Workspace Docs Index

This page is the onboarding index for contributors working in the monorepo.

## Workspace Hook (Single Source)

- Pre-commit hook config: `/.pre-commit-config.yaml`
- Native git hook script: `/.githooks/pre-commit`

Use this once at the workspace root:

```/dev/null/commands.txt#L1-2
chmod +x .githooks/pre-commit
git config core.hooksPath .githooks
```

## Canonical Documentation Sources

- Root project README: `/README.md`
- Change log: `/CHANGELOG.md`
- Docs book source: `/docs/src`
- Crate/Module map: `/docs/modules.md`
- Architecture diagram (Mermaid): `/docs/arch.mmd`
- Docs book config: `/docs/book.toml`

## Crate Overview (Monorepo)

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

## Crate Docs & Changelog Links

| Crate                  | README                    | Docs index                    | Changelog                   |
| ---------------------- | ------------------------- | ----------------------------- | --------------------------- |
| Root server            | `/README.md`              | `/docs/src/README.md`         | `/CHANGELOG.md`             |
| `adapter`              | `/adapter/README.md`      | —                             | —                           |
| `advisors`             | `/advisors/README.md`     | `/advisors/docs/README.md`    | `/advisors/CHANGELOG.md`    |
| `vulnera-cli`          | `/vulnera-cli/README.md`  | `/vulnera-cli/docs/README.md` | `/vulnera-cli/CHANGELOG.md` |
| `vulnera-sast`         | `/vulnera-sast/README.md` | —                             | —                           |
| `vulnera-core`         | —                         | —                             | —                           |
| `vulnera-orchestrator` | —                         | —                             | —                           |
| `vulnera-deps`         | —                         | —                             | —                           |
| `vulnera-secrets`      | —                         | —                             | —                           |
| `vulnera-api`          | —                         | —                             | —                           |
| `vulnera-llm`          | —                         | —                             | —                           |
| `vulnera-sandbox`      | —                         | —                             | —                           |

## Contributor Quick Path

1. Start at `/README.md` and this file (`/docs/README.md`).
2. Set root git hooks once.
3. Use `/docs/src` for canonical technical docs and `/docs/modules.md` for crate-level responsibilities.
4. Use crate-local README/docs where present.
5. Track changes in `/CHANGELOG.md` (root) and crate-specific changelogs where applicable.
