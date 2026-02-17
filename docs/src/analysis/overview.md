# Analysis Capabilities Overview

Vulnera provides four specialized analysis modules powered by purpose-built detection techniques. Each module is independently selectable and produces findings in a unified schema.

## The Four Analysis Modules

| Module                                        | Purpose                                 | Method                                            | Offline? | Coverage                                                     |
| --------------------------------------------- | --------------------------------------- | ------------------------------------------------- | -------- | ------------------------------------------------------------ |
| [Dependency Analysis](dependency-analysis.md) | Find known CVEs in third-party packages | Registry lookup (OSV · NVD · GHSA)                | ❌ No    | npm, PyPI, Cargo, Maven/Gradle, Go, Composer, Bundler, NuGet |
| [SAST](sast.md)                               | Find security flaws in source code      | Tree-sitter AST + inter-procedural taint analysis | ✅ Yes   | Python, JavaScript, TypeScript, Rust, Go, C, C++             |
| [Secrets Detection](secrets-detection.md)     | Find exposed credentials and tokens     | Regex + entropy detection                         | ✅ Yes   | All text files                                               |
| [API Security](api-security.md)               | Find misconfigurations in API specs     | Rule-based spec analysis                          | ✅ Yes   | OpenAPI 3.0 / 3.1                                            |

LLM enrichment (Google Gemini, OpenAI, Azure OpenAI) is a separate post-processing pass that explains and proposes fixes for findings produced by the modules above. It is never part of detection and requires network access.

---

## How Module Selection Works

The orchestrator uses `RuleBasedModuleSelector` to automatically activate modules based on file patterns and analysis depth. You do not need to specify modules manually — the right ones run based on what is in the project.

```
Incoming source (directory / git / S3)
        │
        ▼
  File pattern detection
        │
        ├─ dependency manifests found?  → Dependency Analysis
        ├─ .py / .js / .ts / .rs / .go / .c / .cpp files?  → SAST
        ├─ all files  → Secrets Detection (always runs in Full)
        └─ openapi.yaml / openapi.json / swagger.yaml found?  → API Security
        │
        ▼
  Parallel execution (one sandbox per module)
        │
        ▼
  Aggregated findings report
```

---

## Analysis Depth (Orchestrator)

The **orchestrator** uses a coarse analysis depth to decide which modules to run:

| Depth               | Description                                      | Modules                     |
| ------------------- | ------------------------------------------------ | --------------------------- |
| `dependencies_only` | Dependencies only                                | deps                        |
| `fast_scan`         | Fast scan (dependencies + minimal code analysis) | deps + sast                 |
| `full`              | Full analysis (all applicable modules)           | deps + sast + secrets + api |

> Note: Module coverage still depends on project content. For example, SAST only runs if supported source files are present, and API Security only runs if an OpenAPI spec is detected.

---

## Analysis Depth (SAST)

The **SAST module** has its own depth semantics (separate from orchestrator depth):

| Depth      | Description                                                          |
| ---------- | -------------------------------------------------------------------- |
| `quick`    | Fast pattern matching only (no data-flow analysis)                   |
| `standard` | Balanced analysis (patterns + intra-procedural data flow)            |
| `deep`     | Full analysis (patterns + data flow + call graph + inter-procedural) |

Dynamic depth adjustment is enabled by default. Large repositories are auto-downgraded to keep scans within time budgets. Disable via `VULNERA__SAST__DYNAMIC_DEPTH_ENABLED=false`.

---

## Offline vs. Online Capabilities

### Fully offline (no network required)

- SAST — rule packs embedded at compile time
- Secrets Detection — regex + entropy detection locally
- API Security — OpenAPI rules locally

### Requires network

- **Dependency Analysis** — CVE lookup against OSV, NVD, GHSA, and registries
- **LLM enrichment** — explanations and fixes via external providers

---

## Unified Finding Schema

Every module emits findings in the same structure:

```/dev/null/finding.json#L1-28
{
  "id": "SAST-PY-SQL-001",
  "type": "vulnerability",
  "rule_id": "python-sql-injection",
  "location": {
    "path": "src/db.py",
    "line": 42,
    "column": 5,
    "end_line": 42,
    "end_column": 48
  },
  "severity": "high",
  "confidence": "high",
  "description": "User input concatenated directly into SQL query.",
  "recommendation": "Use parameterized queries or a query builder.",
  "secret_metadata": null,
  "vulnerability_metadata": {
    "snippet": "query = f\"SELECT * FROM users WHERE id={user_id}\"",
    "bindings": null,
    "semantic_path": null
  },
  "enrichment": null
}
```

The `enrichment` field is populated only when LLM enrichment is requested after analysis; `secret_metadata` is only present for secret findings.

---

## Module-Specific Documentation

- [Dependency Analysis](dependency-analysis.md) — ecosystem coverage, lockfile strategy, version recommendations
- [SAST](sast.md) — supported languages, rule packs, taint analysis, confidence scoring
- [Secrets Detection](secrets-detection.md) — detection methods, secret types, baselines
- [API Security](api-security.md) — analysis categories, detected issue types, strict mode
