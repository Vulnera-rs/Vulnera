# SAST Module (Static Application Security Testing)

The SAST module performs offline, multi-language static analysis using Tree-sitter parsing, optional OXC frontend for JS/TS, and inter-procedural taint analysis with call-graph support.

## Overview

SAST analyzes source code to detect security flaws such as injection, insecure crypto, unsafe deserialization, and risky `unsafe` usage patterns. It emits findings in Vulnera’s unified schema and supports SARIF output.

## Supported Languages

| Language   | Parser                       | File Extensions       |
| ---------- | ---------------------------- | --------------------- |
| Python     | tree-sitter-python           | `.py`                 |
| JavaScript | tree-sitter-javascript / OXC | `.js`                 |
| TypeScript | tree-sitter-javascript / OXC | `.ts`                 |
| Rust       | tree-sitter-rust             | `.rs`                 |
| Go         | tree-sitter-go               | `.go`                 |
| C          | tree-sitter-c                | `.c`, `.h`            |
| C++        | tree-sitter-cpp              | `.cpp`, `.cc`, `.hpp` |

**Note:** JSX/TSX files are not scanned.

## Pipeline (High-Level)

1. **Discovery** — Walks files and maps them to supported languages.
2. **Parsing** — Builds ASTs with Tree-sitter; optional OXC for JS/TS.
3. **Rule matching** — Applies TOML rule packs to AST patterns.
4. **Taint analysis** — Tracks source → sink flow across functions and files.
5. **Call graph** — Resolves cross-file calls to expand reachability.
6. **Post-process** — Dedupes, scores severity/confidence, emits findings.

## Rule System

SAST rules are TOML-based and embedded at build time. Optional Git-based rule packs can be configured.

**Rule locations:**

- `vulnera-sast/rules/*.toml` — core rule packs
- `vulnera-sast/taint-patterns/*.toml` — taint sources/sinks/sanitizers
- `vulnera-sast/tests/fixtures/` — CVE fixtures for quality gates

## Analysis Depth (SAST)

Depth controls the SAST engine’s thoroughness (separate from orchestrator depth):

| Depth      | Description                                                          |
| ---------- | -------------------------------------------------------------------- |
| `quick`    | Pattern matching only (no data-flow analysis)                        |
| `standard` | Patterns + intra-procedural data flow                                |
| `deep`     | Full analysis (patterns + data flow + call graph + inter-procedural) |

Dynamic depth adjustment is enabled by default to keep large repos within time budgets.

## CLI Usage (Actual Flags)

```/dev/null/commands.txt#L1-12
# Basic scan
vulnera sast .

# Severity filter
vulnera sast . --min-severity high

# Only changed files (git required)
vulnera sast . --changed-only

# Exclude paths (glob patterns)
vulnera sast . --exclude "tests/*,vendor/*"
```

**Available flags:**

- `--min-severity <critical|high|medium|low>`
- `--fail-on-vuln`
- `--changed-only`
- `--files <path1,path2,...>`
- `--exclude <glob1,glob2,...>`
- `--languages <lang1,lang2,...>` (override auto-detection)
- `--rules <category1,category2,...>` (rule categories)
- `--no-cache` (disable incremental cache)
- `--watch` (continuous scanning)
- `--fix` (LLM-powered bulk fixes; requires online + auth + quota)
- `--baseline <path>` (baseline file for diff)
- `--save-baseline` (save current findings to baseline)
- `--only-new` (report only findings not in baseline)

## Configuration

Configured via `vulnera_core::config::SastConfig` and `AnalysisConfig`.

Key settings:

- `analysis_depth = "quick|standard|deep"`
- `js_ts_frontend = "oxc_preferred" | "tree_sitter"`
- `enable_data_flow`, `enable_call_graph`
- `enable_ast_cache`, `ast_cache_ttl_hours`
- `dynamic_depth_enabled`, file/size thresholds
- `min_finding_severity`, `min_finding_confidence`
- `rule_packs` and `rule_pack_allowlist`

Example (TOML):

```/dev/null/config.toml#L1-16
[sast]
analysis_depth = "standard"
js_ts_frontend = "oxc_preferred"
enable_data_flow = true
enable_call_graph = true
enable_ast_cache = true
dynamic_depth_enabled = true
min_finding_severity = "low"
min_finding_confidence = "low"
```

## Output

Findings include:

- `severity` and `confidence`
- `location` (path + line/column)
- optional `snippet` and `semantic_path` (taint trace)

SARIF output:

```/dev/null/commands.txt#L1-2
vulnera sast . --format sarif > report.sarif
```

## Quality Gates

Fixture-based accuracy thresholds are enforced in CI (from `config/default.toml`):

- Precision: ≥ 0.70
- Recall: ≥ 0.50
- Unique CWE coverage: ≥ 12
- Languages with fixtures: ≥ 7

## Limitations

- Tree-sitter is syntax-level; no macro expansion or full type resolution.
- Runtime behavior and dynamic code generation are out of scope.
- JSX/TSX files are excluded.

## Next Steps

- [Analysis Overview](../analysis/overview.md)
- [Configuration Reference](../reference/configuration.md)
