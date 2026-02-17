# SAST (Static Application Security Testing)

Vulnera SAST detects security issues in source code using Tree-sitter parsing, a call-graph builder, and inter-procedural taint analysis. It is fully offline and runs locally.

## What It Detects

Common categories include:

- SQL injection and command injection
- XSS and HTML injection
- Unsafe deserialization and dynamic code execution
- Insecure crypto and weak randomness
- Path traversal and file disclosure
- Unsafe `unsafe` usage patterns (Rust)

## How It Works

**Pipeline overview:**

1. **Discovery** — Walks the project and maps files to supported languages.
2. **Parsing** — Builds syntax trees using Tree-sitter (with OXC for JS/TS when enabled).
3. **Rule matching** — Applies TOML rule packs to AST patterns.
4. **Taint analysis** — Tracks source → sink flow, intra- and inter-procedural.
5. **Call graph** — Resolves function calls across files to expand taint reachability.
6. **Post-process** — Dedupes, scores confidence/severity, emits unified findings.

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

## Analysis Depth (SAST)

Depth controls the SAST engine’s thoroughness (separate from orchestrator depth):

| Depth      | Description                                                          |
| ---------- | -------------------------------------------------------------------- |
| `quick`    | Pattern matching only (no data-flow analysis)                        |
| `standard` | Patterns + intra-procedural data flow                                |
| `deep`     | Full analysis (patterns + data flow + call graph + inter-procedural) |

Dynamic depth adjustment is enabled by default. Large repositories are auto-downgraded to keep scans within time budgets. Disable with `VULNERA__SAST__DYNAMIC_DEPTH_ENABLED=false`.

## Rule System

Rules are TOML-based and embedded at build time. You can optionally load Git-based rule packs.

**Locations:**

- `vulnera-sast/rules/*.toml` — core rule packs
- `vulnera-sast/taint-patterns/*.toml` — taint sources/sinks/sanitizers
- `vulnera-sast/tests/fixtures/` — CVE fixtures for quality gates

## CLI Usage (Actual Flags)

SAST runs via `vulnera sast`:

```/dev/null/commands.txt#L1-12
# Basic scan
vulnera sast .

# Severity filter
vulnera sast . --min-severity high

# Only changed files (git required)
vulnera sast . --changed-only

# Explicit file list
vulnera sast . --files src/main.rs,src/lib.rs

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

## Output

SAST findings are emitted in the unified finding schema:

- `severity` and `confidence`
- `location` (path + line/column)
- optional `snippet` and `semantic_path` (taint trace)

You can emit SARIF:

```/dev/null/commands.txt#L1-2
vulnera sast . --format sarif > report.sarif
```

## Configuration (Server + Library)

The SAST engine is configured via `vulnera_core::config::SastConfig` and `AnalysisConfig`.

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

## Offline Guarantees

SAST runs fully offline:

- No network calls
- All rule packs embedded unless you configure external rule packs

## Quality Gates

The SAST module ships with a fixture-based accuracy harness enforced in CI.

Thresholds (from `config/default.toml`):

- Precision: ≥ 0.70
- Recall: ≥ 0.50
- Unique CWE coverage: ≥ 12
- Languages with fixtures: ≥ 7

## Limitations

- Tree-sitter is syntax-level; no macro expansion or full type resolution.
- Dynamic code generation and runtime behavior are out of scope.
- JSX/TSX files are excluded.

## Next Steps

- [Analysis Overview](overview.md)
- [Module Reference: SAST](../modules/sast.md)
- [Configuration Reference](../reference/configuration.md)
