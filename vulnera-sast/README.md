# Vulnera SAST

Static Application Security Testing (SAST) module for Vulnera. It scans source code with tree‑sitter queries, builds a call graph, and runs taint analysis to surface security findings and SARIF output.

## Supported languages

- Python
- JavaScript
- TypeScript
- Rust
- Go
- C
- C++

JSX/TSX files are not scanned.

## Pipeline (high level)

1. **Scan**: discover files and map them to a language.
2. **Call graph**: parse all files and resolve cross‑file calls.
3. **Pattern rules**: run tree‑sitter queries and metavariable rules per file.
4. **Taint analysis**: sources → sinks with sanitizer awareness.
5. **Post‑process**: dedupe, adjust severity, and export SARIF.

## Core components

- `ScanProjectUseCase`: pipeline orchestration.
- `SastEngine`: parsing, query execution, and taint detection.
- `RuleRepository`: built‑in rules + optional file rules (TOML/YAML/JSON).
- `AstCacheService`: optional AST caching (Dragonfly or in‑memory).
- `IncrementalTracker`: skip unchanged files when enabled.

## Configuration

Configuration is provided via `vulnera_core::config::SastConfig` and `AnalysisConfig`.

Key settings:

- Scan depth and exclude patterns
- Rule file path and taint config path
- Analysis depth (Quick / Standard / Deep)
- AST caching and incremental analysis
- JS/TS frontend rollout (`js_ts_frontend = "oxc_preferred"` by default; set to `tree_sitter` to opt out)
- Policy gates (`min_finding_severity`, `min_finding_confidence`, recommendation/evidence requirements)

## Rule system

- **Pattern rules**: tree‑sitter queries and metavariable patterns.
- **Taint rules**: sources, sinks, and sanitizers (built‑in + optional custom).

Rules are stored under `vulnera-sast/rules/` and taint patterns under `vulnera-sast/taint-patterns/`.

## Outputs

- `Finding` list with location, severity, confidence, and optional data‑flow path.
- SARIF v2.1.0 export via `ScanResult::to_sarif_json`.

## Testing

- Unit tests: `cargo test -p vulnera-sast`
- Data-driven SAST rules: `cargo test -p vulnera-sast --test datatest_sast_rules`
- Snapshot review: `cargo insta review`

## Benchmarking at scale

Run baseline vs tuned parallelism comparison on a target repository:

- `cargo run -p vulnera-sast --example scale_benchmark -- /path/to/repo`
- Optional args: `iterations` and `depth` (`quick|standard|deep`)
- Example: `cargo run -p vulnera-sast --example scale_benchmark -- . 5 deep`

## Limitations

- Tree‑sitter is syntax‑level; no macro expansion or full type resolution.
- Data‑flow is conservative and may produce false positives in complex flows.

## License

See the root project LICENSE.
