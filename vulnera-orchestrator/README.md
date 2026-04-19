# vulnera-orchestrator

Async job orchestration, module registry, and REST API server for Vulnera.

## Purpose

This crate implements the HTTP server and job management layer:

- **Job queue** - Dragonfly-backed async job processing
- **Module registry** - Registration and lifecycle of analysis modules
- **REST API** - Axum-based HTTP controllers with OpenAPI documentation
- **Workflow engine** - `JobWorkflow` state machine for job lifecycle

## Architecture

```
presentation/     HTTP controllers and DTOs
application/      Use cases (CreateAnalysisJob, etc.)
domain/           Job entities, traits, value objects
infrastructure/   Job queue, store, module selector
```

## Key Features

- Async job worker pool with semaphore-based concurrency control
- Job status state machine: Pending → Queued → Running → Completed/Failed/Cancelled
- Webhook delivery with HMAC-SHA256 and exponential backoff retries
- Tiered rate limiting (anonymous / API key / organization)
- Organization model with RBAC (owner/admin/analyst/viewer)

## Usage

This is the main server crate. Run via:

```bash
cargo run -p vulnera-rust
```

## License

AGPL-3.0-or-later. See [LICENSE](../LICENSE) for details.
