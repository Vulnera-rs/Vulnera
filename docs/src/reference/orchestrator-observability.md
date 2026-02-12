# Orchestrator Observability Architecture

This document defines the observability architecture for the orchestration pipeline from job creation through module execution and lifecycle persistence.

## Goals

- Make orchestration failures actionable in production.
- Preserve request/job context across async boundaries.
- Keep logging structured and queryable.
- Minimize hidden failure modes in state transitions.

## Scope

Applies to:

- `CreateAnalysisJobUseCase`
- `ExecuteAnalysisJobUseCase`
- `JobWorkflow`
- Worker execution path in `job_queue`

## Design Principles

1. **Context at boundaries**
   - Every public use-case/workflow entrypoint must emit structured context at start and finish.
   - Required identifiers: `job_id`, `project_id`, `module`, and transition target when applicable.

2. **Error locality**
   - Failures should be logged as close as possible to their source with operation-specific metadata.
   - Callers should receive typed errors; logs carry operational detail.

3. **State-machine visibility**
   - Every job transition (`Pending -> Queued -> Running -> Completed/Failed/Cancelled`) must be visible in logs with reason and timing.

4. **Async fan-out accountability**
   - Parallel module execution logs should expose:
     - module spawn
     - module completion/failure
     - aggregate completion counts

5. **No panic paths in orchestration**
   - Runtime errors should not panic in production paths.

## Event Model

### Job Lifecycle Events

- `job.lifecycle.enqueue`
- `job.lifecycle.start`
- `job.lifecycle.complete`
- `job.lifecycle.fail`
- `job.lifecycle.cancel`

Suggested fields:

- `job_id`
- `project_id`
- `status_from`
- `status_to`
- `reason`
- `duration_ms` (where applicable)

### Module Execution Events

- `job.module.spawn`
- `job.module.complete`
- `job.module.error`
- `job.module.panic` (unexpected task panic)

Suggested fields:

- `job_id`
- `module`
- `duration_ms`
- `error`

## Instrumentation Strategy

- Use `#[instrument]` on public async orchestration methods.
- Use `info` for lifecycle milestones.
- Use `warn` for degraded-but-continued paths.
- Use `error` for failed operations and panics.
- Include elapsed timing at operation boundaries for coarse latency tracking.

## Operational Outcomes

With this architecture, operators can answer:

- Which phase is failing most often?
- Which module frequently exceeds expected runtime?
- Which jobs failed due to transition/persistence errors vs module logic?
- How long jobs spend in each phase.

## Future Extensions

- Export spans to OpenTelemetry collector.
- Add metrics counters/histograms aligned with event model.
- Correlate webhook delivery outcomes with lifecycle events.
