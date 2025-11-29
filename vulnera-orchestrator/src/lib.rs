//! Vulnera Orchestrator - Central orchestration service for security analysis
//!
//! This crate provides the main API server and job orchestration for Vulnera,
//! coordinating multi-module security analysis across the platform.
//!
//! # Features
//!
//! - **HTTP API** — RESTful API with OpenAPI/Swagger documentation
//! - **Job Orchestration** — Async job queue with parallel module execution
//! - **Module Registry** — Centralized registration of analysis modules
//! - **Authentication** — HttpOnly cookie-based auth (browser) with CSRF protection, and API keys (CLI)
//! - **Rate Limiting** — Tier-based rate limiting with Dragonfly backend
//!
//! # Architecture
//!
//! ```text
//! vulnera-orchestrator/
//! ├── presentation/     # HTTP layer
//! │   ├── controllers/  # Request handlers
//! │   ├── middleware/   # Auth, rate limiting
//! │   ├── models/       # DTOs with OpenAPI schemas
//! │   └── routes.rs     # API route definitions
//! ├── application/      # Use cases
//! │   ├── job_worker.rs # Background job processor
//! │   └── use_cases/    # Business operations
//! ├── infrastructure/   # External integrations
//! │   ├── job_queue.rs  # Dragonfly-backed job store
//! │   └── module_selector.rs
//! └── domain/           # Domain models
//! ```
//!
//! # API Endpoints
//!
//! | Endpoint | Method | Description |
//! |----------|--------|-------------|
//! | `/api/v1/analyze/job` | POST | Create analysis job |
//! | `/api/v1/jobs/{id}` | GET | Get job status |
//! | `/api/v1/auth/login` | POST | User authentication |
//! | `/api/v1/auth/register` | POST | User registration |
//! | `/health` | GET | Health check |
//! | `/metrics` | GET | Prometheus metrics |
//!
//! # Usage
//!
//! The orchestrator is typically started via the main binary:
//!
//! ```bash
//! cargo run
//! ```
//!
//! Or via Docker:
//!
//! ```bash
//! docker run -p 3000:3000 vulnera
//! ```

pub mod application;
pub mod domain;
pub mod infrastructure;
pub mod presentation;
