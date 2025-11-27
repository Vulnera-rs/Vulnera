//! Rate Limiting Infrastructure
//!
//! This module provides a unified rate limiting system with:
//! - Token bucket algorithm for general API rate limiting (allows bursts)
//! - Sliding window counter for auth endpoint protection (stricter, no bursts)
//! - Tiered limits based on authentication type (API Key > Cookie Auth > Anonymous)
//! - Dragonfly/Redis storage for distributed rate limiting

pub mod service;
pub mod sliding_window;
pub mod storage;
pub mod token_bucket;
pub mod types;

pub use service::RateLimiterService;
pub use types::{AuthTier, RateLimitKey, RateLimitResult};
