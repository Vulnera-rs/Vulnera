//! Authentication infrastructure services

pub mod api_key_generator;
pub mod api_key_repository;
pub mod brute_force_protection;
pub mod csrf_service;
pub mod distributed_rate_limiter;
pub mod jwt_service;
pub mod password_hasher;
pub mod token_blacklist;
pub mod user_repository;

pub use api_key_generator::ApiKeyGenerator;
pub use api_key_repository::SqlxApiKeyRepository;
pub use brute_force_protection::{
    BruteForceConfig, BruteForceProtection, CacheBruteForceProtection, LoginAttemptData,
    LoginPermission,
};
pub use csrf_service::CsrfService;
pub use distributed_rate_limiter::{
    CacheDistributedRateLimiter, DistributedRateLimitConfig, DistributedRateLimiter,
    RateLimitResult,
};
pub use jwt_service::JwtService;
pub use password_hasher::PasswordHasher;
pub use token_blacklist::{CacheTokenBlacklistService, TokenBlacklistService};
pub use user_repository::SqlxUserRepository;
