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

// Organization & analytics repositories
pub mod analysis_events_repository;
pub mod organization_member_repository;
pub mod organization_repository;
pub mod persisted_job_repository;
pub mod personal_stats_repository;
pub mod subscription_limits_repository;
pub mod user_stats_repository;

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

// Organization & analytics repository exports
pub use analysis_events_repository::SqlxAnalysisEventRepository;
pub use organization_member_repository::SqlxOrganizationMemberRepository;
pub use organization_repository::SqlxOrganizationRepository;
pub use persisted_job_repository::SqlxPersistedJobResultRepository;
pub use personal_stats_repository::SqlxPersonalStatsMonthlyRepository;
pub use subscription_limits_repository::SqlxSubscriptionLimitsRepository;
pub use user_stats_repository::SqlxUserStatsMonthlyRepository;
