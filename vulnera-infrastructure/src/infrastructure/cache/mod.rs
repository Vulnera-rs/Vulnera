//! Cache infrastructure implementations

pub mod dragonfly_cache;
pub mod moka_cache;
pub mod null_cache;
pub mod tiered_cache;

pub use dragonfly_cache::DragonflyCache;
pub use moka_cache::MokaCache;
pub use null_cache::NoOpCache;
pub use tiered_cache::TieredCache;

/// Statistics returned by cache health probes
#[derive(Debug, Clone, Default)]
pub struct CacheStatistics {
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
    pub total_entries: u64,
    pub total_size_bytes: u64,
}
