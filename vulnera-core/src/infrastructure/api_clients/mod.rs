//! API clients for external vulnerability databases

pub mod circuit_breaker_wrapper;
pub mod ghsa;
pub mod nvd;
pub mod osv;
pub mod traits;

pub use circuit_breaker_wrapper::CircuitBreakerApiClient;
pub use ghsa::*;
pub use nvd::*;
pub use osv::*;
pub use traits::*;
