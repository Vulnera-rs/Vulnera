//! AST caching service for SAST analysis
//!
//! This module provides efficient caching of parsed ASTs using Dragonfly DB.
//! Features:
//! - Content-based hashing (sha256) for cache keys
//! - Binary serialization via bincode for efficiency
//! - Configurable TTL
//! - Support for both raw tree-sitter trees and serialized AST nodes

use crate::domain::value_objects::Language;
use crate::infrastructure::parsers::AstNode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, instrument, warn};

/// Cache key prefix for SAST AST entries
const AST_CACHE_PREFIX: &str = "sast:ast";

/// Default TTL for cached ASTs (4 hours)
const DEFAULT_AST_TTL_SECS: u64 = 4 * 3600;

/// Errors that can occur during AST caching
#[derive(Debug, Error)]
pub enum AstCacheError {
    #[error("Cache backend error: {0}")]
    Backend(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Cache miss for key: {0}")]
    CacheMiss(String),
}

/// Serializable AST node for bincode encoding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAstNode {
    pub node_type: String,
    pub field_name: Option<String>,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_row: u32,
    pub start_col: u32,
    pub end_row: u32,
    pub end_col: u32,
    pub children: Vec<CachedAstNode>,
    pub source: String,
}

impl From<&AstNode> for CachedAstNode {
    fn from(node: &AstNode) -> Self {
        Self {
            node_type: node.node_type.clone(),
            field_name: node.field_name.clone(),
            start_byte: node.start_byte,
            end_byte: node.end_byte,
            start_row: node.start_point.0,
            start_col: node.start_point.1,
            end_row: node.end_point.0,
            end_col: node.end_point.1,
            children: node.children.iter().map(CachedAstNode::from).collect(),
            source: node.source.clone(),
        }
    }
}

impl From<CachedAstNode> for AstNode {
    fn from(cached: CachedAstNode) -> Self {
        Self {
            node_type: cached.node_type,
            field_name: cached.field_name,
            start_byte: cached.start_byte,
            end_byte: cached.end_byte,
            start_point: (cached.start_row, cached.start_col),
            end_point: (cached.end_row, cached.end_col),
            children: cached.children.into_iter().map(AstNode::from).collect(),
            source: cached.source,
        }
    }
}

/// Cached AST entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAstEntry {
    /// The cached AST root node
    pub ast: CachedAstNode,
    /// Language of the source
    pub language: String,
    /// Timestamp when cached (Unix epoch seconds)
    pub cached_at: u64,
    /// SHA256 hash of the source content
    pub content_hash: String,
}

/// AST cache service trait for dependency injection
#[async_trait::async_trait]
pub trait AstCacheService: Send + Sync {
    /// Get cached AST for source content
    async fn get(
        &self,
        content_hash: &str,
        language: &Language,
    ) -> Result<Option<AstNode>, AstCacheError>;

    /// Store AST in cache
    async fn set(
        &self,
        content_hash: &str,
        language: &Language,
        ast: &AstNode,
        ttl: Option<Duration>,
    ) -> Result<(), AstCacheError>;

    /// Check if AST is cached
    async fn exists(&self, content_hash: &str, language: &Language) -> Result<bool, AstCacheError>;

    /// Remove cached AST
    async fn remove(&self, content_hash: &str, language: &Language) -> Result<(), AstCacheError>;

    /// Clear all cached ASTs
    async fn clear(&self) -> Result<(), AstCacheError>;

    /// Generate cache key from content hash and language
    fn cache_key(&self, content_hash: &str, language: &Language) -> String {
        format!(
            "{}:{}:{}",
            AST_CACHE_PREFIX,
            language.to_tree_sitter_name(),
            content_hash
        )
    }

    /// Generate content hash from source code
    fn hash_content(&self, content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Dragonfly-backed AST cache implementation
pub struct DragonflyAstCache {
    /// Reference to the core Dragonfly cache
    dragonfly: Arc<vulnera_core::infrastructure::cache::DragonflyCache>,
    /// Default TTL for AST entries
    default_ttl: Duration,
}

impl DragonflyAstCache {
    /// Create a new Dragonfly AST cache
    pub fn new(dragonfly: Arc<vulnera_core::infrastructure::cache::DragonflyCache>) -> Self {
        Self {
            dragonfly,
            default_ttl: Duration::from_secs(DEFAULT_AST_TTL_SECS),
        }
    }

    /// Create with custom TTL
    pub fn with_ttl(
        dragonfly: Arc<vulnera_core::infrastructure::cache::DragonflyCache>,
        ttl: Duration,
    ) -> Self {
        Self {
            dragonfly,
            default_ttl: ttl,
        }
    }

    /// Serialize AST entry to bytes using bincode
    fn serialize_entry(entry: &CachedAstEntry) -> Result<Vec<u8>, AstCacheError> {
        bincode::serialize(entry).map_err(|e| AstCacheError::Serialization(e.to_string()))
    }

    /// Deserialize AST entry from bytes
    fn deserialize_entry(data: &[u8]) -> Result<CachedAstEntry, AstCacheError> {
        bincode::deserialize(data).map_err(|e| AstCacheError::Deserialization(e.to_string()))
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[async_trait::async_trait]
impl AstCacheService for DragonflyAstCache {
    #[instrument(skip(self), fields(language = %language))]
    async fn get(
        &self,
        content_hash: &str,
        language: &Language,
    ) -> Result<Option<AstNode>, AstCacheError> {
        let key = self.cache_key(content_hash, language);

        // Get raw bytes from cache
        let data: Option<Vec<u8>> = self
            .dragonfly
            .get_raw(&key)
            .await
            .map_err(|e| AstCacheError::Backend(e.to_string()))?;

        match data {
            Some(bytes) => {
                let entry = Self::deserialize_entry(&bytes)?;
                debug!(
                    content_hash = %content_hash,
                    cached_at = entry.cached_at,
                    "AST cache hit"
                );
                Ok(Some(AstNode::from(entry.ast)))
            }
            None => {
                debug!(content_hash = %content_hash, "AST cache miss");
                Ok(None)
            }
        }
    }

    #[instrument(skip(self, ast), fields(language = %language, ast_nodes = ast.children.len()))]
    async fn set(
        &self,
        content_hash: &str,
        language: &Language,
        ast: &AstNode,
        ttl: Option<Duration>,
    ) -> Result<(), AstCacheError> {
        let key = self.cache_key(content_hash, language);
        let ttl = ttl.unwrap_or(self.default_ttl);

        let entry = CachedAstEntry {
            ast: CachedAstNode::from(ast),
            language: language.to_tree_sitter_name().to_string(),
            cached_at: Self::current_timestamp(),
            content_hash: content_hash.to_string(),
        };

        let bytes = Self::serialize_entry(&entry)?;

        debug!(
            content_hash = %content_hash,
            bytes = bytes.len(),
            ttl_secs = ttl.as_secs(),
            "Caching AST"
        );

        self.dragonfly
            .set_raw(&key, &bytes, ttl)
            .await
            .map_err(|e| AstCacheError::Backend(e.to_string()))
    }

    #[instrument(skip(self), fields(language = %language))]
    async fn exists(&self, content_hash: &str, language: &Language) -> Result<bool, AstCacheError> {
        let key = self.cache_key(content_hash, language);
        // Check if key exists by trying to get it
        self.dragonfly
            .get_raw(&key)
            .await
            .map(|opt| opt.is_some())
            .map_err(|e| AstCacheError::Backend(e.to_string()))
    }

    #[instrument(skip(self), fields(language = %language))]
    async fn remove(&self, content_hash: &str, language: &Language) -> Result<(), AstCacheError> {
        let key = self.cache_key(content_hash, language);
        self.dragonfly
            .delete(&key)
            .await
            .map(|_| ())
            .map_err(|e| AstCacheError::Backend(e.to_string()))
    }

    #[instrument(skip(self))]
    async fn clear(&self) -> Result<(), AstCacheError> {
        // Delete all keys matching the AST cache prefix using SCAN + DEL
        let pattern = format!("{}:*", AST_CACHE_PREFIX);
        let deleted = self
            .dragonfly
            .delete_by_pattern(&pattern)
            .await
            .map_err(|e| AstCacheError::Backend(e.to_string()))?;

        info!(deleted_keys = deleted, "Cleared AST cache");
        Ok(())
    }
}

/// In-memory AST cache for testing and development
pub struct InMemoryAstCache {
    cache:
        tokio::sync::RwLock<std::collections::HashMap<String, (CachedAstEntry, std::time::Instant)>>,
    default_ttl: Duration,
}

impl InMemoryAstCache {
    /// Create new in-memory cache
    pub fn new() -> Self {
        Self {
            cache: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            default_ttl: Duration::from_secs(DEFAULT_AST_TTL_SECS),
        }
    }

    /// Create with custom TTL
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            cache: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            default_ttl: ttl,
        }
    }
}

impl Default for InMemoryAstCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AstCacheService for InMemoryAstCache {
    async fn get(
        &self,
        content_hash: &str,
        language: &Language,
    ) -> Result<Option<AstNode>, AstCacheError> {
        let key = self.cache_key(content_hash, language);
        let cache = self.cache.read().await;

        if let Some((entry, cached_at)) = cache.get(&key) {
            // Check if expired
            if cached_at.elapsed() < self.default_ttl {
                return Ok(Some(AstNode::from(entry.ast.clone())));
            }
        }
        Ok(None)
    }

    async fn set(
        &self,
        content_hash: &str,
        language: &Language,
        ast: &AstNode,
        _ttl: Option<Duration>,
    ) -> Result<(), AstCacheError> {
        let key = self.cache_key(content_hash, language);
        let entry = CachedAstEntry {
            ast: CachedAstNode::from(ast),
            language: language.to_tree_sitter_name().to_string(),
            cached_at: DragonflyAstCache::current_timestamp(),
            content_hash: content_hash.to_string(),
        };

        let mut cache = self.cache.write().await;
        cache.insert(key, (entry, std::time::Instant::now()));
        Ok(())
    }

    async fn exists(&self, content_hash: &str, language: &Language) -> Result<bool, AstCacheError> {
        let key = self.cache_key(content_hash, language);
        let cache = self.cache.read().await;

        if let Some((_, cached_at)) = cache.get(&key) {
            return Ok(cached_at.elapsed() < self.default_ttl);
        }
        Ok(false)
    }

    async fn remove(&self, content_hash: &str, language: &Language) -> Result<(), AstCacheError> {
        let key = self.cache_key(content_hash, language);
        let mut cache = self.cache.write().await;
        cache.remove(&key);
        Ok(())
    }

    async fn clear(&self) -> Result<(), AstCacheError> {
        let mut cache = self.cache.write().await;
        cache.clear();
        Ok(())
    }
}

/// Parse source code and cache the AST
pub async fn parse_with_cache<C: AstCacheService, P: crate::infrastructure::parsers::Parser>(
    cache: &C,
    parser: &mut P,
    source: &str,
) -> Result<AstNode, crate::infrastructure::parsers::ParseError> {
    let content_hash = cache.hash_content(source);
    let language = parser.language();

    // Try cache first
    if let Ok(Some(ast)) = cache.get(&content_hash, &language).await {
        debug!("Using cached AST for content hash: {}", content_hash);
        return Ok(ast);
    }

    // Parse and cache
    let ast = parser.parse(source)?;

    if let Err(e) = cache.set(&content_hash, &language, &ast, None).await {
        warn!("Failed to cache AST: {}", e);
    }

    Ok(ast)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_cache_basic() {
        let cache = InMemoryAstCache::new();

        let ast = AstNode {
            node_type: "test".to_string(),
            field_name: None,
            start_byte: 0,
            end_byte: 10,
            start_point: (0, 0),
            end_point: (0, 10),
            children: vec![],
            source: "test code".to_string(),
        };

        let content_hash = cache.hash_content("test code");
        let language = Language::Python;

        // Initially not cached
        assert!(!cache.exists(&content_hash, &language).await.unwrap());

        // Set and verify
        cache
            .set(&content_hash, &language, &ast, None)
            .await
            .unwrap();
        assert!(cache.exists(&content_hash, &language).await.unwrap());

        // Get and verify
        let cached = cache.get(&content_hash, &language).await.unwrap().unwrap();
        assert_eq!(cached.node_type, "test");
        assert_eq!(cached.source, "test code");

        // Remove and verify
        cache.remove(&content_hash, &language).await.unwrap();
        assert!(!cache.exists(&content_hash, &language).await.unwrap());
    }

    #[test]
    fn test_content_hash() {
        let cache = InMemoryAstCache::new();
        let hash1 = cache.hash_content("hello world");
        let hash2 = cache.hash_content("hello world");
        let hash3 = cache.hash_content("different content");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 64); // SHA256 hex is 64 chars
    }

    #[test]
    fn test_cache_key_format() {
        let cache = InMemoryAstCache::new();
        let key = cache.cache_key("abc123", &Language::Python);
        assert_eq!(key, "sast:ast:python:abc123");
    }

    #[test]
    fn test_ast_node_serialization_roundtrip() {
        let ast = AstNode {
            node_type: "function_definition".to_string(),
            field_name: None,
            start_byte: 0,
            end_byte: 100,
            start_point: (0, 0),
            end_point: (5, 0),
            children: vec![AstNode {
                node_type: "identifier".to_string(),
                field_name: Some("name".to_string()),
                start_byte: 4,
                end_byte: 8,
                start_point: (0, 4),
                end_point: (0, 8),
                children: vec![],
                source: "test".to_string(),
            }],
            source: "def test(): pass".to_string(),
        };

        let cached = CachedAstNode::from(&ast);
        let restored = AstNode::from(cached);

        assert_eq!(restored.node_type, ast.node_type);
        assert_eq!(restored.start_byte, ast.start_byte);
        assert_eq!(restored.children.len(), ast.children.len());
        assert_eq!(restored.children[0].node_type, "identifier");
    }
}
