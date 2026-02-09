//! Unified SAST analysis engine
//!
//! Eliminates triple-nested locks by combining query caching,
//! parsing, and TaintQueryEngine into a single structure with consistent locking.
//!
//! ## Lock Ordering Policy 
//!
//! All mutable state uses `tokio::sync::RwLock`. To prevent deadlocks,
//! locks **must** be acquired in the following strict order:
//!
//! 1. `compiled_queries` — query compilation cache (read-heavy, rarely written)
//! 2. `parser`           — tree-sitter parser state (write per language switch)
//! 3. `taint_engine`     — taint query engine (write for detection runs)
//!
//! **Rules:**
//! - Never hold `parser` while acquiring `compiled_queries`.
//! - Never hold `taint_engine` while acquiring `parser` or `compiled_queries`.
//! - Each public method acquires at most **two** locks, always in order.
//! - `query()` acquires `compiled_queries` then `parser`.
//! - `detect_taint()` acquires only `taint_engine`.
//! - `parse()` acquires only `parser`.

use std::collections::HashMap;
use std::sync::Arc;
use streaming_iterator::StreamingIterator;
use tokio::sync::RwLock;
use tree_sitter::{Query, Tree};
use tracing::{debug, instrument};

use crate::domain::{Finding, Location, Pattern, Rule};
use crate::domain::value_objects::{Confidence, Language};
use crate::infrastructure::parsers::{ParseError, Parser, TreeSitterParser};
use crate::infrastructure::query_engine::{QueryEngineError, QueryMatchResult};
use crate::infrastructure::data_flow::{TaintMatch, TaintQueryEngine};
use crate::infrastructure::taint_queries::{TaintConfig};

/// Unified SAST engine with consistent locking
///
/// Combines pattern matching and taint analysis in a single structure
/// with unified lock management to prevent deadlocks.
pub struct SastEngine {
    /// Parser state - reinitialized per language
    parser: RwLock<TreeSitterParser>,
    /// Taint query engine for data flow analysis
    taint_engine: RwLock<TaintQueryEngine>,
    /// Cache of compiled tree-sitter queries
    compiled_queries: RwLock<HashMap<(Language, String), Arc<Query>>>,
}

/// Thread-safe handle to SastEngine
pub type SastEngineHandle = Arc<SastEngine>;

/// Errors that can occur during SAST engine operations
#[derive(Debug, thiserror::Error)]
pub enum SastEngineError {
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    #[error("Query error: {0}")]
    Query(#[from] QueryEngineError),
    #[error("Invalid query: {0}")]
    InvalidQuery(String),
    #[error("Language not supported: {0:?}")]
    UnsupportedLanguage(Language),
}

/// Result type for SAST engine operations
pub type Result<T> = std::result::Result<T, SastEngineError>;

impl SastEngine {
    /// Create a new SAST engine with default configuration
    pub fn new() -> Self {
        // Default parser for Python - will be reconfigured per language
        let parser = TreeSitterParser::new(Language::Python)
            .unwrap_or_else(|_| TreeSitterParser::new(Language::Rust).expect("Rust parser should work"));

        Self {
            parser: RwLock::new(parser),
            taint_engine: RwLock::new(TaintQueryEngine::new_owned()),
            compiled_queries: RwLock::new(HashMap::new()),
        }
    }

    /// Parse source code into AST for the given language
    #[instrument(skip(self, source), fields(language = %language, source_len = source.len()))]
    pub async fn parse(&self, source: &str, language: Language) -> Result<Tree> {
        let mut parser = self.parser.write().await;
        
        // Reinitialize parser for the target language if needed
        if (*parser).language() != language {
            *parser = TreeSitterParser::new(language)?;
        }
        
        parser.parse_tree(source).map_err(SastEngineError::Parse)
    }

    /// Execute a tree-sitter query against source code
    #[instrument(skip(self, source), fields(language = %language))]
    pub async fn query(
        &self,
        source: &str,
        language: Language,
        query_str: &str,
    ) -> Result<Vec<QueryMatchResult>> {
        let query = self.get_or_compile_query(language, query_str).await?;
        
        // Parse the source
        let tree = self.parse(source, language).await?;
        
        // Execute query against the tree
        let mut cursor = tree_sitter::QueryCursor::new();
        let root_node = tree.root_node();
        let mut matches = cursor.matches(&query, root_node, source.as_bytes());
        
        let mut results = Vec::new();
        while let Some(match_result) = {
            matches.advance();
            matches.get()
        } {
            let mut captures = HashMap::new();
            
            for capture in match_result.captures {
                let node = capture.node;
                let capture_name = query.capture_names()[capture.index as usize];
                
                captures.insert(
                    capture_name.to_string(),
                    crate::infrastructure::query_engine::CaptureInfo {
                        text: source[node.start_byte()..node.end_byte()].to_string(),
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                        start_position: (node.start_position().row, node.start_position().column),
                        end_position: (node.end_position().row, node.end_position().column),
                        kind: node.kind().to_string(),
                    },
                );
            }
            
            results.push(QueryMatchResult {
                pattern_index: match_result.pattern_index,
                captures,
                start_byte: match_result.captures.first().map(|c| c.node.start_byte()).unwrap_or(0),
                end_byte: match_result.captures.first().map(|c| c.node.end_byte()).unwrap_or(0),
                start_position: match_result.captures.first()
                    .map(|c| (c.node.start_position().row, c.node.start_position().column))
                    .unwrap_or((0, 0)),
                end_position: match_result.captures.first()
                    .map(|c| (c.node.end_position().row, c.node.end_position().column))
                    .unwrap_or((0, 0)),
            });
        }
        
        debug!(match_count = results.len(), "Query executed");
        Ok(results)
    }

    /// Execute multiple rules against source code
    #[instrument(skip(self, source, rules), fields(language = %language, rule_count = rules.len()))]
    pub async fn query_batch(
        &self,
        source: &str,
        language: Language,
        rules: &[&Rule],
    ) -> Vec<(String, Vec<QueryMatchResult>)> {
        let mut results = Vec::new();
        
        for rule in rules {
            if let Pattern::TreeSitterQuery(query_str) = &rule.pattern {
                match self.query(source, language, query_str).await {
                    Ok(matches) if !matches.is_empty() => {
                        results.push((rule.id.clone(), matches));
                    }
                    Err(e) => {
                        debug!(rule_id = %rule.id, error = %e, "Query failed");
                    }
                    _ => {}
                }
            }
        }
        
        results
    }

    /// Detect taint sources, sinks, and sanitizers
    #[instrument(skip(self, tree, source_bytes), fields(language = %language))]
    pub async fn detect_taint(
        &self,
        tree: &Tree,
        source_bytes: &[u8],
        language: Language,
        config: &TaintConfig,
    ) -> Vec<TaintMatch> {
        let mut engine = self.taint_engine.write().await;
        
        // Combine sources, sinks, and sanitizers into one list
        let mut matches = Vec::new();
        matches.extend(engine.detect_sources(tree, source_bytes, &language).await);
        matches.extend(engine.detect_sinks(tree, source_bytes, &language).await);
        matches.extend(engine.detect_sanitizers(tree, source_bytes, &language).await);
        
        debug!(match_count = matches.len(), "Taint detection complete");
        
        matches
    }

    /// Compile a tree-sitter query (for backward compatibility with call graph)
    pub fn compile_query(&self, query_str: &str, language: &Language) -> Result<Query> {
        let grammar = language.grammar();
        Query::new(&grammar, query_str)
            .map_err(|e| SastEngineError::InvalidQuery(format!("{:?}", e)))
    }

    /// Execute a compiled query against a tree (for backward compatibility with call graph)
    pub fn execute_query(
        &self,
        query: &Query,
        tree: &Tree,
        source_bytes: &[u8],
    ) -> Vec<QueryMatchResult> {
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(query, tree.root_node(), source_bytes);
        let mut results = Vec::new();
        
        while let Some(match_result) = {
            matches.advance();
            matches.get()
        } {
            let mut captures = HashMap::new();
            
            for capture in match_result.captures {
                let node = capture.node;
                let capture_name = query.capture_names()[capture.index as usize];
                
                captures.insert(
                    capture_name.to_string(),
                    crate::infrastructure::query_engine::CaptureInfo {
                        text: String::from_utf8_lossy(&source_bytes[node.start_byte()..node.end_byte()]).to_string(),
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                        start_position: (node.start_position().row, node.start_position().column),
                        end_position: (node.end_position().row, node.end_position().column),
                        kind: node.kind().to_string(),
                    },
                );
            }
            
            results.push(QueryMatchResult {
                pattern_index: match_result.pattern_index,
                captures,
                start_byte: match_result.captures.first().map(|c| c.node.start_byte()).unwrap_or(0),
                end_byte: match_result.captures.first().map(|c| c.node.end_byte()).unwrap_or(0),
                start_position: match_result.captures.first()
                    .map(|c| (c.node.start_position().row, c.node.start_position().column))
                    .unwrap_or((0, 0)),
                end_position: match_result.captures.first()
                    .map(|c| (c.node.end_position().row, c.node.end_position().column))
                    .unwrap_or((0, 0)),
            });
        }
        
        results
    }

    /// Convert a query match to a Finding
    pub fn match_to_finding(
        &self,
        match_result: &QueryMatchResult,
        rule: &Rule,
        file_path: &str,
        source: &str,
    ) -> Finding {
        let line = match_result.start_position.0 as u32 + 1;
        let column = Some(match_result.start_position.1 as u32);
        let end_line = Some(match_result.end_position.0 as u32 + 1);
        let end_column = Some(match_result.end_position.1 as u32);
        
        // Extract code snippet
        let snippet = source[match_result.start_byte..match_result.end_byte].to_string();
        
        Finding {
            id: format!("{}-{}-{}", rule.id, file_path, line),
            rule_id: rule.id.clone(),
            location: Location {
                file_path: file_path.to_string(),
                line,
                column,
                end_line,
                end_column,
            },
            severity: rule.severity.clone(),
            confidence: Confidence::High,
            description: rule.description.clone(),
            recommendation: rule.fix.clone(),
            data_flow_path: None,
            snippet: Some(snippet),
        }
    }

    /// Get or compile a query, caching the result
    async fn get_or_compile_query(
        &self,
        language: Language,
        query_str: &str,
    ) -> Result<Arc<Query>> {
        let cache_key = (language, query_str.to_string());
        
        // Fast path: check cache
        {
            let cache = self.compiled_queries.read().await;
            if let Some(query) = cache.get(&cache_key) {
                debug!("Query cache hit");
                return Ok(query.clone());
            }
        }
        
        // Slow path: compile and cache
        debug!("Query cache miss - compiling");
        let grammar = language.grammar();
        let query = Query::new(&grammar, query_str)
            .map_err(|e| SastEngineError::InvalidQuery(format!("{:?}", e)))?;
        
        let mut cache = self.compiled_queries.write().await;
        let query = Arc::new(query);
        cache.insert(cache_key, query.clone());
        
        Ok(query)
    }
}

impl Default for SastEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of taint detection
pub type TaintDetectionResult = Vec<TaintMatch>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sast_engine_creation() {
        let engine = SastEngine::new();
        assert!(engine.parser.try_write().is_ok());
    }

    #[tokio::test]
    async fn test_parse_simple_code() {
        let engine = SastEngine::new();
        let result = engine.parse("fn main() {}", Language::Rust).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_query_with_cache() {
        let engine = SastEngine::new();
        
        // First query - cache miss
        let result1 = engine.query(
            "fn main() {}",
            Language::Rust,
            "(function_item) @fn"
        ).await;
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap().len(), 1);
        
        // Second query - cache hit
        let result2 = engine.query(
            "fn test() {}",
            Language::Rust,
            "(function_item) @fn"
        ).await;
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap().len(), 1);
    }
}
