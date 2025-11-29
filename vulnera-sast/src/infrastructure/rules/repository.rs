//! PostgreSQL-backed rule repository
//!
//! This module provides database storage for SAST rules with support for:
//! - Tree-sitter pattern rules (sast_rules table)
//! - Semgrep rules (sast_semgrep_rules table)
//! - Hot-reload via updated_at timestamp polling
//! - Caching with invalidation

use crate::domain::entities::{
    Rule, RuleOptions, RulePattern, SemgrepRule, SemgrepRuleMode, Severity, TaintConfig,
    TaintPattern, TaintPropagator,
};
use crate::domain::value_objects::Language;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// Errors that can occur during rule repository operations
#[derive(Debug, Error)]
pub enum RuleRepositoryError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Rule not found: {0}")]
    NotFound(String),

    #[error("Invalid rule data: {0}")]
    InvalidData(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Repository trait for SAST rules
#[async_trait]
pub trait SastRuleRepository: Send + Sync {
    /// Get all tree-sitter rules
    async fn get_tree_sitter_rules(&self) -> Result<Vec<Rule>, RuleRepositoryError>;

    /// Get tree-sitter rules for a specific language
    async fn get_tree_sitter_rules_for_language(
        &self,
        language: &Language,
    ) -> Result<Vec<Rule>, RuleRepositoryError>;

    /// Get all Semgrep rules
    async fn get_semgrep_rules(&self) -> Result<Vec<SemgrepRule>, RuleRepositoryError>;

    /// Get Semgrep rules for a specific language
    async fn get_semgrep_rules_for_language(
        &self,
        language: &Language,
    ) -> Result<Vec<SemgrepRule>, RuleRepositoryError>;

    /// Get a specific tree-sitter rule by ID
    async fn get_tree_sitter_rule(
        &self,
        rule_id: &str,
    ) -> Result<Option<Rule>, RuleRepositoryError>;

    /// Get a specific Semgrep rule by ID
    async fn get_semgrep_rule(
        &self,
        rule_id: &str,
    ) -> Result<Option<SemgrepRule>, RuleRepositoryError>;

    /// Insert or update a tree-sitter rule
    async fn upsert_tree_sitter_rule(&self, rule: &Rule) -> Result<(), RuleRepositoryError>;

    /// Insert or update a Semgrep rule
    async fn upsert_semgrep_rule(&self, rule: &SemgrepRule) -> Result<(), RuleRepositoryError>;

    /// Delete a tree-sitter rule
    async fn delete_tree_sitter_rule(&self, rule_id: &str) -> Result<bool, RuleRepositoryError>;

    /// Delete a Semgrep rule
    async fn delete_semgrep_rule(&self, rule_id: &str) -> Result<bool, RuleRepositoryError>;

    /// Get rules updated since a timestamp (for hot-reload)
    async fn get_updated_rules_since(
        &self,
        since: DateTime<Utc>,
    ) -> Result<(Vec<Rule>, Vec<SemgrepRule>), RuleRepositoryError>;

    /// Get the latest updated_at timestamp
    async fn get_latest_update_time(&self) -> Result<Option<DateTime<Utc>>, RuleRepositoryError>;
}

/// Database row for sast_rules table
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)] // Fields read by SQLx via FromRow
struct SastRuleRow {
    id: Uuid,
    rule_id: String,
    name: String,
    description: String,
    severity: String,
    languages: Vec<String>,
    pattern_type: String,
    query: String,
    options: Option<serde_json::Value>,
    cwe_ids: Vec<String>,
    owasp_categories: Vec<String>,
    tags: Vec<String>,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Database row for sast_semgrep_rules table
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)] // Fields read by SQLx via FromRow
struct SastSemgrepRuleRow {
    id: Uuid,
    rule_id: String,
    name: String,
    message: String,
    languages: Vec<String>,
    severity: String,
    mode: String,
    pattern: Option<String>,
    patterns: Option<serde_json::Value>,
    taint_sources: Option<serde_json::Value>,
    taint_sinks: Option<serde_json::Value>,
    taint_sanitizers: Option<serde_json::Value>,
    taint_propagators: Option<serde_json::Value>,
    fix: Option<String>,
    cwe_ids: Vec<String>,
    owasp_categories: Vec<String>,
    tags: Vec<String>,
    metadata: Option<serde_json::Value>,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// PostgreSQL-backed rule repository
pub struct PostgresRuleRepository {
    pool: PgPool,
    /// Cached tree-sitter rules
    ts_rule_cache: Arc<RwLock<Option<CachedRules<Rule>>>>,
    /// Cached Semgrep rules
    sg_rule_cache: Arc<RwLock<Option<CachedRules<SemgrepRule>>>>,
    /// Cache TTL
    cache_ttl: Duration,
}

/// Cached rules with timestamp
#[allow(dead_code)] // Struct fields used for cache invalidation logic
struct CachedRules<T> {
    rules: Vec<T>,
    cached_at: Instant,
    updated_at: DateTime<Utc>,
}

impl PostgresRuleRepository {
    /// Create a new PostgreSQL rule repository
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            ts_rule_cache: Arc::new(RwLock::new(None)),
            sg_rule_cache: Arc::new(RwLock::new(None)),
            cache_ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create with custom cache TTL
    pub fn with_cache_ttl(pool: PgPool, cache_ttl: Duration) -> Self {
        Self {
            pool,
            ts_rule_cache: Arc::new(RwLock::new(None)),
            sg_rule_cache: Arc::new(RwLock::new(None)),
            cache_ttl,
        }
    }

    /// Check if cache is valid
    fn is_cache_valid<T>(cache: &Option<CachedRules<T>>, ttl: Duration) -> bool {
        cache
            .as_ref()
            .map(|c| c.cached_at.elapsed() < ttl)
            .unwrap_or(false)
    }

    /// Convert severity string to enum
    fn parse_severity(s: &str) -> Severity {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    /// Convert severity enum to string
    fn severity_to_string(severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    /// Parse language strings to Language enums
    fn parse_languages(langs: &[String]) -> Vec<Language> {
        langs
            .iter()
            .filter_map(|s| match s.to_lowercase().as_str() {
                "python" | "py" => Some(Language::Python),
                "javascript" | "js" => Some(Language::JavaScript),
                "rust" | "rs" => Some(Language::Rust),
                "go" | "golang" => Some(Language::Go),
                "c" => Some(Language::C),
                "cpp" | "c++" => Some(Language::Cpp),
                _ => None,
            })
            .collect()
    }

    /// Convert languages to strings
    fn languages_to_strings(langs: &[Language]) -> Vec<String> {
        langs
            .iter()
            .map(|l| l.to_tree_sitter_name().to_string())
            .collect()
    }

    /// Convert database row to Rule
    fn row_to_rule(row: SastRuleRow) -> Result<Rule, RuleRepositoryError> {
        let pattern = RulePattern::TreeSitterQuery(row.query);

        let options: RuleOptions = row
            .options
            .map(|v| serde_json::from_value(v).unwrap_or_default())
            .unwrap_or_default();

        Ok(Rule {
            id: row.rule_id,
            name: row.name,
            description: row.description,
            severity: Self::parse_severity(&row.severity),
            languages: Self::parse_languages(&row.languages),
            pattern,
            options,
            cwe_ids: row.cwe_ids,
            owasp_categories: row.owasp_categories,
            tags: row.tags,
        })
    }

    /// Convert database row to SemgrepRule
    fn row_to_semgrep_rule(row: SastSemgrepRuleRow) -> Result<SemgrepRule, RuleRepositoryError> {
        let mode = match row.mode.to_lowercase().as_str() {
            "taint" => SemgrepRuleMode::Taint,
            _ => SemgrepRuleMode::Search,
        };

        let patterns: Option<Vec<String>> = row
            .patterns
            .map(|v| serde_json::from_value(v).unwrap_or_default());

        let taint_config = if mode == SemgrepRuleMode::Taint {
            let sources: Vec<TaintPattern> = row
                .taint_sources
                .map(|v| serde_json::from_value(v).unwrap_or_default())
                .unwrap_or_default();
            let sinks: Vec<TaintPattern> = row
                .taint_sinks
                .map(|v| serde_json::from_value(v).unwrap_or_default())
                .unwrap_or_default();
            let sanitizers: Vec<TaintPattern> = row
                .taint_sanitizers
                .map(|v| serde_json::from_value(v).unwrap_or_default())
                .unwrap_or_default();
            let propagators: Vec<TaintPropagator> = row
                .taint_propagators
                .map(|v| serde_json::from_value(v).unwrap_or_default())
                .unwrap_or_default();

            Some(TaintConfig {
                sources,
                sinks,
                sanitizers,
                propagators,
            })
        } else {
            None
        };

        let metadata: HashMap<String, serde_json::Value> = row
            .metadata
            .map(|v| serde_json::from_value(v).unwrap_or_default())
            .unwrap_or_default();

        Ok(SemgrepRule {
            id: row.rule_id,
            name: row.name,
            message: row.message,
            languages: Self::parse_languages(&row.languages),
            severity: Self::parse_severity(&row.severity),
            mode,
            pattern: row.pattern,
            patterns,
            taint_config,
            cwe_ids: row.cwe_ids,
            owasp_categories: row.owasp_categories,
            tags: row.tags,
            fix: row.fix,
            metadata,
        })
    }
}

#[async_trait]
impl SastRuleRepository for PostgresRuleRepository {
    #[instrument(skip(self))]
    async fn get_tree_sitter_rules(&self) -> Result<Vec<Rule>, RuleRepositoryError> {
        // Check cache first
        {
            let cache = self.ts_rule_cache.read().await;
            if Self::is_cache_valid(&cache, self.cache_ttl) {
                debug!("Using cached tree-sitter rules");
                return Ok(cache.as_ref().unwrap().rules.clone());
            }
        }

        // Query database
        let rows = sqlx::query_as::<_, SastRuleRow>(
            r#"
            SELECT id, rule_id, name, description, severity, languages, 
                   pattern_type, query, options, cwe_ids, owasp_categories, 
                   tags, enabled, created_at, updated_at
            FROM sast_rules
            WHERE enabled = true
            ORDER BY severity, name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let rules: Vec<Rule> = rows
            .into_iter()
            .filter_map(|row| Self::row_to_rule(row).ok())
            .collect();

        // Update cache
        {
            let mut cache = self.ts_rule_cache.write().await;
            *cache = Some(CachedRules {
                rules: rules.clone(),
                cached_at: Instant::now(),
                updated_at: Utc::now(),
            });
        }

        debug!(
            rule_count = rules.len(),
            "Loaded tree-sitter rules from database"
        );
        Ok(rules)
    }

    #[instrument(skip(self), fields(language = %language))]
    async fn get_tree_sitter_rules_for_language(
        &self,
        language: &Language,
    ) -> Result<Vec<Rule>, RuleRepositoryError> {
        let lang_str = language.to_tree_sitter_name();

        let rows = sqlx::query_as::<_, SastRuleRow>(
            r#"
            SELECT id, rule_id, name, description, severity, languages, 
                   pattern_type, query, options, cwe_ids, owasp_categories, 
                   tags, enabled, created_at, updated_at
            FROM sast_rules
            WHERE enabled = true AND $1 = ANY(languages)
            ORDER BY severity, name
            "#,
        )
        .bind(lang_str)
        .fetch_all(&self.pool)
        .await?;

        let rules: Vec<Rule> = rows
            .into_iter()
            .filter_map(|row| Self::row_to_rule(row).ok())
            .collect();

        debug!(
            rule_count = rules.len(),
            language = %lang_str,
            "Loaded tree-sitter rules for language"
        );
        Ok(rules)
    }

    #[instrument(skip(self))]
    async fn get_semgrep_rules(&self) -> Result<Vec<SemgrepRule>, RuleRepositoryError> {
        // Check cache first
        {
            let cache = self.sg_rule_cache.read().await;
            if Self::is_cache_valid(&cache, self.cache_ttl) {
                debug!("Using cached Semgrep rules");
                return Ok(cache.as_ref().unwrap().rules.clone());
            }
        }

        let rows = sqlx::query_as::<_, SastSemgrepRuleRow>(
            r#"
            SELECT id, rule_id, name, message, languages, severity, mode,
                   pattern, patterns, taint_sources, taint_sinks, 
                   taint_sanitizers, taint_propagators, fix, cwe_ids,
                   owasp_categories, tags, metadata, enabled, 
                   created_at, updated_at
            FROM sast_semgrep_rules
            WHERE enabled = true
            ORDER BY severity, name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let rules: Vec<SemgrepRule> = rows
            .into_iter()
            .filter_map(|row| Self::row_to_semgrep_rule(row).ok())
            .collect();

        // Update cache
        {
            let mut cache = self.sg_rule_cache.write().await;
            *cache = Some(CachedRules {
                rules: rules.clone(),
                cached_at: Instant::now(),
                updated_at: Utc::now(),
            });
        }

        debug!(
            rule_count = rules.len(),
            "Loaded Semgrep rules from database"
        );
        Ok(rules)
    }

    #[instrument(skip(self), fields(language = %language))]
    async fn get_semgrep_rules_for_language(
        &self,
        language: &Language,
    ) -> Result<Vec<SemgrepRule>, RuleRepositoryError> {
        let lang_str = language.to_semgrep_id();

        let rows = sqlx::query_as::<_, SastSemgrepRuleRow>(
            r#"
            SELECT id, rule_id, name, message, languages, severity, mode,
                   pattern, patterns, taint_sources, taint_sinks, 
                   taint_sanitizers, taint_propagators, fix, cwe_ids,
                   owasp_categories, tags, metadata, enabled, 
                   created_at, updated_at
            FROM sast_semgrep_rules
            WHERE enabled = true AND $1 = ANY(languages)
            ORDER BY severity, name
            "#,
        )
        .bind(lang_str)
        .fetch_all(&self.pool)
        .await?;

        let rules: Vec<SemgrepRule> = rows
            .into_iter()
            .filter_map(|row| Self::row_to_semgrep_rule(row).ok())
            .collect();

        debug!(
            rule_count = rules.len(),
            language = %lang_str,
            "Loaded Semgrep rules for language"
        );
        Ok(rules)
    }

    #[instrument(skip(self))]
    async fn get_tree_sitter_rule(
        &self,
        rule_id: &str,
    ) -> Result<Option<Rule>, RuleRepositoryError> {
        let row = sqlx::query_as::<_, SastRuleRow>(
            r#"
            SELECT id, rule_id, name, description, severity, languages, 
                   pattern_type, query, options, cwe_ids, owasp_categories, 
                   tags, enabled, created_at, updated_at
            FROM sast_rules
            WHERE rule_id = $1
            "#,
        )
        .bind(rule_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(|r| Self::row_to_rule(r).ok()))
    }

    #[instrument(skip(self))]
    async fn get_semgrep_rule(
        &self,
        rule_id: &str,
    ) -> Result<Option<SemgrepRule>, RuleRepositoryError> {
        let row = sqlx::query_as::<_, SastSemgrepRuleRow>(
            r#"
            SELECT id, rule_id, name, message, languages, severity, mode,
                   pattern, patterns, taint_sources, taint_sinks, 
                   taint_sanitizers, taint_propagators, fix, cwe_ids,
                   owasp_categories, tags, metadata, enabled, 
                   created_at, updated_at
            FROM sast_semgrep_rules
            WHERE rule_id = $1
            "#,
        )
        .bind(rule_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(|r| Self::row_to_semgrep_rule(r).ok()))
    }

    #[instrument(skip(self, rule), fields(rule_id = %rule.id))]
    async fn upsert_tree_sitter_rule(&self, rule: &Rule) -> Result<(), RuleRepositoryError> {
        let RulePattern::TreeSitterQuery(query) = &rule.pattern;

        let languages = Self::languages_to_strings(&rule.languages);
        let severity = Self::severity_to_string(&rule.severity);
        let options = serde_json::to_value(&rule.options)
            .map_err(|e| RuleRepositoryError::Serialization(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO sast_rules (
                rule_id, name, description, severity, languages, 
                pattern_type, query, options, cwe_ids, owasp_categories, tags
            )
            VALUES ($1, $2, $3, $4, $5, 'tree_sitter_query', $6, $7, $8, $9, $10)
            ON CONFLICT (rule_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                severity = EXCLUDED.severity,
                languages = EXCLUDED.languages,
                query = EXCLUDED.query,
                options = EXCLUDED.options,
                cwe_ids = EXCLUDED.cwe_ids,
                owasp_categories = EXCLUDED.owasp_categories,
                tags = EXCLUDED.tags,
                updated_at = NOW()
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(severity)
        .bind(&languages)
        .bind(&query)
        .bind(&options)
        .bind(&rule.cwe_ids)
        .bind(&rule.owasp_categories)
        .bind(&rule.tags)
        .execute(&self.pool)
        .await?;

        // Invalidate cache
        {
            let mut cache = self.ts_rule_cache.write().await;
            *cache = None;
        }

        info!(rule_id = %rule.id, "Upserted tree-sitter rule");
        Ok(())
    }

    #[instrument(skip(self, rule), fields(rule_id = %rule.id))]
    async fn upsert_semgrep_rule(&self, rule: &SemgrepRule) -> Result<(), RuleRepositoryError> {
        let languages = Self::languages_to_strings(&rule.languages);
        let severity = Self::severity_to_string(&rule.severity);
        let mode = match rule.mode {
            SemgrepRuleMode::Taint => "taint",
            SemgrepRuleMode::Search => "search",
        };

        let patterns = rule
            .patterns
            .as_ref()
            .map(|p| serde_json::to_value(p).unwrap());

        let (taint_sources, taint_sinks, taint_sanitizers, taint_propagators) =
            if let Some(tc) = &rule.taint_config {
                (
                    Some(serde_json::to_value(&tc.sources).unwrap()),
                    Some(serde_json::to_value(&tc.sinks).unwrap()),
                    Some(serde_json::to_value(&tc.sanitizers).unwrap()),
                    Some(serde_json::to_value(&tc.propagators).unwrap()),
                )
            } else {
                (None, None, None, None)
            };

        let metadata = serde_json::to_value(&rule.metadata)
            .map_err(|e| RuleRepositoryError::Serialization(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO sast_semgrep_rules (
                rule_id, name, message, languages, severity, mode,
                pattern, patterns, taint_sources, taint_sinks,
                taint_sanitizers, taint_propagators, fix, cwe_ids,
                owasp_categories, tags, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            ON CONFLICT (rule_id) DO UPDATE SET
                name = EXCLUDED.name,
                message = EXCLUDED.message,
                languages = EXCLUDED.languages,
                severity = EXCLUDED.severity,
                mode = EXCLUDED.mode,
                pattern = EXCLUDED.pattern,
                patterns = EXCLUDED.patterns,
                taint_sources = EXCLUDED.taint_sources,
                taint_sinks = EXCLUDED.taint_sinks,
                taint_sanitizers = EXCLUDED.taint_sanitizers,
                taint_propagators = EXCLUDED.taint_propagators,
                fix = EXCLUDED.fix,
                cwe_ids = EXCLUDED.cwe_ids,
                owasp_categories = EXCLUDED.owasp_categories,
                tags = EXCLUDED.tags,
                metadata = EXCLUDED.metadata,
                updated_at = NOW()
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.name)
        .bind(&rule.message)
        .bind(&languages)
        .bind(severity)
        .bind(mode)
        .bind(&rule.pattern)
        .bind(&patterns)
        .bind(&taint_sources)
        .bind(&taint_sinks)
        .bind(&taint_sanitizers)
        .bind(&taint_propagators)
        .bind(&rule.fix)
        .bind(&rule.cwe_ids)
        .bind(&rule.owasp_categories)
        .bind(&rule.tags)
        .bind(&metadata)
        .execute(&self.pool)
        .await?;

        // Invalidate cache
        {
            let mut cache = self.sg_rule_cache.write().await;
            *cache = None;
        }

        info!(rule_id = %rule.id, "Upserted Semgrep rule");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_tree_sitter_rule(&self, rule_id: &str) -> Result<bool, RuleRepositoryError> {
        let result = sqlx::query("DELETE FROM sast_rules WHERE rule_id = $1")
            .bind(rule_id)
            .execute(&self.pool)
            .await?;

        // Invalidate cache
        {
            let mut cache = self.ts_rule_cache.write().await;
            *cache = None;
        }

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self))]
    async fn delete_semgrep_rule(&self, rule_id: &str) -> Result<bool, RuleRepositoryError> {
        let result = sqlx::query("DELETE FROM sast_semgrep_rules WHERE rule_id = $1")
            .bind(rule_id)
            .execute(&self.pool)
            .await?;

        // Invalidate cache
        {
            let mut cache = self.sg_rule_cache.write().await;
            *cache = None;
        }

        Ok(result.rows_affected() > 0)
    }

    #[instrument(skip(self))]
    async fn get_updated_rules_since(
        &self,
        since: DateTime<Utc>,
    ) -> Result<(Vec<Rule>, Vec<SemgrepRule>), RuleRepositoryError> {
        let ts_rows = sqlx::query_as::<_, SastRuleRow>(
            r#"
            SELECT id, rule_id, name, description, severity, languages, 
                   pattern_type, query, options, cwe_ids, owasp_categories, 
                   tags, enabled, created_at, updated_at
            FROM sast_rules
            WHERE updated_at > $1 AND enabled = true
            "#,
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        let ts_rules: Vec<Rule> = ts_rows
            .into_iter()
            .filter_map(|row| Self::row_to_rule(row).ok())
            .collect();

        let sg_rows = sqlx::query_as::<_, SastSemgrepRuleRow>(
            r#"
            SELECT id, rule_id, name, message, languages, severity, mode,
                   pattern, patterns, taint_sources, taint_sinks, 
                   taint_sanitizers, taint_propagators, fix, cwe_ids,
                   owasp_categories, tags, metadata, enabled, 
                   created_at, updated_at
            FROM sast_semgrep_rules
            WHERE updated_at > $1 AND enabled = true
            "#,
        )
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        let sg_rules: Vec<SemgrepRule> = sg_rows
            .into_iter()
            .filter_map(|row| Self::row_to_semgrep_rule(row).ok())
            .collect();

        debug!(
            ts_updated = ts_rules.len(),
            sg_updated = sg_rules.len(),
            "Found updated rules since {}",
            since
        );

        Ok((ts_rules, sg_rules))
    }

    #[instrument(skip(self))]
    async fn get_latest_update_time(&self) -> Result<Option<DateTime<Utc>>, RuleRepositoryError> {
        let result = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
            r#"
            SELECT MAX(updated_at) FROM (
                SELECT MAX(updated_at) as updated_at FROM sast_rules
                UNION ALL
                SELECT MAX(updated_at) as updated_at FROM sast_semgrep_rules
            ) combined
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }
}

/// Hot-reload watcher for rule changes
pub struct RuleHotReloader {
    repository: Arc<dyn SastRuleRepository>,
    poll_interval: Duration,
    last_check: Arc<RwLock<DateTime<Utc>>>,
}

impl RuleHotReloader {
    /// Create a new hot reloader
    pub fn new(repository: Arc<dyn SastRuleRepository>, poll_interval: Duration) -> Self {
        Self {
            repository,
            poll_interval,
            last_check: Arc::new(RwLock::new(Utc::now())),
        }
    }

    /// Check for rule updates
    #[instrument(skip(self))]
    pub async fn check_for_updates(
        &self,
    ) -> Result<(Vec<Rule>, Vec<SemgrepRule>), RuleRepositoryError> {
        let last = *self.last_check.read().await;
        let (ts_rules, sg_rules) = self.repository.get_updated_rules_since(last).await?;

        if !ts_rules.is_empty() || !sg_rules.is_empty() {
            info!(
                ts_updated = ts_rules.len(),
                sg_updated = sg_rules.len(),
                "Rules updated since {}",
                last
            );
        }

        // Update last check time
        *self.last_check.write().await = Utc::now();

        Ok((ts_rules, sg_rules))
    }

    /// Start background polling task
    pub fn start_polling(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let reloader = self.clone();
        let interval = self.poll_interval;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);

            loop {
                ticker.tick().await;

                match reloader.check_for_updates().await {
                    Ok((ts, sg)) => {
                        if !ts.is_empty() || !sg.is_empty() {
                            debug!(
                                "Hot-reload detected {} tree-sitter and {} Semgrep rule updates",
                                ts.len(),
                                sg.len()
                            );
                            // Here you could emit an event or callback for rule updates
                        }
                    }
                    Err(e) => {
                        warn!("Failed to check for rule updates: {}", e);
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity() {
        assert!(matches!(
            PostgresRuleRepository::parse_severity("critical"),
            Severity::Critical
        ));
        assert!(matches!(
            PostgresRuleRepository::parse_severity("HIGH"),
            Severity::High
        ));
        assert!(matches!(
            PostgresRuleRepository::parse_severity("Medium"),
            Severity::Medium
        ));
        assert!(matches!(
            PostgresRuleRepository::parse_severity("low"),
            Severity::Low
        ));
        assert!(matches!(
            PostgresRuleRepository::parse_severity("unknown"),
            Severity::Info
        ));
    }

    #[test]
    fn test_parse_languages() {
        let langs = PostgresRuleRepository::parse_languages(&[
            "python".to_string(),
            "javascript".to_string(),
            "rust".to_string(),
            "unknown".to_string(),
        ]);

        assert_eq!(langs.len(), 3);
        assert!(langs.contains(&Language::Python));
        assert!(langs.contains(&Language::JavaScript));
        assert!(langs.contains(&Language::Rust));
    }

    #[test]
    fn test_languages_to_strings() {
        let langs = vec![Language::Python, Language::JavaScript];
        let strings = PostgresRuleRepository::languages_to_strings(&langs);

        assert_eq!(strings.len(), 2);
        assert!(strings.contains(&"python".to_string()));
        assert!(strings.contains(&"javascript".to_string()));
    }
}
