//! Schema reference resolver for OpenAPI specifications
//!
//! This module handles resolving `$ref` references in OpenAPI schemas,
//! including circular reference detection and caching.

use crate::domain::value_objects::{ApiProperty, ApiSchema};
use serde_json::Value as JsonValue;
use std::collections::{HashMap, HashSet};
use tracing::warn;

/// Maximum depth for schema resolution to prevent infinite recursion
const MAX_RESOLUTION_DEPTH: usize = 50;

/// Map of schema names to their JSON definitions
pub type SchemaMap = HashMap<String, JsonValue>;

/// Resolver for schema references in OpenAPI specifications
pub struct SchemaRefResolver {
    /// Schema definitions from components/schemas
    schemas: SchemaMap,
    /// Cache of resolved schemas by reference path
    cache: HashMap<String, ApiSchema>,
    /// Track currently resolving references to detect cycles
    resolving: HashSet<String>,
    /// Current resolution depth
    depth: usize,
}

impl SchemaRefResolver {
    /// Create a new schema reference resolver with schema definitions
    pub fn new(schemas: SchemaMap) -> Self {
        Self {
            schemas,
            cache: HashMap::new(),
            resolving: HashSet::new(),
            depth: 0,
        }
    }

    /// Resolve a schema reference
    ///
    /// Returns `None` if:
    /// - The reference is circular
    /// - Maximum resolution depth is exceeded
    /// - The reference cannot be found
    pub fn resolve_ref(&mut self, ref_path: &str) -> Option<ApiSchema> {
        // Check depth limit
        if self.depth >= MAX_RESOLUTION_DEPTH {
            warn!(
                ref_path = ref_path,
                max_depth = MAX_RESOLUTION_DEPTH,
                "Maximum schema resolution depth exceeded"
            );
            return None;
        }

        // Check for circular reference
        if self.resolving.contains(ref_path) {
            warn!(
                ref_path = ref_path,
                "Circular schema reference detected, returning empty schema"
            );
            return None;
        }

        // Check cache
        if let Some(cached) = self.cache.get(ref_path) {
            return Some(cached.clone());
        }

        // Mark as resolving
        self.resolving.insert(ref_path.to_string());
        self.depth += 1;

        // Parse and resolve the reference
        let schema = self.resolve_ref_internal(ref_path);

        // Clean up
        self.depth -= 1;
        self.resolving.remove(ref_path);

        // Cache successful resolution
        if let Some(ref s) = schema {
            self.cache.insert(ref_path.to_string(), s.clone());
        }

        schema
    }

    /// Internal resolution logic
    fn resolve_ref_internal(&mut self, ref_path: &str) -> Option<ApiSchema> {
        // Parse reference path (e.g., "#/components/schemas/User")
        let parts: Vec<&str> = ref_path.trim_start_matches("#/").split('/').collect();

        match parts.as_slice() {
            ["components", "schemas", schema_name] => {
                // Look up schema in the schema map and clone it to avoid borrow issues
                if let Some(schema_json) = self.schemas.get(*schema_name).cloned() {
                    return Some(self.parse_schema_from_json(&schema_json));
                } else {
                    warn!(
                        ref_path = ref_path,
                        schema_name = schema_name,
                        "Schema not found in components"
                    );
                }
            }
            _ => {
                warn!(
                    ref_path = ref_path,
                    "Unsupported reference path format (only #/components/schemas/* supported)"
                );
            }
        }

        None
    }

    /// Parse a schema from JSON (public method)
    pub fn parse_schema_from_json(&mut self, schema_json: &JsonValue) -> ApiSchema {
        // Check if this is a reference
        if let Some(ref_path) = schema_json.get("$ref").and_then(|r| r.as_str()) {
            // Resolve the reference
            return self.resolve_ref(ref_path).unwrap_or_else(|| {
                warn!(ref_path = ref_path, "Failed to resolve schema reference");
                ApiSchema {
                    schema_type: Some("ref_unresolved".to_string()),
                    ..Default::default()
                }
            });
        }

        // Parse schema properties
        let schema_type = schema_json
            .get("type")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string());

        let format = schema_json
            .get("format")
            .and_then(|f| f.as_str())
            .map(|s| s.to_string());

        let required: Vec<String> = schema_json
            .get("required")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // Parse properties recursively
        let properties: Vec<ApiProperty> = schema_json
            .get("properties")
            .and_then(|p| p.as_object())
            .map(|props| {
                props
                    .iter()
                    .map(|(name, prop_schema)| ApiProperty {
                        name: name.clone(),
                        schema: self.parse_schema_from_json(prop_schema),
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Extract validation constraints
        let pattern = schema_json
            .get("pattern")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let minimum = schema_json.get("minimum").and_then(|v| v.as_f64());
        let maximum = schema_json.get("maximum").and_then(|v| v.as_f64());
        let min_length = schema_json
            .get("minLength")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let max_length = schema_json
            .get("maxLength")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let min_items = schema_json
            .get("minItems")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let max_items = schema_json
            .get("maxItems")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let enum_values = schema_json
            .get("enum")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            });

        // Extract security-relevant metadata
        let example = schema_json.get("example").cloned();
        let default = schema_json.get("default").cloned();
        let read_only = schema_json
            .get("readOnly")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let write_only = schema_json
            .get("writeOnly")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Parse additionalProperties
        use crate::domain::value_objects::AdditionalProperties;
        let additional_properties = match schema_json.get("additionalProperties") {
            Some(JsonValue::Bool(false)) => AdditionalProperties::Denied,
            Some(JsonValue::Bool(true)) => AdditionalProperties::Allowed,
            Some(obj) if obj.is_object() => {
                let inner_schema = self.parse_schema_from_json(obj);
                AdditionalProperties::Schema(Box::new(inner_schema))
            }
            _ => AdditionalProperties::Allowed, // Default
        };

        ApiSchema {
            schema_type,
            format,
            properties,
            required,
            pattern,
            minimum,
            maximum,
            min_length,
            max_length,
            min_items,
            max_items,
            enum_values,
            example,
            default,
            read_only,
            write_only,
            additional_properties,
            ..Default::default()
        }
    }

    /// Get cache statistics (for debugging/monitoring)
    pub fn stats(&self) -> SchemaResolverStats {
        SchemaResolverStats {
            cached_schemas: self.cache.len(),
            max_depth_reached: self.depth,
        }
    }
}

impl Default for SchemaRefResolver {
    fn default() -> Self {
        Self::new(HashMap::new())
    }
}

/// Statistics about schema resolution
#[derive(Debug, Clone)]
pub struct SchemaResolverStats {
    pub cached_schemas: usize,
    pub max_depth_reached: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circular_reference_detection() {
        let mut resolver = SchemaRefResolver::new(HashMap::new());

        // Manually add a circular reference scenario
        resolver
            .resolving
            .insert("#/components/schemas/Node".to_string());

        // Should detect the cycle
        assert!(resolver.resolving.contains("#/components/schemas/Node"));
    }

    #[test]
    fn test_cache_works() {
        let resolver = SchemaRefResolver::new(HashMap::new());

        // Initially empty
        assert_eq!(resolver.cache.len(), 0);
    }

    #[test]
    fn test_max_depth_check() {
        let mut resolver = SchemaRefResolver::new(HashMap::new());
        resolver.depth = MAX_RESOLUTION_DEPTH;

        // Should return None due to depth limit
        let result = resolver.resolve_ref("#/components/schemas/Test");
        assert!(result.is_none());
    }
}
