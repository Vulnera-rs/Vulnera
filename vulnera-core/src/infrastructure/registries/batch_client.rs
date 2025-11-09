//! Batch registry client for efficient package version queries
//!
//! This module provides batch operations for querying multiple packages
//! from registries in a single request, reducing network overhead.

use crate::domain::vulnerability::value_objects::Ecosystem;
use async_trait::async_trait;
use std::collections::HashMap;

use super::{PackageRegistryClient, RegistryError, VersionInfo};

/// Query for a package version
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageQuery {
    pub ecosystem: Ecosystem,
    pub name: String,
}

/// Batch registry client trait
#[async_trait]
pub trait BatchRegistryClient: Send + Sync {
    /// Query multiple packages in a single batch request
    async fn list_versions_batch(
        &self,
        queries: &[PackageQuery],
    ) -> Result<HashMap<PackageQuery, Vec<VersionInfo>>, RegistryError>;
}

/// Wrapper that implements batch operations using individual registry clients
pub struct BatchRegistryClientWrapper {
    clients: HashMap<Ecosystem, Box<dyn PackageRegistryClient>>,
    batch_size: usize,
}

impl BatchRegistryClientWrapper {
    pub fn new(batch_size: usize) -> Self {
        Self {
            clients: HashMap::new(),
            batch_size,
        }
    }

    pub fn add_client(&mut self, ecosystem: Ecosystem, client: Box<dyn PackageRegistryClient>) {
        self.clients.insert(ecosystem, client);
    }
}

#[async_trait]
impl BatchRegistryClient for BatchRegistryClientWrapper {
    async fn list_versions_batch(
        &self,
        queries: &[PackageQuery],
    ) -> Result<HashMap<PackageQuery, Vec<VersionInfo>>, RegistryError> {
        let mut results = HashMap::new();

        // Group queries by ecosystem
        let mut queries_by_ecosystem: HashMap<Ecosystem, Vec<&PackageQuery>> = HashMap::new();
        for query in queries {
            queries_by_ecosystem
                .entry(query.ecosystem.clone())
                .or_insert_with(Vec::new)
                .push(query);
        }

        // Process each ecosystem's queries in batches
        for (ecosystem, ecosystem_queries) in queries_by_ecosystem {
            if let Some(client) = self.clients.get(&ecosystem) {
                // Process in batches to avoid overwhelming the registry
                for chunk in ecosystem_queries.chunks(self.batch_size) {
                    for query in chunk {
                        let query_clone = (*query).clone();
                        match client
                            .list_versions(query.ecosystem.clone(), &query.name)
                            .await
                        {
                            Ok(versions) => {
                                results.insert(query_clone, versions);
                            }
                            Err(e) => {
                                // Log error but continue with other queries
                                tracing::warn!(
                                    "Failed to query {}:{}: {}",
                                    query.ecosystem.canonical_name(),
                                    query.name,
                                    e
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(results)
    }
}
