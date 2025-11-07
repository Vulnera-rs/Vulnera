//! Vulnerability analysis use cases

use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use vulnera_core::application::errors::ApplicationError;
use vulnera_core::application::vulnerability::services::CacheService;
use vulnera_core::domain::vulnerability::{
    entities::{AnalysisReport, Package, Vulnerability},
    repositories::IVulnerabilityRepository,
    value_objects::{Ecosystem, VulnerabilityId},
};
use vulnera_core::infrastructure::parsers::ParserFactory;
use vulnera_core::infrastructure::registries::{CratesIoRegistryClient, PackageRegistryClient};

use crate::services::{PopularPackageService, PopularPackageVulnerabilityResult};

/// Use case for analyzing dependencies from a file
pub struct AnalyzeDependenciesUseCase<C: CacheService> {
    parser_factory: Arc<ParserFactory>,
    vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
    cache_service: Arc<C>,
    max_concurrent_requests: usize,
    max_concurrent_registry_queries: usize,
}

impl<C: CacheService + 'static> AnalyzeDependenciesUseCase<C> {
    /// Create a new use case instance
    pub fn new(
        parser_factory: Arc<ParserFactory>,
        vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
        cache_service: Arc<C>,
        max_concurrent_requests: usize,
    ) -> Self {
        Self {
            parser_factory,
            vulnerability_repository,
            cache_service,
            max_concurrent_requests,
            max_concurrent_registry_queries: 5, // Default value
        }
    }

    /// Create a new use case instance with full configuration
    pub fn new_with_config(
        parser_factory: Arc<ParserFactory>,
        vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
        cache_service: Arc<C>,
        max_concurrent_requests: usize,
        max_concurrent_registry_queries: usize,
    ) -> Self {
        Self {
            parser_factory,
            vulnerability_repository,
            cache_service,
            max_concurrent_requests,
            max_concurrent_registry_queries,
        }
    }

    /// Execute the use case to analyze dependencies
    pub async fn execute(
        &self,
        file_content: &str,
        ecosystem: Ecosystem,
        filename: Option<&str>,
    ) -> Result<AnalysisReport, ApplicationError> {
        let start_time = Instant::now();
        info!(
            "Starting dependency analysis for ecosystem: {:?}",
            ecosystem
        );

        // Precompute Cargo resolution flag before moving ecosystem
        let do_cargo_resolution = matches!(ecosystem, Ecosystem::Cargo)
            && filename.map(|f| f.ends_with("Cargo.toml")).unwrap_or(false);

        // Parse the dependency file
        let mut packages = self
            .parse_dependencies(file_content, ecosystem, filename)
            .await?;

        // Resolve Cargo.toml minor/major specs to latest available version from crates.io (caret semantics)
        // Use parallel processing for better performance
        if do_cargo_resolution {
            let cargo_packages: Vec<_> = packages
                .iter()
                .enumerate()
                .filter_map(|(idx, pkg)| {
                    if matches!(pkg.ecosystem, Ecosystem::Cargo) {
                        Some((idx, pkg))
                    } else {
                        None
                    }
                })
                .collect();

            if !cargo_packages.is_empty() {
                // Process registry queries in parallel with bounded concurrency
                let semaphore = Arc::new(tokio::sync::Semaphore::new(
                    self.max_concurrent_registry_queries,
                ));
                let mut join_set: JoinSet<
                    Result<
                        (
                            usize,
                            Option<vulnera_core::domain::vulnerability::value_objects::Version>,
                        ),
                        ApplicationError,
                    >,
                > = JoinSet::new();

                for (idx, pkg) in cargo_packages {
                    let pkg_name = pkg.name.clone();
                    let lower = pkg.version.clone();
                    let upper = if lower.0.major > 0 {
                        vulnera_core::domain::vulnerability::value_objects::Version::new(
                            lower.0.major + 1,
                            0,
                            0,
                        )
                    } else if lower.0.minor > 0 {
                        vulnera_core::domain::vulnerability::value_objects::Version::new(
                            0,
                            lower.0.minor + 1,
                            0,
                        )
                    } else {
                        vulnera_core::domain::vulnerability::value_objects::Version::new(
                            0,
                            0,
                            lower.0.patch + 1,
                        )
                    };
                    let permit = Arc::clone(&semaphore);

                    join_set.spawn(async move {
                        let _permit = permit.acquire().await.map_err(|e| {
                            ApplicationError::Vulnerability(
                                vulnera_core::application::errors::VulnerabilityError::Api(
                                    vulnera_core::application::errors::ApiError::Http {
                                        status: 500,
                                        message: format!("Failed to acquire semaphore: {}", e),
                                    },
                                ),
                            )
                        })?;
                        // Create a new registry client instance for each task (CratesIoRegistryClient is stateless)
                        let registry = CratesIoRegistryClient;
                        match registry.list_versions(Ecosystem::Cargo, &pkg_name).await {
                            Ok(mut vers) => {
                                // Prefer stable, non-yanked versions within [lower, upper)
                                vers.retain(|vi| {
                                    !vi.yanked
                                        && !vi.is_prerelease
                                        && vi.version >= lower
                                        && vi.version < upper
                                });
                                vers.sort_by(|a, b| a.version.cmp(&b.version));
                                Ok((
                                    idx,
                                    vers.last().map(|best| {
                                        if best.version > lower {
                                            best.version.clone()
                                        } else {
                                            lower
                                        }
                                    }),
                                ))
                            }
                            Err(e) => {
                                debug!(
                                    "crates.io version resolution failed for {}: {}",
                                    pkg_name, e
                                );
                                Ok((idx, None))
                            }
                        }
                    });
                }

                // Collect results and update packages
                while let Some(result) = join_set.join_next().await {
                    match result {
                        Ok(Ok((idx, Some(resolved_version)))) => {
                            if let Some(pkg) = packages.get_mut(idx) {
                                if resolved_version > pkg.version {
                                    debug!(
                                        "Resolved Cargo.toml spec for {}: {} -> {}",
                                        pkg.name, pkg.version, resolved_version
                                    );
                                    pkg.version = resolved_version;
                                }
                            }
                        }
                        Ok(Ok((_idx, None))) => {
                            // Resolution failed, keep original version
                        }
                        Ok(Err(e)) => {
                            warn!("Error during parallel Cargo version resolution: {}", e);
                        }
                        Err(e) => {
                            warn!("Join error during parallel Cargo version resolution: {}", e);
                        }
                    }
                }
            }
        }

        if packages.is_empty() {
            warn!("No packages found in dependency file");
            let analysis_duration = start_time.elapsed();
            return Ok(AnalysisReport::new(
                packages,
                vec![],
                analysis_duration,
                vec!["No packages found".to_string()],
            ));
        }

        info!("Parsed {} packages from dependency file", packages.len());

        // Convert packages to Arc for shared ownership to avoid cloning
        let packages_arc: Vec<Arc<Package>> =
            packages.iter().map(|p| Arc::new(p.clone())).collect();

        // Look up vulnerabilities for all packages concurrently
        let vulnerabilities = self
            .process_packages_concurrently_arc(&packages_arc)
            .await?;

        let analysis_duration = start_time.elapsed();
        let sources_queried = {
            let mut set = std::collections::BTreeSet::new();
            for v in &vulnerabilities {
                for src in &v.sources {
                    set.insert(format!("{:?}", src));
                }
            }
            if set.is_empty() {
                vec!["OSV".to_string(), "NVD".to_string()]
            } else {
                set.into_iter().collect()
            }
        };

        let report = AnalysisReport::new(
            packages,
            vulnerabilities,
            analysis_duration,
            sources_queried,
        );

        info!(
            "Analysis completed in {:?}: {} packages, {} vulnerabilities",
            analysis_duration,
            report.metadata.total_packages,
            report.metadata.total_vulnerabilities
        );

        Ok(report)
    }

    /// Parse dependency file content into packages
    async fn parse_dependencies(
        &self,
        file_content: &str,
        ecosystem: Ecosystem,
        filename: Option<&str>,
    ) -> Result<Vec<Package>, ApplicationError> {
        // Try to find a parser based on filename first
        if let Some(filename) = filename {
            if let Some(parser) = self.parser_factory.create_parser(filename) {
                debug!("Using parser for filename: {}", filename);
                return parser
                    .parse_file(file_content)
                    .await
                    .map_err(ApplicationError::Parse);
            }
        }

        // Fall back to ecosystem-based parsing by trying common filenames for the ecosystem
        let common_filenames = match ecosystem {
            Ecosystem::Npm => vec!["package.json", "package-lock.json", "yarn.lock"],
            Ecosystem::PyPI => vec!["requirements.txt", "Pipfile", "pyproject.toml"],
            Ecosystem::Maven => vec!["pom.xml"],
            Ecosystem::Cargo => vec!["Cargo.toml", "Cargo.lock"],
            Ecosystem::Go => vec!["go.mod", "go.sum"],
            Ecosystem::Packagist => vec!["composer.json", "composer.lock"],
            _ => vec![],
        };

        // Try each common filename for the ecosystem
        for filename in common_filenames {
            if let Some(parser) = self.parser_factory.create_parser(filename) {
                debug!(
                    "Using parser for ecosystem {:?} with filename: {}",
                    ecosystem, filename
                );
                return parser
                    .parse_file(file_content)
                    .await
                    .map_err(ApplicationError::Parse);
            }
        }

        error!("No parser found for ecosystem: {:?}", ecosystem);
        Err(ApplicationError::InvalidEcosystem {
            ecosystem: format!("{:?}", ecosystem),
        })
    }

    /// Process packages concurrently with proper error handling and bounded concurrency
    /// Uses Arc<Package> to avoid unnecessary cloning
    async fn process_packages_concurrently_arc(
        &self,
        packages: &[Arc<Package>],
    ) -> Result<Vec<Vulnerability>, ApplicationError> {
        // Pre-allocate vector with estimated capacity to avoid reallocations
        // Estimate: average 2-3 vulnerabilities per package
        let estimated_capacity = packages.len() * 3;
        let mut all_vulnerabilities = Vec::with_capacity(estimated_capacity);
        let mut processed_count = 0;
        let mut join_set: JoinSet<Result<(String, Vec<Vulnerability>), ApplicationError>> =
            JoinSet::new();

        info!(
            "Processing {} packages with max_concurrent_requests: {}",
            packages.len(),
            self.max_concurrent_requests
        );

        // Process packages in chunks to respect concurrency limits
        for chunk in packages.chunks(self.max_concurrent_requests) {
            // Spawn tasks for current chunk
            for package_arc in chunk {
                let package_arc = Arc::clone(package_arc);
                let vuln_repo = self.vulnerability_repository.clone();
                let cache_service = self.cache_service.clone();

                join_set.spawn(async move {
                            let package_id = package_arc.identifier();

                            // Use optimized cache key generation
                            let cache_key = vulnera_core::infrastructure::cache::CacheServiceImpl::package_vulnerabilities_key(&package_arc);

                            // Check cache first
                            if let Ok(Some(cached_vulns)) =
                                cache_service.get::<Vec<Vulnerability>>(&cache_key).await
                            {
                                let total = cached_vulns.len();
                                // Filter to only vulnerabilities that actually affect this package version
                                let filtered: Vec<Vulnerability> = cached_vulns
                                    .into_iter()
                                    .filter(|v| v.affects_package(&package_arc))
                                    .collect();
                                debug!("Cache hit for package: {} (filtered {} -> {} affecting current version)", package_id, total, filtered.len());
                                return Ok((package_id, filtered));
                            }

                            // Cache miss - query repository
                            debug!(
                                "Cache miss for package: {}, querying repository",
                                package_id
                            );

                            match vuln_repo.find_vulnerabilities(&package_arc).await {
                                Ok(vulnerabilities) => {
                                    let total = vulnerabilities.len();
                                    let filtered: Vec<Vulnerability> = vulnerabilities
                                        .into_iter()
                                        .filter(|v| v.affects_package(&package_arc))
                                        .collect();

                                    // Cache the filtered result for future use
                                    let cache_ttl = std::time::Duration::from_secs(24 * 3600); // 24 hours
                                    if let Err(e) = cache_service
                                        .set(&cache_key, &filtered, cache_ttl)
                                        .await
                                    {
                                        warn!("Failed to cache vulnerabilities for {}: {}", package_id, e);
                                    }

                                    debug!(
                                        "Found {} vulnerabilities for package: {} ({} affect current version)",
                                        total,
                                        package_id,
                                        filtered.len()
                                    );
                                    Ok((package_id, filtered))
                                }
                                Err(e) => {
                                    error!(
                                        "Failed to lookup vulnerabilities for package {}: {}",
                                        package_id, e
                                    );
                                    // Continue processing other packages instead of failing completely
                                    Ok((package_id, vec![]))
                                }
                            }
                        });
            }

            // Collect results from current chunk
            while let Some(result) = join_set.join_next().await {
                match result {
                    Ok(Ok((package_id, vulnerabilities))) => {
                        processed_count += 1;
                        debug!("Completed processing package: {}", package_id);
                        all_vulnerabilities.extend(vulnerabilities);
                    }
                    Ok(Err(e)) => {
                        error!("Package processing error: {}", e);
                        processed_count += 1;
                    }
                    Err(e) => {
                        error!("Join error: {}", e);
                        processed_count += 1;
                    }
                }
            }
        }

        info!(
            "Processed {} packages, found {} total vulnerabilities",
            processed_count,
            all_vulnerabilities.len()
        );

        Ok(all_vulnerabilities)
    }
}

/// Use case for getting vulnerability details by ID
pub struct GetVulnerabilityDetailsUseCase<C: CacheService> {
    vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
    cache_service: Arc<C>,
}

impl<C: CacheService + 'static> GetVulnerabilityDetailsUseCase<C> {
    /// Create a new use case instance
    pub fn new(
        vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
        cache_service: Arc<C>,
    ) -> Self {
        Self {
            vulnerability_repository,
            cache_service,
        }
    }

    /// Execute the use case to get vulnerability details
    pub async fn execute(
        &self,
        vulnerability_id: &VulnerabilityId,
    ) -> Result<Vulnerability, ApplicationError> {
        let cache_key = format!("vuln_details:{}", vulnerability_id.as_str());

        // Try cache first
        if let Some(cached_vulnerability) =
            self.cache_service.get::<Vulnerability>(&cache_key).await?
        {
            debug!("Cache hit for vulnerability: {}", vulnerability_id.as_str());
            return Ok(cached_vulnerability);
        }

        debug!(
            "Cache miss for vulnerability: {}, querying repository",
            vulnerability_id.as_str()
        );

        // Query repository
        let vulnerability = self
            .vulnerability_repository
            .get_vulnerability_by_id(vulnerability_id)
            .await
            .map_err(ApplicationError::Vulnerability)?
            .ok_or_else(|| ApplicationError::NotFound {
                resource: "vulnerability".to_string(),
                id: vulnerability_id.as_str().to_string(),
            })?;

        // Cache for 24 hours
        let cache_ttl = std::time::Duration::from_secs(24 * 60 * 60);
        if let Err(e) = self
            .cache_service
            .set(&cache_key, &vulnerability, cache_ttl)
            .await
        {
            warn!(
                "Failed to cache vulnerability {}: {}",
                vulnerability_id.as_str(),
                e
            );
        }

        Ok(vulnerability)
    }
}

/// Use case for listing vulnerabilities with pagination and filtering
pub struct ListVulnerabilitiesUseCase {
    popular_package_service: Arc<dyn PopularPackageService>,
}

impl ListVulnerabilitiesUseCase {
    /// Create a new use case instance
    pub fn new(popular_package_service: Arc<dyn PopularPackageService>) -> Self {
        Self {
            popular_package_service,
        }
    }

    /// Execute the use case to list vulnerabilities
    pub async fn execute(
        &self,
        page: u32,
        per_page: u32,
        ecosystem_filter: Option<&str>,
        severity_filter: Option<&str>,
    ) -> Result<PopularPackageVulnerabilityResult, ApplicationError> {
        self.popular_package_service
            .list_vulnerabilities(page, per_page, ecosystem_filter, severity_filter)
            .await
    }
}
