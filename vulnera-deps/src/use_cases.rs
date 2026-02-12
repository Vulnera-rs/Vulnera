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
use vulnera_core::infrastructure::registries::{PackageRegistryClient, VulneraRegistryAdapter};

use crate::application::analysis_context::{AnalysisContext, detect_workspace};
use crate::domain::{DependencyGraph, PackageId};
use crate::services::resolution_algorithms::{BacktrackingResolver, LexicographicOptimizer};
use crate::services::{
    PopularPackageService, PopularPackageVulnerabilityResult,
    dependency_resolver::{DependencyResolverService, DependencyResolverServiceImpl},
    resolution::RecursiveResolver,
};
use std::collections::HashMap;
use std::path::PathBuf;

/// Use case for analyzing dependencies from a file
pub struct AnalyzeDependenciesUseCase<C: CacheService + 'static> {
    parser_factory: Arc<ParserFactory>,
    vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
    cache_service: Arc<C>,
    max_concurrent_requests: usize,
    max_concurrent_registry_queries: usize,
    dependency_resolver: Arc<dyn DependencyResolverService>,
    recursive_resolver: Arc<RecursiveResolver<C>>,
    analysis_context: Option<Arc<AnalysisContext>>,
}

impl<C: CacheService + 'static> AnalyzeDependenciesUseCase<C> {
    /// Create a new use case instance
    pub fn new(
        parser_factory: Arc<ParserFactory>,
        vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
        cache_service: Arc<C>,
        max_concurrent_requests: usize,
    ) -> Self {
        let dependency_resolver =
            Arc::new(DependencyResolverServiceImpl::new(parser_factory.clone()));
        let registry_client = Arc::new(VulneraRegistryAdapter::new());
        let recursive_resolver = Arc::new(RecursiveResolver::new(
            registry_client,
            cache_service.clone(),
            5, // Default max depth
        ));
        Self {
            parser_factory,
            vulnerability_repository,
            cache_service,
            max_concurrent_requests,
            max_concurrent_registry_queries: 5, // Default value
            dependency_resolver,
            recursive_resolver,
            analysis_context: None,
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
        let dependency_resolver =
            Arc::new(DependencyResolverServiceImpl::new(parser_factory.clone()));
        let registry_client = Arc::new(VulneraRegistryAdapter::new());
        let recursive_resolver = Arc::new(RecursiveResolver::new(
            registry_client,
            cache_service.clone(),
            5, // Default max depth
        ));
        Self {
            parser_factory,
            vulnerability_repository,
            cache_service,
            max_concurrent_requests,
            max_concurrent_registry_queries,
            dependency_resolver,
            recursive_resolver,
            analysis_context: None,
        }
    }

    /// Create a new use case instance with analysis context
    pub fn new_with_context(
        parser_factory: Arc<ParserFactory>,
        vulnerability_repository: Arc<dyn IVulnerabilityRepository>,
        cache_service: Arc<C>,
        max_concurrent_requests: usize,
        max_concurrent_registry_queries: usize,
        project_root: Option<PathBuf>,
    ) -> Self {
        let dependency_resolver =
            Arc::new(DependencyResolverServiceImpl::new(parser_factory.clone()));
        let registry_client = Arc::new(VulneraRegistryAdapter::new());
        let recursive_resolver = Arc::new(RecursiveResolver::new(
            registry_client,
            cache_service.clone(),
            5, // Default max depth
        ));
        let analysis_context = project_root.map(|root| Arc::new(AnalysisContext::new(root)));
        Self {
            parser_factory,
            vulnerability_repository,
            cache_service,
            max_concurrent_requests,
            max_concurrent_registry_queries,
            dependency_resolver,
            recursive_resolver,
            analysis_context,
        }
    }

    /// Execute the use case to analyze dependencies
    /// Returns both the analysis report and the dependency graph
    pub async fn execute(
        &self,
        file_content: &str,
        ecosystem: Ecosystem,
        filename: Option<&str>,
    ) -> Result<(AnalysisReport, DependencyGraph), ApplicationError> {
        let start_time = Instant::now();
        info!(
            "Starting dependency analysis for ecosystem: {:?}",
            ecosystem
        );

        // Use analysis context for workspace detection and caching if available
        let file_path = filename.map(PathBuf::from);
        if let (Some(ctx), Some(path)) = (&self.analysis_context, &file_path) {
            // Check if file should be ignored
            if ctx.should_ignore(path) {
                info!("File {} is ignored by analysis context", path.display());
                let empty_graph = DependencyGraph::new();
                return Ok((
                    AnalysisReport::new(
                        vec![],
                        vec![],
                        start_time.elapsed(),
                        vec!["File ignored".to_string()],
                    ),
                    empty_graph,
                ));
            }

            // Check if file needs re-analysis (cache check)
            if !ctx.needs_analysis(path) {
                debug!(
                    "File {} is up-to-date in cache, attempting to retrieve cached results",
                    path.display()
                );

                // Try to retrieve cached results
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                file_content.hash(&mut hasher);
                let content_hash = hasher.finish();
                let cache_key = format!("analysis_result:{}:{}", path.display(), content_hash);

                // Try to get cached report and graph
                if let Ok(Some(cached_result)) = self
                    .cache_service
                    .get::<(AnalysisReport, DependencyGraph)>(&cache_key)
                    .await
                {
                    info!("Retrieved cached analysis results for {}", path.display());
                    return Ok(cached_result);
                } else {
                    debug!(
                        "No cached results found for {}, proceeding with analysis",
                        path.display()
                    );
                }
            }

            // Detect workspace if not already detected
            if ctx.workspace.is_none() {
                if let Some(workspace) = detect_workspace(&ctx.project_root) {
                    // Note: We can't mutate ctx here, but we could update it in a future version
                    debug!("Detected workspace: {:?}", workspace);
                }
            }
        }

        // Precompute Cargo resolution flag before moving ecosystem
        let do_cargo_resolution = matches!(ecosystem, Ecosystem::Cargo)
            && filename.map(|f| f.ends_with("Cargo.toml")).unwrap_or(false);

        // Parse the dependency file
        let parse_result = self
            .parse_dependencies(file_content, ecosystem.clone(), filename)
            .await?;
        let mut packages = parse_result.packages;
        let dependencies = parse_result.dependencies;

        if packages.is_empty() {
            warn!("No packages found in dependency file");
            let analysis_duration = start_time.elapsed();
            let empty_graph = DependencyGraph::new();
            return Ok((
                AnalysisReport::new(
                    packages,
                    vec![],
                    analysis_duration,
                    vec!["No packages found".to_string()],
                ),
                empty_graph,
            ));
        }

        // Build dependency graph using DependencyResolverService
        let mut dependency_graph = self
            .dependency_resolver
            .build_graph(packages.clone(), dependencies, ecosystem.clone())
            .await?;

        // If the graph is empty (manifest-only project without lockfile),
        // use the RecursiveResolver to perform a deep subtree resolution.
        if dependency_graph.dependency_count() == 0 && !packages.is_empty() {
            debug!(
                "No dependency edges found for {:?}. Triggering recursive resolution for deep analysis.",
                ecosystem
            );
            match self
                .recursive_resolver
                .resolve(packages.clone(), ecosystem.clone())
                .await
            {
                Ok(res) => {
                    dependency_graph = res.graph;
                    debug!(
                        "Recursive resolution completed: {} packages, {} dependencies",
                        dependency_graph.package_count(),
                        dependency_graph.dependency_count()
                    );
                }
                Err(e) => {
                    warn!(
                        "Recursive resolution failed, falling back to flat analysis: {}",
                        e
                    );
                }
            }
        } else {
            debug!(
                "Built dependency graph: {} packages, {} dependencies",
                dependency_graph.package_count(),
                dependency_graph.dependency_count()
            );
        }

        // Final synchronization: ensure the packages list matches the nodes in the graph.
        // This ensures that any packages discovered during resolution are included in the analysis.
        // We filter out the project root node if it's present in the graph but not in the original
        // packages list, as it's typically the starting point rather than a dependency to be scanned.
        let mut final_packages = Vec::new();
        let initial_package_ids: std::collections::HashSet<_> =
            packages.iter().map(PackageId::from_package).collect();

        for node in dependency_graph.nodes.values() {
            let pkg = &node.package;
            let id = &node.id;

            // Include if it's an original package OR discovered transitive dependency (has incoming edges).
            let has_incoming = dependency_graph.edges.iter().any(|e| &e.to == id);

            if (initial_package_ids.contains(id) || has_incoming)
                && !final_packages
                    .iter()
                    .any(|p: &Package| p.name == pkg.name && p.version == pkg.version)
            {
                final_packages.push(pkg.clone());
            }
        }
        packages = final_packages;

        // Keep the graph in sync with the filtered packages list
        let final_package_ids: std::collections::HashSet<_> =
            packages.iter().map(PackageId::from_package).collect();
        dependency_graph
            .nodes
            .retain(|id, _| final_package_ids.contains(id));
        dependency_graph
            .edges
            .retain(|e| final_package_ids.contains(&e.from) && final_package_ids.contains(&e.to));
        dependency_graph
            .root_packages
            .retain(|id| final_package_ids.contains(id));

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
                        // Create a new registry client instance for each task
                        let registry = VulneraRegistryAdapter::new();
                        match registry.list_versions(Ecosystem::Cargo, &pkg_name).await {
                            Ok(mut vers) => {
                                // Prefer stable, non-yanked versions within [lower, upper)
                                vers.retain(|vi| {
                                    !vi.yanked
                                        && !vi.is_prerelease
                                        && vi.version >= lower
                                        && vi.version < upper
                                });
                                // Use LexicographicOptimizer to select best version
                                // (prefers patch > minor > major upgrades)
                                let candidate_versions: Vec<_> =
                                    vers.iter().map(|vi| vi.version.clone()).collect();
                                let selected = LexicographicOptimizer::select_version(
                                    Some(&lower),
                                    &candidate_versions,
                                );
                                Ok((
                                    idx,
                                    selected.and_then(|v| if v > lower { Some(v) } else { None }),
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

        info!(
            "Parsed {} packages from dependency file (graph has {} packages)",
            packages.len(),
            dependency_graph.package_count()
        );

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

        // Use BacktrackingResolver for complex constraint resolution if needed
        // This could be used for resolving version conflicts in the dependency graph
        if dependency_graph.dependency_count() > 0 {
            debug!(
                "Dependency graph available with {} edges for constraint resolution",
                dependency_graph.dependency_count()
            );

            // Fetch available versions for all packages in the graph
            match self
                .get_available_versions(&dependency_graph, ecosystem.clone())
                .await
            {
                Ok(available_versions) => {
                    if !available_versions.is_empty() {
                        let resolution_result =
                            BacktrackingResolver::resolve(&dependency_graph, &available_versions);
                        if !resolution_result.conflicts.is_empty() {
                            warn!(
                                "Found {} dependency conflicts in the dependency graph",
                                resolution_result.conflicts.len()
                            );
                            for conflict in &resolution_result.conflicts {
                                warn!("Conflict for {}: {}", conflict.package, conflict.message);
                            }
                        } else {
                            debug!(
                                "Successfully resolved {} packages with no conflicts",
                                resolution_result.resolved.len()
                            );
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to fetch available versions for conflict resolution: {}",
                        e
                    );
                    // Continue without conflict resolution - this is best-effort
                }
            }
        }

        let report = AnalysisReport::new(
            packages,
            vulnerabilities,
            analysis_duration,
            sources_queried,
        );

        info!(
            "Analysis completed in {:?}: {} packages, {} vulnerabilities (graph: {} nodes, {} edges)",
            analysis_duration,
            report.metadata.total_packages,
            report.metadata.total_vulnerabilities,
            dependency_graph.package_count(),
            dependency_graph.dependency_count()
        );

        // Store results in cache if analysis context is available
        if let (Some(_ctx), Some(path)) = (&self.analysis_context, &file_path) {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            file_content.hash(&mut hasher);
            let content_hash = hasher.finish();
            let cache_key = format!("analysis_result:{}:{}", path.display(), content_hash);

            // Cache the results with a TTL of 24 hours
            let cache_ttl = std::time::Duration::from_secs(24 * 3600);
            let result_to_cache = (report.clone(), dependency_graph.clone());
            if let Err(e) = self
                .cache_service
                .set(&cache_key, &result_to_cache, cache_ttl)
                .await
            {
                warn!(
                    "Failed to cache analysis results for {}: {}",
                    path.display(),
                    e
                );
            } else {
                debug!("Cached analysis results for {}", path.display());
            }
        }

        Ok((report, dependency_graph))
    }

    /// Parse dependency file content into packages
    async fn parse_dependencies(
        &self,
        file_content: &str,
        ecosystem: Ecosystem,
        filename: Option<&str>,
    ) -> Result<vulnera_core::infrastructure::parsers::ParseResult, ApplicationError> {
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
            Ecosystem::PyPI => vec![
                "uv.lock",
                "poetry.lock",
                "Pipfile.lock",
                "requirements.txt",
                "Pipfile",
                "pyproject.toml",
            ],
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

    /// Helper method to fetch available versions for all packages in a dependency graph
    async fn get_available_versions(
        &self,
        graph: &DependencyGraph,
        ecosystem: Ecosystem,
    ) -> Result<
        HashMap<PackageId, Vec<vulnera_core::domain::vulnerability::value_objects::Version>>,
        ApplicationError,
    > {
        use vulnera_core::infrastructure::registries::VulneraRegistryAdapter;

        let registry: Arc<dyn PackageRegistryClient> = Arc::new(VulneraRegistryAdapter::new());

        let mut available_versions = HashMap::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            self.max_concurrent_registry_queries,
        ));
        let mut join_set: JoinSet<
            Result<
                (
                    PackageId,
                    Vec<vulnera_core::domain::vulnerability::value_objects::Version>,
                ),
                ApplicationError,
            >,
        > = JoinSet::new();

        // Fetch versions for each package in the graph
        for package_id in graph.nodes.keys() {
            let package_id_clone = package_id.clone();
            let package_name = package_id.name.clone();
            let ecosystem_clone = ecosystem.clone();
            let registry_clone = registry.clone();
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

                match registry_clone
                    .list_versions(ecosystem_clone, &package_name)
                    .await
                {
                    Ok(version_infos) => {
                        let versions: Vec<
                            vulnera_core::domain::vulnerability::value_objects::Version,
                        > = version_infos.into_iter().map(|vi| vi.version).collect();
                        Ok((package_id_clone, versions))
                    }
                    Err(e) => {
                        debug!("Failed to fetch versions for {}: {}", package_name, e);
                        // Return empty vector rather than error - best effort
                        Ok((package_id_clone, Vec::new()))
                    }
                }
            });
        }

        // Collect results
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok((package_id, versions))) => {
                    if !versions.is_empty() {
                        available_versions.insert(package_id, versions);
                    }
                }
                Ok(Err(e)) => {
                    warn!("Error fetching available versions: {}", e);
                    // Continue with other packages
                }
                Err(e) => {
                    warn!("Join error while fetching available versions: {}", e);
                    // Continue with other packages
                }
            }
        }

        Ok(available_versions)
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
