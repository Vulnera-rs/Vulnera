//! Provider Registry
//!
//! Manages provider instances and supports dynamic provider selection.

use std::collections::HashMap;
use std::sync::Arc;

use crate::domain::{LlmError, LlmProvider};
use crate::infrastructure::providers::{GoogleAIProvider, OpenAIProvider, ResilienceConfig};

/// Provider type identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProviderType {
    GoogleAI,
    OpenAI,
    Azure,
    Custom(String),
}

impl ProviderType {
    /// Parse from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "google_ai" | "gemini" | "google" => Self::GoogleAI,
            "openai" | "gpt" => Self::OpenAI,
            "azure" | "azure_openai" => Self::Azure,
            other => Self::Custom(other.to_string()),
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &str {
        match self {
            Self::GoogleAI => "google_ai",
            Self::OpenAI => "openai",
            Self::Azure => "azure",
            Self::Custom(s) => s,
        }
    }
}

/// Configuration for provider creation
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// Provider type
    pub provider_type: ProviderType,
    /// API key
    pub api_key: String,
    /// Model name
    pub model: String,
    /// Azure endpoint (for Azure provider)
    pub azure_endpoint: Option<String>,
    /// Azure deployment (for Azure provider)
    pub azure_deployment: Option<String>,
    /// Azure API version (for Azure provider)
    pub azure_api_version: Option<String>,
    /// OpenAI organization ID
    pub organization_id: Option<String>,
    /// Custom base URL
    pub base_url: Option<String>,
    /// Resilience configuration
    pub resilience: Option<ResilienceConfig>,
}

impl ProviderConfig {
    /// Create a Google AI provider config
    pub fn google_ai(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            provider_type: ProviderType::GoogleAI,
            api_key: api_key.into(),
            model: model.into(),
            azure_endpoint: None,
            azure_deployment: None,
            azure_api_version: None,
            organization_id: None,
            base_url: None,
            resilience: Some(ResilienceConfig::default()),
        }
    }

    /// Create an OpenAI provider config
    pub fn openai(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            provider_type: ProviderType::OpenAI,
            api_key: api_key.into(),
            model: model.into(),
            azure_endpoint: None,
            azure_deployment: None,
            azure_api_version: None,
            organization_id: None,
            base_url: None,
            resilience: Some(ResilienceConfig::default()),
        }
    }

    /// Create an Azure OpenAI provider config
    pub fn azure(
        endpoint: impl Into<String>,
        api_key: impl Into<String>,
        deployment: impl Into<String>,
    ) -> Self {
        Self {
            provider_type: ProviderType::Azure,
            api_key: api_key.into(),
            model: String::new(),
            azure_endpoint: Some(endpoint.into()),
            azure_deployment: Some(deployment.into()),
            azure_api_version: Some("2024-02-15-preview".to_string()),
            organization_id: None,
            base_url: None,
            resilience: Some(ResilienceConfig::default()),
        }
    }

    /// Disable resilience wrapper
    pub fn without_resilience(mut self) -> Self {
        self.resilience = None;
        self
    }

    /// Set custom resilience config
    pub fn with_resilience(mut self, config: ResilienceConfig) -> Self {
        self.resilience = Some(config);
        self
    }
}

/// Registry for managing LLM providers
///
/// # Example
///
/// ```rust,ignore
/// use vulnera_llm::ProviderRegistry;
///
/// let mut registry = ProviderRegistry::new();
/// registry.register_from_config(
///     "main",
///     ProviderConfig::google_ai("api-key", "gemini-2.0-flash")
/// )?;
///
/// let provider = registry.get("main").unwrap();
/// let response = provider.complete(request).await?;
/// ```
pub struct ProviderRegistry {
    providers: HashMap<String, Arc<dyn LlmProvider>>,
    default_name: Option<String>,
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            default_name: None,
        }
    }

    /// Register a provider with a name
    pub fn register(&mut self, name: impl Into<String>, provider: Arc<dyn LlmProvider>) {
        let name = name.into();
        if self.default_name.is_none() {
            self.default_name = Some(name.clone());
        }
        self.providers.insert(name, provider);
    }

    /// Register a provider from configuration
    pub fn register_from_config(
        &mut self,
        name: impl Into<String>,
        config: ProviderConfig,
    ) -> Result<(), LlmError> {
        let provider = Self::create_provider(config)?;
        self.register(name, provider);
        Ok(())
    }

    /// Create a provider from configuration
    fn create_provider(config: ProviderConfig) -> Result<Arc<dyn LlmProvider>, LlmError> {
        let base_provider: Arc<dyn LlmProvider> = match config.provider_type {
            ProviderType::GoogleAI => {
                let mut provider = GoogleAIProvider::new(&config.api_key, &config.model);
                if let Some(ref url) = config.base_url {
                    provider = provider.with_base_url(url);
                }
                Arc::new(provider)
            }
            ProviderType::OpenAI => {
                let mut provider = OpenAIProvider::new(&config.api_key, &config.model);
                if let Some(ref url) = config.base_url {
                    provider = provider.with_base_url(url);
                }
                if let Some(ref org) = config.organization_id {
                    provider = provider.with_organization(org);
                }
                Arc::new(provider)
            }
            ProviderType::Azure => {
                let endpoint = config.azure_endpoint.ok_or_else(|| {
                    LlmError::Configuration("Azure endpoint required".to_string())
                })?;
                let deployment = config.azure_deployment.ok_or_else(|| {
                    LlmError::Configuration("Azure deployment required".to_string())
                })?;
                let api_version = config
                    .azure_api_version
                    .unwrap_or_else(|| "2024-02-15-preview".to_string());

                Arc::new(OpenAIProvider::azure(
                    endpoint,
                    &config.api_key,
                    deployment,
                    api_version,
                ))
            }
            ProviderType::Custom(name) => {
                return Err(LlmError::ProviderNotFound(format!(
                    "Unknown provider type: {}",
                    name
                )));
            }
        };

        // Wrap with resilience if configured
        if config.resilience.is_some() {
            // TODO: Implement dynamic resilience wrapping
            // Currently resilience should be applied at the call site
            Ok(base_provider)
        } else {
            Ok(base_provider)
        }
    }

    /// Get a provider by name
    pub fn get(&self, name: &str) -> Option<Arc<dyn LlmProvider>> {
        self.providers.get(name).cloned()
    }

    /// Get the default provider
    pub fn default(&self) -> Option<Arc<dyn LlmProvider>> {
        self.default_name
            .as_ref()
            .and_then(|name| self.providers.get(name).cloned())
    }

    /// Set the default provider
    pub fn set_default(&mut self, name: impl Into<String>) {
        self.default_name = Some(name.into());
    }

    /// List all registered provider names
    pub fn list(&self) -> Vec<&String> {
        self.providers.keys().collect()
    }

    /// Create a registry with provider from LlmConfig
    ///
    /// Reads the active provider from config and creates the appropriate provider.
    pub fn from_llm_config(config: &vulnera_core::config::LlmConfig) -> Result<Self, LlmError> {
        let mut registry = Self::new();

        let provider: Arc<dyn LlmProvider> = match config.provider.to_lowercase().as_str() {
            "google_ai" | "gemini" | "google" => {
                let api_key = config
                    .google_ai
                    .api_key
                    .clone()
                    .or_else(|| std::env::var("GOOGLE_AI_KEY").ok())
                    .ok_or_else(|| {
                        LlmError::Configuration(
                            "Google AI API key not configured. Set google_ai.api_key or GOOGLE_AI_KEY env var".to_string(),
                        )
                    })?;

                let mut provider = GoogleAIProvider::new(&api_key, &config.default_model);
                if !config.google_ai.base_url.is_empty() {
                    provider = provider.with_base_url(&config.google_ai.base_url);
                }
                Arc::new(provider)
            }
            "openai" | "gpt" => {
                let api_key = config
                    .openai
                    .api_key
                    .clone()
                    .or_else(|| std::env::var("OPENAI_API_KEY").ok())
                    .ok_or_else(|| {
                        LlmError::Configuration(
                            "OpenAI API key not configured. Set openai.api_key or OPENAI_API_KEY env var".to_string(),
                        )
                    })?;

                let mut provider = OpenAIProvider::new(&api_key, &config.default_model);
                if !config.openai.base_url.is_empty()
                    && config.openai.base_url != "https://api.openai.com/v1"
                {
                    provider = provider.with_base_url(&config.openai.base_url);
                }
                if let Some(ref org) = config.openai.organization_id {
                    provider = provider.with_organization(org);
                }
                Arc::new(provider)
            }
            "azure" | "azure_openai" => {
                let api_key = config
                    .azure
                    .api_key
                    .clone()
                    .or_else(|| std::env::var("AZURE_OPENAI_KEY").ok())
                    .ok_or_else(|| {
                        LlmError::Configuration(
                            "Azure OpenAI API key not configured. Set azure.api_key or AZURE_OPENAI_KEY env var".to_string(),
                        )
                    })?;

                if config.azure.endpoint.is_empty() {
                    return Err(LlmError::Configuration(
                        "Azure endpoint not configured".to_string(),
                    ));
                }
                if config.azure.deployment.is_empty() {
                    return Err(LlmError::Configuration(
                        "Azure deployment not configured".to_string(),
                    ));
                }

                Arc::new(OpenAIProvider::azure(
                    &config.azure.endpoint,
                    &api_key,
                    &config.azure.deployment,
                    &config.azure.api_version,
                ))
            }
            other => {
                return Err(LlmError::ProviderNotFound(format!(
                    "Unknown provider: {}. Valid options: google_ai, openai, azure",
                    other
                )));
            }
        };

        registry.register("default", provider);
        Ok(registry)
    }

    /// Check if a provider is registered
    pub fn contains(&self, name: &str) -> bool {
        self.providers.contains_key(name)
    }

    /// Remove a provider
    pub fn remove(&mut self, name: &str) -> Option<Arc<dyn LlmProvider>> {
        self.providers.remove(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_type_parsing() {
        assert_eq!(ProviderType::from_str("google_ai"), ProviderType::GoogleAI);
        assert_eq!(ProviderType::from_str("gemini"), ProviderType::GoogleAI);
        assert_eq!(ProviderType::from_str("openai"), ProviderType::OpenAI);
        assert_eq!(ProviderType::from_str("azure"), ProviderType::Azure);
    }

    #[test]
    fn test_registry_new() {
        let registry = ProviderRegistry::new();
        assert!(registry.default().is_none());
        assert!(registry.list().is_empty());
    }

    #[test]
    fn test_provider_config_google_ai() {
        let config = ProviderConfig::google_ai("key", "model");
        assert_eq!(config.provider_type, ProviderType::GoogleAI);
        assert!(config.resilience.is_some());
    }

    #[test]
    fn test_provider_config_without_resilience() {
        let config = ProviderConfig::openai("key", "model").without_resilience();
        assert!(config.resilience.is_none());
    }
}
