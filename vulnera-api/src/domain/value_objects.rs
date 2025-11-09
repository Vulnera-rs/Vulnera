//! API security value objects

use serde::{Deserialize, Serialize};

/// API vulnerability types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiVulnerabilityType {
    // Authentication issues
    MissingAuthentication,
    WeakAuthentication,
    MissingRateLimiting,
    JwtWithoutExpiration,

    // Authorization issues
    MissingAuthorization,
    OverlyPermissiveAccess,
    MissingRbac,

    // Input validation
    MissingRequestValidation,
    MissingInputSanitization,
    MissingFileUploadSizeLimit,
    SqlInjectionRisk,

    // Data exposure
    SensitiveDataInUrl,
    SensitiveDataInHeaders,
    MissingEncryption,
    PiiWithoutConsent,

    // Security headers
    MissingSecurityHeaders,
    InsecureCors,
    MissingRateLimitingHeaders,

    // API design
    VersioningIssues,
    MissingErrorHandling,
    InformationDisclosure,
    MissingPagination,

    // OAuth/OIDC
    InsecureOAuthFlow,
    MissingTokenValidation,
    InsecureRedirectUri,
}

/// OpenAPI specification model (simplified)
#[derive(Debug, Clone)]
pub struct OpenApiSpec {
    pub version: String,
    pub paths: Vec<ApiPath>,
    pub security_schemes: Vec<SecurityScheme>,
    pub global_security: Vec<SecurityRequirement>,
}

/// API path definition
#[derive(Debug, Clone)]
pub struct ApiPath {
    pub path: String,
    pub operations: Vec<ApiOperation>,
}

/// API operation (GET, POST, etc.)
#[derive(Debug, Clone)]
pub struct ApiOperation {
    pub method: String,
    pub security: Vec<SecurityRequirement>,
    pub parameters: Vec<ApiParameter>,
    pub request_body: Option<ApiRequestBody>,
    pub responses: Vec<ApiResponse>,
}

/// API parameter
#[derive(Debug, Clone)]
pub struct ApiParameter {
    pub name: String,
    pub location: ParameterLocation,
    pub required: bool,
    pub schema: Option<ApiSchema>,
}

/// Parameter location
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterLocation {
    Query,
    Header,
    Path,
    Cookie,
}

/// API request body
#[derive(Debug, Clone)]
pub struct ApiRequestBody {
    pub required: bool,
    pub content: Vec<ApiContent>,
}

/// API content (media type)
#[derive(Debug, Clone)]
pub struct ApiContent {
    pub media_type: String,
    pub schema: Option<ApiSchema>,
}

/// API response
#[derive(Debug, Clone)]
pub struct ApiResponse {
    pub status_code: String,
    pub content: Vec<ApiContent>,
    pub headers: Vec<ApiHeader>,
}

/// API header
#[derive(Debug, Clone)]
pub struct ApiHeader {
    pub name: String,
    pub schema: Option<ApiSchema>,
}

/// API schema
#[derive(Debug, Clone)]
pub struct ApiSchema {
    pub schema_type: Option<String>,
    pub format: Option<String>,
    pub properties: Vec<ApiProperty>,
    pub required: Vec<String>,
}

/// API property
#[derive(Debug, Clone)]
pub struct ApiProperty {
    pub name: String,
    pub schema: ApiSchema,
}

/// Security scheme
#[derive(Debug, Clone)]
pub struct SecurityScheme {
    pub name: String,
    pub scheme_type: SecuritySchemeType,
}

/// Security scheme type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecuritySchemeType {
    ApiKey {
        location: String,
        name: String,
    },
    Http {
        scheme: String,
        bearer_format: Option<String>,
    },
    OAuth2 {
        flows: Vec<OAuthFlow>,
    },
    OpenIdConnect {
        url: String,
    },
}

/// OAuth flow
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthFlow {
    pub flow_type: OAuthFlowType,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub scopes: Vec<OAuthScope>,
}

/// OAuth flow type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthFlowType {
    Implicit,
    AuthorizationCode,
    ClientCredentials,
    Password,
}

/// OAuth scope
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthScope {
    pub name: String,
    pub description: Option<String>,
}

/// Security requirement
#[derive(Debug, Clone)]
pub struct SecurityRequirement {
    pub scheme_name: String,
    pub scopes: Vec<String>,
}
