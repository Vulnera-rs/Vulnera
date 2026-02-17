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
    BolaRisk,        // NEW: Broken Object Level Authorization
    ScopeEscalation, // NEW: Over-permissive scopes

    // Input validation
    MissingRequestValidation,
    MissingInputSanitization,
    MissingFileUploadSizeLimit,
    SqlInjectionRisk,
    WeakSchemaValidation, // NEW: Missing pattern/constraints
    MassAssignmentRisk,   // NEW: additionalProperties: true
    UnboundedInput,       // NEW: No min/max length

    // Data exposure
    SensitiveDataInUrl,
    SensitiveDataInHeaders,
    MissingEncryption,
    PiiWithoutConsent,
    ExposedSecretInSpec, // NEW: JWT/key in example/default

    // Security headers
    MissingSecurityHeaders,
    InsecureCors,
    MissingRateLimitingHeaders,
    CorsWildcard,  // NEW: CORS: *
    VerbTampering, // NEW: TRACE enabled

    // API design
    VersioningIssues,
    MissingErrorHandling,
    InformationDisclosure,
    MissingPagination,
    ResourceExhaustion, // NEW: No pagination/limits ,the only new that not tested.

    // OAuth/OIDC
    InsecureOAuthFlow,
    MissingTokenValidation,
    InsecureRedirectUri,
    IneffectiveScopeHierarchy,
}

/// OpenAPI specification model for analyzer pipelines
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

/// API schema with validation constraints for security analysis
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApiSchema {
    // Core schema fields
    pub schema_type: Option<String>,
    pub format: Option<String>,
    pub properties: Vec<ApiProperty>,
    pub required: Vec<String>,
    pub summary: Option<String>,
    pub description: Option<String>,

    // Validation constraints (for schema "tightness" analysis)
    pub pattern: Option<String>,          // Regex pattern for strings
    pub minimum: Option<f64>,             // Minimum value for numbers
    pub maximum: Option<f64>,             // Maximum value for numbers
    pub min_length: Option<u32>,          // Minimum string length
    pub max_length: Option<u32>,          // Maximum string length
    pub enum_values: Option<Vec<String>>, // Allowed enumerated values
    pub multiple_of: Option<f64>,         // Number must be multiple of this
    pub min_items: Option<u32>,           // Minimum array items
    pub max_items: Option<u32>,           // Maximum array items
    pub items: Option<Box<ApiSchema>>,    // Array item schema

    // Logical constraints (composition)
    pub one_of: Vec<ApiSchema>,
    pub any_of: Vec<ApiSchema>,
    pub all_of: Vec<ApiSchema>,

    // Security-relevant metadata
    pub example: Option<serde_json::Value>,
    pub default: Option<serde_json::Value>,
    pub read_only: bool,
    pub write_only: bool,
    pub additional_properties: AdditionalProperties,
}

/// Controls whether additional properties are allowed in object schemas
#[derive(Debug, Clone, PartialEq, Default)]
pub enum AdditionalProperties {
    /// Additional properties are allowed (default, less secure)
    #[default]
    Allowed,
    /// Additional properties are denied (more secure)
    Denied,
    /// Additional properties must match a specific schema
    Schema(Box<ApiSchema>),
}

/// API property
#[derive(Debug, Clone, Default, PartialEq)]
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
