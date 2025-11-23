//! OpenAPI 3.x and Swagger 2.0 parser

use crate::domain::value_objects::*;
use crate::infrastructure::parser::SchemaMap;
use serde_json::Value as JsonValue;
use std::path::Path;
use tracing::{debug, error, info, warn};

/// Parser for OpenAPI/Swagger specifications
pub struct OpenApiParser;

impl OpenApiParser {
    /// Parse an OpenAPI/Swagger specification from a file
    pub fn parse_file(file_path: &Path) -> Result<OpenApiSpec, ParseError> {
        let content = std::fs::read_to_string(file_path).map_err(|e| {
            error!(
                error = %e,
                file = %file_path.display(),
                "Failed to read OpenAPI file"
            );
            e
        })?;
        Self::parse(&content, file_path)
    }

    /// Parse an OpenAPI/Swagger specification from content
    pub fn parse(content: &str, file_path: &Path) -> Result<OpenApiSpec, ParseError> {
        info!(file = %file_path.display(), "Parsing OpenAPI specification");

        // First, parse raw JSON/YAML to extract security requirements (oas3 crate doesn't expose them)
        let raw_spec: JsonValue = if content.trim_start().starts_with('{') {
            // JSON format
            serde_json::from_str(content).map_err(|e| {
                error!(
                    error = %e,
                    file = %file_path.display(),
                    "Failed to parse JSON"
                );
                ParseError::ParseError {
                    message: format!("JSON parse error: {}", e),
                    file: file_path.display().to_string(),
                    line: None,
                }
            })?
        } else {
            // YAML format
            serde_yml::from_str(content).map_err(|e| {
                error!(
                    error = %e,
                    file = %file_path.display(),
                    "Failed to parse YAML"
                );
                ParseError::ParseError {
                    message: format!("YAML parse error: {}", e),
                    file: file_path.display().to_string(),
                    line: None,
                }
            })?
        };

        // Extract security requirements from raw spec
        let global_security = Self::extract_security_from_json(&raw_spec, None);
        let path_securities = Self::extract_path_securities_from_json(&raw_spec);

        // Extract OAuth flow token URLs from raw JSON
        let oauth_token_urls = Self::extract_oauth_token_urls(&raw_spec);

        // Extract component schemas for reference resolution
        let schema_map = Self::extract_schemas_from_json(&raw_spec);

        // Parse using oas3 crate for the rest of the spec
        let spec = if content.trim_start().starts_with('{') {
            // JSON format
            oas3::from_json(content).map_err(|e| {
                error!(
                    error = %e,
                    file = %file_path.display(),
                    "Failed to parse OpenAPI specification with oas3 crate"
                );
                ParseError::ParseError {
                    message: format!("OpenAPI parse error: {}", e),
                    file: file_path.display().to_string(),
                    line: None,
                }
            })?
        } else {
            // YAML format
            oas3::from_yaml(content).map_err(|e| {
                error!(
                    error = %e,
                    file = %file_path.display(),
                    "Failed to parse OpenAPI specification with oas3 crate"
                );
                ParseError::ParseError {
                    message: format!("OpenAPI parse error: {}", e),
                    file: file_path.display().to_string(),
                    line: None,
                }
            })?
        };

        // Validate OpenAPI version
        if !spec.openapi.starts_with("3.") {
            return Err(ParseError::InvalidVersion {
                version: spec.openapi.clone(),
            });
        }

        Self::convert_spec_with_security(
            spec,
            file_path,
            global_security,
            path_securities,
            oauth_token_urls,
            schema_map,
        )
    }

    fn convert_spec_with_security(
        spec: oas3::Spec,
        _file_path: &Path,
        global_security: Vec<SecurityRequirement>,
        path_securities: std::collections::HashMap<
            String,
            std::collections::HashMap<String, Vec<SecurityRequirement>>,
        >,
        oauth_token_urls: std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        >,
        schema_map: crate::infrastructure::parser::SchemaMap,
    ) -> Result<OpenApiSpec, ParseError> {
        debug!(
            version = %spec.openapi,
            path_count = spec.paths.as_ref().map(|p| p.len()).unwrap_or(0),
            "Parsed OpenAPI specification"
        );

        // Create schema resolver for reference resolution
        use crate::infrastructure::parser::SchemaRefResolver;
        let mut schema_resolver = SchemaRefResolver::new(schema_map);

        // Convert oas3::Spec to our domain model
        let paths = Self::parse_paths_with_security(
            spec.paths
                .as_ref()
                .unwrap_or(&std::collections::BTreeMap::new()),
            &path_securities,
            &mut schema_resolver,
        );
        let security_schemes =
            Self::parse_security_schemes_with_oauth_urls(&spec.components, &oauth_token_urls);

        Ok(OpenApiSpec {
            version: spec.openapi,
            paths,
            security_schemes,
            global_security,
        })
    }

    fn parse_paths_with_security(
        paths: &std::collections::BTreeMap<String, oas3::spec::PathItem>,
        path_securities: &std::collections::HashMap<
            String,
            std::collections::HashMap<String, Vec<SecurityRequirement>>,
        >,
        schema_resolver: &mut crate::infrastructure::parser::SchemaRefResolver,
    ) -> Vec<ApiPath> {
        let mut api_paths = Vec::new();

        for (path_str, path_item) in paths.iter() {
            // Get path-level and operation-level security from parsed JSON
            let path_security = path_securities
                .get(path_str)
                .and_then(|ops| ops.get("_path"))
                .cloned()
                .unwrap_or_default();

            let mut operations = Vec::new();

            // Parse operations from path item with their security requirements
            if let Some(ref get) = path_item.get {
                let op_security = path_securities
                    .get(path_str)
                    .and_then(|ops| ops.get("get"))
                    .cloned()
                    .unwrap_or_else(|| path_security.clone());
                operations.push(Self::parse_operation(
                    "GET",
                    get,
                    &op_security,
                    schema_resolver,
                ));
            }
            if let Some(ref post) = path_item.post {
                let op_security = path_securities
                    .get(path_str)
                    .and_then(|ops| ops.get("post"))
                    .cloned()
                    .unwrap_or_else(|| path_security.clone());
                operations.push(Self::parse_operation(
                    "POST",
                    post,
                    &op_security,
                    schema_resolver,
                ));
            }
            if let Some(ref put) = path_item.put {
                let op_security = path_securities
                    .get(path_str)
                    .and_then(|ops| ops.get("put"))
                    .cloned()
                    .unwrap_or_else(|| path_security.clone());
                operations.push(Self::parse_operation(
                    "PUT",
                    put,
                    &op_security,
                    schema_resolver,
                ));
            }
            if let Some(ref delete) = path_item.delete {
                let op_security = path_securities
                    .get(path_str)
                    .and_then(|ops| ops.get("delete"))
                    .cloned()
                    .unwrap_or_else(|| path_security.clone());
                operations.push(Self::parse_operation(
                    "DELETE",
                    delete,
                    &op_security,
                    schema_resolver,
                ));
            }
            if let Some(ref patch) = path_item.patch {
                let op_security = path_securities
                    .get(path_str)
                    .and_then(|ops| ops.get("patch"))
                    .cloned()
                    .unwrap_or_else(|| path_security.clone());
                operations.push(Self::parse_operation(
                    "PATCH",
                    patch,
                    &op_security,
                    schema_resolver,
                ));
            }
            if let Some(ref head) = path_item.head {
                let op_security = path_securities
                    .get(path_str)
                    .and_then(|ops| ops.get("head"))
                    .cloned()
                    .unwrap_or_else(|| path_security.clone());
                operations.push(Self::parse_operation(
                    "HEAD",
                    head,
                    &op_security,
                    schema_resolver,
                ));
            }
            if let Some(ref options) = path_item.options {
                let op_security = path_securities
                    .get(path_str)
                    .and_then(|ops| ops.get("options"))
                    .cloned()
                    .unwrap_or_else(|| path_security.clone());
                operations.push(Self::parse_operation(
                    "OPTIONS",
                    options,
                    &op_security,
                    schema_resolver,
                ));
            }
            if let Some(ref trace) = path_item.trace {
                let op_security = path_securities
                    .get(path_str)
                    .and_then(|ops| ops.get("trace"))
                    .cloned()
                    .unwrap_or_else(|| path_security.clone());
                operations.push(Self::parse_operation(
                    "TRACE",
                    trace,
                    &op_security,
                    schema_resolver,
                ));
            }

            api_paths.push(ApiPath {
                path: path_str.clone(),
                operations,
            });
        }

        api_paths
    }

    fn parse_operation(
        method: &str,
        operation: &oas3::spec::Operation,
        security: &[crate::domain::value_objects::SecurityRequirement],
        schema_resolver: &mut crate::infrastructure::parser::SchemaRefResolver,
    ) -> ApiOperation {
        // Security requirements are now passed in from the raw JSON/YAML parsing
        // Operation-level security overrides path-level security (handled in parse_paths_with_security)

        let parameters = Self::parse_parameters(&operation.parameters, schema_resolver);
        let request_body = Self::parse_request_body(
            operation
                .request_body
                .as_ref()
                .unwrap_or(&oas3::spec::ObjectOrReference::Object(
                    oas3::spec::RequestBody {
                        description: None,
                        content: std::collections::BTreeMap::new(),
                        required: None,
                    },
                )),
            schema_resolver,
        );
        let responses = Self::parse_responses(
            operation
                .responses
                .as_ref()
                .unwrap_or(&std::collections::BTreeMap::new()),
            schema_resolver,
        );

        ApiOperation {
            method: method.to_uppercase(),
            security: security.to_vec(),
            parameters,
            request_body,
            responses,
        }
    }

    fn parse_parameters(
        parameters: &[oas3::spec::ObjectOrReference<oas3::spec::Parameter>],
        schema_resolver: &mut crate::infrastructure::parser::SchemaRefResolver,
    ) -> Vec<ApiParameter> {
        let mut api_params = Vec::new();

        for param_ref in parameters {
            match param_ref {
                oas3::spec::ObjectOrReference::Object(param) => {
                    let location = match param.location {
                        oas3::spec::ParameterIn::Query => ParameterLocation::Query,
                        oas3::spec::ParameterIn::Header => ParameterLocation::Header,
                        oas3::spec::ParameterIn::Path => ParameterLocation::Path,
                        oas3::spec::ParameterIn::Cookie => ParameterLocation::Cookie,
                    };

                    api_params.push(ApiParameter {
                        name: param.name.clone(),
                        location,
                        required: param.required.unwrap_or(false),
                        schema: param.schema.as_ref().and_then(|s| match s {
                            oas3::spec::ObjectOrReference::Object(_) => {
                                Some(Self::parse_schema(s, schema_resolver))
                            }
                            oas3::spec::ObjectOrReference::Ref { .. } => {
                                warn!("Skipping schema reference in parameter");
                                None
                            }
                        }),
                    });
                }
                oas3::spec::ObjectOrReference::Ref { .. } => {
                    // Skip references for now - could be resolved later
                    warn!("Skipping parameter reference");
                }
            }
        }

        api_params
    }

    fn parse_request_body(
        rb_ref: &oas3::spec::ObjectOrReference<oas3::spec::RequestBody>,
        schema_resolver: &mut crate::infrastructure::parser::SchemaRefResolver,
    ) -> Option<ApiRequestBody> {
        match rb_ref {
            oas3::spec::ObjectOrReference::Object(rb) => {
                let content = Self::parse_content(&Some(rb.content.clone()), schema_resolver);
                Some(ApiRequestBody {
                    required: rb.required.unwrap_or(false),
                    content,
                })
            }
            oas3::spec::ObjectOrReference::Ref { .. } => {
                // We could resolve request body refs here too if we extracted them
                warn!("Skipping request body reference");
                None
            }
        }
    }

    fn parse_responses(
        responses: &std::collections::BTreeMap<
            String,
            oas3::spec::ObjectOrReference<oas3::spec::Response>,
        >,
        schema_resolver: &mut crate::infrastructure::parser::SchemaRefResolver,
    ) -> Vec<ApiResponse> {
        let mut api_responses = Vec::new();

        for (status_code, response_ref) in responses.iter() {
            match response_ref {
                oas3::spec::ObjectOrReference::Object(response) => {
                    let content =
                        Self::parse_content(&Some(response.content.clone()), schema_resolver);
                    let headers = Self::parse_response_headers(&response.headers, schema_resolver);

                    api_responses.push(ApiResponse {
                        status_code: status_code.clone(),
                        content,
                        headers,
                    });
                }
                oas3::spec::ObjectOrReference::Ref { .. } => {
                    // Skip references for now - could be resolved later
                    warn!(status_code = %status_code, "Skipping response reference");
                }
            }
        }

        api_responses
    }

    fn parse_content(
        content: &Option<std::collections::BTreeMap<String, oas3::spec::MediaType>>,
        schema_resolver: &mut crate::infrastructure::parser::SchemaRefResolver,
    ) -> Vec<ApiContent> {
        let mut api_content = Vec::new();

        if let Some(content_map) = content {
            for (media_type, media_type_obj) in content_map.iter() {
                let schema = media_type_obj.schema.as_ref().and_then(|schema_ref| {
                    match schema_ref {
                        oas3::spec::ObjectOrReference::Object(_) => {
                            Some(Self::parse_schema(schema_ref, schema_resolver))
                        }
                        oas3::spec::ObjectOrReference::Ref { ref_path, .. } => {
                            // Use resolver to resolve the reference
                            schema_resolver.resolve_ref(ref_path)
                        }
                    }
                });
                api_content.push(ApiContent {
                    media_type: media_type.clone(),
                    schema,
                });
            }
        }

        api_content
    }

    fn parse_response_headers(
        headers: &std::collections::BTreeMap<
            String,
            oas3::spec::ObjectOrReference<oas3::spec::Header>,
        >,
        schema_resolver: &mut crate::infrastructure::parser::SchemaRefResolver,
    ) -> Vec<ApiHeader> {
        let mut api_headers = Vec::new();

        for (name, header_ref) in headers.iter() {
            match header_ref {
                oas3::spec::ObjectOrReference::Object(header) => {
                    let schema = header
                        .schema
                        .as_ref()
                        .and_then(|schema_ref| match schema_ref {
                            oas3::spec::ObjectOrReference::Object(_) => {
                                Some(Self::parse_schema(schema_ref, schema_resolver))
                            }
                            oas3::spec::ObjectOrReference::Ref { .. } => {
                                warn!("Skipping schema reference in header");
                                None
                            }
                        });
                    api_headers.push(ApiHeader {
                        name: name.clone(),
                        schema,
                    });
                }
                oas3::spec::ObjectOrReference::Ref { .. } => {
                    // Skip references for now
                    warn!(header_name = %name, "Skipping header reference");
                }
            }
        }

        api_headers
    }

    fn parse_schema(
        schema: &oas3::spec::ObjectOrReference<oas3::spec::ObjectSchema>,
        schema_resolver: &mut crate::infrastructure::parser::SchemaRefResolver,
    ) -> ApiSchema {
        match schema {
            oas3::spec::ObjectOrReference::Object(obj_schema) => {
                let properties: Vec<ApiProperty> = obj_schema
                    .properties
                    .iter()
                    .map(|(name, prop_schema_ref)| {
                        let schema = match prop_schema_ref {
                            oas3::spec::ObjectOrReference::Object(_) => {
                                Self::parse_schema(prop_schema_ref, schema_resolver)
                            }
                            oas3::spec::ObjectOrReference::Ref { ref_path, .. } => {
                                schema_resolver.resolve_ref(ref_path).unwrap_or_default()
                            }
                        };
                        ApiProperty {
                            name: name.clone(),
                            schema,
                        }
                    })
                    .collect();

                let schema_type = obj_schema.schema_type.as_ref().map(|t| format!("{:?}", t));

                ApiSchema {
                    schema_type,
                    format: obj_schema.format.clone(),
                    properties,
                    required: obj_schema.required.clone(),
                    summary: None,
                    description: None,
                }
            }
            oas3::spec::ObjectOrReference::Ref { ref_path, .. } => {
                schema_resolver.resolve_ref(ref_path).unwrap_or_default()
            }
        }
    }

    fn parse_security_schemes_with_oauth_urls(
        components: &Option<oas3::spec::Components>,
        oauth_token_urls: &std::collections::HashMap<
            String,
            std::collections::HashMap<String, String>,
        >,
    ) -> Vec<SecurityScheme> {
        let mut schemes = Vec::new();

        if let Some(components) = components {
            for (name, scheme_ref) in components.security_schemes.iter() {
                match scheme_ref {
                    oas3::spec::ObjectOrReference::Object(scheme) => {
                        let scheme_type = match scheme {
                            oas3::spec::SecurityScheme::ApiKey {
                                location,
                                name: key_name,
                                description: _,
                            } => SecuritySchemeType::ApiKey {
                                location: format!("{:?}", location),
                                name: key_name.clone(),
                            },
                            oas3::spec::SecurityScheme::Http {
                                scheme: http_scheme,
                                bearer_format,
                                description: _,
                            } => SecuritySchemeType::Http {
                                scheme: http_scheme.clone(),
                                bearer_format: bearer_format.clone(),
                            },
                            oas3::spec::SecurityScheme::OAuth2 {
                                flows,
                                description: _,
                            } => {
                                // Get token URLs for this scheme from extracted JSON
                                let scheme_token_urls =
                                    oauth_token_urls.get(name).cloned().unwrap_or_default();
                                let oauth_flows =
                                    Self::parse_oauth_flows_with_urls(&flows, &scheme_token_urls);
                                SecuritySchemeType::OAuth2 { flows: oauth_flows }
                            }
                            oas3::spec::SecurityScheme::OpenIdConnect {
                                open_id_connect_url,
                                description: _,
                            } => SecuritySchemeType::OpenIdConnect {
                                url: open_id_connect_url.clone(),
                            },
                            oas3::spec::SecurityScheme::MutualTls { description: _ } => {
                                // MutualTLS is not currently supported in our domain model
                                warn!("MutualTLS security scheme is not supported, skipping");
                                continue;
                            }
                        };

                        schemes.push(SecurityScheme {
                            name: name.clone(),
                            scheme_type,
                        });
                    }
                    oas3::spec::ObjectOrReference::Ref { .. } => {
                        // Skip references for now
                        warn!(scheme_name = %name, "Skipping security scheme reference");
                    }
                }
            }
        }

        schemes
    }

    fn parse_oauth_flows_with_urls(
        flows: &oas3::spec::Flows,
        token_urls: &std::collections::HashMap<String, String>,
    ) -> Vec<OAuthFlow> {
        let mut oauth_flows = Vec::new();

        if let Some(ref implicit) = flows.implicit {
            oauth_flows.push(OAuthFlow {
                flow_type: OAuthFlowType::Implicit,
                authorization_url: Some(implicit.authorization_url.to_string()),
                token_url: None, // Implicit flow doesn't have token_url
                scopes: Self::parse_oauth_scopes(&implicit.scopes),
            });
        }

        if let Some(ref authorization_code) = flows.authorization_code {
            oauth_flows.push(OAuthFlow {
                flow_type: OAuthFlowType::AuthorizationCode,
                authorization_url: Some(authorization_code.authorization_url.to_string()),
                token_url: Some(authorization_code.token_url.to_string()),
                scopes: Self::parse_oauth_scopes(&authorization_code.scopes),
            });
        }

        if let Some(ref client_credentials) = flows.client_credentials {
            // token_url is private in ClientCredentialsFlow, extract from raw JSON
            let token_url = token_urls.get("clientCredentials").cloned();
            oauth_flows.push(OAuthFlow {
                flow_type: OAuthFlowType::ClientCredentials,
                authorization_url: None,
                token_url,
                scopes: Self::parse_oauth_scopes(&client_credentials.scopes),
            });
        }

        if let Some(ref password) = flows.password {
            // token_url is private in PasswordFlow, extract from raw JSON
            let token_url = token_urls.get("password").cloned();
            oauth_flows.push(OAuthFlow {
                flow_type: OAuthFlowType::Password,
                authorization_url: None,
                token_url,
                scopes: Self::parse_oauth_scopes(&password.scopes),
            });
        }

        oauth_flows
    }

    fn parse_oauth_scopes(scopes: &std::collections::BTreeMap<String, String>) -> Vec<OAuthScope> {
        scopes
            .iter()
            .map(|(name, description)| OAuthScope {
                name: name.clone(),
                description: Some(description.clone()),
            })
            .collect()
    }

    /// Extract security requirements from raw JSON/YAML spec at a specific path
    fn extract_security_from_json(
        spec: &JsonValue,
        path: Option<&str>,
    ) -> Vec<SecurityRequirement> {
        let mut requirements = Vec::new();

        // Navigate to the target object (spec root or a specific path)
        let target = if let Some(path_key) = path {
            spec.get("paths").and_then(|paths| paths.get(path_key))
        } else {
            Some(spec)
        };

        if let Some(obj) = target {
            if let Some(security_array) = obj.get("security").and_then(|s| s.as_array()) {
                for security_item in security_array {
                    if let Some(security_obj) = security_item.as_object() {
                        for (scheme_name, scopes_value) in security_obj {
                            let scopes = if let Some(scopes_array) = scopes_value.as_array() {
                                scopes_array
                                    .iter()
                                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                                    .collect()
                            } else {
                                Vec::new()
                            };

                            requirements.push(SecurityRequirement {
                                scheme_name: scheme_name.clone(),
                                scopes,
                            });
                        }
                    }
                }
            }
        }

        requirements
    }

    /// Extract security requirements for all paths and operations from raw JSON/YAML
    /// Returns a map: path -> (operation -> security_requirements)
    fn extract_path_securities_from_json(
        spec: &JsonValue,
    ) -> std::collections::HashMap<
        String,
        std::collections::HashMap<String, Vec<SecurityRequirement>>,
    > {
        let mut result = std::collections::HashMap::new();

        if let Some(paths) = spec.get("paths").and_then(|p| p.as_object()) {
            for (path_str, path_value) in paths {
                let mut path_ops = std::collections::HashMap::new();

                // Extract path-level security
                let path_security = Self::extract_security_from_json(spec, Some(path_str));
                if !path_security.is_empty() {
                    path_ops.insert("_path".to_string(), path_security);
                }

                // Extract operation-level security
                if let Some(path_obj) = path_value.as_object() {
                    for op_method in &[
                        "get", "post", "put", "delete", "patch", "head", "options", "trace",
                    ] {
                        if let Some(op_value) = path_obj.get(*op_method) {
                            if let Some(op_obj) = op_value.as_object() {
                                if let Some(security_array) =
                                    op_obj.get("security").and_then(|s| s.as_array())
                                {
                                    let mut op_requirements = Vec::new();
                                    for security_item in security_array {
                                        if let Some(security_obj) = security_item.as_object() {
                                            for (scheme_name, scopes_value) in security_obj {
                                                let scopes = if let Some(scopes_array) =
                                                    scopes_value.as_array()
                                                {
                                                    scopes_array
                                                        .iter()
                                                        .filter_map(|s| {
                                                            s.as_str().map(|s| s.to_string())
                                                        })
                                                        .collect()
                                                } else {
                                                    Vec::new()
                                                };

                                                op_requirements.push(SecurityRequirement {
                                                    scheme_name: scheme_name.clone(),
                                                    scopes,
                                                });
                                            }
                                        }
                                    }
                                    if !op_requirements.is_empty() {
                                        path_ops.insert(op_method.to_string(), op_requirements);
                                    }
                                }
                            }
                        }
                    }
                }

                if !path_ops.is_empty() {
                    result.insert(path_str.clone(), path_ops);
                }
            }
        }

        result
    }

    /// Extract OAuth flow token URLs from raw JSON/YAML
    /// Returns a map: scheme_name -> (flow_type -> token_url)
    fn extract_oauth_token_urls(
        spec: &JsonValue,
    ) -> std::collections::HashMap<String, std::collections::HashMap<String, String>> {
        let mut result = std::collections::HashMap::new();

        if let Some(components) = spec.get("components") {
            if let Some(security_schemes) = components.get("securitySchemes") {
                if let Some(schemes_obj) = security_schemes.as_object() {
                    for (scheme_name, scheme_value) in schemes_obj {
                        if let Some(scheme_obj) = scheme_value.as_object() {
                            if let Some(type_str) = scheme_obj.get("type").and_then(|t| t.as_str())
                            {
                                if type_str == "oauth2" {
                                    if let Some(flows_obj) =
                                        scheme_obj.get("flows").and_then(|f| f.as_object())
                                    {
                                        let mut flow_urls = std::collections::HashMap::new();

                                        // Extract clientCredentials token URL
                                        if let Some(client_creds) =
                                            flows_obj.get("clientCredentials")
                                        {
                                            if let Some(client_creds_obj) = client_creds.as_object()
                                            {
                                                if let Some(token_url) = client_creds_obj
                                                    .get("tokenUrl")
                                                    .and_then(|u| u.as_str())
                                                {
                                                    flow_urls.insert(
                                                        "clientCredentials".to_string(),
                                                        token_url.to_string(),
                                                    );
                                                }
                                            }
                                        }

                                        // Extract password token URL
                                        if let Some(password) = flows_obj.get("password") {
                                            if let Some(password_obj) = password.as_object() {
                                                if let Some(token_url) = password_obj
                                                    .get("tokenUrl")
                                                    .and_then(|u| u.as_str())
                                                {
                                                    flow_urls.insert(
                                                        "password".to_string(),
                                                        token_url.to_string(),
                                                    );
                                                }
                                            }
                                        }

                                        if !flow_urls.is_empty() {
                                            result.insert(scheme_name.clone(), flow_urls);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        result
    }

    /// Extract component schemas from raw JSON/YAML spec
    fn extract_schemas_from_json(spec: &JsonValue) -> SchemaMap {
        let mut schemas = SchemaMap::new();

        if let Some(components) = spec.get("components") {
            if let Some(schemas_obj) = components.get("schemas").and_then(|s| s.as_object()) {
                for (schema_name, schema_def) in schemas_obj {
                    schemas.insert(schema_name.clone(), schema_def.clone());
                }
            }
        }

        schemas
    }
}

/// Parse error with context
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {message} (file: {file}, line: {line:?})")]
    ParseError {
        message: String,
        file: String,
        line: Option<usize>,
    },

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yml::Error),

    #[error("OpenAPI version validation failed: {version}")]
    InvalidVersion { version: String },
}
