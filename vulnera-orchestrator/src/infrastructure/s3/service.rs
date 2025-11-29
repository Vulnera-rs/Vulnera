//! S3 bucket download service implementation

use std::path::{Path, PathBuf};

use aws_config::Region;
use aws_credential_types::Credentials;
use aws_sdk_s3::Client as S3Client;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use crate::domain::services::ProjectDetectionError;
use crate::domain::value_objects::AwsCredentials;

/// Parsed S3 bucket URI components
#[derive(Debug, Clone)]
pub struct S3BucketUri {
    /// S3 bucket name
    pub bucket: String,
    /// Optional prefix/path within the bucket
    pub prefix: Option<String>,
    /// Optional region extracted from URI (for s3.region.amazonaws.com format)
    pub region: Option<String>,
}

impl S3BucketUri {
    /// Parse an S3 URI into its components
    ///
    /// Supported formats:
    /// - s3://bucket-name
    /// - s3://bucket-name/prefix/path
    /// - https://bucket-name.s3.amazonaws.com
    /// - https://bucket-name.s3.region.amazonaws.com/prefix
    /// - https://s3.region.amazonaws.com/bucket-name/prefix
    pub fn parse(uri: &str) -> Result<Self, ProjectDetectionError> {
        // Handle s3:// protocol
        if let Some(path) = uri.strip_prefix("s3://") {
            let parts: Vec<&str> = path.splitn(2, '/').collect();
            let bucket = parts
                .first()
                .ok_or_else(|| {
                    ProjectDetectionError::InvalidS3Uri("Empty bucket name".to_string())
                })?
                .to_string();

            if bucket.is_empty() {
                return Err(ProjectDetectionError::InvalidS3Uri(
                    "Empty bucket name".to_string(),
                ));
            }

            let prefix = parts
                .get(1)
                .filter(|p| !p.is_empty())
                .map(|p| p.to_string());

            return Ok(Self {
                bucket,
                prefix,
                region: None,
            });
        }

        // Handle https:// URLs
        if uri.starts_with("https://") || uri.starts_with("http://") {
            return Self::parse_https_uri(uri);
        }

        Err(ProjectDetectionError::InvalidS3Uri(format!(
            "Unsupported S3 URI format: {}. Expected s3://bucket/prefix or https://bucket.s3.amazonaws.com/prefix",
            uri
        )))
    }

    fn parse_https_uri(uri: &str) -> Result<Self, ProjectDetectionError> {
        let url = url::Url::parse(uri)
            .map_err(|e| ProjectDetectionError::InvalidS3Uri(format!("Invalid URL: {}", e)))?;

        let host = url.host_str().ok_or_else(|| {
            ProjectDetectionError::InvalidS3Uri("Missing host in URL".to_string())
        })?;

        let path = url.path().trim_start_matches('/');

        // Pattern 1: bucket-name.s3.amazonaws.com or bucket-name.s3.region.amazonaws.com
        if host.ends_with(".amazonaws.com") {
            let host_parts: Vec<&str> = host.split('.').collect();

            // bucket.s3.amazonaws.com (4 parts) or bucket.s3.region.amazonaws.com (5 parts)
            if host_parts.len() >= 4 && host_parts[1] == "s3" {
                let bucket = host_parts[0].to_string();
                let region = if host_parts.len() == 5 {
                    Some(host_parts[2].to_string())
                } else {
                    None
                };
                let prefix = if path.is_empty() {
                    None
                } else {
                    Some(path.to_string())
                };

                return Ok(Self {
                    bucket,
                    prefix,
                    region,
                });
            }

            // Pattern 2: s3.region.amazonaws.com/bucket/prefix
            if host_parts.len() >= 3 && host_parts[0] == "s3" {
                let region = if host_parts.len() == 4 {
                    Some(host_parts[1].to_string())
                } else {
                    None
                };

                let path_parts: Vec<&str> = path.splitn(2, '/').collect();
                let bucket = path_parts
                    .first()
                    .filter(|b| !b.is_empty())
                    .map(|b| b.to_string())
                    .ok_or_else(|| {
                        ProjectDetectionError::InvalidS3Uri(
                            "Missing bucket name in path-style URL".to_string(),
                        )
                    })?;

                let prefix = path_parts
                    .get(1)
                    .filter(|p| !p.is_empty())
                    .map(|p| p.to_string());

                return Ok(Self {
                    bucket,
                    prefix,
                    region,
                });
            }
        }

        Err(ProjectDetectionError::InvalidS3Uri(format!(
            "Could not parse S3 URL: {}",
            uri
        )))
    }
}

/// Service for downloading S3 bucket contents to a local directory
pub struct S3Service {
    /// Maximum number of objects to download (safety limit)
    max_objects: usize,
    /// Maximum total download size in bytes (safety limit)
    max_total_size: u64,
}

/// Result of an S3 bucket download operation
#[derive(Debug)]
pub struct S3DownloadResult {
    /// Path to the root of downloaded content (persists on filesystem)
    pub root_path: PathBuf,
    /// Number of objects downloaded
    pub objects_downloaded: usize,
    /// Total bytes downloaded
    pub bytes_downloaded: u64,
}

impl S3Service {
    /// Create a new S3 service with default limits
    ///
    /// Default limits:
    /// - Max 10,000 objects
    /// - Max 1 GB total size
    pub fn new() -> Self {
        Self {
            max_objects: 10_000,
            max_total_size: 1024 * 1024 * 1024, // 1 GB
        }
    }

    /// Create S3 service with custom limits
    pub fn with_limits(max_objects: usize, max_total_size: u64) -> Self {
        Self {
            max_objects,
            max_total_size,
        }
    }

    /// Build an S3 client from AWS credentials
    async fn build_client(&self, credentials: &AwsCredentials) -> S3Client {
        let region = Region::new(credentials.effective_region().to_string());

        let creds = if let Some(ref session_token) = credentials.session_token {
            Credentials::new(
                &credentials.access_key_id,
                &credentials.secret_access_key,
                Some(session_token.clone()),
                None,
                "vulnera-s3-analysis",
            )
        } else {
            Credentials::new(
                &credentials.access_key_id,
                &credentials.secret_access_key,
                None,
                None,
                "vulnera-s3-analysis",
            )
        };

        let config = aws_sdk_s3::Config::builder()
            .region(region)
            .credentials_provider(creds)
            .build();

        S3Client::from_conf(config)
    }

    /// Download S3 bucket contents to a temporary directory
    ///
    /// # Arguments
    /// * `bucket_uri` - S3 bucket URI (s3://bucket/prefix or https://bucket.s3.amazonaws.com/prefix)
    /// * `credentials` - AWS credentials for authentication
    ///
    /// # Returns
    /// Download result containing the temporary directory and statistics
    pub async fn download_bucket(
        &self,
        bucket_uri: &str,
        credentials: &AwsCredentials,
    ) -> Result<S3DownloadResult, ProjectDetectionError> {
        // Parse the bucket URI
        let parsed = S3BucketUri::parse(bucket_uri)?;

        // Use region from credentials or URI
        let effective_credentials = if credentials.region.is_none() && parsed.region.is_some() {
            AwsCredentials {
                access_key_id: credentials.access_key_id.clone(),
                secret_access_key: credentials.secret_access_key.clone(),
                session_token: credentials.session_token.clone(),
                region: parsed.region.clone(),
            }
        } else {
            credentials.clone()
        };

        let client = self.build_client(&effective_credentials).await;

        info!(
            bucket = %parsed.bucket,
            prefix = ?parsed.prefix,
            region = %effective_credentials.effective_region(),
            "Starting S3 bucket download"
        );

        // Create temporary directory for download (persists on filesystem)
        // Use a stable location so it survives serialization through the job queue
        let temp_dir_path =
            std::env::temp_dir().join(format!("vulnera-s3-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir_path)
            .await
            .map_err(|e| {
                ProjectDetectionError::S3Error(format!(
                    "Failed to create download directory: {}",
                    e
                ))
            })?;

        // List and download objects
        let (objects_downloaded, bytes_downloaded) = self
            .download_objects(
                &client,
                &parsed.bucket,
                parsed.prefix.as_deref(),
                &temp_dir_path,
            )
            .await?;

        info!(
            objects = objects_downloaded,
            bytes = bytes_downloaded,
            path = %temp_dir_path.display(),
            "S3 bucket download complete"
        );

        Ok(S3DownloadResult {
            root_path: temp_dir_path,
            objects_downloaded,
            bytes_downloaded,
        })
    }

    async fn download_objects(
        &self,
        client: &S3Client,
        bucket: &str,
        prefix: Option<&str>,
        target_dir: &Path,
    ) -> Result<(usize, u64), ProjectDetectionError> {
        let mut continuation_token: Option<String> = None;
        let mut objects_downloaded = 0usize;
        let mut bytes_downloaded = 0u64;

        loop {
            let mut request = client.list_objects_v2().bucket(bucket);

            if let Some(prefix) = prefix {
                request = request.prefix(prefix);
            }

            if let Some(token) = &continuation_token {
                request = request.continuation_token(token);
            }

            let response = request.send().await.map_err(|e| {
                ProjectDetectionError::S3Error(format!("Failed to list objects: {}", e))
            })?;

            if let Some(contents) = response.contents {
                for object in contents {
                    // Check limits
                    if objects_downloaded >= self.max_objects {
                        warn!(max = self.max_objects, "Reached maximum object count limit");
                        return Ok((objects_downloaded, bytes_downloaded));
                    }

                    if bytes_downloaded >= self.max_total_size {
                        warn!(
                            max = self.max_total_size,
                            "Reached maximum download size limit"
                        );
                        return Ok((objects_downloaded, bytes_downloaded));
                    }

                    let key = match object.key() {
                        Some(k) => k,
                        None => continue,
                    };

                    // Skip directory markers
                    if key.ends_with('/') {
                        continue;
                    }

                    // Skip objects outside our safety limits
                    let size = object.size.unwrap_or(0) as u64;
                    if bytes_downloaded + size > self.max_total_size {
                        warn!(key = key, size = size, "Skipping object due to size limit");
                        continue;
                    }

                    // Download the object
                    match self
                        .download_object(client, bucket, key, prefix, target_dir)
                        .await
                    {
                        Ok(downloaded_size) => {
                            objects_downloaded += 1;
                            bytes_downloaded += downloaded_size;
                            debug!(key = key, size = downloaded_size, "Downloaded object");
                        }
                        Err(e) => {
                            warn!(key = key, error = %e, "Failed to download object, skipping");
                        }
                    }
                }
            }

            // Check if there are more objects to list
            if response.is_truncated == Some(true) {
                continuation_token = response.next_continuation_token;
            } else {
                break;
            }
        }

        Ok((objects_downloaded, bytes_downloaded))
    }

    async fn download_object(
        &self,
        client: &S3Client,
        bucket: &str,
        key: &str,
        prefix: Option<&str>,
        target_dir: &Path,
    ) -> Result<u64, ProjectDetectionError> {
        // Calculate relative path (remove prefix if present)
        let relative_path = if let Some(prefix) = prefix {
            key.strip_prefix(prefix)
                .map(|p| p.trim_start_matches('/'))
                .unwrap_or(key)
        } else {
            key
        };

        // Build target file path
        let target_path = target_dir.join(relative_path);

        // Create parent directories
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                ProjectDetectionError::S3Error(format!(
                    "Failed to create directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        // Download the object
        let response = client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                ProjectDetectionError::S3Error(format!("Failed to download {}: {}", key, e))
            })?;

        // Write to file
        let body = response.body.collect().await.map_err(|e| {
            ProjectDetectionError::S3Error(format!("Failed to read body for {}: {}", key, e))
        })?;

        let bytes = body.into_bytes();
        let size = bytes.len() as u64;

        let mut file = fs::File::create(&target_path).await.map_err(|e| {
            ProjectDetectionError::S3Error(format!(
                "Failed to create file {}: {}",
                target_path.display(),
                e
            ))
        })?;

        file.write_all(&bytes).await.map_err(|e| {
            ProjectDetectionError::S3Error(format!(
                "Failed to write file {}: {}",
                target_path.display(),
                e
            ))
        })?;

        Ok(size)
    }
}

impl Default for S3Service {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_s3_uri() {
        // Simple s3:// format
        let uri = S3BucketUri::parse("s3://my-bucket").unwrap();
        assert_eq!(uri.bucket, "my-bucket");
        assert!(uri.prefix.is_none());
        assert!(uri.region.is_none());

        // s3:// with prefix
        let uri = S3BucketUri::parse("s3://my-bucket/path/to/project").unwrap();
        assert_eq!(uri.bucket, "my-bucket");
        assert_eq!(uri.prefix, Some("path/to/project".to_string()));
        assert!(uri.region.is_none());
    }

    #[test]
    fn test_parse_https_virtual_hosted_style() {
        // Virtual-hosted style without region
        let uri = S3BucketUri::parse("https://my-bucket.s3.amazonaws.com").unwrap();
        assert_eq!(uri.bucket, "my-bucket");
        assert!(uri.prefix.is_none());
        assert!(uri.region.is_none());

        // Virtual-hosted style with region
        let uri =
            S3BucketUri::parse("https://my-bucket.s3.us-west-2.amazonaws.com/prefix").unwrap();
        assert_eq!(uri.bucket, "my-bucket");
        assert_eq!(uri.prefix, Some("prefix".to_string()));
        assert_eq!(uri.region, Some("us-west-2".to_string()));
    }

    #[test]
    fn test_parse_https_path_style() {
        // Path-style with region
        let uri =
            S3BucketUri::parse("https://s3.us-east-1.amazonaws.com/my-bucket/prefix").unwrap();
        assert_eq!(uri.bucket, "my-bucket");
        assert_eq!(uri.prefix, Some("prefix".to_string()));
        assert_eq!(uri.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn test_invalid_uris() {
        // Empty bucket
        assert!(S3BucketUri::parse("s3://").is_err());

        // Unsupported protocol
        assert!(S3BucketUri::parse("ftp://bucket").is_err());

        // Invalid URL
        assert!(S3BucketUri::parse("not-a-valid-url").is_err());
    }

    #[test]
    fn test_aws_credentials_effective_region() {
        let creds = AwsCredentials::new("key".to_string(), "secret".to_string());
        assert_eq!(creds.effective_region(), "us-east-1");

        let creds_with_region = creds.with_region("eu-west-1".to_string());
        assert_eq!(creds_with_region.effective_region(), "eu-west-1");
    }
}
