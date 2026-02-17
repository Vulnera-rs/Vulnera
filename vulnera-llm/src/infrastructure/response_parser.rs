//! Shared response parsing utilities for LLM outputs
//!
//! Provides robust JSON extraction from model responses that may include
//! markdown code fences or surrounding narrative text.

use serde::de::DeserializeOwned;

use crate::domain::LlmError;

/// Utilities for extracting and parsing JSON from LLM responses.
pub struct ResponseParser;

impl ResponseParser {
    /// Parse a JSON value from an LLM response.
    ///
    /// Strategy order:
    /// 1) Try the full trimmed content as JSON.
    /// 2) Extract a fenced JSON code block (```json ... ```).
    /// 3) Extract any fenced code block (``` ... ```).
    /// 4) Extract the first valid JSON object/array found in the text.
    pub fn parse_json<T: DeserializeOwned>(content: &str) -> Result<T, LlmError> {
        let trimmed = content.trim();
        if let Ok(parsed) = serde_json::from_str::<T>(trimmed) {
            return Ok(parsed);
        }

        if let Some(json) = Self::extract_fenced_json(trimmed)
            && let Ok(parsed) = serde_json::from_str::<T>(&json)
        {
            return Ok(parsed);
        }

        if let Some(json) = Self::extract_any_fenced_code(trimmed)
            && let Ok(parsed) = serde_json::from_str::<T>(&json)
        {
            return Ok(parsed);
        }

        if let Some(json) = Self::extract_first_json_value(trimmed)
            && let Ok(parsed) = serde_json::from_str::<T>(&json)
        {
            return Ok(parsed);
        }

        Err(LlmError::InvalidResponse(
            "Failed to extract valid JSON from LLM response".to_string(),
        ))
    }

    /// Extract a ```json fenced code block.
    pub fn extract_fenced_json(content: &str) -> Option<String> {
        Self::extract_fenced_block(content, Some("json"))
    }

    /// Extract any fenced code block.
    pub fn extract_any_fenced_code(content: &str) -> Option<String> {
        Self::extract_fenced_block(content, None)
    }

    /// Extract the first valid JSON value (object or array) from text.
    ///
    /// Uses `serde_json::Deserializer` to detect a valid JSON prefix.
    pub fn extract_first_json_value(content: &str) -> Option<String> {
        for (idx, ch) in content.char_indices() {
            if ch == '{' || ch == '[' {
                let candidate = &content[idx..];
                let mut de =
                    serde_json::Deserializer::from_str(candidate).into_iter::<serde_json::Value>();
                if let Some(Ok(_value)) = de.next() {
                    let end = de.byte_offset();
                    if end > 0 && end <= candidate.len() {
                        return Some(candidate[..end].to_string());
                    }
                }
            }
        }
        None
    }

    fn extract_fenced_block(content: &str, language: Option<&str>) -> Option<String> {
        let fence = "```";
        let mut search = content;

        loop {
            let start = search.find(fence)?;
            let after_start = &search[start + fence.len()..];

            // Determine language tag
            let (lang_tag, rest) = if let Some(line_end) = after_start.find('\n') {
                let tag = after_start[..line_end].trim();
                (tag, &after_start[line_end + 1..])
            } else {
                return None;
            };

            if let Some(expected) = language
                && !lang_tag.eq_ignore_ascii_case(expected)
            {
                // Continue scanning after this fence
                search = after_start;
                continue;
            }

            let end = rest.find(fence)?;
            let block = rest[..end].trim().to_string();
            return Some(block);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_direct() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Payload {
            key: String,
        }

        let json = r#"{ "key": "value" }"#;
        let parsed: Payload = ResponseParser::parse_json(json).unwrap();
        assert_eq!(
            parsed,
            Payload {
                key: "value".into()
            }
        );
    }

    #[test]
    fn test_parse_json_fenced_json() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Payload {
            ok: bool,
        }

        let content = r#"
Here is the result:
```json
{ "ok": true }
```
"#;
        let parsed: Payload = ResponseParser::parse_json(content).unwrap();
        assert_eq!(parsed, Payload { ok: true });
    }

    #[test]
    fn test_parse_json_any_fence() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Payload {
            count: u32,
        }

        let content = r#"
```text
{ "count": 7 }
```
"#;
        let parsed: Payload = ResponseParser::parse_json(content).unwrap();
        assert_eq!(parsed, Payload { count: 7 });
    }

    #[test]
    fn test_parse_json_first_value() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Payload {
            status: String,
        }

        let content = "Some text before {\"status\":\"ok\"} trailing text";
        let parsed: Payload = ResponseParser::parse_json(content).unwrap();
        assert_eq!(
            parsed,
            Payload {
                status: "ok".into()
            }
        );
    }

    #[test]
    fn test_extract_fenced_json_none() {
        let content = "no fences here";
        assert!(ResponseParser::extract_fenced_json(content).is_none());
    }
}
