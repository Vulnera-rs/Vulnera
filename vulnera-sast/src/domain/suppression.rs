//! Suppression directives for SAST findings
//!
//! Parse and manage suppression comments like `// vulnera-ignore-next-line`.

/// Suppression directive parsed from source comments
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppression {
    /// The line this suppression applies to (1-based)
    pub target_line: u32,
    /// Specific rule IDs to suppress, or empty for all rules
    pub rule_ids: Vec<String>,
    /// Reason for suppression (optional)
    pub reason: Option<String>,
}

/// Collection of suppressions for a file
#[derive(Debug, Clone, Default)]
pub struct FileSuppressions {
    suppressions: Vec<Suppression>,
}

impl FileSuppressions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse suppressions from file content
    pub fn parse(content: &str) -> Self {
        let mut suppressions = Vec::new();

        for (idx, line) in content.lines().enumerate() {
            let line_num = (idx + 1) as u32;
            let trimmed = line.trim();

            if let Some(suppression) = Self::parse_ignore_next_line(trimmed, line_num) {
                suppressions.push(suppression);
            }

            if let Some(suppression) = Self::parse_rust_allow_attribute(trimmed, line_num) {
                suppressions.push(suppression);
            }
        }

        Self { suppressions }
    }

    fn parse_ignore_next_line(line: &str, line_num: u32) -> Option<Suppression> {
        let comment_content = if let Some(rest) = line.strip_prefix("//") {
            rest.trim()
        } else if let Some(rest) = line.strip_prefix('#') {
            if rest.trim_start().starts_with('[') {
                return None;
            }
            rest.trim()
        } else if line.starts_with("/*") && line.ends_with("*/") {
            line[2..line.len() - 2].trim()
        } else {
            return None;
        };

        let directive = comment_content.strip_prefix("vulnera-ignore-next-line")?;
        let directive = directive.trim_start();

        let (rule_ids, reason) = if directive.is_empty() {
            (vec![], None)
        } else if let Some(rest) = directive.strip_prefix(':') {
            Self::parse_rule_ids_and_reason(rest.trim())
        } else {
            (vec![], None)
        };

        Some(Suppression {
            target_line: line_num + 1,
            rule_ids,
            reason,
        })
    }

    fn parse_rust_allow_attribute(line: &str, line_num: u32) -> Option<Suppression> {
        let attr_content = line.strip_prefix("#[allow(")?.strip_suffix(")]")?;

        let mut rule_ids = Vec::new();
        for part in attr_content.split(',') {
            let part = part.trim();
            if let Some(rule_id) = part.strip_prefix("vulnera::") {
                rule_ids.push(rule_id.replace('_', "-"));
            }
        }

        if rule_ids.is_empty() {
            return None;
        }

        Some(Suppression {
            target_line: line_num + 1,
            rule_ids,
            reason: None,
        })
    }

    fn parse_rule_ids_and_reason(input: &str) -> (Vec<String>, Option<String>) {
        let (ids_part, reason) = if let Some(idx) = input.find("--") {
            let reason = input[idx + 2..].trim();
            (
                &input[..idx],
                if reason.is_empty() {
                    None
                } else {
                    Some(reason.to_string())
                },
            )
        } else {
            (input, None)
        };

        let rule_ids: Vec<String> = ids_part
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        (rule_ids, reason)
    }

    /// Check if a finding on the given line should be suppressed
    pub fn is_suppressed(&self, line: u32, rule_id: &str) -> bool {
        self.suppressions.iter().any(|s| {
            s.target_line == line
                && (s.rule_ids.is_empty() || s.rule_ids.contains(&rule_id.to_string()))
        })
    }

    /// Get suppressions for a specific line
    pub fn get_suppressions_for_line(&self, line: u32) -> Vec<&Suppression> {
        self.suppressions
            .iter()
            .filter(|s| s.target_line == line)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_ignore() {
        let content = "// vulnera-ignore-next-line\nfoo();";
        let suppressions = FileSuppressions::parse(content);
        assert!(suppressions.is_suppressed(2, "any-rule"));
    }

    #[test]
    fn test_parse_ignore_with_rule() {
        let content = "// vulnera-ignore-next-line: my-rule\nfoo();";
        let suppressions = FileSuppressions::parse(content);
        assert!(suppressions.is_suppressed(2, "my-rule"));
        assert!(!suppressions.is_suppressed(2, "other-rule"));
    }
}
