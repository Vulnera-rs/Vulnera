//! Regex cache utilities for SAST
//!
//! Uses once_cell to keep compiled regexes for reuse across matches.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::sync::RwLock;

static REGEX_CACHE: Lazy<RwLock<HashMap<String, Regex>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

static METAVAR_TEMPLATE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\$[A-Za-z_][A-Za-z0-9_]*").expect("valid regex"));

pub fn get_regex(pattern: &str) -> Result<Regex, regex::Error> {
    if let Some(existing) = REGEX_CACHE
        .read()
        .ok()
        .and_then(|guard| guard.get(pattern).cloned())
    {
        return Ok(existing);
    }

    let compiled = Regex::new(pattern)?;
    if let Ok(mut guard) = REGEX_CACHE.write() {
        guard
            .entry(pattern.to_string())
            .or_insert_with(|| compiled.clone());
    }

    Ok(compiled)
}

pub fn metavar_template_regex() -> &'static Regex {
    &METAVAR_TEMPLATE_REGEX
}
