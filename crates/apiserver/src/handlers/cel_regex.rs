//! `matches()` for CRD CEL rules, with compiled regexes cached across calls.
//!
//! The `cel` crate's own `matches` compiles the pattern on every call, so a rule that
//! matches a large literal pattern against every element of a list pays one compile per
//! element. Here a pattern compiles once while it stays cached.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use regex::Regex;

/// Total pattern bytes the cache holds before it is emptied. Patterns can come from request
/// data, so the cache must not grow with traffic.
const MAX_CACHED_PATTERN_BYTES: usize = 4 * 1024 * 1024;

#[derive(Default)]
struct RegexCache {
    compiled: HashMap<String, Regex>,
    pattern_bytes: usize,
}

static CACHE: Mutex<Option<RegexCache>> = Mutex::new(None);

#[cfg(test)]
pub(crate) static COMPILES: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);

fn compile(pattern: &str) -> Result<Regex, regex::Error> {
    #[cfg(test)]
    {
        *COMPILES
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .entry(pattern.to_string())
            .or_default() += 1;
    }
    Regex::new(pattern)
}

fn cached_regex(pattern: &str) -> Result<Regex, regex::Error> {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.get_or_insert_with(RegexCache::default);
    if let Some(re) = cache.compiled.get(pattern) {
        return Ok(re.clone());
    }
    let re = compile(pattern)?;
    if cache.pattern_bytes + pattern.len() > MAX_CACHED_PATTERN_BYTES {
        *cache = RegexCache::default();
    }
    cache.pattern_bytes += pattern.len();
    cache.compiled.insert(pattern.to_string(), re.clone());
    Ok(re)
}

/// `string.matches(re)` and `matches(string, re)`.
pub(crate) fn cel_matches(
    cel::extractors::This(this): cel::extractors::This<Arc<String>>,
    pattern: Arc<String>,
) -> Result<bool, cel::ExecutionError> {
    match cached_regex(&pattern) {
        Ok(re) => Ok(re.is_match(&this)),
        Err(err) => Err(cel::ExecutionError::function_error(
            "matches",
            format!("'{pattern}' not a valid regex:\n{err}"),
        )),
    }
}
