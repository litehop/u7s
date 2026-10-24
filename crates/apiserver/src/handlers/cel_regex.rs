//! `matches()` for CRD CEL rules, with compiled regexes cached across calls.
//!
//! The `cel` crate's own `matches` compiles the pattern on every call, so a rule that
//! matches a large literal pattern against every element of a list pays one compile per
//! element. Here a pattern compiles once while it stays cached.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use regex::{Regex, RegexBuilder};

/// Estimated compiled bytes the cache holds before it evicts. Patterns can come from request
/// data, so the cache must not grow with traffic.
const MAX_CACHED_BYTES: usize = 32 * 1024 * 1024;

/// The most one pattern may occupy. Compilation is refused past this size, so it also bounds
/// what a single entry can really use and how much of the cache one pattern can displace.
const MAX_ENTRY_BYTES: usize = MAX_CACHED_BYTES / 8;

/// Compiled-size estimate per pattern byte; the `regex` crate does not report the real size.
const COMPILED_BYTES_PER_PATTERN_BYTE: usize = 64;

struct Entry {
    regex: Regex,
    bytes: usize,
    last_used: u64,
}

#[derive(Default)]
struct RegexCache {
    entries: HashMap<String, Entry>,
    bytes: usize,
    clock: u64,
}

impl RegexCache {
    fn get(&mut self, pattern: &str) -> Option<Regex> {
        self.clock += 1;
        let entry = self.entries.get_mut(pattern)?;
        entry.last_used = self.clock;
        Some(entry.regex.clone())
    }

    fn insert_if_absent(&mut self, pattern: &str, regex: &Regex) {
        if self.entries.contains_key(pattern) {
            return;
        }
        let bytes = (pattern.len() * COMPILED_BYTES_PER_PATTERN_BYTE).clamp(1024, MAX_ENTRY_BYTES);
        while self.bytes + bytes > MAX_CACHED_BYTES {
            let Some(coldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(evicted) = self.entries.remove(&coldest) {
                self.bytes -= evicted.bytes;
            }
        }
        self.clock += 1;
        self.bytes += bytes;
        self.entries.insert(
            pattern.to_string(),
            Entry {
                regex: regex.clone(),
                bytes,
                last_used: self.clock,
            },
        );
    }
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
    RegexBuilder::new(pattern)
        .size_limit(MAX_ENTRY_BYTES)
        .build()
}

/// Compiles outside the lock: a slow compile of one pattern must not hold up cache hits for
/// every other pattern. Concurrent first uses of one pattern may each compile it.
fn lookup_or_compile(
    cache: &Mutex<Option<RegexCache>>,
    pattern: &str,
    compile: impl FnOnce(&str) -> Result<Regex, regex::Error>,
) -> Result<Regex, regex::Error> {
    let lock = || cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(re) = lock().get_or_insert_with(RegexCache::default).get(pattern) {
        return Ok(re);
    }
    let re = compile(pattern)?;
    lock()
        .get_or_insert_with(RegexCache::default)
        .insert_if_absent(pattern, &re);
    Ok(re)
}

/// `string.matches(re)` and `matches(string, re)`.
pub(crate) fn cel_matches(
    cel::extractors::This(this): cel::extractors::This<Arc<String>>,
    pattern: Arc<String>,
) -> Result<bool, cel::ExecutionError> {
    match lookup_or_compile(&CACHE, &pattern, compile) {
        Ok(re) => Ok(re.is_match(&this)),
        Err(err) => Err(cel::ExecutionError::function_error(
            "matches",
            format!("'{pattern}' not a valid regex:\n{err}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(pattern: &str) -> Result<Regex, regex::Error> {
        Regex::new(pattern)
    }

    /// One slow compile used to hold the process-wide lock, stalling every `matches()` on every
    /// CRD behind it.
    #[test]
    fn a_compile_in_progress_does_not_block_cache_hits_for_other_patterns() {
        let cache = Mutex::new(None);
        lookup_or_compile(&cache, "hot", plain).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let cache = &cache;
        std::thread::scope(|s| {
            s.spawn(move || {
                lookup_or_compile(cache, "slow", |p| {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Regex::new(p)
                })
                .unwrap();
            });
            started_rx.recv().unwrap();
            let (hit_tx, hit_rx) = std::sync::mpsc::channel();
            s.spawn(move || {
                let hit = lookup_or_compile(cache, "hot", |_| panic!("must be a cache hit"));
                hit_tx.send(hit.is_ok()).unwrap();
            });
            let hit = hit_rx.recv_timeout(std::time::Duration::from_secs(10));
            release_tx.send(()).unwrap();
            assert_eq!(
                hit,
                Ok(true),
                "a cache hit waited on another pattern's compile"
            );
        });
    }

    /// Patterns come from request data; one huge pattern must displace only what it needs,
    /// least recently used first, never the whole cache.
    #[test]
    fn a_huge_pattern_evicts_cold_entries_not_the_hot_ones() {
        let cache = Mutex::new(None);
        let filler = "x".repeat(MAX_ENTRY_BYTES / COMPILED_BYTES_PER_PATTERN_BYTE);
        let filler_count = MAX_CACHED_BYTES / MAX_ENTRY_BYTES - 1;
        for i in 0..filler_count {
            lookup_or_compile(&cache, &format!("{filler}{i}"), plain).unwrap();
        }
        lookup_or_compile(&cache, "hot", plain).unwrap();
        let huge = "y".repeat(MAX_ENTRY_BYTES / COMPILED_BYTES_PER_PATTERN_BYTE);
        lookup_or_compile(&cache, &huge, plain).unwrap();
        lookup_or_compile(&cache, "hot", |_| panic!("hot pattern was evicted")).unwrap();
        lookup_or_compile(&cache, &huge, |_| panic!("new pattern was not cached")).unwrap();
        let guard = cache.lock().unwrap();
        let state = guard.as_ref().unwrap();
        assert!(
            state.bytes <= MAX_CACHED_BYTES,
            "cache exceeded its byte bound"
        );
        assert!(
            state.entries.len() > 2,
            "one pattern flushed the whole cache"
        );
    }
}
