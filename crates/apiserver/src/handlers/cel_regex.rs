//! `matches()` for CRD CEL rules, with compiled regexes cached across calls.
//!
//! The `cel` crate's own `matches` compiles the pattern on every call, so a rule that
//! matches a large literal pattern against every element of a list pays one compile per
//! element. Here a pattern compiles once while it stays cached.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use regex_automata::meta::{self, BuildError};

type Regex = meta::Regex;

/// Real compiled bytes the cache holds before it evicts. Patterns can come from request
/// data, so the cache must not grow with traffic.
const MAX_CACHED_BYTES: usize = 32 * 1024 * 1024;

/// NFA size limit per pattern; compilation is refused past it, which bounds how much of the
/// cache one pattern can displace.
const MAX_ENTRY_BYTES: usize = MAX_CACHED_BYTES / 8;

struct Entry {
    regex: Arc<Regex>,
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
    fn get(&mut self, pattern: &str) -> Option<Arc<Regex>> {
        self.clock += 1;
        let entry = self.entries.get_mut(pattern)?;
        entry.last_used = self.clock;
        Some(entry.regex.clone())
    }

    fn insert_if_absent(&mut self, pattern: &str, regex: &Arc<Regex>) {
        if self.entries.contains_key(pattern) {
            return;
        }
        let bytes = pattern.len() + regex.memory_usage();
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

fn compile(pattern: &str) -> Result<Regex, Box<BuildError>> {
    #[cfg(test)]
    {
        *COMPILES
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .entry(pattern.to_string())
            .or_default() += 1;
    }
    Regex::builder()
        .configure(Regex::config().nfa_size_limit(Some(MAX_ENTRY_BYTES)))
        .build(pattern)
        .map_err(Box::new)
}

/// Compiles outside the lock: a slow compile of one pattern must not hold up cache hits for
/// every other pattern. Concurrent first uses of one pattern may each compile it.
fn lookup_or_compile(
    cache: &Mutex<Option<RegexCache>>,
    pattern: &str,
    compile: impl FnOnce(&str) -> Result<Regex, Box<BuildError>>,
) -> Result<Arc<Regex>, Box<BuildError>> {
    let lock = || cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(re) = lock().get_or_insert_with(RegexCache::default).get(pattern) {
        return Ok(re);
    }
    let re = Arc::new(compile(pattern)?);
    lock()
        .get_or_insert_with(RegexCache::default)
        .insert_if_absent(pattern, &re);
    Ok(re)
}

/// `BuildError`'s own Display omits the cause ("error parsing pattern 0"); the syntax or
/// size-limit detail lives in its source.
fn build_error_message(err: &BuildError) -> String {
    match std::error::Error::source(err) {
        Some(cause) => format!("{err}: {cause}"),
        None => err.to_string(),
    }
}

/// `string.matches(re)` and `matches(string, re)`.
pub(crate) fn cel_matches(
    cel::extractors::This(this): cel::extractors::This<Arc<String>>,
    pattern: Arc<String>,
) -> Result<bool, cel::ExecutionError> {
    match lookup_or_compile(&CACHE, &pattern, compile) {
        Ok(re) => Ok(re.is_match(this.as_str())),
        Err(err) => Err(cel::ExecutionError::function_error(
            "matches",
            format!(
                "'{pattern}' not a valid regex:\n{}",
                build_error_message(&err)
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(pattern: &str) -> Result<Regex, Box<BuildError>> {
        Regex::new(pattern).map_err(Box::new)
    }

    fn cost(pattern: &str) -> usize {
        pattern.len() + Regex::new(pattern).unwrap().memory_usage()
    }

    /// Cloning a `meta::Regex` allocates a fresh cache pool, which made every `matches()` over
    /// a list ~3x slower than sharing one handle.
    #[test]
    fn cache_hits_share_one_regex_handle() {
        let cache = Mutex::new(None);
        let a = lookup_or_compile(&cache, "x+", plain).unwrap();
        let b = lookup_or_compile(&cache, "x+", |_| panic!("must be a cache hit")).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }

    /// Without the source, every bad pattern reported only "error parsing pattern 0", leaving
    /// the CRD author no clue what was wrong.
    #[test]
    fn build_errors_keep_syntax_and_size_limit_detail() {
        let syntax = compile("(").unwrap_err();
        let msg = build_error_message(&syntax);
        assert!(msg.contains("unclosed group"), "syntax detail lost: {msg}");

        let big = compile(&format!(r"\pL{{{}}}", 400)).unwrap_err();
        let msg = build_error_message(&big);
        assert!(
            msg.contains("exceeded limit of"),
            "size-limit detail lost: {msg}"
        );
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
                    Regex::new(p).map_err(Box::new)
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

    /// A 7-byte `\pL{50}` compiles to megabytes; a per-pattern-byte estimate would admit tens of
    /// GiB of them, so the cache must charge the real compiled size.
    #[test]
    fn many_small_class_heavy_patterns_stay_within_the_real_memory_budget() {
        let cache = Mutex::new(None);
        for n in 20..80 {
            lookup_or_compile(&cache, &format!(r"\pL{{{n}}}"), plain).unwrap();
        }
        let guard = cache.lock().unwrap();
        let state = guard.as_ref().unwrap();
        let real: usize = state.entries.values().map(|e| e.regex.memory_usage()).sum();
        assert!(
            real <= MAX_CACHED_BYTES,
            "cached regexes really use {real} bytes, over the {MAX_CACHED_BYTES} budget"
        );
        assert!(
            state.entries.len() < 60,
            "nothing was evicted, so the test never exercised the bound"
        );
    }

    /// Patterns come from request data; one huge pattern must displace only what it needs,
    /// least recently used first, never the whole cache.
    #[test]
    fn a_huge_pattern_evicts_cold_entries_not_the_hot_ones() {
        let cache = Mutex::new(None);
        let huge = r"\pL{200}";
        let mut used = cost("hot");
        let mut i = 0;
        loop {
            let filler = format!(r"\pL{{{}}}", 30 + i);
            if used + cost(&filler) + cost(huge) > MAX_CACHED_BYTES {
                break;
            }
            used += cost(&filler);
            lookup_or_compile(&cache, &filler, plain).unwrap();
            i += 1;
        }
        lookup_or_compile(&cache, "hot", plain).unwrap();
        lookup_or_compile(&cache, huge, plain).unwrap();
        lookup_or_compile(&cache, "hot", |_| panic!("hot pattern was evicted")).unwrap();
        lookup_or_compile(&cache, huge, |_| panic!("new pattern was not cached")).unwrap();
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
