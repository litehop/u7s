//! Measurement-only: per-CRD `pattern` compile cost for real-world CRD YAMLs.
//! Fetch CRDs into `temp/research/crds/` (see findings doc), then run
//! `cargo test -p apiserver --release crd_pattern_real_world -- --ignored --nocapture`.

use std::collections::BTreeMap;
use std::time::Instant;

use yaml_rust2::Yaml;

fn to_json(y: &Yaml) -> serde_json::Value {
    use serde_json::Value;
    match y {
        Yaml::Hash(h) => Value::Object(
            h.iter()
                .map(|(k, v)| {
                    let key = match k {
                        Yaml::String(s) => s.clone(),
                        Yaml::Integer(i) => i.to_string(),
                        Yaml::Boolean(b) => b.to_string(),
                        Yaml::Real(r) => r.clone(),
                        _ => String::new(),
                    };
                    (key, to_json(v))
                })
                .collect(),
        ),
        Yaml::Array(a) => Value::Array(a.iter().map(to_json).collect()),
        Yaml::String(s) => Value::String(s.clone()),
        Yaml::Integer(i) => Value::from(*i),
        Yaml::Real(r) => r
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map_or(Value::Null, Value::Number),
        Yaml::Boolean(b) => Value::Bool(*b),
        _ => Value::Null,
    }
}

fn collect_patterns(node: &serde_json::Value, out: &mut Vec<String>) {
    match node {
        serde_json::Value::Object(map) => {
            if let Some(p) = map.get("pattern").and_then(|v| v.as_str()) {
                out.push(p.to_string());
            }
            map.values().for_each(|v| collect_patterns(v, out));
        }
        serde_json::Value::Array(a) => a.iter().for_each(|v| collect_patterns(v, out)),
        _ => {}
    }
}

const SEARCH_CAP: usize = 1 << 27;

/// Smallest `size_limit` the pattern compiles under (bytes), or None if above `SEARCH_CAP`
/// or not compilable by the regex crate.
fn compiled_size(pattern: &str) -> Option<usize> {
    let src = super::crd::ascii_shorthands(pattern);
    let builds = |limit: usize| -> Result<(), bool> {
        match regex::RegexBuilder::new(&src).size_limit(limit).build() {
            Ok(_) => Ok(()),
            Err(regex::Error::CompiledTooBig(_)) => Err(true),
            Err(_) => Err(false),
        }
    };
    crate::cel_runtime::format::on_compile_stack(|| {
        match builds(SEARCH_CAP) {
            Ok(()) => {}
            Err(_) => return None,
        }
        let (mut lo, mut hi) = (1usize, SEARCH_CAP);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if builds(mid).is_ok() {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        Some(lo)
    })
}

fn max_rss_mib() -> f64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let raw = ru.ru_maxrss as f64;
    if cfg!(target_os = "macos") {
        raw / (1024.0 * 1024.0)
    } else {
        raw / 1024.0
    }
}

fn boon_compile_ms(schema: &serde_json::Value) -> f64 {
    let start = Instant::now();
    let _ = crate::cel_runtime::format::on_compile_stack(|| {
        let mut schemas = boon::Schemas::new();
        let mut compiler = boon::Compiler::new();
        compiler
            .add_resource("schema.json", schema.clone())
            .map_err(|e| e.to_string())?;
        compiler
            .compile("schema.json", &mut schemas)
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
    start.elapsed().as_secs_f64() * 1e3
}

fn load_crds(path: &std::path::Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(path).unwrap();
    let text: String = text
        .lines()
        .filter(|l| !l.contains("{{"))
        .collect::<Vec<_>>()
        .join("\n");
    yaml_rust2::YamlLoader::load_from_str(&text)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .iter()
        .map(to_json)
        .filter(|d| d["kind"] == "CustomResourceDefinition")
        .collect()
}

fn bucket(sz: usize) -> usize {
    match sz {
        0..=4095 => 0,
        4096..=16383 => 1,
        16384..=65535 => 2,
        65536..=262144 => 3,
        262145..=1048576 => 4,
        _ => 5,
    }
}

#[test]
#[ignore = "measurement only; needs temp/research/crds"]
fn real_world_crd_pattern_cost() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../temp/research/crds");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    let mut cache: BTreeMap<String, Option<usize>> = BTreeMap::new();
    eprintln!(
        "ROW crd | yaml_bytes | schema_json_bytes | patterns | distinct | longest_pat | max_compiled | sum_compiled | distinct_sum | buckets(<4K,<16K,<64K,<=256K,<=1M,>1M) | uncompilable | budget_fn | len1024_cap | boon_ms | rss_mib"
    );
    for f in files {
        let yaml_len = std::fs::metadata(&f).unwrap().len();
        for crd in load_crds(&f) {
            let name = crd["metadata"]["name"].as_str().unwrap_or("?").to_string();
            let mut pats = Vec::new();
            let mut json_bytes = 0;
            let mut ok_all = true;
            let mut dos_ok = true;
            let mut boon_ms = 0.0;
            for v in crd["spec"]["versions"].as_array().into_iter().flatten() {
                let schema = &v["schema"]["openAPIV3Schema"];
                if schema.is_null() {
                    continue;
                }
                json_bytes += schema.to_string().len();
                collect_patterns(schema, &mut pats);
                ok_all &= super::crd::check_pattern_compile_budget(schema, "s").is_ok();
                dos_ok &= super::crd::walk_schema_dos_bounds(schema, "s").is_ok();
                boon_ms += boon_compile_ms(schema);
            }
            let mut sizes = Vec::new();
            let mut uncompilable = 0;
            for p in &pats {
                let sz = *cache.entry(p.clone()).or_insert_with(|| compiled_size(p));
                match sz {
                    Some(s) => sizes.push((p.clone(), s)),
                    None => uncompilable += 1,
                }
            }
            let mut hist = [0usize; 6];
            sizes.iter().for_each(|(_, s)| hist[bucket(*s)] += 1);
            let mut seen = std::collections::BTreeSet::new();
            let distinct_sum: usize = sizes
                .iter()
                .filter(|(p, _)| seen.insert(p.clone()))
                .map(|(_, s)| s)
                .sum();
            eprintln!(
                "ROW {name} | {yaml_len} | {json_bytes} | {} | {} | {} | {} | {} | {distinct_sum} | {hist:?} | {uncompilable} | {} | {} | {boon_ms:.0} | {:.0}",
                pats.len(),
                seen.len(),
                pats.iter().map(String::len).max().unwrap_or(0),
                sizes.iter().map(|(_, s)| *s).max().unwrap_or(0),
                sizes.iter().map(|(_, s)| *s).sum::<usize>(),
                if ok_all { "pass" } else { "REJECT" },
                if dos_ok { "pass" } else { "REJECT" },
                max_rss_mib()
            );
        }
    }
}

#[test]
#[ignore = "measurement only"]
fn upstream_e2e_pattern_cost() {
    for p in [
        r"^(\d+|\*)(/\d+)?(\s+(\d+|\*)(/\d+)?){4}$",
        "in-tree|out-of-tree",
        r"\pL{244}",
        r"\pL{100}",
        r"[a-z]{1000}",
        r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
    ] {
        eprintln!("E2E {p} -> {:?} bytes", compiled_size(p));
    }
}
