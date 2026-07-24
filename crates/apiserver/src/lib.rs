//! Additive library target, parallel to (and never depended on by) the
//! `u7s-apiserver` binary's own module tree in `main.rs`. `main.rs` has no
//! `[lib]` to link against, so `benches/list_filter.rs` — a separate
//! compilation unit — cannot see any of its code no matter how a function's
//! visibility is set; only a `[lib]` target is linkable at all. This mirrors
//! main.rs's module list (Cargo also always builds a package's `[lib]` as a
//! prerequisite of its `[[bin]]`s, so it must fully compile either way) so
//! the bench exercises the real, unmodified `apply_label_selector` rather
//! than a hand-copied twin that could drift from it. The server binary's own
//! behavior is untouched: main.rs still declares and compiles this same
//! module tree itself, exactly as before `Args` moved into its own file
//! (see `args.rs`) to be `mod args;`-shared by both crate roots.
//!
//! Most of what this pulls in (proto/gen/gen_adapter decoding, admission,
//! rbac, ...) has no caller within this narrow surface — dead_code is
//! expected and blanket-allowed here rather than chasing it file by file.
//! `main.rs` being bin-only meant `private_interfaces` never had a real
//! public-API boundary to check before now; several handler entry points
//! are `pub` (for cross-module route wiring) with a `pub(crate)` query-param
//! type, harmless for a bin but now flagged for this lib target — pre-existing
//! visibility choices unrelated to this bench, not tightened here.
#![allow(dead_code, private_interfaces)]

mod admission;
mod admissionreg_gen;
mod admissionreg_gen_adapter;
mod apiextensions_gen;
mod apiextensions_gen_adapter;
mod apiregistration_gen;
mod apiregistration_gen_adapter;
mod apps_gen;
mod apps_gen_adapter;
mod args;
mod auth;
mod batch_gen_adapter;
mod content_type;
mod coord_gen;
mod coord_gen_adapter;
mod core_gen_adapter;
pub mod handlers;
mod inflight;
mod keys;
mod limit_range;
mod metrics;
mod net_disc_cert_policy_events_gen;
mod net_disc_cert_policy_events_gen_adapter;
mod patch;
mod proto;
mod quota;
mod rbac;
mod rbac_authz_authn_gen;
mod rbac_gen_adapter;
mod state;
mod status;
mod storage_node_flow_gen;
mod storage_node_flow_gen_adapter;
mod tls;
mod types;
mod util;

// `tls.rs` refers to `crate::Args` (matching `main.rs`'s own top-level
// `Args`) — re-export it here so this crate root satisfies that path too.
use args::Args;
