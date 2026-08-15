// The generated message types (and the prost invocation that produces them) now live in
// u7s-proto-generated — see that crate's lib.rs. This module is kept as a thin re-export rather
// than deleted so every existing `crate::net_disc_cert_policy_events_gen::...` call site keeps
// resolving without a crate-wide rename. Notably, this wrapper used to `include!()` its own
// independent copy of `api::core::v1` (nominally distinct from `apps_gen`'s and
// `storage_node_flow_gen`'s own copies) — that triplication is now gone too, since all three
// wrappers re-export the same canonical tree. Its only remaining call sites are `#[cfg(test)]`
// fixtures in proto.rs, so a non-test build sees this re-export as unused.
#[allow(unused_imports)]
pub use u7s_proto_generated::k8s;
