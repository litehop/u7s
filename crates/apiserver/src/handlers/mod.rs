pub mod aggregation;
pub mod approval;
pub mod authorization;
pub mod cel_cost;
pub mod cel_regex;
pub mod cel_rules;
pub mod certificates;
pub mod core;
pub mod cr;
pub mod crd;
pub mod csr;
pub mod defaults;
pub mod device_taint_rule;
pub mod discovery;
pub mod field_selector;
#[cfg(test)]
mod field_selector_tests;
pub mod generic;
pub mod json_patch;
pub(crate) mod jsonpath;
pub mod metrics;
pub mod namespaces;
pub mod oidc;
pub mod pods;
pub mod proxy;
pub mod resource;
pub mod scale;
pub mod status;
pub mod storage_versions;
pub mod storagemigration;
pub mod stream;
#[cfg(test)]
mod subresource_admission_tests;
pub mod table;
#[cfg(test)]
pub(crate) mod test_support;
pub mod tokens;
pub mod watch;
