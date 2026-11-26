//! Narrow object shapes: only the fields controllers read, so each cached
//! object stays small. Unknown fields are dropped at decode time.

use crate::informer::Object;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerRef {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub uid: String,
    pub controller: Option<bool>,
    pub block_owner_deletion: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub name: String,
    pub namespace: Option<String>,
    pub uid: Option<String>,
    pub resource_version: Option<String>,
    pub labels: Option<BTreeMap<String, String>>,
    pub owner_references: Option<Vec<OwnerRef>>,
}

impl Meta {
    pub fn key(&self) -> String {
        format!("{}/{}", self.namespace.as_deref().unwrap_or(""), self.name)
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Cond {
    #[serde(rename = "type")]
    pub type_: String,
    pub status: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PodStatus {
    pub phase: Option<String>,
    pub conditions: Option<Vec<Cond>>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NarrowPod {
    pub metadata: Meta,
    pub status: Option<PodStatus>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RsSpec {
    pub replicas: Option<i32>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NarrowRs {
    pub metadata: Meta,
    pub spec: Option<RsSpec>,
}

impl Object for NarrowPod {
    fn key(&self) -> String {
        self.metadata.key()
    }
}

impl Object for NarrowRs {
    fn key(&self) -> String {
        self.metadata.key()
    }
}
