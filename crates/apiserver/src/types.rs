use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Every Kubernetes object in memory.
/// Body is kept as a serde_json::Value for cheap pass-through.
/// Accessors parse individual fields on demand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Object {
    #[serde(flatten)]
    pub body: Value,
}

impl Object {
    pub fn name(&self) -> Option<&str> {
        self.body["metadata"]["name"].as_str()
    }

    #[allow(dead_code)]
    pub fn namespace(&self) -> Option<&str> {
        self.body["metadata"]["namespace"].as_str()
    }

    pub fn resource_version(&self) -> Option<&str> {
        self.body["metadata"]["resourceVersion"].as_str()
    }

    #[allow(dead_code)]
    pub fn resource_version_u64(&self) -> Option<u64> {
        self.resource_version()?.parse().ok()
    }

    pub fn set_resource_version(&mut self, rv: u64) {
        self.body["metadata"]["resourceVersion"] = Value::String(rv.to_string());
    }

    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(serde_json::to_vec(&self.body).unwrap())
    }

    pub fn from_bytes(bytes: &Bytes) -> Result<Self, serde_json::Error> {
        let body: Value = serde_json::from_slice(bytes)?;
        Ok(Self { body })
    }
}
