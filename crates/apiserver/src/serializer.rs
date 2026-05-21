/// Wire-format serialization abstraction for API responses.
///
/// Introducing this trait centralizes the two wire formats (JSON and Kubernetes protobuf)
/// behind a single interface. Callers can select a serializer at request time based on the
/// `Accept` header without scattering format-detection logic across every handler.
///
/// NOTE: No handler has been migrated to use this trait yet — that is future work.
/// This module introduces the abstraction and unit-tests it in isolation.
#[allow(dead_code)]
pub(crate) trait ApiSerializer: Send + Sync {
    fn serialize(&self, val: &serde_json::Value) -> bytes::Bytes;
    fn content_type(&self) -> &'static str;
}

#[allow(dead_code)]
pub(crate) struct JsonSerializer;

impl ApiSerializer for JsonSerializer {
    fn serialize(&self, val: &serde_json::Value) -> bytes::Bytes {
        bytes::Bytes::from(val.to_string())
    }

    fn content_type(&self) -> &'static str {
        "application/json"
    }
}

#[allow(dead_code)]
pub(crate) struct ProtoSerializer;

impl ApiSerializer for ProtoSerializer {
    fn serialize(&self, val: &serde_json::Value) -> bytes::Bytes {
        crate::proto::encode_proto_response(val)
    }

    fn content_type(&self) -> &'static str {
        "application/vnd.kubernetes.protobuf"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// JsonSerializer must round-trip a JSON value: deserializing the output must
    /// equal the input. If this breaks, every JSON response handler would return
    /// garbled data.
    #[test]
    fn json_serializer_round_trips_value() {
        let val = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "default" }
        });
        let serializer = JsonSerializer;
        let bytes = serializer.serialize(&val);
        let recovered: serde_json::Value =
            serde_json::from_slice(&bytes).expect("output must be valid JSON");
        assert_eq!(
            recovered, val,
            "JsonSerializer output must round-trip to the original value"
        );
        assert_eq!(serializer.content_type(), "application/json");
    }

    /// ProtoSerializer output must start with the 4-byte Kubernetes protobuf magic prefix.
    /// kubectl and client-go verify this magic before decoding — a missing or wrong prefix
    /// causes "proto: illegal wireType" or silent decode failures.
    #[test]
    fn proto_serializer_output_starts_with_k8s_magic() {
        let val = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": { "name": "smoke-test" }
        });
        let serializer = ProtoSerializer;
        let bytes = serializer.serialize(&val);
        assert!(
            bytes.len() >= 4,
            "proto output must be at least 4 bytes long"
        );
        assert_eq!(
            &bytes[..4],
            &[0x6b, 0x38, 0x73, 0x00],
            "proto output must start with k8s magic [0x6b, 0x38, 0x73, 0x00]; \
             without this prefix client-go rejects the response"
        );
        assert_eq!(
            serializer.content_type(),
            "application/vnd.kubernetes.protobuf"
        );
    }
}
