//! Kubernetes protobuf wire format decoder.
//!
//! kubectl sends write requests with `Content-Type: application/vnd.kubernetes.protobuf` by
//! default. The encoding is NOT standard protobuf alone — it uses a 4-byte magic prefix followed
//! by a protobuf-encoded `Unknown` envelope whose `raw` field (field 2) contains the actual object
//! (usually JSON when contentType = "application/json", or proto when contentType =
//! "application/vnd.kubernetes.protobuf" for types with registered proto codecs like Namespace).
//!
//! Wire format:
//!   [4 bytes magic: 0x6b, 0x38, 0x73, 0x00]
//!   [protobuf-encoded Unknown message]
//!
//! Unknown fields (from k8s.io/apimachinery/pkg/runtime/generated.proto):
//!   field 1 (TypeMeta, wire type 2):  tag = 0x0a
//!   field 2 (raw bytes, wire type 2): tag = 0x12  <- the encoded object
//!   field 3 (contentEncoding, wire 2): tag = 0x1a
//!   field 4 (contentType, wire 2):    tag = 0x22  <- "application/json" or ".../protobuf"

const K8S_PROTO_MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];

/// The decoded `Unknown` envelope fields we care about.
pub struct ProtoEnvelope {
    /// The raw bytes of `Unknown.raw` (field 2).
    pub raw: Vec<u8>,
    /// The content type of the raw bytes (field 4), e.g. "application/json" or
    /// "application/vnd.kubernetes.protobuf". Empty string if the field was absent.
    pub content_type: String,
}

/// Attempt to decode the Kubernetes protobuf envelope and return both the raw payload and its
/// declared content-type.
///
/// Returns `Some(envelope)` when the body starts with the k8s magic prefix and contains a
/// decodable `Unknown.raw` field (field 2). Returns `None` otherwise.
pub fn decode_k8s_proto_envelope(body: &[u8]) -> Option<ProtoEnvelope> {
    if body.len() < 4 || &body[..4] != K8S_PROTO_MAGIC {
        return None;
    }
    let proto_bytes = &body[4..];
    let mut raw: Option<Vec<u8>> = None;
    let mut content_type = String::new();
    scan_length_delimited_fields(proto_bytes, |field_number, data| {
        match field_number {
            2 => raw = Some(data.to_vec()),
            4 => content_type = String::from_utf8_lossy(data).into_owned(),
            _ => {}
        }
    })?;
    Some(ProtoEnvelope { raw: raw?, content_type })
}

/// Attempt to decode a Kubernetes protobuf body and extract the embedded raw payload.
///
/// Returns `Some(bytes)` when the body starts with the k8s magic prefix and contains
/// a decodable `Unknown.raw` field (field 2). Returns `None` otherwise — the caller
/// should treat the body as-is (e.g. plain JSON).
pub fn decode_k8s_proto(body: &[u8]) -> Option<Vec<u8>> {
    // Must start with the 4-byte magic.
    if body.len() < 4 || &body[..4] != K8S_PROTO_MAGIC {
        return None;
    }

    let proto_bytes = &body[4..];
    extract_field2(proto_bytes)
}

/// Decode a proto-encoded Namespace object into a `serde_json::Value`.
///
/// Namespace proto layout (k8s.io/api/core/v1/generated.proto):
///   field 1 (ObjectMeta, wire 2): metadata
///   field 2 (NamespaceSpec, wire 2): spec
///   field 3 (NamespaceStatus, wire 2): status
///
/// ObjectMeta proto layout (k8s.io/apimachinery/pkg/apis/meta/v1/generated.proto):
///   field 1 (string): name
///   field 2 (string): generateName
///   field 3 (string): namespace
///   field 5 (string): uid
///   field 6 (string): resourceVersion
///   field 8 (Time, wire 2): creationTimestamp — always emitted by kubectl even when zero
///   field 11 (MapEntry, wire 2 repeated): labels
///   field 12 (MapEntry, wire 2 repeated): annotations
///
/// Map entries are each a 2-field sub-message: field 1 = key (string), field 2 = value (string).
pub fn decode_namespace_proto(data: &[u8]) -> Option<serde_json::Value> {
    let mut meta = serde_json::json!({ "creationTimestamp": null });
    let mut labels: Option<serde_json::Map<String, serde_json::Value>> = None;
    let mut annotations: Option<serde_json::Map<String, serde_json::Value>> = None;

    // --- Parse the Namespace message: extract field 1 (ObjectMeta) ---
    scan_length_delimited_fields(data, |field_number, field_data| {
        if field_number == 1 {
            // field 1 = ObjectMeta
            scan_mixed_fields(field_data, |fn2, wt, fd| {
                match (fn2, wt) {
                    (1, 2) => {
                        // name (string)
                        meta["name"] =
                            serde_json::Value::String(String::from_utf8_lossy(fd).into_owned());
                    }
                    (2, 2) => {
                        // generateName (string)
                        let s = String::from_utf8_lossy(fd).into_owned();
                        if !s.is_empty() {
                            meta["generateName"] = serde_json::Value::String(s);
                        }
                    }
                    (3, 2) => {
                        // namespace (string) — usually empty for cluster-scoped objects
                        let s = String::from_utf8_lossy(fd).into_owned();
                        if !s.is_empty() {
                            meta["namespace"] = serde_json::Value::String(s);
                        }
                    }
                    (5, 2) => {
                        // uid (string)
                        let s = String::from_utf8_lossy(fd).into_owned();
                        if !s.is_empty() {
                            meta["uid"] = serde_json::Value::String(s);
                        }
                    }
                    (6, 2) => {
                        // resourceVersion (string)
                        let s = String::from_utf8_lossy(fd).into_owned();
                        if !s.is_empty() {
                            meta["resourceVersion"] = serde_json::Value::String(s);
                        }
                    }
                    (11, 2) => {
                        // labels map entry
                        if let Some((k, v)) = decode_map_entry(fd) {
                            labels
                                .get_or_insert_with(serde_json::Map::new)
                                .insert(k, serde_json::Value::String(v));
                        }
                    }
                    (12, 2) => {
                        // annotations map entry
                        if let Some((k, v)) = decode_map_entry(fd) {
                            annotations
                                .get_or_insert_with(serde_json::Map::new)
                                .insert(k, serde_json::Value::String(v));
                        }
                    }
                    _ => {} // ignore other fields (creationTimestamp wire type 2, generation varint, etc.)
                }
            });
        }
        // field 2 (NamespaceSpec) and field 3 (NamespaceStatus) are ignored —
        // create_namespace fills in status.phase=Active unconditionally.
    })?;

    if let Some(l) = labels {
        meta["labels"] = serde_json::Value::Object(l);
    }
    if let Some(a) = annotations {
        meta["annotations"] = serde_json::Value::Object(a);
    }

    Some(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": meta
    }))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Scan length-delimited (wire type 2) fields of a protobuf message, calling `f(field_number,
/// field_data)` for each. Non-length-delimited fields are skipped silently. Returns `None` if the
/// data is malformed (truncated varint or truncated field payload).
fn scan_length_delimited_fields<F>(mut data: &[u8], mut f: F) -> Option<()>
where
    F: FnMut(u64, &[u8]),
{
    while !data.is_empty() {
        let (tag, rest) = decode_varint(data)?;
        data = rest;
        let field_number = tag >> 3;
        let wire_type = tag & 0x7;
        match wire_type {
            0 => {
                let (_, rest) = decode_varint(data)?;
                data = rest;
            }
            1 => {
                if data.len() < 8 {
                    return None;
                }
                data = &data[8..];
            }
            2 => {
                let (len, rest) = decode_varint(data)?;
                let len = len as usize;
                data = rest;
                if data.len() < len {
                    return None;
                }
                f(field_number, &data[..len]);
                data = &data[len..];
            }
            5 => {
                if data.len() < 4 {
                    return None;
                }
                data = &data[4..];
            }
            _ => return None,
        }
    }
    Some(())
}

/// Scan ALL wire types of a protobuf message, calling `f(field_number, wire_type, field_data)`.
/// For length-delimited (wire type 2), `field_data` is the payload bytes. For other wire types,
/// `field_data` is the raw bytes consumed (not interpreted). Returns `None` on malformed input.
fn scan_mixed_fields<F>(mut data: &[u8], mut f: F) -> Option<()>
where
    F: FnMut(u64, u64, &[u8]),
{
    while !data.is_empty() {
        let (tag, rest) = decode_varint(data)?;
        data = rest;
        let field_number = tag >> 3;
        let wire_type = tag & 0x7;
        match wire_type {
            0 => {
                let (_, rest) = decode_varint(data)?;
                let consumed = data.len() - rest.len();
                f(field_number, wire_type, &data[..consumed]);
                data = rest;
            }
            1 => {
                if data.len() < 8 {
                    return None;
                }
                f(field_number, wire_type, &data[..8]);
                data = &data[8..];
            }
            2 => {
                let (len, rest) = decode_varint(data)?;
                let len = len as usize;
                data = rest;
                if data.len() < len {
                    return None;
                }
                f(field_number, wire_type, &data[..len]);
                data = &data[len..];
            }
            5 => {
                if data.len() < 4 {
                    return None;
                }
                f(field_number, wire_type, &data[..4]);
                data = &data[4..];
            }
            _ => return None,
        }
    }
    Some(())
}

/// Decode a protobuf map entry: `{ field 1 (key, string), field 2 (value, string) }`.
/// Returns `Some((key, value))` on success, `None` if malformed or key is empty.
fn decode_map_entry(data: &[u8]) -> Option<(String, String)> {
    let mut key = String::new();
    let mut value = String::new();
    scan_length_delimited_fields(data, |field_number, fd| match field_number {
        1 => key = String::from_utf8_lossy(fd).into_owned(),
        2 => value = String::from_utf8_lossy(fd).into_owned(),
        _ => {}
    })?;
    if key.is_empty() {
        return None;
    }
    Some((key, value))
}

/// Scan `data` for a length-delimited field with field number 2 (tag byte 0x12) and return its
/// contents. Unknown fields are skipped using their wire type. Returns `None` if field 2 is not
/// found or the data is malformed.
fn extract_field2(mut data: &[u8]) -> Option<Vec<u8>> {
    while !data.is_empty() {
        let (tag, rest) = decode_varint(data)?;
        data = rest;

        let field_number = tag >> 3;
        let wire_type = tag & 0x7;

        match wire_type {
            0 => {
                // varint — consume and discard
                let (_, rest) = decode_varint(data)?;
                data = rest;
            }
            1 => {
                // 64-bit — consume 8 bytes
                if data.len() < 8 {
                    return None;
                }
                data = &data[8..];
            }
            2 => {
                // length-delimited
                let (len, rest) = decode_varint(data)?;
                let len = len as usize;
                data = rest;
                if data.len() < len {
                    return None;
                }
                if field_number == 2 {
                    return Some(data[..len].to_vec());
                }
                data = &data[len..];
            }
            5 => {
                // 32-bit — consume 4 bytes
                if data.len() < 4 {
                    return None;
                }
                data = &data[4..];
            }
            _ => {
                // Unknown wire type — bail out.
                return None;
            }
        }
    }

    None // field 2 not found
}

/// Decode a protobuf varint from the front of `data`.
/// Returns `Some((value, remaining))` or `None` if the data is too short or the varint
/// exceeds 10 bytes (which would overflow a u64).
fn decode_varint(data: &[u8]) -> Option<(u64, &[u8])> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        if shift >= 64 {
            return None; // varint too long
        }
        result |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((result, &data[i + 1..]));
        }
    }
    None // ran out of data
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------------
    // Varint encoder — used only in tests to build synthetic protobuf payloads.
    // ---------------------------------------------------------------------------

    fn encode_varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    fn encode_length_delimited(field_number: u64, payload: &[u8]) -> Vec<u8> {
        let tag = (field_number << 3) | 2;
        let mut out = encode_varint(tag);
        out.extend_from_slice(&encode_varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    /// Build a minimal Kubernetes protobuf body: magic prefix + Unknown message containing
    /// only the `raw` field (field 2) with the given payload.
    fn build_k8s_proto(raw: &[u8]) -> Vec<u8> {
        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend_from_slice(&encode_length_delimited(2, raw));
        body
    }

    /// Build a Kubernetes protobuf body with raw (field 2) and contentType (field 4).
    fn build_k8s_proto_with_content_type(raw: &[u8], content_type: &[u8]) -> Vec<u8> {
        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend_from_slice(&encode_length_delimited(2, raw));
        body.extend_from_slice(&encode_length_delimited(4, content_type));
        body
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_k8s_proto
    // ---------------------------------------------------------------------------

    /// decode_k8s_proto must extract the embedded JSON from a well-formed protobuf body.
    /// This is the primary case kubectl triggers: a write request with
    /// Content-Type: application/vnd.kubernetes.protobuf where Unknown.raw contains JSON.
    #[test]
    fn extracts_raw_json_from_valid_proto_body() {
        let json = br#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"test"}}"#;
        let proto_body = build_k8s_proto(json);

        let result = decode_k8s_proto(&proto_body).expect("must decode successfully");
        assert_eq!(result, json, "extracted raw must equal the original JSON payload");
    }

    /// decode_k8s_proto must return None for a body without the magic prefix.
    /// Ensures plain JSON bodies are not misinterpreted as protobuf.
    #[test]
    fn returns_none_for_plain_json_body() {
        let json = br#"{"apiVersion":"v1","kind":"Namespace"}"#;
        assert!(
            decode_k8s_proto(json).is_none(),
            "plain JSON must not match the protobuf magic prefix"
        );
    }

    /// decode_k8s_proto must return None for an empty body.
    #[test]
    fn returns_none_for_empty_body() {
        assert!(decode_k8s_proto(&[]).is_none());
    }

    /// decode_k8s_proto must return None when the body is only the magic prefix with no proto data.
    /// This verifies we don't panic on truncated input.
    #[test]
    fn returns_none_for_magic_only_body() {
        assert!(decode_k8s_proto(K8S_PROTO_MAGIC).is_none());
    }

    /// A proto body with a different field (field 1 only, no field 2) must return None.
    /// Ensures we only return data when field 2 is actually present.
    #[test]
    fn returns_none_when_field2_absent() {
        let mut body = K8S_PROTO_MAGIC.to_vec();
        // Only encode field 1 (TypeMeta).
        body.extend_from_slice(&encode_length_delimited(1, b"some-type-meta"));
        assert!(
            decode_k8s_proto(&body).is_none(),
            "must return None when only field 1 is present"
        );
    }

    /// A proto body with fields before and after field 2 must still extract field 2 correctly.
    /// This mirrors real kubectl output which includes field 1 (TypeMeta) before field 2 (raw).
    #[test]
    fn extracts_field2_when_preceded_by_field1() {
        let json = br#"{"kind":"Pod"}"#;
        let mut proto = Vec::new();
        // Field 1 first (TypeMeta embedded message — encode as bytes).
        proto.extend_from_slice(&encode_length_delimited(1, b"\x0a\x02v1\x12\x03Pod"));
        // Field 2 next (raw JSON).
        proto.extend_from_slice(&encode_length_delimited(2, json));
        // Field 4 last (contentType).
        proto.extend_from_slice(&encode_length_delimited(4, b"application/json"));

        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend_from_slice(&proto);

        let result = decode_k8s_proto(&body).expect("must decode field 2 even when other fields are present");
        assert_eq!(result, json);
    }

    /// decode_varint must round-trip a single-byte value.
    #[test]
    fn decode_varint_single_byte() {
        let (v, rest) = decode_varint(&[0x05]).unwrap();
        assert_eq!(v, 5);
        assert!(rest.is_empty());
    }

    /// decode_varint must decode a multi-byte varint correctly.
    #[test]
    fn decode_varint_multi_byte() {
        // 300 in varint = [0xac, 0x02]
        let (v, rest) = decode_varint(&[0xac, 0x02]).unwrap();
        assert_eq!(v, 300);
        assert!(rest.is_empty());
    }

    /// decode_varint must return None for an empty slice.
    #[test]
    fn decode_varint_empty_returns_none() {
        assert!(decode_varint(&[]).is_none());
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_k8s_proto_envelope
    // ---------------------------------------------------------------------------

    /// decode_k8s_proto_envelope must extract both raw and contentType fields.
    /// This is the real kubectl behavior for core types (e.g. Namespace): the Unknown envelope
    /// has contentType = "application/vnd.kubernetes.protobuf" and raw = proto-encoded object.
    #[test]
    fn envelope_extracts_raw_and_content_type() {
        let raw = b"some-proto-bytes";
        let ct = b"application/vnd.kubernetes.protobuf";
        let body = build_k8s_proto_with_content_type(raw, ct);

        let env = decode_k8s_proto_envelope(&body).expect("must decode envelope");
        assert_eq!(env.raw, raw);
        assert_eq!(env.content_type, "application/vnd.kubernetes.protobuf");
    }

    /// When contentType (field 4) is absent, decode_k8s_proto_envelope must still return the raw
    /// field with an empty content_type.
    #[test]
    fn envelope_raw_without_content_type() {
        let raw = br#"{"kind":"Namespace"}"#;
        let body = build_k8s_proto(raw);

        let env = decode_k8s_proto_envelope(&body).expect("must decode envelope");
        assert_eq!(env.raw, raw);
        assert_eq!(env.content_type, "", "contentType must be empty when field 4 is absent");
    }

    /// decode_k8s_proto_envelope must return None when the magic prefix is absent.
    #[test]
    fn envelope_returns_none_for_plain_json() {
        let json = br#"{"kind":"Namespace"}"#;
        assert!(decode_k8s_proto_envelope(json).is_none());
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_namespace_proto
    // ---------------------------------------------------------------------------

    /// decode_namespace_proto must reconstruct a Namespace JSON from proto-encoded bytes
    /// that contain only the name field. This is what kubectl sends for
    /// `kubectl create namespace <name>`.
    ///
    /// This test is the PRIMARY regression guard for the smoke CI failure:
    ///   Error from server (BadRequest): invalid JSON: expected value at line 2 column 1
    /// which occurred because Unknown.raw contained a proto-encoded Namespace (starting with
    /// 0x0a = '\n'), and the JSON parser treated 0x0a as a newline before failing at line 2.
    #[test]
    fn decode_namespace_proto_extracts_name() {
        // Build a minimal Namespace proto:
        // Namespace { metadata: ObjectMeta { name: "smoke-test" } }
        //
        // ObjectMeta field 1 (name, wire 2): tag=0x0a, len=10, "smoke-test"
        let obj_meta = encode_length_delimited(1, b"smoke-test");
        // Namespace field 1 (ObjectMeta, wire 2):
        let namespace_proto = encode_length_delimited(1, &obj_meta);

        let result = decode_namespace_proto(&namespace_proto).expect("must decode namespace proto");

        assert_eq!(result["kind"], "Namespace");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "smoke-test");
        // creationTimestamp must be null for kubectl compatibility
        assert!(result["metadata"]["creationTimestamp"].is_null());
    }

    /// decode_namespace_proto must also extract labels and annotations when present.
    #[test]
    fn decode_namespace_proto_extracts_labels_and_annotations() {
        // Build: ObjectMeta { name: "ns", labels: {"env": "test"}, annotations: {"note": "hi"} }
        let mut obj_meta = encode_length_delimited(1, b"ns"); // field 1 = name
        // Labels map entry (field 11): {field 1="env", field 2="test"}
        let mut label_entry = encode_length_delimited(1, b"env");
        label_entry.extend_from_slice(&encode_length_delimited(2, b"test"));
        obj_meta.extend_from_slice(&encode_length_delimited(11, &label_entry));
        // Annotations map entry (field 12): {field 1="note", field 2="hi"}
        let mut annot_entry = encode_length_delimited(1, b"note");
        annot_entry.extend_from_slice(&encode_length_delimited(2, b"hi"));
        obj_meta.extend_from_slice(&encode_length_delimited(12, &annot_entry));

        let namespace_proto = encode_length_delimited(1, &obj_meta);
        let result = decode_namespace_proto(&namespace_proto).expect("must decode");

        assert_eq!(result["metadata"]["name"], "ns");
        assert_eq!(result["metadata"]["labels"]["env"], "test");
        assert_eq!(result["metadata"]["annotations"]["note"], "hi");
    }

    /// decode_namespace_proto must return None for malformed proto input.
    #[test]
    fn decode_namespace_proto_returns_none_for_garbage() {
        assert!(decode_namespace_proto(&[0xff, 0xff, 0xff]).is_none());
    }

    /// Full round-trip: kubectl create namespace smoke-test sends a k8s proto envelope
    /// where Unknown.raw is a proto-encoded Namespace. The server must decode it to JSON
    /// with the correct name. This is the regression test for the smoke CI failure.
    #[test]
    fn full_kubectl_create_namespace_smoke_regression() {
        // Build proto-encoded Namespace{metadata:{name:"smoke-test", creationTimestamp:{}}}
        let mut obj_meta = encode_length_delimited(1, b"smoke-test"); // name
        // creationTimestamp (field 8, wire 2) — empty Time{} message (len=0)
        obj_meta.extend_from_slice(&encode_length_delimited(8, &[])); // empty Time
        let namespace_proto = encode_length_delimited(1, &obj_meta);

        // Wrap in k8s Unknown envelope with contentType=protobuf
        let type_meta: Vec<u8> = {
            let mut t = encode_length_delimited(1, b"v1"); // apiVersion
            t.extend_from_slice(&encode_length_delimited(2, b"Namespace")); // kind
            t
        };
        let mut unknown = encode_length_delimited(1, &type_meta); // TypeMeta
        unknown.extend_from_slice(&encode_length_delimited(2, &namespace_proto)); // raw
        unknown.extend_from_slice(&encode_length_delimited(
            4,
            b"application/vnd.kubernetes.protobuf",
        )); // contentType

        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend_from_slice(&unknown);

        // Decode the envelope
        let env = decode_k8s_proto_envelope(&body).expect("envelope decode must succeed");
        assert_eq!(env.content_type, "application/vnd.kubernetes.protobuf");

        // Decode the inner proto-encoded Namespace
        let json = decode_namespace_proto(&env.raw).expect("namespace proto decode must succeed");
        assert_eq!(json["metadata"]["name"], "smoke-test", "name must be extracted from proto");
        assert_eq!(json["kind"], "Namespace");
        assert_eq!(json["apiVersion"], "v1");
    }
}
