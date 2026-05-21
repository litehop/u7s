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

// ---------------------------------------------------------------------------
// Encoder — produces Kubernetes protobuf wire format from a JSON value.
// ---------------------------------------------------------------------------

/// Encode a varint into a byte vector.
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

/// Encode a length-delimited (wire type 2) field: tag + length varint + payload.
fn encode_ld_field(field_number: u64, payload: &[u8]) -> Vec<u8> {
    let tag = (field_number << 3) | 2;
    let mut out = encode_varint(tag);
    out.extend_from_slice(&encode_varint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

/// Encode a `serde_json::Value` as a Kubernetes protobuf response body.
///
/// Wire format:
///   [4 bytes magic: 0x6b, 0x38, 0x73, 0x00]
///   [protobuf-encoded Unknown message]
///     field 1 (TypeMeta, LEN): apiVersion (field 1, string) + kind (field 2, string)
///     field 2 (raw, LEN): the raw JSON bytes of the object
///     field 4 (contentType, LEN): "application/json"
///
/// client-go reads the `contentType` field (field 4) to determine how to decode
/// the `raw` field (field 2).  By setting contentType to "application/json" and
/// placing the original JSON bytes in `raw`, the client decodes it with its JSON
/// decoder regardless of the outer content-type header — this is why this scheme
/// works for all object types without needing a per-type proto encoder.
pub fn encode_proto_response(val: &serde_json::Value) -> bytes::Bytes {
    let api_version = val["apiVersion"].as_str().unwrap_or("");
    let kind = val["kind"].as_str().unwrap_or("");

    // TypeMeta sub-message: field 1 = apiVersion, field 2 = kind.
    let type_meta = {
        let mut t = encode_ld_field(1, api_version.as_bytes());
        t.extend_from_slice(&encode_ld_field(2, kind.as_bytes()));
        t
    };

    let json_bytes = val.to_string();
    let json_bytes = json_bytes.as_bytes();

    // Unknown envelope: field 1 = TypeMeta, field 2 = raw JSON, field 4 = contentType.
    let mut envelope = encode_ld_field(1, &type_meta);
    envelope.extend_from_slice(&encode_ld_field(2, json_bytes));
    envelope.extend_from_slice(&encode_ld_field(4, b"application/json"));

    let mut out = Vec::with_capacity(4 + envelope.len());
    out.extend_from_slice(K8S_PROTO_MAGIC);
    out.extend_from_slice(&envelope);
    bytes::Bytes::from(out)
}

/// The decoded `Unknown` envelope fields we care about.
pub struct ProtoEnvelope {
    /// The raw bytes of `Unknown.raw` (field 2).
    pub raw: Vec<u8>,
    /// The content type of the raw bytes (field 4), e.g. "application/json" or
    /// "application/vnd.kubernetes.protobuf". Empty string if the field was absent.
    pub content_type: String,
    /// The Kubernetes kind extracted from the TypeMeta (field 1 of the envelope), e.g.
    /// "Namespace" or "ConfigMap". Empty string if absent.
    pub kind: String,
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
    let mut kind = String::new();
    scan_length_delimited_fields(proto_bytes, |field_number, data| {
        match field_number {
            1 => {
                // TypeMeta: field 1 = apiVersion (string), field 2 = kind (string)
                scan_length_delimited_fields(data, |f, d| {
                    if f == 2 {
                        kind = String::from_utf8_lossy(d).into_owned();
                    }
                });
            }
            2 => raw = Some(data.to_vec()),
            4 => content_type = String::from_utf8_lossy(data).into_owned(),
            _ => {}
        }
    })?;
    Some(ProtoEnvelope {
        raw: raw?,
        content_type,
        kind,
    })
}

/// Decode one ObjectMeta proto field into `meta`, `labels`, and `annotations`.
///
/// Called from within a `scan_mixed_fields` closure for field 1 (ObjectMeta) of any top-level
/// Kubernetes object.  All three decoders (Namespace, ConfigMap, Node) share the identical
/// ObjectMeta wire layout — this function consolidates that logic.
fn decode_object_meta_field(
    fn2: u64,
    wt: u64,
    fd: &[u8],
    meta: &mut serde_json::Value,
    labels: &mut Option<serde_json::Map<String, serde_json::Value>>,
    annotations: &mut Option<serde_json::Map<String, serde_json::Value>>,
) {
    match (fn2, wt) {
        (1, 2) => {
            // name (string)
            meta["name"] = serde_json::Value::String(String::from_utf8_lossy(fd).into_owned());
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
                decode_object_meta_field(fn2, wt, fd, &mut meta, &mut labels, &mut annotations);
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

/// Decode a proto-encoded ConfigMap object into a `serde_json::Value`.
///
/// ConfigMap proto layout (k8s.io/api/core/v1/generated.proto):
///   field 1 (ObjectMeta, wire 2): metadata
///   field 2 (map<string,string> data, wire 2 repeated): data entries
///   field 3 (map<string,string> binaryData, wire 2 repeated): ignored
///   field 4 (bool immutable, wire 0): ignored
///
/// Map entries use the same two-field sub-message format as Namespace labels/annotations:
///   field 1 = key (string), field 2 = value (string).
pub fn decode_configmap_proto(data: &[u8]) -> Option<serde_json::Value> {
    let mut meta = serde_json::json!({ "creationTimestamp": null });
    let mut labels: Option<serde_json::Map<String, serde_json::Value>> = None;
    let mut annotations: Option<serde_json::Map<String, serde_json::Value>> = None;
    let mut cm_data: Option<serde_json::Map<String, serde_json::Value>> = None;

    scan_length_delimited_fields(data, |field_number, field_data| {
        match field_number {
            1 => {
                // ObjectMeta — same layout as decode_namespace_proto
                scan_mixed_fields(field_data, |fn2, wt, fd| {
                    decode_object_meta_field(fn2, wt, fd, &mut meta, &mut labels, &mut annotations);
                });
            }
            2 => {
                // data map entry
                if let Some((k, v)) = decode_map_entry(field_data) {
                    cm_data
                        .get_or_insert_with(serde_json::Map::new)
                        .insert(k, serde_json::Value::String(v));
                }
            }
            _ => {} // binaryData, immutable: ignored
        }
    })?;

    if let Some(l) = labels {
        meta["labels"] = serde_json::Value::Object(l);
    }
    if let Some(a) = annotations {
        meta["annotations"] = serde_json::Value::Object(a);
    }

    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": meta
    });
    if let Some(d) = cm_data {
        obj["data"] = serde_json::Value::Object(d);
    }
    Some(obj)
}

/// Decode a proto-encoded Node object into a `serde_json::Value`.
///
/// Node proto layout (k8s.io/api/core/v1/generated.proto):
///   field 1 (ObjectMeta, wire 2): metadata
///   field 2 (NodeSpec, wire 2): spec
///   field 3 (NodeStatus, wire 2): status — treated as opaque, ignored
///
/// NodeSpec proto layout (k8s.io/api/core/v1/generated.proto):
///   field 1 (string): podCIDR
///   field 2 (string): externalID (deprecated)
///   field 3 (string): providerID
///   field 4 (bool, wire 0): unschedulable — ignored
///   field 5+ (complex messages): taints, configSource — ignored
///   field 7 (string, repeated): podCIDRs
///
/// NodeStatus is not decoded — it contains complex repeated fields (conditions, addresses,
/// capacity, etc.) that require a full proto schema. The status subresource PATCH path
/// handles status separately.
pub fn decode_node_proto(data: &[u8]) -> Option<serde_json::Value> {
    let mut meta = serde_json::json!({ "creationTimestamp": null });
    let mut labels: Option<serde_json::Map<String, serde_json::Value>> = None;
    let mut annotations: Option<serde_json::Map<String, serde_json::Value>> = None;
    let mut spec = serde_json::Map::new();
    let mut pod_cidrs: Vec<serde_json::Value> = Vec::new();

    scan_length_delimited_fields(data, |field_number, field_data| {
        match field_number {
            1 => {
                // field 1 = ObjectMeta — same layout as decode_namespace_proto
                scan_mixed_fields(field_data, |fn2, wt, fd| {
                    decode_object_meta_field(fn2, wt, fd, &mut meta, &mut labels, &mut annotations);
                });
            }
            2 => {
                // field 2 = NodeSpec — decode simple string fields
                scan_length_delimited_fields(field_data, |fn2, fd| match fn2 {
                    1 => {
                        // podCIDR (string)
                        let s = String::from_utf8_lossy(fd).into_owned();
                        if !s.is_empty() {
                            spec.insert("podCIDR".to_string(), serde_json::Value::String(s));
                        }
                    }
                    3 => {
                        // providerID (string)
                        let s = String::from_utf8_lossy(fd).into_owned();
                        if !s.is_empty() {
                            spec.insert("providerID".to_string(), serde_json::Value::String(s));
                        }
                    }
                    7 => {
                        // podCIDRs (repeated string)
                        let s = String::from_utf8_lossy(fd).into_owned();
                        if !s.is_empty() {
                            pod_cidrs.push(serde_json::Value::String(s));
                        }
                    }
                    _ => {} // unschedulable (varint), taints, configSource: ignored
                });
            }
            _ => {} // field 3 (NodeStatus) and others: ignored
        }
    })?;

    if let Some(l) = labels {
        meta["labels"] = serde_json::Value::Object(l);
    }
    if let Some(a) = annotations {
        meta["annotations"] = serde_json::Value::Object(a);
    }
    if !pod_cidrs.is_empty() {
        spec.insert("podCIDRs".to_string(), serde_json::Value::Array(pod_cidrs));
    }

    let mut obj = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": meta
    });
    if !spec.is_empty() {
        obj["spec"] = serde_json::Value::Object(spec);
    }
    Some(obj)
}

/// Decode a proto-encoded core Kubernetes object by kind.
///
/// Dispatches to the appropriate type-specific decoder based on `kind`. Returns `Some(json)` for
/// known types; `None` for unknown kinds or malformed input.
pub fn decode_core_proto_by_kind(kind: &str, raw: &[u8]) -> Option<serde_json::Value> {
    match kind {
        "Namespace" => decode_namespace_proto(raw),
        "ConfigMap" => decode_configmap_proto(raw),
        "Node" => decode_node_proto(raw),
        _ => None,
    }
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
    // Tests — envelope raw field extraction
    // ---------------------------------------------------------------------------

    /// The envelope decoder must extract raw bytes from a well-formed protobuf body.
    /// This is the primary case kubectl triggers: a write request with
    /// Content-Type: application/vnd.kubernetes.protobuf where Unknown.raw contains JSON.
    #[test]
    fn extracts_raw_json_from_valid_proto_body() {
        let json = br#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"test"}}"#;
        let proto_body = build_k8s_proto(json);

        let result = decode_k8s_proto_envelope(&proto_body).expect("must decode successfully");
        assert_eq!(
            result.raw, json,
            "extracted raw must equal the original JSON payload"
        );
    }

    /// The envelope decoder must return None for a body without the magic prefix.
    /// Ensures plain JSON bodies are not misinterpreted as protobuf.
    #[test]
    fn returns_none_for_plain_json_body() {
        let json = br#"{"apiVersion":"v1","kind":"Namespace"}"#;
        assert!(
            decode_k8s_proto_envelope(json).is_none(),
            "plain JSON must not match the protobuf magic prefix"
        );
    }

    /// The envelope decoder must return None for an empty body.
    #[test]
    fn returns_none_for_empty_body() {
        assert!(decode_k8s_proto_envelope(&[]).is_none());
    }

    /// The envelope decoder must return None when the body is only the magic prefix with no proto data.
    /// This verifies we don't panic on truncated input.
    #[test]
    fn returns_none_for_magic_only_body() {
        assert!(decode_k8s_proto_envelope(K8S_PROTO_MAGIC).is_none());
    }

    /// A proto body with a different field (field 1 only, no field 2) must return None.
    /// Ensures we only return data when field 2 is actually present.
    #[test]
    fn returns_none_when_field2_absent() {
        let mut body = K8S_PROTO_MAGIC.to_vec();
        // Only encode field 1 (TypeMeta with no raw field).
        let type_meta = encode_length_delimited(2, b"Namespace"); // kind only
        body.extend_from_slice(&encode_length_delimited(1, &type_meta));
        assert!(
            decode_k8s_proto_envelope(&body).is_none(),
            "must return None when only field 1 (TypeMeta) is present and field 2 (raw) is absent"
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

        let result = decode_k8s_proto_envelope(&body)
            .expect("must decode field 2 even when other fields are present");
        assert_eq!(result.raw, json);
        assert_eq!(result.content_type, "application/json");
        assert_eq!(result.kind, "Pod");
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
        assert_eq!(
            env.content_type, "",
            "contentType must be empty when field 4 is absent"
        );
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
        assert_eq!(
            json["metadata"]["name"], "smoke-test",
            "name must be extracted from proto"
        );
        assert_eq!(json["kind"], "Namespace");
        assert_eq!(json["apiVersion"], "v1");
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_configmap_proto
    // ---------------------------------------------------------------------------

    /// decode_configmap_proto must decode a proto-encoded ConfigMap with name, namespace, and data.
    /// This is the regression test for the smoke CI failure on `kubectl create configmap`.
    ///
    /// kubectl sends ConfigMap as a proto-encoded object in Unknown.raw (contentType=""),
    /// which must be decoded to JSON before being stored. Previously, the server tried to parse
    /// the proto bytes as JSON, hitting the "control character found" error at the 0x0a byte.
    #[test]
    fn decode_configmap_proto_extracts_name_namespace_and_data() {
        // Build: ObjectMeta { name: "smoke-cm", namespace: "smoke-test" }
        let mut obj_meta = encode_length_delimited(1, b"smoke-cm"); // field 1 = name
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"smoke-test")); // field 3 = namespace
                                                                                // data map entry (field 2 of ConfigMap): { key="key", value="value" }
        let mut data_entry = encode_length_delimited(1, b"key");
        data_entry.extend_from_slice(&encode_length_delimited(2, b"value"));

        let mut configmap_proto = encode_length_delimited(1, &obj_meta); // ObjectMeta
        configmap_proto.extend_from_slice(&encode_length_delimited(2, &data_entry)); // data entry

        let result = decode_configmap_proto(&configmap_proto).expect("must decode configmap proto");

        assert_eq!(result["kind"], "ConfigMap");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "smoke-cm");
        assert_eq!(result["metadata"]["namespace"], "smoke-test");
        assert_eq!(result["data"]["key"], "value");
        assert!(result["metadata"]["creationTimestamp"].is_null());
    }

    /// decode_core_proto_by_kind must dispatch to the correct decoder.
    /// This verifies that extract_body can decode both Namespace and ConfigMap by kind.
    #[test]
    fn decode_core_proto_by_kind_dispatches_correctly() {
        let mut obj_meta = encode_length_delimited(1, b"test-ns"); // name
        let namespace_proto = encode_length_delimited(1, &obj_meta);
        let ns_json = decode_core_proto_by_kind("Namespace", &namespace_proto)
            .expect("Namespace must decode");
        assert_eq!(ns_json["kind"], "Namespace");
        assert_eq!(ns_json["metadata"]["name"], "test-ns");

        obj_meta = encode_length_delimited(1, b"test-cm"); // name
        let configmap_proto = encode_length_delimited(1, &obj_meta);
        let cm_json = decode_core_proto_by_kind("ConfigMap", &configmap_proto)
            .expect("ConfigMap must decode");
        assert_eq!(cm_json["kind"], "ConfigMap");
        assert_eq!(cm_json["metadata"]["name"], "test-cm");

        // Unknown kind returns None
        assert!(decode_core_proto_by_kind("Pod", &namespace_proto).is_none());
    }

    // ---------------------------------------------------------------------------
    // Tests — decode_node_proto
    // ---------------------------------------------------------------------------

    /// decode_node_proto must extract ObjectMeta fields from a proto-encoded Node.
    /// This is the primary fix for kubelet PUT /api/v1/nodes/{name}/status with proto body —
    /// previously decode_core_proto_by_kind returned None for "Node", causing extract_body to
    /// return raw proto bytes that serde_json::from_slice then failed to parse as JSON.
    #[test]
    fn decode_node_proto_extracts_name() {
        // Build: Node { metadata: ObjectMeta { name: "node-1" } }
        let obj_meta = encode_length_delimited(1, b"node-1"); // field 1 = name
        let node_proto = encode_length_delimited(1, &obj_meta); // Node.field 1 = ObjectMeta

        let result = decode_node_proto(&node_proto).expect("must decode node proto");

        assert_eq!(result["kind"], "Node");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "node-1");
        assert!(result["metadata"]["creationTimestamp"].is_null());
    }

    /// decode_node_proto must extract podCIDR and providerID from NodeSpec (field 2).
    /// Kubelet sends a full Node proto on registration including spec fields — without this,
    /// stored nodes have empty spec and controllers see a malformed node.
    #[test]
    fn decode_node_proto_preserves_spec_fields() {
        // Build: Node {
        //   metadata: ObjectMeta { name: "node-1" },
        //   spec: NodeSpec { podCIDR: "10.244.0.0/24", providerID: "aws://us-east-1a/i-1234" }
        // }
        let obj_meta = encode_length_delimited(1, b"node-1"); // ObjectMeta.name
        let mut node_spec = Vec::new();
        node_spec.extend_from_slice(&encode_length_delimited(1, b"10.244.0.0/24")); // NodeSpec.podCIDR
        node_spec.extend_from_slice(&encode_length_delimited(3, b"aws://us-east-1a/i-1234")); // NodeSpec.providerID
        node_spec.extend_from_slice(&encode_length_delimited(7, b"10.244.0.0/24")); // NodeSpec.podCIDRs[0]

        let mut node_proto = encode_length_delimited(1, &obj_meta); // Node.field 1 = ObjectMeta
        node_proto.extend_from_slice(&encode_length_delimited(2, &node_spec)); // Node.field 2 = NodeSpec

        let result = decode_node_proto(&node_proto).expect("must decode node with spec");

        assert_eq!(result["kind"], "Node");
        assert_eq!(result["apiVersion"], "v1");
        assert_eq!(result["metadata"]["name"], "node-1");
        assert_eq!(
            result["spec"]["podCIDR"], "10.244.0.0/24",
            "podCIDR must be extracted from NodeSpec field 1"
        );
        assert_eq!(
            result["spec"]["providerID"], "aws://us-east-1a/i-1234",
            "providerID must be extracted from NodeSpec field 3"
        );
        assert_eq!(
            result["spec"]["podCIDRs"][0], "10.244.0.0/24",
            "podCIDRs must be extracted from NodeSpec field 7"
        );
    }

    /// decode_node_proto must not panic when NodeSpec contains unrecognized fields (e.g. taints).
    /// Guards against kubelet sending a full Node proto with complex nested spec fields.
    #[test]
    fn decode_node_proto_with_unknown_spec_fields_does_not_panic() {
        // Build: Node { metadata: ObjectMeta { name: "node-2" }, spec: NodeSpec { podCIDR: "10.0.0.0/24", <unknown field> } }
        let obj_meta = encode_length_delimited(1, b"node-2"); // ObjectMeta.name
        let mut node_spec = Vec::new();
        node_spec.extend_from_slice(&encode_length_delimited(1, b"10.0.0.0/24")); // NodeSpec.podCIDR
                                                                                  // field 5 = taints (repeated Taint message) — not decoded, must be silently skipped
        node_spec.extend_from_slice(&encode_length_delimited(5, b"\x0a\x08NoSchedule")); // opaque Taint bytes

        let mut node_proto = encode_length_delimited(1, &obj_meta);
        node_proto.extend_from_slice(&encode_length_delimited(2, &node_spec));

        let result =
            decode_node_proto(&node_proto).expect("must not panic on unknown NodeSpec fields");

        assert_eq!(result["metadata"]["name"], "node-2");
        assert_eq!(result["spec"]["podCIDR"], "10.0.0.0/24");
    }

    /// decode_node_proto must not panic and must return Some when NodeSpec contains the
    /// `unschedulable` field (field 4, wire type 0, varint=1).
    ///
    /// Real kubelets send `unschedulable=true` during maintenance (node cordoning). The NodeSpec
    /// scanner uses scan_length_delimited_fields, which silently skips varint fields. This test
    /// guards against a future change to the scanner accidentally turning the silent-skip into a
    /// panic or a None return for nodes that are unschedulable.
    ///
    /// Protobuf encoding of `unschedulable=true` in NodeSpec:
    ///   tag = (field 4 << 3) | wire_type 0 = 0x20
    ///   value = varint 1 = 0x01
    #[test]
    fn decode_node_proto_unschedulable_node_does_not_panic() {
        // Build: Node {
        //   metadata: ObjectMeta { name: "maintenance-node" },
        //   spec: NodeSpec { podCIDR: "10.0.1.0/24", unschedulable: true }
        // }
        let obj_meta = encode_length_delimited(1, b"maintenance-node");
        let mut node_spec = Vec::new();
        node_spec.extend_from_slice(&encode_length_delimited(1, b"10.0.1.0/24")); // NodeSpec.podCIDR
                                                                                  // NodeSpec.unschedulable = true: tag=0x20 (field 4, wire type 0), value=0x01
        node_spec.push(0x20);
        node_spec.push(0x01);

        let mut node_proto = encode_length_delimited(1, &obj_meta);
        node_proto.extend_from_slice(&encode_length_delimited(2, &node_spec));

        // Must return Some — the varint field must be silently skipped, not cause a panic or None.
        let result = decode_node_proto(&node_proto)
            .expect("decode_node_proto must return Some even when unschedulable=true is present");

        assert_eq!(result["metadata"]["name"], "maintenance-node");
        assert_eq!(result["spec"]["podCIDR"], "10.0.1.0/24");
    }

    /// Walk every tag in a proto message (non-recursive, top-level only) and assert that no
    /// tag has an illegal wire type (3, 4, 6, or 7).  Called from regression tests below.
    ///
    /// Returns the list of fields encountered as `(field_number, wire_type, payload_len)`.
    fn assert_valid_wire_types(msg: &[u8]) -> Vec<(u64, u64, usize)> {
        let mut pos = 0;
        let mut fields = Vec::new();
        while pos < msg.len() {
            let (tag, rest) = decode_varint(&msg[pos..])
                .unwrap_or_else(|| panic!("truncated varint at pos {pos}"));
            pos += msg[pos..].len() - rest.len();
            let wire_type = tag & 0x7;
            let field_number = tag >> 3;
            assert!(
                !matches!(wire_type, 3 | 4 | 6 | 7),
                "illegal wire type {wire_type} at pos {}: tag=0x{tag:02x} field_number={field_number}\n\
                 Full envelope hex: {}",
                pos - 1,
                msg.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
            );
            match wire_type {
                0 => {
                    let (_, rest2) = decode_varint(&msg[pos..])
                        .unwrap_or_else(|| panic!("truncated varint value at pos {pos}"));
                    let consumed = msg[pos..].len() - rest2.len();
                    fields.push((field_number, wire_type, consumed));
                    pos += consumed;
                }
                2 => {
                    let (len, rest2) = decode_varint(&msg[pos..])
                        .unwrap_or_else(|| panic!("truncated length varint at pos {pos}"));
                    pos += msg[pos..].len() - rest2.len();
                    let len = len as usize;
                    assert!(
                        pos + len <= msg.len(),
                        "field {field_number} payload extends past end: pos={pos} len={len} msg_len={}",
                        msg.len()
                    );
                    fields.push((field_number, wire_type, len));
                    pos += len;
                }
                _ => unreachable!("wire_type checked above"),
            }
        }
        fields
    }

    /// Regression test: encode_proto_response must produce a valid Kubernetes protobuf envelope
    /// for the exact JSON returned by the create_namespace handler (smoke-test scenario).
    ///
    /// This test reproduces the FULL response path:
    ///   1. decode_namespace_proto (decodes kubectl's proto request body to JSON)
    ///   2. handler adds status + resourceVersion
    ///   3. middleware calls encode_proto_response on the JSON
    ///   4. we walk every tag in the Unknown envelope and assert no illegal wire types
    ///
    /// A regression here means `kubectl create namespace smoke-test` would fail with
    /// "proto: illegal wireType N" — the smoke CI gate failure this bead addresses.
    #[test]
    fn encode_proto_response_no_illegal_wire_types_namespace_create() {
        // Reproduce what create_namespace returns after decode_namespace_proto:
        let mut obj_meta = encode_length_delimited(1, b"smoke-test");
        obj_meta.extend_from_slice(&encode_length_delimited(8, &[])); // creationTimestamp (empty Time{})
        let namespace_proto = encode_length_delimited(1, &obj_meta);
        let mut ns_json =
            decode_namespace_proto(&namespace_proto).expect("decode_namespace_proto must succeed");
        ns_json["status"] = serde_json::json!({ "phase": "Active" });
        ns_json["metadata"]["resourceVersion"] = serde_json::Value::String("1".to_string());

        // Simulate the middleware: parse JSON body then re-serialize via encode_proto_response.
        let json_str = ns_json.to_string();
        let val: serde_json::Value = serde_json::from_str(&json_str).expect("round-trip JSON");

        let encoded = encode_proto_response(&val);
        assert_eq!(
            &encoded[..4],
            &[0x6b, 0x38, 0x73, 0x00],
            "must start with k8s proto magic"
        );

        let envelope = &encoded[4..];

        // Walk the Unknown envelope: check top-level fields for illegal wire types.
        let fields = assert_valid_wire_types(envelope);

        // Verify the envelope has the three expected fields.
        let field_numbers: Vec<u64> = fields.iter().map(|(fn_, _, _)| *fn_).collect();
        assert!(
            field_numbers.contains(&1),
            "Unknown envelope must have field 1 (TypeMeta)"
        );
        assert!(
            field_numbers.contains(&2),
            "Unknown envelope must have field 2 (raw JSON)"
        );
        assert!(
            field_numbers.contains(&4),
            "Unknown envelope must have field 4 (contentType)"
        );

        // Also walk the TypeMeta sub-message.
        let type_meta_payload: &[u8] = {
            let mut p = envelope;
            let mut result: &[u8] = &[];
            let mut tmp_pos = 0;
            while tmp_pos < envelope.len() {
                let (tag, rest) = decode_varint(&envelope[tmp_pos..]).expect("valid tag");
                tmp_pos += envelope[tmp_pos..].len() - rest.len();
                let field_number = tag >> 3;
                let wire_type = tag & 0x7;
                if wire_type == 2 {
                    let (len, rest2) = decode_varint(&envelope[tmp_pos..]).expect("valid len");
                    tmp_pos += envelope[tmp_pos..].len() - rest2.len();
                    if field_number == 1 {
                        result = &envelope[tmp_pos..tmp_pos + len as usize];
                        break;
                    }
                    tmp_pos += len as usize;
                }
                p = &p[1..]; // ensure p advances (unused after first iteration)
            }
            result
        };
        let _ = assert_valid_wire_types(type_meta_payload);

        // Verify the encoded body is decodable end-to-end.
        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("envelope raw must be valid JSON");
        assert_eq!(recovered["kind"], "Namespace");
        assert_eq!(recovered["metadata"]["name"], "smoke-test");
        assert_eq!(env.content_type, "application/json");
    }

    /// decode_core_proto_by_kind must dispatch to decode_node_proto for kind="Node".
    /// This is the dispatch fix that ensures extract_body can handle kubelet Node proto bodies.
    #[test]
    fn decode_core_proto_by_kind_dispatches_node() {
        let obj_meta = encode_length_delimited(1, b"test-node");
        let node_proto = encode_length_delimited(1, &obj_meta);

        let result = decode_core_proto_by_kind("Node", &node_proto)
            .expect("Node must decode via decode_core_proto_by_kind");

        assert_eq!(result["kind"], "Node");
        assert_eq!(result["metadata"]["name"], "test-node");
    }

    /// Full round-trip for ConfigMap: kubectl create configmap sends a k8s proto envelope
    /// where Unknown.raw is a proto-encoded ConfigMap and contentType is empty.
    /// This is the regression test for the smoke CI failure on ConfigMap creation.
    #[test]
    fn full_kubectl_create_configmap_smoke_regression() {
        // Build: ObjectMeta { name: "smoke-cm", namespace: "smoke-test" }
        let mut obj_meta = encode_length_delimited(1, b"smoke-cm");
        obj_meta.extend_from_slice(&encode_length_delimited(3, b"smoke-test"));
        obj_meta.extend_from_slice(&encode_length_delimited(8, &[])); // creationTimestamp

        let mut data_entry = encode_length_delimited(1, b"key");
        data_entry.extend_from_slice(&encode_length_delimited(2, b"value"));

        let mut configmap_proto = encode_length_delimited(1, &obj_meta);
        configmap_proto.extend_from_slice(&encode_length_delimited(2, &data_entry));

        // Wrap in k8s Unknown envelope with empty contentType (as kubectl sends)
        let type_meta: Vec<u8> = {
            let mut t = encode_length_delimited(1, b"v1");
            t.extend_from_slice(&encode_length_delimited(2, b"ConfigMap"));
            t
        };
        let mut unknown = encode_length_delimited(1, &type_meta); // TypeMeta
        unknown.extend_from_slice(&encode_length_delimited(2, &configmap_proto)); // raw
                                                                                  // contentType field 4 is absent (empty = kubectl behavior)

        let mut body = K8S_PROTO_MAGIC.to_vec();
        body.extend_from_slice(&unknown);

        let env = decode_k8s_proto_envelope(&body).expect("envelope decode must succeed");
        assert_eq!(env.kind, "ConfigMap");
        assert_eq!(
            env.content_type, "",
            "kubectl sends empty contentType for core types"
        );

        let json = decode_core_proto_by_kind(&env.kind, &env.raw)
            .expect("ConfigMap proto decode must succeed");
        assert_eq!(json["kind"], "ConfigMap");
        assert_eq!(json["metadata"]["name"], "smoke-cm");
        assert_eq!(json["data"]["key"], "value");
    }

    /// encode_proto_response must produce a valid proto envelope for APIVersions
    /// (the /api discovery response). kubectl requests this with Accept: proto
    /// before attempting any resource operations. A wireType 6 in this response
    /// would cause "proto: illegal wireType 6" before kubectl even issues the
    /// namespace create command.
    #[test]
    fn encode_proto_response_no_illegal_wire_types_api_versions() {
        let val = serde_json::json!({
            "kind": "APIVersions",
            "apiVersion": "v1",
            "versions": ["v1"],
            "serverAddressByClientCIDRs": [{
                "clientCIDR": "0.0.0.0/0",
                "serverAddress": "https://127.0.0.1:6443"
            }]
        });

        let encoded = encode_proto_response(&val);
        assert_eq!(&encoded[..4], &[0x6b, 0x38, 0x73, 0x00]);

        let fields = assert_valid_wire_types(&encoded[4..]);
        let field_numbers: Vec<u64> = fields.iter().map(|(fn_, _, _)| *fn_).collect();
        assert!(field_numbers.contains(&1), "TypeMeta field must be present");
        assert!(field_numbers.contains(&2), "raw field must be present");
        assert!(
            field_numbers.contains(&4),
            "contentType field must be present"
        );

        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("raw must be valid JSON");
        assert_eq!(recovered["kind"], "APIVersions");
    }

    /// encode_proto_response must produce a valid proto envelope for APIResourceList
    /// (the /api/v1 discovery response). kubectl fetches this to discover core resources.
    #[test]
    fn encode_proto_response_no_illegal_wire_types_api_resource_list() {
        let val = serde_json::json!({
            "kind": "APIResourceList",
            "apiVersion": "v1",
            "groupVersion": "v1",
            "resources": [
                {
                    "name": "namespaces",
                    "singularName": "namespace",
                    "namespaced": false,
                    "kind": "Namespace",
                    "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]
                },
                {
                    "name": "pods",
                    "singularName": "pod",
                    "namespaced": true,
                    "kind": "Pod",
                    "shortNames": ["po"],
                    "verbs": ["create", "delete", "get", "list", "patch", "update", "watch"]
                }
            ]
        });

        let encoded = encode_proto_response(&val);
        assert_eq!(&encoded[..4], &[0x6b, 0x38, 0x73, 0x00]);
        assert_valid_wire_types(&encoded[4..]);

        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("raw must be valid JSON");
        assert_eq!(recovered["kind"], "APIResourceList");
    }

    /// encode_proto_response must produce a valid proto envelope for APIGroupList
    /// (the /apis discovery response). kubectl fetches this to enumerate all API groups.
    /// This response can be large (11+ groups) and contains slash-containing strings
    /// like "rbac.authorization.k8s.io/v1" which must not produce illegal wire types.
    #[test]
    fn encode_proto_response_no_illegal_wire_types_api_group_list() {
        let val = serde_json::json!({
            "kind": "APIGroupList",
            "apiVersion": "v1",
            "groups": [
                {
                    "name": "admissionregistration.k8s.io",
                    "versions": [{"groupVersion": "admissionregistration.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "admissionregistration.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "apiextensions.k8s.io",
                    "versions": [{"groupVersion": "apiextensions.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "apiextensions.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "apps",
                    "versions": [{"groupVersion": "apps/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"}
                },
                {
                    "name": "authentication.k8s.io",
                    "versions": [{"groupVersion": "authentication.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "authentication.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "authorization.k8s.io",
                    "versions": [{"groupVersion": "authorization.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "authorization.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "coordination.k8s.io",
                    "versions": [{"groupVersion": "coordination.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "coordination.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "networking.k8s.io",
                    "versions": [{"groupVersion": "networking.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "networking.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "node.k8s.io",
                    "versions": [{"groupVersion": "node.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "node.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "policy",
                    "versions": [{"groupVersion": "policy/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "policy/v1", "version": "v1"}
                },
                {
                    "name": "rbac.authorization.k8s.io",
                    "versions": [{"groupVersion": "rbac.authorization.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "rbac.authorization.k8s.io/v1", "version": "v1"}
                },
                {
                    "name": "storage.k8s.io",
                    "versions": [{"groupVersion": "storage.k8s.io/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": "storage.k8s.io/v1", "version": "v1"}
                }
            ]
        });

        let encoded = encode_proto_response(&val);
        assert_eq!(&encoded[..4], &[0x6b, 0x38, 0x73, 0x00]);
        assert_valid_wire_types(&encoded[4..]);

        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("raw must be valid JSON");
        assert_eq!(recovered["kind"], "APIGroupList");
        assert_eq!(
            recovered["groups"].as_array().unwrap().len(),
            11,
            "all 11 groups must be present"
        );
    }

    /// Regression test for mayor-cux: encode_proto_response must produce a valid Kubernetes
    /// protobuf envelope for a realistic Namespace JSON with name, uid, resourceVersion,
    /// creationTimestamp, and labels — the exact fields present in a real `kubectl create
    /// namespace smoke-test` response.
    ///
    /// This test walks EVERY byte of the encoded output, checking that each proto tag has a
    /// legal wire type. It must fail if encode_proto_response produces an illegal wire type,
    /// and must pass after the fix is applied.
    ///
    /// The "proto: illegal wireType 6" CI failure is reproduced when the Go proto decoder
    /// misaligns while reading the Unknown envelope — e.g., due to a wrong length varint that
    /// causes it to stop reading the raw field too early, leaving JSON bytes to be mis-read
    /// as proto tags. ('n' = 0x6E has wire type 6.)
    #[test]
    fn encode_proto_response_no_illegal_wire_types_realistic_namespace() {
        // Build a realistic namespace JSON matching what the server returns after
        // create_namespace: includes uid, resourceVersion, labels, and creationTimestamp.
        let val = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "creationTimestamp": null,
                "labels": {
                    "kubernetes.io/metadata.name": "smoke-test"
                },
                "name": "smoke-test",
                "resourceVersion": "5",
                "uid": "12345678-1234-1234-1234-123456789012"
            },
            "status": {
                "phase": "Active"
            }
        });

        let encoded = encode_proto_response(&val);

        // Must start with k8s proto magic.
        assert_eq!(
            &encoded[..4],
            &[0x6b, 0x38, 0x73, 0x00],
            "must start with k8s proto magic"
        );

        let envelope = &encoded[4..];

        // Walk every tag in the Unknown envelope, asserting no illegal wire types.
        // This is the core of the regression: if any tag byte has wire type 6 (or 3, 4, 7),
        // the Go proto decoder would produce "proto: illegal wireType N".
        let fields = assert_valid_wire_types(envelope);

        // Verify the expected fields are present.
        let field_numbers: Vec<u64> = fields.iter().map(|(fn_, _, _)| *fn_).collect();
        assert!(
            field_numbers.contains(&1),
            "field 1 (TypeMeta) must be in Unknown envelope"
        );
        assert!(
            field_numbers.contains(&2),
            "field 2 (raw JSON) must be in Unknown envelope"
        );
        assert!(
            field_numbers.contains(&4),
            "field 4 (contentType) must be in Unknown envelope"
        );

        // Also walk the TypeMeta sub-message.
        let type_meta_len = fields
            .iter()
            .find(|(fn_, _, _)| *fn_ == 1)
            .map(|(_, _, l)| *l)
            .unwrap();
        let type_meta_start = {
            // field 1 tag byte (1 byte) + len varint (1 byte for len < 128)
            let mut p = 0;
            let (tag, rest) = decode_varint(envelope).unwrap();
            p += envelope.len() - rest.len();
            let (_len, rest2) = decode_varint(rest).unwrap();
            p += rest.len() - rest2.len();
            p
        };
        let type_meta_bytes = &envelope[type_meta_start..type_meta_start + type_meta_len];
        assert_valid_wire_types(type_meta_bytes);

        // Full round-trip: raw field must be valid JSON containing our namespace data.
        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        assert_eq!(env.content_type, "application/json");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("raw field must be valid JSON");
        assert_eq!(recovered["kind"], "Namespace");
        assert_eq!(recovered["metadata"]["name"], "smoke-test");
        assert_eq!(
            recovered["metadata"]["uid"],
            "12345678-1234-1234-1234-123456789012"
        );
        assert_eq!(
            recovered["metadata"]["labels"]["kubernetes.io/metadata.name"],
            "smoke-test"
        );
        assert_eq!(recovered["metadata"]["resourceVersion"], "5");
        assert!(recovered["metadata"]["creationTimestamp"].is_null());
    }

    /// Regression test for mayor-ajtd: encode_proto_response must produce a valid Kubernetes
    /// protobuf envelope for a realistic Node JSON with status conditions and addresses —
    /// the exact response shape the kubelet receives when reading its own node status.
    ///
    /// This test verifies that encode_proto_response itself does NOT produce wireType 7.
    /// The actual kubelet failure ("proto: illegal wireType 7") arises because client-go's
    /// typed Node proto decoder ignores the contentType=application/json field inside the
    /// Unknown envelope and tries to decode Unknown.raw as a typed proto Node. The JSON bytes
    /// (e.g. '/' in CIDRs, 'o' in "conditions") happen to have low 3 bits = 0b111 at the
    /// position the decoder is reading, producing wireType 7. The fix is to not re-encode
    /// Node responses at all (see content_type.rs). This test guards the encoder itself:
    /// the proto envelope we produce is structurally correct even if client-go won't use
    /// the contentType field.
    #[test]
    fn encode_proto_response_no_illegal_wire_types_node_with_status() {
        let val = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": "ci-node",
                "uid": "abc-def-123",
                "resourceVersion": "7",
                "creationTimestamp": "2026-05-21T00:00:00Z"
            },
            "spec": {
                "podCIDR": "10.244.0.0/24",
                "podCIDRs": ["10.244.0.0/24"],
                "providerID": "kind://docker/local/local-worker"
            },
            "status": {
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "True",
                        "lastHeartbeatTime": "2026-05-21T00:01:00Z",
                        "lastTransitionTime": "2026-05-21T00:00:30Z",
                        "reason": "KubeletReady",
                        "message": "kubelet is posting ready status"
                    },
                    {
                        "type": "MemoryPressure",
                        "status": "False",
                        "reason": "KubeletHasSufficientMemory"
                    }
                ],
                "addresses": [
                    {"type": "InternalIP", "address": "192.168.1.10"},
                    {"type": "Hostname", "address": "ci-node"}
                ],
                "nodeInfo": {
                    "machineID": "abc123",
                    "systemUUID": "abc123",
                    "bootID": "xyz",
                    "kernelVersion": "6.1.0",
                    "osImage": "Ubuntu 22.04",
                    "containerRuntimeVersion": "containerd://1.7.0",
                    "kubeletVersion": "v1.36.0",
                    "kubeProxyVersion": "v1.36.0",
                    "operatingSystem": "linux",
                    "architecture": "amd64"
                }
            }
        });

        let encoded = encode_proto_response(&val);
        assert_eq!(
            &encoded[..4],
            &[0x6b, 0x38, 0x73, 0x00],
            "must start with k8s proto magic"
        );

        // Walk every tag in the Unknown envelope: no wireType 7 (or 3, 4, 6) allowed.
        // wireType 7 = 0b111 in low 3 bits; any such byte as a proto tag is illegal.
        let fields = assert_valid_wire_types(&encoded[4..]);

        let field_numbers: Vec<u64> = fields.iter().map(|(fn_, _, _)| *fn_).collect();
        assert!(field_numbers.contains(&1), "TypeMeta field must be present");
        assert!(
            field_numbers.contains(&2),
            "raw Node JSON field must be present"
        );
        assert!(
            field_numbers.contains(&4),
            "contentType field must be present"
        );

        // The envelope must be decodable and the raw field must be valid JSON.
        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        assert_eq!(env.content_type, "application/json");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("raw field must be valid JSON");
        assert_eq!(recovered["kind"], "Node");
        assert_eq!(recovered["metadata"]["name"], "ci-node");
        assert_eq!(recovered["spec"]["podCIDR"], "10.244.0.0/24");
        assert_eq!(recovered["status"]["conditions"][0]["type"], "Ready");
        assert_eq!(recovered["status"]["conditions"][0]["status"], "True");
        assert_eq!(
            recovered["status"]["addresses"][0]["address"],
            "192.168.1.10"
        );
    }

    /// encode_proto_response must produce a valid proto envelope for the /version response.
    /// This JSON has no apiVersion or kind fields, resulting in empty TypeMeta strings.
    /// Empty strings still produce valid LEN-encoded fields with zero-length payloads.
    #[test]
    fn encode_proto_response_no_illegal_wire_types_server_version() {
        let val = serde_json::json!({
            "major": "1",
            "minor": "36",
            "gitVersion": "v1.36.0",
            "gitCommit": "0000000000000000000000000000000000000000",
            "gitTreeState": "clean",
            "buildDate": "1970-01-01T00:00:00Z",
            "goVersion": "go1.24.0",
            "compiler": "gc",
            "platform": "linux/amd64"
        });

        let encoded = encode_proto_response(&val);
        assert_eq!(&encoded[..4], &[0x6b, 0x38, 0x73, 0x00]);
        assert_valid_wire_types(&encoded[4..]);

        let env = decode_k8s_proto_envelope(&encoded).expect("must decode as k8s envelope");
        let recovered: serde_json::Value =
            serde_json::from_slice(&env.raw).expect("raw must be valid JSON");
        assert_eq!(recovered["gitVersion"], "v1.36.0");
    }
}
