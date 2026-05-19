//! Kubernetes protobuf wire format decoder.
//!
//! kubectl sends write requests with `Content-Type: application/vnd.kubernetes.protobuf` by
//! default. The encoding is NOT standard protobuf alone — it uses a 4-byte magic prefix followed
//! by a protobuf-encoded `Unknown` envelope whose `raw` field (field 2) contains the actual object
//! (usually JSON). We decode only what we need: the `raw` bytes, then hand them to the existing
//! JSON parser.
//!
//! Wire format:
//!   [4 bytes magic: 0x6b, 0x38, 0x73, 0x00]
//!   [protobuf-encoded Unknown message]
//!
//! Unknown fields (from k8s.io/apimachinery/pkg/runtime/generated.proto):
//!   field 1 (TypeMeta, wire type 2):  tag = 0x0a
//!   field 2 (raw bytes, wire type 2): tag = 0x12  <- we want this
//!   field 3 (contentEncoding, wire 2): tag = 0x1a
//!   field 4 (contentType, wire 2):    tag = 0x22

const K8S_PROTO_MAGIC: &[u8; 4] = &[0x6b, 0x38, 0x73, 0x00];

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

    // ---------------------------------------------------------------------------
    // Tests
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
}
