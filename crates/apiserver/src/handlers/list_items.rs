//! The per-item LIST pipeline shared by every response encoding: decide membership, apply
//! read-time defaults, hand back the survivors one at a time.
//!
//! Membership is decided from the stored bytes through the watch path's `SelectorProjection`
//! (labels plus the handful of field-selector labels it carries) before any full parse, so an
//! item a selector excludes costs one skim instead of a `Value` tree. The projection answers
//! "excluded", "included" or "don't know"; "don't know" falls through to the full parse, which
//! checks the real matchers after defaulting.
//!
//! An included item whose kind has no read-time defaults is served as its stored bytes. The
//! store writes every object as `serde_json::to_vec` of a `Value` (it re-serializes on every
//! put), so those bytes are exactly what parsing and re-serializing would produce.
//!
//! Every response encoding consumes the survivors one item at a time: a LIST's peak memory is
//! dominated by how many parsed `Value` trees are alive at once, so only the encoded output
//! (and, for a Table, its small rows) is ever held in full.

use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::Value;

use super::field_selector::FieldSelector;
use super::generic::{
    build_list_response, item_matches_label_terms, label_terms_match, LabelSelectorTerm,
};
use super::watch::SelectorProjection;
use crate::content_type::ProtobufListBuilder;
use crate::status::{Status, StatusError};

pub(crate) struct ListFilter<'a> {
    group: &'a str,
    plural: &'a str,
    terms: &'a [LabelSelectorTerm<'a>],
    field_selector: &'a FieldSelector,
    on_item: Option<fn(&Value)>,
}

/// A surviving item: its stored bytes when no parse was needed, else the defaulted object.
pub(crate) enum Selected<'a> {
    Raw(&'a [u8]),
    Parsed(Value),
}

impl Selected<'_> {
    pub(crate) fn into_value(self) -> Result<Value, StatusError> {
        match self {
            Selected::Parsed(v) => Ok(v),
            Selected::Raw(raw) => {
                serde_json::from_slice(raw).map_err(|e| Status::internal(e.to_string()))
            }
        }
    }
}

enum Membership {
    Excluded,
    Included,
    Unknown,
}

/// How a LIST is encoded when the client asked for something other than plain JSON.
#[derive(Clone)]
pub(crate) enum ListFormat {
    PartialObjectMetadata,
    Table { api_version: String },
    Protobuf,
}

impl ListFormat {
    /// `None` means a plain JSON LIST. Protobuf only counts for kinds with a registered
    /// encoder: clients send `protobuf, json` on every request and get JSON for the rest.
    pub(crate) fn negotiate(
        accept: &str,
        pom: bool,
        table: bool,
        group: &str,
        version: &str,
        kind: &str,
    ) -> Option<Self> {
        if pom {
            return Some(Self::PartialObjectMetadata);
        }
        if table {
            return Some(Self::Table {
                api_version: super::table::table_api_version(accept),
            });
        }
        let api_version = if group.is_empty() {
            version.to_string()
        } else {
            format!("{group}/{version}")
        };
        (crate::content_type::wants_protobuf(accept)
            && crate::content_type::has_encoder(&api_version, &format!("{kind}List")))
        .then_some(Self::Protobuf)
    }
}

/// Everything about a LIST response that is not an item: the list's identity and paging state.
pub(crate) struct ListEnvelope<'a> {
    pub kind: &'a str,
    pub version: &'a str,
    pub revision: u64,
    pub continue_key: Option<String>,
    pub remaining_count: Option<u64>,
    pub signing_key: &'a [u8; 32],
}

impl<'a> ListFilter<'a> {
    pub(crate) fn new(
        group: &'a str,
        plural: &'a str,
        terms: &'a [LabelSelectorTerm<'a>],
        field_selector: &'a FieldSelector,
        on_item: Option<fn(&Value)>,
    ) -> Self {
        Self {
            group,
            plural,
            terms,
            field_selector,
            on_item,
        }
    }

    /// Decides from the stored bytes alone. Always `Unknown` for kinds whose read-time defaults
    /// rewrite `metadata.labels`, where the raw labels are not what LIST matches against.
    fn membership(&self, raw: &[u8]) -> Membership {
        if self.terms.is_empty() && self.field_selector.is_empty() {
            return Membership::Included;
        }
        if super::defaults::defaults_may_alter_labels(self.group, self.plural) {
            return Membership::Unknown;
        }
        let Ok(projection) = serde_json::from_slice::<SelectorProjection>(raw) else {
            return Membership::Unknown;
        };
        let labels = &projection.metadata.labels;
        if !label_terms_match(
            self.terms,
            |key| labels.contains_key(key),
            |key| labels.get(key).copied(),
        ) {
            return Membership::Excluded;
        }
        if self.field_selector.is_empty() {
            return Membership::Included;
        }
        match projection.field_selector_verdict(self.field_selector) {
            Some(true) => Membership::Included,
            Some(false) => Membership::Excluded,
            None => Membership::Unknown,
        }
    }

    /// Whether a surviving item must be parsed: defaults could change it, or `on_item` reads it.
    fn needs_parsed_survivor(&self, raw: &[u8]) -> bool {
        self.on_item.is_some() || super::defaults::defaults_may_change(self.group, self.plural, raw)
    }

    /// Filters one stored object; `None` when a selector excludes it.
    pub(crate) fn select<'r>(&self, raw: &'r [u8]) -> Result<Option<Selected<'r>>, StatusError> {
        match self.membership(raw) {
            Membership::Excluded => return Ok(None),
            Membership::Included if !self.needs_parsed_survivor(raw) => {
                return Ok(Some(Selected::Raw(raw)));
            }
            Membership::Included | Membership::Unknown => {}
        }
        let mut item: Value =
            serde_json::from_slice(raw).map_err(|e| Status::internal(e.to_string()))?;
        super::defaults::apply_defaults(self.group, self.plural, &mut item);
        if !item_matches_label_terms(&item, self.terms) || !self.field_selector.matches(&item) {
            return Ok(None);
        }
        if let Some(f) = self.on_item {
            f(&item);
        }
        Ok(Some(Selected::Parsed(item)))
    }

    /// Hands `consume` the surviving items as parsed values, one alive at a time. A stored
    /// object that fails to parse ends the iteration and is reported instead of `consume`'s
    /// result.
    fn with_values<T>(
        &self,
        raw_items: &[u7s_store::StoreObject],
        consume: impl FnOnce(&mut dyn Iterator<Item = Value>) -> T,
    ) -> Result<T, StatusError> {
        let mut failure = None;
        let out = {
            let mut values = raw_items
                .iter()
                .filter_map(|obj| {
                    self.select(&obj.value)
                        .and_then(|s| s.map(Selected::into_value).transpose())
                        .transpose()
                })
                .map_while(|r| r.map_err(|e| failure = Some(e)).ok());
            consume(&mut values)
        };
        failure.map_or(Ok(out), Err)
    }

    /// The JSON body: the envelope as `build_list_response` shapes it with an empty items array,
    /// with the survivors spliced into the one place that placeholder appears, so it cannot
    /// drift from that function's byte-for-byte-tested envelope.
    pub(crate) fn render_json(
        &self,
        raw_items: &[u7s_store::StoreObject],
        env: ListEnvelope<'_>,
    ) -> Result<Vec<u8>, StatusError> {
        let envelope = build_list_response(
            env.kind,
            self.group,
            env.version,
            env.revision,
            Vec::new(),
            env.continue_key,
            env.remaining_count,
            env.signing_key,
        );
        let envelope_bytes =
            serde_json::to_vec(&envelope).map_err(|e| Status::internal(e.to_string()))?;
        let marker = b"\"items\":[]";
        let marker_pos = envelope_bytes
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("build_list_response always emits an empty items array for an empty items Vec");

        let mut body = Vec::with_capacity(
            envelope_bytes.len() + raw_items.iter().map(|o| o.value.len() + 1).sum::<usize>(),
        );
        body.extend_from_slice(&envelope_bytes[..marker_pos]);
        body.extend_from_slice(b"\"items\":[");
        let mut wrote_item = false;
        for obj in raw_items {
            let Some(item) = self.select(&obj.value)? else {
                continue;
            };
            if wrote_item {
                body.push(b',');
            }
            wrote_item = true;
            match item {
                Selected::Raw(raw) => body.extend_from_slice(raw),
                Selected::Parsed(item) => serde_json::to_writer(&mut body, &item)
                    .map_err(|e| Status::internal(e.to_string()))?,
            }
        }
        body.push(b']');
        body.extend_from_slice(&envelope_bytes[marker_pos + marker.len()..]);
        Ok(body)
    }

    pub(crate) fn respond(
        &self,
        format: Option<ListFormat>,
        raw_items: &[u7s_store::StoreObject],
        env: ListEnvelope<'_>,
    ) -> Result<Response, StatusError> {
        let revision = env.revision;
        match format {
            None => {
                let body = self.render_json(raw_items, env)?;
                Ok((
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    body,
                )
                    .into_response())
            }
            Some(ListFormat::PartialObjectMetadata) => {
                let items = self.with_values(raw_items, |values| {
                    values
                        .map(|v| super::watch::to_partial_object_metadata(&v))
                        .collect::<Vec<_>>()
                })?;
                Ok(Json(serde_json::json!({
                    "apiVersion": "meta.k8s.io/v1",
                    "kind": "PartialObjectMetadataList",
                    "metadata": { "resourceVersion": revision.to_string() },
                    "items": items
                }))
                .into_response())
            }
            Some(ListFormat::Table { api_version }) => {
                let continue_token = env
                    .continue_key
                    .map(|key| super::generic::encode_continue(&key, revision, env.signing_key));
                let built = self.with_values(raw_items, |values| {
                    super::table::build_table(self.group, self.plural, values)
                })?;
                Ok(Json(super::table::finalize_table(
                    built,
                    &api_version,
                    Some(&revision.to_string()),
                    continue_token,
                ))
                .into_response())
            }
            Some(ListFormat::Protobuf) => {
                let envelope = build_list_response(
                    env.kind,
                    self.group,
                    env.version,
                    revision,
                    Vec::new(),
                    env.continue_key,
                    env.remaining_count,
                    env.signing_key,
                );
                let encoded_size_hint = raw_items.iter().map(|o| o.value.len()).sum::<usize>() / 2;
                let mut builder = ProtobufListBuilder::new(&envelope, encoded_size_hint)
                    .expect("ListFormat::negotiate only picks Protobuf for kinds with an encoder");
                self.with_values(raw_items, |values| values.for_each(|v| builder.push(&v)))?;
                Ok(builder.finish())
            }
        }
    }
}

#[cfg(test)]
#[path = "list_items_tests.rs"]
mod tests;
