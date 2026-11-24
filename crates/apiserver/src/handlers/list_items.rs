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

use serde_json::Value;

use super::field_selector::FieldSelector;
use super::generic::{item_matches_label_terms, label_terms_match, LabelSelectorTerm};
use super::watch::SelectorProjection;
use crate::status::{Status, StatusError};

pub(crate) struct ListFilter<'a> {
    group: &'a str,
    plural: &'a str,
    terms: &'a [LabelSelectorTerm<'a>],
    field_selector: &'a FieldSelector,
    on_item: Option<fn(&Value)>,
    /// Whether a surviving item must be parsed: its kind has defaults, or `on_item` reads it.
    parse_survivors: bool,
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
            parse_survivors: on_item.is_some() || super::defaults::defaults_apply(group, plural),
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

    /// Filters one stored object; `None` when a selector excludes it.
    pub(crate) fn select<'r>(&self, raw: &'r [u8]) -> Result<Option<Selected<'r>>, StatusError> {
        match self.membership(raw) {
            Membership::Excluded => return Ok(None),
            Membership::Included if !self.parse_survivors => {
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

    pub(crate) fn select_all(
        &self,
        raw_items: &[u7s_store::StoreObject],
    ) -> Result<Vec<Value>, StatusError> {
        let mut items = Vec::new();
        for obj in raw_items {
            if let Some(selected) = self.select(&obj.value)? {
                items.push(selected.into_value()?);
            }
        }
        Ok(items)
    }
}

#[cfg(test)]
#[path = "list_items_tests.rs"]
mod tests;
