//! The per-item LIST pipeline shared by every response encoding: decide membership, apply
//! read-time defaults, hand back the survivors one at a time.
//!
//! Membership is decided from the stored bytes through the watch path's `SelectorProjection`
//! (labels plus the handful of field-selector labels it carries) before any full parse, so an
//! item a selector excludes costs one skim instead of a `Value` tree. The projection only ever
//! answers "definitely excluded" or "don't know"; the full object is still checked against the
//! real matchers after defaulting.

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

    /// `true` only when the stored bytes definitely fail the selectors. Skipped for kinds whose
    /// read-time defaults rewrite `metadata.labels`, where the raw labels are not what LIST
    /// matches against.
    fn definitely_excluded(&self, raw: &[u8]) -> bool {
        if (self.terms.is_empty() && self.field_selector.is_empty())
            || super::defaults::defaults_may_alter_labels(self.group, self.plural)
        {
            return false;
        }
        let Ok(projection) = serde_json::from_slice::<SelectorProjection>(raw) else {
            return false;
        };
        let labels = &projection.metadata.labels;
        !label_terms_match(
            self.terms,
            |key| labels.contains_key(key),
            |key| labels.get(key).copied(),
        ) || (!self.field_selector.is_empty()
            && projection.field_selector_verdict(self.field_selector) == Some(false))
    }

    /// Parses, defaults and filters one stored object; `None` when a selector excludes it.
    pub(crate) fn select(&self, raw: &[u8]) -> Result<Option<Value>, StatusError> {
        if self.definitely_excluded(raw) {
            return Ok(None);
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
        Ok(Some(item))
    }

    pub(crate) fn select_all(
        &self,
        raw_items: &[u7s_store::StoreObject],
    ) -> Result<Vec<Value>, StatusError> {
        let mut items = Vec::new();
        for obj in raw_items {
            items.extend(self.select(&obj.value)?);
        }
        Ok(items)
    }
}

#[cfg(test)]
#[path = "list_items_tests.rs"]
mod tests;
