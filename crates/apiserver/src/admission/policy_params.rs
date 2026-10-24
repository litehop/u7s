//! Parameter resolution (`paramKind` / `paramRef`) and the request-user authorizer shared by
//! ValidatingAdmissionPolicy and MutatingAdmissionPolicy evaluation.

use std::collections::BTreeMap;

use serde::Deserialize;
use u7s_store::{ListOptions, Store};

#[cfg(test)]
mod tests;

use super::{label_selector_matches, LabelSelector};
use crate::cel_runtime::{AuthorizeFn, AuthzAttributes, AuthzDecision, AuthzPrincipal};
use crate::handlers::discovery::resolve_kind_resource;
use crate::keys::{group_list_prefix, group_object_key};
use crate::node_authz::{self, NodeGraph};
use crate::rbac::{AuthzRequest, RbacIndex};
use crate::state::AppState;

/// The params to evaluate a policy-binding pair against: `[None]` when the pair takes no
/// params, one entry per matched param object otherwise, and none when no param was found and
/// the binding's `parameterNotFoundAction` is not `Deny`.
///
/// The `Err` text is the configuration error; callers apply the policy's `failurePolicy`.
pub(super) async fn collect_params<S: Store>(
    state: &AppState<S>,
    policy: &serde_json::Value,
    binding: &serde_json::Value,
    request_namespace: Option<&str>,
) -> Result<Vec<Option<serde_json::Value>>, String> {
    let param_kind = &policy["spec"]["paramKind"];
    let param_ref = &binding["spec"]["paramRef"];
    if !param_kind.is_object() || !param_ref.is_object() {
        return Ok(vec![None]);
    }

    let api_version = param_kind["apiVersion"].as_str().unwrap_or("");
    let kind = param_kind["kind"].as_str().unwrap_or("");
    let (group, version) = api_version.split_once('/').unwrap_or(("", api_version));
    let Some((plural, namespaced)) = resolve_kind_resource(state, group, version, kind).await
    else {
        return Err(format!(
            "paramKind kind `&ParamKind{{APIVersion:{api_version},Kind:{kind},}}` not known"
        ));
    };

    let ref_namespace = param_ref["namespace"].as_str().unwrap_or("");
    let namespace = if namespaced {
        let ns = if ref_namespace.is_empty() {
            request_namespace.unwrap_or("")
        } else {
            ref_namespace
        };
        if ns.is_empty() {
            return Err(
                "cannot use namespaced paramRef in policy binding that matches \
                        cluster-scoped resources"
                    .into(),
            );
        }
        Some(ns)
    } else if !ref_namespace.is_empty() {
        return Err(
            "paramRef.namespace must not be provided for a cluster-scoped `paramKind`".into(),
        );
    } else {
        None
    };

    let name = param_ref["name"].as_str().unwrap_or("");
    let found = if !name.is_empty() {
        if param_ref["selector"].is_object() {
            return Err("paramRef.name and paramRef.selector are mutually exclusive".into());
        }
        let key = group_object_key(group, &plural, namespace, name);
        match state.store.get(&key).await.map_err(|e| e.to_string())? {
            Some(obj) => vec![serde_json::from_slice(&obj.value).map_err(|e| e.to_string())?],
            None => vec![],
        }
    } else if param_ref["selector"].is_object() {
        let selector =
            LabelSelector::deserialize(&param_ref["selector"]).map_err(|e| e.to_string())?;
        let listed = state
            .store
            .list(
                &group_list_prefix(group, &plural, namespace),
                ListOptions::default(),
            )
            .await
            .map_err(|e| e.to_string())?;
        let mut matched = Vec::new();
        for item in listed.items {
            let obj: serde_json::Value =
                serde_json::from_slice(&item.value).map_err(|e| e.to_string())?;
            if label_selector_matches(Some(&selector), &labels_of(&obj)) {
                matched.push(obj);
            }
        }
        matched
    } else {
        return Err("one of name or selector must be provided".into());
    };

    if found.is_empty() && param_ref["parameterNotFoundAction"].as_str() == Some("Deny") {
        return Err(
            "no params found for policy binding with `Deny` parameterNotFoundAction".into(),
        );
    }
    Ok(found.into_iter().map(Some).collect())
}

fn labels_of(obj: &serde_json::Value) -> BTreeMap<String, String> {
    obj["metadata"]["labels"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// The `Forbidden` message for a policy-binding pair that could not be configured.
pub(super) fn config_error_message(policy: &str, binding: &str, err: &str) -> String {
    format!(
        "policy '{policy}' with binding '{binding}' denied request: failed to configure \
         binding: {err}"
    )
}

/// The authenticated user a CEL `authorizer` check is made for.
pub(super) struct RequestUser {
    username: String,
    groups: Vec<String>,
}

impl RequestUser {
    pub(super) fn from_user_info(user_info: Option<&serde_json::Value>) -> Self {
        let username = user_info
            .and_then(|u| u["username"].as_str())
            .unwrap_or("")
            .to_string();
        let groups = user_info
            .and_then(|u| u["groups"].as_array())
            .map(|g| {
                g.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        RequestUser { username, groups }
    }
}

fn non_empty(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

/// An `authorizer` backend over the same Node and RBAC authorizers that gate requests.
pub(super) fn authorizer<'a>(
    rbac: &'a RbacIndex,
    graph: &'a NodeGraph,
    user: &'a RequestUser,
) -> AuthorizeFn<'a> {
    Box::new(move |principal: &AuthzPrincipal, attrs: &AuthzAttributes| {
        let sa_username;
        let sa_groups;
        let (username, groups) = match principal {
            None => (user.username.as_str(), user.groups.as_slice()),
            Some((ns, name)) => {
                sa_username = format!("system:serviceaccount:{ns}:{name}");
                sa_groups = vec![
                    "system:serviceaccounts".to_string(),
                    format!("system:serviceaccounts:{ns}"),
                ];
                (sa_username.as_str(), sa_groups.as_slice())
            }
        };
        let path = attrs.path.as_deref().map(|p| {
            if p.starts_with('/') {
                p.to_string()
            } else {
                format!("/{p}")
            }
        });
        let req = AuthzRequest {
            username,
            groups,
            verb: &attrs.verb,
            api_group: &attrs.group,
            resource: &attrs.resource,
            subresource: &attrs.subresource,
            namespace: non_empty(&attrs.namespace),
            name: non_empty(&attrs.name),
            non_resource_url: path.as_deref(),
        };
        let allowed = node_authz::authorize(&req, None, graph, rbac) || rbac.is_allowed(&req);
        AuthzDecision {
            allowed,
            reason: if allowed {
                "allowed".into()
            } else {
                String::new()
            },
            error: None,
        }
    })
}
