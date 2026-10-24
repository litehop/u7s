//! The Kubernetes CEL `authorizer` library: `authorizer.group(g).resource(r).namespace(n)
//! .name(n).check(verb).allowed()` and its path and service-account variants.

use std::sync::Arc;

use super::format::{is_dns1123_label, is_dns1123_subdomain};
use super::interp::Evaluator;
use super::value::{CelError, Value, R};

type V<'a> = Value<'a>;

/// The principal a check is made for: `None` is the request's user, `Some((namespace,
/// name))` a service account named through `authorizer.serviceAccount`.
pub(crate) type Principal = Option<(String, String)>;

/// One authorization question, as the library builds it.
#[derive(Clone, Debug, Default)]
pub(crate) struct Attributes {
    pub(crate) verb: String,
    /// `Some` for a non-resource (`authorizer.path`) check.
    pub(crate) path: Option<String>,
    pub(crate) group: String,
    pub(crate) resource: String,
    pub(crate) subresource: String,
    pub(crate) namespace: String,
    pub(crate) name: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Decision {
    pub(crate) allowed: bool,
    pub(crate) reason: String,
    pub(crate) error: Option<String>,
}

/// Answers an [`Attributes`] question for a principal.
pub(crate) type AuthorizeFn<'a> = Box<dyn Fn(&Principal, &Attributes) -> Decision + 'a>;

#[derive(Clone, Debug)]
pub(crate) struct ResourceCheck {
    principal: Principal,
    group: String,
    resource: String,
    subresource: String,
    namespace: String,
    name: String,
}

#[derive(Clone, Debug)]
pub(crate) enum Authz {
    Authorizer {
        principal: Principal,
        /// `authorizer.requestResource`: the resource under admission, checked for the
        /// request's user. Only the `authorizer` root carries it.
        request_resource: Option<ResourceCheck>,
    },
    PathCheck {
        principal: Principal,
        path: String,
    },
    GroupCheck {
        principal: Principal,
        group: String,
    },
    ResourceCheck(ResourceCheck),
    Decision(Decision),
}

/// The resource a request addresses, as `authorizer.requestResource` exposes it.
#[derive(Clone, Debug, Default)]
pub(crate) struct RequestResource {
    pub(crate) group: String,
    pub(crate) resource: String,
    pub(crate) subresource: String,
    pub(crate) namespace: String,
    pub(crate) name: String,
}

/// The `authorizer` root value.
pub(crate) fn root<'a>(request: RequestResource) -> V<'a> {
    V::Authz(Arc::new(Authz::Authorizer {
        principal: None,
        request_resource: Some(ResourceCheck {
            principal: None,
            group: request.group,
            resource: request.resource,
            subresource: request.subresource,
            namespace: request.namespace,
            name: request.name,
        }),
    }))
}

impl Authz {
    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Authz::Authorizer { .. } => "kubernetes.authorization.Authorizer",
            Authz::PathCheck { .. } => "kubernetes.authorization.PathCheck",
            Authz::GroupCheck { .. } => "kubernetes.authorization.GroupCheck",
            Authz::ResourceCheck(_) => "kubernetes.authorization.ResourceCheck",
            Authz::Decision(_) => "kubernetes.authorization.Decision",
        }
    }

    /// `authorizer.requestResource` is a variable of its own upstream; here it is a field of
    /// the root `authorizer` value.
    pub(crate) fn select<'a>(&self, field: &str) -> Option<V<'a>> {
        match (self, field) {
            (
                Authz::Authorizer {
                    request_resource: Some(r),
                    ..
                },
                "requestResource",
            ) => Some(wrap(Authz::ResourceCheck(r.clone()))),
            _ => None,
        }
    }
}

fn wrap<'a>(a: Authz) -> V<'a> {
    V::Authz(Arc::new(a))
}

fn err<'a>(msg: &str) -> R<V<'a>> {
    Err(CelError::new(msg))
}

impl ResourceCheck {
    fn with(&self, f: impl FnOnce(&mut ResourceCheck)) -> ResourceCheck {
        let mut next = self.clone();
        f(&mut next);
        next
    }
}

pub(crate) fn call_method<'a>(
    ev: &Evaluator<'a, '_>,
    name: &str,
    recv: &V<'a>,
    args: &[V<'a>],
) -> Option<R<V<'a>>> {
    let V::Authz(a) = recv else { return None };
    Some(match (&**a, name, args) {
        (Authz::Authorizer { principal, .. }, "path", [V::Str(p)]) => {
            if p.trim().is_empty() {
                err("path must not be empty")
            } else {
                Ok(wrap(Authz::PathCheck {
                    principal: principal.clone(),
                    path: p.to_string(),
                }))
            }
        }
        (Authz::Authorizer { principal, .. }, "group", [V::Str(g)]) => {
            Ok(wrap(Authz::GroupCheck {
                principal: principal.clone(),
                group: g.to_string(),
            }))
        }
        (Authz::Authorizer { .. }, "serviceAccount", [V::Str(ns), V::Str(sa)]) => {
            if !is_dns1123_subdomain(sa).is_empty() {
                err("Invalid service account name")
            } else if !is_dns1123_label(ns).is_empty() {
                err("Invalid service account namespace")
            } else {
                Ok(wrap(Authz::Authorizer {
                    principal: Some((ns.to_string(), sa.to_string())),
                    request_resource: None,
                }))
            }
        }
        (Authz::GroupCheck { principal, group }, "resource", [V::Str(r)]) => {
            if r.trim().is_empty() {
                err("resource must not be empty")
            } else {
                Ok(wrap(Authz::ResourceCheck(ResourceCheck {
                    principal: principal.clone(),
                    group: group.clone(),
                    resource: r.to_string(),
                    subresource: String::new(),
                    namespace: String::new(),
                    name: String::new(),
                })))
            }
        }
        (Authz::ResourceCheck(r), "subresource", [V::Str(s)]) => Ok(wrap(Authz::ResourceCheck(
            r.with(|r| r.subresource = s.to_string()),
        ))),
        (Authz::ResourceCheck(r), "namespace", [V::Str(s)]) => Ok(wrap(Authz::ResourceCheck(
            r.with(|r| r.namespace = s.to_string()),
        ))),
        (Authz::ResourceCheck(r), "name", [V::Str(s)]) => Ok(wrap(Authz::ResourceCheck(
            r.with(|r| r.name = s.to_string()),
        ))),
        (Authz::PathCheck { principal, path }, "check", [V::Str(verb)]) => {
            Ok(decision(ev.authorize(
                principal,
                &Attributes {
                    verb: verb.to_string(),
                    path: Some(path.clone()),
                    ..Attributes::default()
                },
            )))
        }
        (Authz::ResourceCheck(r), "check", [V::Str(verb)]) => Ok(decision(ev.authorize(
            &r.principal,
            &Attributes {
                verb: verb.to_string(),
                path: None,
                group: r.group.clone(),
                resource: r.resource.clone(),
                subresource: r.subresource.clone(),
                namespace: r.namespace.clone(),
                name: r.name.clone(),
            },
        ))),
        (Authz::Decision(d), "allowed", []) => Ok(V::Bool(d.allowed)),
        (Authz::Decision(d), "reason", []) => Ok(V::str(&d.reason)),
        (Authz::Decision(d), "errored", []) => Ok(V::Bool(d.error.is_some())),
        (Authz::Decision(d), "error", []) => Ok(V::str(d.error.as_deref().unwrap_or(""))),
        _ => Err(CelError::overload()),
    })
}

fn decision<'a>(d: Decision) -> V<'a> {
    wrap(Authz::Decision(d))
}
