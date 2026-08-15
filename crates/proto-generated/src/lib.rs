//! prost-generated Kubernetes API types, compiled from the vendored `.proto` schemas exactly
//! once.
//!
//! `u7s-apiserver` used to `include!()` these same generated `.rs` files independently from 8
//! hand-written wrapper modules (`apps_gen`, `admissionreg_gen`, ...), each producing its own
//! nominally-distinct copy of every type it touched (`ObjectMeta`, and for three of those
//! wrappers even `core::v1` itself) despite the underlying struct source being byte-identical —
//! duplicating both compiled code size and the JSON-conversion helpers built on top of it. This
//! crate is now the single source of truth: `u7s-apiserver`'s wrapper modules re-export this
//! crate's `k8s` tree instead of re-including the generated source, so every package's types are
//! one Rust type crate-wide.
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::tabs_in_doc_comments)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(dead_code)]

/// The `FileDescriptorSet` protoc emits alongside the generated structs (see `build.rs`).
/// `u7s-apiserver` depends on this crate as a build-dependency to derive its own
/// `object_reference_gen.rs`/etc. codecs (`build/codegen.rs`) and, at test time, its
/// sentinel-completeness oracle (`proto_descriptor.rs`) from the same bytes, instead of
/// hand-maintaining expected-JSON-key lists that could drift from what the decoders actually do.
pub static DESCRIPTOR_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/k8s_descriptors.bin"));

pub mod k8s {
    pub mod io {
        pub mod apimachinery {
            pub mod pkg {
                pub mod api {
                    pub mod resource {
                        include!(concat!(
                            env!("OUT_DIR"),
                            "/k8s.io.apimachinery.pkg.api.resource.rs"
                        ));
                    }
                }
                pub mod apis {
                    pub mod meta {
                        pub mod v1 {
                            include!(concat!(
                                env!("OUT_DIR"),
                                "/k8s.io.apimachinery.pkg.apis.meta.v1.rs"
                            ));
                        }
                    }
                }
                pub mod runtime {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/k8s.io.apimachinery.pkg.runtime.rs"
                    ));
                }
                pub mod util {
                    pub mod intstr {
                        include!(concat!(
                            env!("OUT_DIR"),
                            "/k8s.io.apimachinery.pkg.util.intstr.rs"
                        ));
                    }
                }
            }
        }
        pub mod api {
            pub mod core {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.core.v1.rs"));
                }
            }
            pub mod apps {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.apps.v1.rs"));
                }
            }
            pub mod batch {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.batch.v1.rs"));
                }
            }
            pub mod autoscaling {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.autoscaling.v1.rs"));
                }
                pub mod v2 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.autoscaling.v2.rs"));
                }
            }
            pub mod resource {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.resource.v1.rs"));
                }
            }
            pub mod admissionregistration {
                pub mod v1 {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/k8s.io.api.admissionregistration.v1.rs"
                    ));
                }
            }
            pub mod rbac {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.rbac.v1.rs"));
                }
            }
            pub mod authentication {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.authentication.v1.rs"));
                }
            }
            pub mod authorization {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.authorization.v1.rs"));
                }
            }
            pub mod coordination {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.coordination.v1.rs"));
                }
            }
            pub mod storage {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.storage.v1.rs"));
                }
            }
            pub mod node {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.node.v1.rs"));
                }
            }
            pub mod flowcontrol {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.flowcontrol.v1.rs"));
                }
            }
            pub mod scheduling {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.scheduling.v1.rs"));
                }
            }
            pub mod networking {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.networking.v1.rs"));
                }
            }
            pub mod discovery {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.discovery.v1.rs"));
                }
            }
            pub mod certificates {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.certificates.v1.rs"));
                }
            }
            pub mod policy {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.policy.v1.rs"));
                }
            }
            pub mod events {
                pub mod v1 {
                    include!(concat!(env!("OUT_DIR"), "/k8s.io.api.events.v1.rs"));
                }
            }
        }
        pub mod apiextensions_apiserver {
            pub mod pkg {
                pub mod apis {
                    pub mod apiextensions {
                        pub mod v1 {
                            include!(concat!(
                                env!("OUT_DIR"),
                                "/k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1.rs"
                            ));
                        }
                    }
                }
            }
        }
        pub mod kube_aggregator {
            pub mod pkg {
                pub mod apis {
                    pub mod apiregistration {
                        pub mod v1 {
                            include!(concat!(
                                env!("OUT_DIR"),
                                "/k8s.io.kube_aggregator.pkg.apis.apiregistration.v1.rs"
                            ));
                        }
                    }
                }
            }
        }
    }
}
