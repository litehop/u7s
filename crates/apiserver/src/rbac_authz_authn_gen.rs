#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::tabs_in_doc_comments)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(dead_code)]

pub mod k8s {
    pub mod io {
        pub mod apimachinery {
            pub mod pkg {
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
            }
        }
        pub mod api {
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
        }
    }
}
