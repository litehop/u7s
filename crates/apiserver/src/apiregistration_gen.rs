#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::tabs_in_doc_comments)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(dead_code)]

pub mod k8s {
    pub mod io {
        pub mod apimachinery {
            pub mod pkg {
                pub mod runtime {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/k8s.io.apimachinery.pkg.runtime.rs"
                    ));
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
