#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::tabs_in_doc_comments)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(dead_code)]

pub mod k8s {
    pub mod io {
        // apimachinery is generated once by build.rs; apps_gen is the sole `include!` site so
        // every wrapper's ObjectMeta/LabelSelector/etc. is one Rust type, not a nominally
        // distinct copy per wrapper.
        pub use crate::apps_gen::k8s::io::apimachinery;
        pub mod api {
            pub mod admissionregistration {
                pub mod v1 {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/k8s.io.api.admissionregistration.v1.rs"
                    ));
                }
            }
        }
    }
}
