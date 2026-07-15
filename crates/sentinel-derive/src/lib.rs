use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

/// Derives `u7s_sentinel::Sentinel::sentinel()` for a prost-generated message struct.
///
/// Every field is initialized via `<FieldType as Sentinel>::sentinel()`: scalars get a
/// distinguishable non-default value, `Vec`/`HashMap` get one synthetic element, and embedded
/// message fields recurse into their own derived `sentinel()` (every prost message type in this
/// workspace carries this same derive, applied blanket by build.rs). This lets a completeness
/// test build one instance that exercises every field of a message in a single encode/decode
/// round trip, rather than hand-writing a fully-populated literal per test.
///
/// Only plain structs with named fields are supported, matching what prost-build actually
/// generates: there are no `oneof` unions or `enum` types anywhere in the vendored .proto schema
/// (k8s API messages model both as plain optional/string fields instead). If a future schema
/// update introduces either, `type_attribute(".", ...)` in build.rs will hand this derive a
/// shape it cannot expand, and it fails the build loudly rather than silently emitting an
/// incomplete sentinel.
#[proc_macro_derive(Sentinel)]
pub fn derive_sentinel(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let data = match &input.data {
        Data::Struct(data) => data,
        Data::Enum(_) | Data::Union(_) => {
            return syn::Error::new_spanned(
                &input.ident,
                "Sentinel does not support enums or unions — a `oneof` or protobuf `enum` may \
                 have been added to the .proto schema; extend u7s-sentinel-derive to handle it",
            )
            .to_compile_error()
            .into();
        }
    };
    let Fields::Named(fields) = &data.fields else {
        return syn::Error::new_spanned(
            &input.ident,
            "Sentinel only supports structs with named fields; prost never generates tuple or \
             unit structs for messages",
        )
        .to_compile_error()
        .into();
    };

    let field_inits = fields.named.iter().map(|field| {
        let ident = field
            .ident
            .as_ref()
            .expect("Fields::Named members always have an ident");
        let ty = &field.ty;
        quote! { #ident: <#ty as ::u7s_sentinel::Sentinel>::sentinel() }
    });

    quote! {
        #[automatically_derived]
        impl ::u7s_sentinel::Sentinel for #name {
            fn sentinel() -> Self {
                Self { #(#field_inits),* }
            }
        }
    }
    .into()
}
