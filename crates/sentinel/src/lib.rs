pub use u7s_sentinel_derive::Sentinel;

use std::any::TypeId;
use std::cell::RefCell;

thread_local! {
    static BUILDING: RefCell<Vec<TypeId>> = const { RefCell::new(Vec::new()) };
}

/// Called by every `#[derive(Sentinel)]`-generated `sentinel()` body instead of
/// constructing `Self` directly, so a self-referential message (e.g. CRD's
/// `JsonSchemaProps`, which nests itself through `properties`/`allOf`/`items`/etc. with
/// no `Option` a derive could treat as a base case) doesn't recurse forever and blow the
/// stack. If `T` is already being built further up the call stack, `build` would
/// construct another `T` which would try to build another `T`... without ever
/// returning, so this short-circuits to `T::default()` instead: the outer occurrence of
/// the recursive field still gets a real, encodable value (proving the corresponding
/// gen_*_to_json function actually reads that field), it just isn't populated a second
/// level deep. Non-recursive types (almost everything) never re-enter their own
/// `TypeId` here, so this is a no-op for them.
#[doc(hidden)]
pub fn sentinel_guard<T, F>(build: F) -> T
where
    T: Default + 'static,
    F: FnOnce() -> T,
{
    let id = TypeId::of::<T>();
    let already_building = BUILDING.with(|stack| stack.borrow().contains(&id));
    if already_building {
        return T::default();
    }
    BUILDING.with(|stack| stack.borrow_mut().push(id));
    let value = build();
    BUILDING.with(|stack| {
        stack.borrow_mut().pop();
    });
    value
}

/// Builds an instance of `Self` with every field set to a distinguishable non-default value.
///
/// `#[derive(Sentinel)]` (applied blanket to every prost-generated message in build.rs)
/// implements this by setting every scalar field via its own `Sentinel::sentinel()`, every
/// `Vec`/`HashMap` field to one synthetic element, and recursing into embedded message fields.
///
/// The point is a single value that a `gen_*_to_json` completeness test can encode, decode
/// through the real adapter code, and use to assert that every field the message carries on the
/// wire actually reaches the JSON output — catching the "field silently dropped from
/// gen_*_to_json" bug class instead of a hand test that only happens to cover the fields its
/// author remembered to set.
pub trait Sentinel {
    fn sentinel() -> Self;
}

impl Sentinel for bool {
    // Some decoders treat `Some(false)` as indistinguishable from "unset" — e.g.
    // PodSpec.hostNetwork is a plain (non-pointer) bool upstream, so protobuf always writes it
    // and the decoder only trusts `Some(true)` as real client intent. `true` is the one value
    // every such decoder still emits, so it is the only choice that exercises all bool fields.
    fn sentinel() -> Self {
        true
    }
}

impl Sentinel for u8 {
    fn sentinel() -> Self {
        0xAB
    }
}

impl Sentinel for i32 {
    fn sentinel() -> Self {
        424_242
    }
}

impl Sentinel for i64 {
    fn sentinel() -> Self {
        4_242_424_242
    }
}

impl Sentinel for f64 {
    fn sentinel() -> Self {
        42.5
    }
}

impl Sentinel for String {
    fn sentinel() -> Self {
        "__sentinel__".to_string()
    }
}

impl<T: Sentinel> Sentinel for Option<T> {
    fn sentinel() -> Self {
        Some(T::sentinel())
    }
}

impl<T: Sentinel> Sentinel for Vec<T> {
    fn sentinel() -> Self {
        vec![T::sentinel()]
    }
}

impl<T: Sentinel> Sentinel for Box<T> {
    fn sentinel() -> Self {
        Box::new(T::sentinel())
    }
}

impl<K, V> Sentinel for std::collections::HashMap<K, V>
where
    K: Sentinel + Eq + std::hash::Hash,
    V: Sentinel,
{
    fn sentinel() -> Self {
        let mut map = std::collections::HashMap::new();
        map.insert(K::sentinel(), V::sentinel());
        map
    }
}
