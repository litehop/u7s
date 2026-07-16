use u7s_sentinel::Sentinel;

// Mirrors the shape that makes apiserver's JsonSchemaProps dangerous: a struct that embeds
// itself both directly (`Vec<Self>`) and through one level of indirection via a second struct
// (`Box<Wrapper>` -> `Wrapper` holds `Self`), matching JsonSchemaProps's own `all_of: Vec<Self>`
// and `items: Box<JsonSchemaPropsOrArray>` respectively. Before `sentinel_guard`, deriving
// `Sentinel` for either of these and calling `.sentinel()` would recurse without ever hitting a
// base case and overflow the stack.
#[derive(Default, Sentinel)]
struct SelfRef {
    name: String,
    direct: Vec<SelfRef>,
    indirect: Option<Box<Wrapper>>,
}

#[derive(Default, Sentinel)]
struct Wrapper {
    inner: Box<SelfRef>,
}

#[test]
fn sentinel_on_self_referential_struct_terminates_instead_of_overflowing_the_stack() {
    // If this call doesn't return, the process crashes with a stack overflow — the real failure
    // mode this test guards against, matching the bug that would otherwise block every
    // completeness test written against apiserver's JsonSchemaProps.
    let value = SelfRef::sentinel();

    assert_eq!(
        value.name, "__sentinel__",
        "the outermost struct's own scalar fields must still be sentinel-populated — the guard \
         must only suppress *recursive* re-entry, not the whole derive"
    );
    assert_eq!(
        value.direct.len(),
        1,
        "the first level of the direct Vec<Self> cycle must still be populated, so a \
         completeness test can prove the field itself survives decode"
    );
    assert_eq!(
        value.direct[0].name,
        String::default(),
        "the second level of recursion (Self inside Self) must be cut off to Default rather than \
         recursing again, or this test would never return"
    );

    let indirect = value
        .indirect
        .expect("the Option<Box<Wrapper>> field must still be populated at the outer level");
    assert_eq!(
        indirect.inner.name,
        String::default(),
        "the cycle closes through Wrapper -> SelfRef, one hop removed from SelfRef itself; the \
         guard must catch this indirect re-entry too, not just a field that names Self directly"
    );
}
