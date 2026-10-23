//! Evaluator behaviour against cel-go and Kubernetes library semantics.

use serde_json::json;

use super::{Env, Evaluator, Value};

/// A stable rendering of an evaluation result.
fn render(v: &Value<'_>) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::UInt(u) => format!("{u}u"),
        Value::Double(d) => format!("{d:?}"),
        Value::Str(s) => format!("{:?}", &**s),
        Value::Bytes(b) => format!("b{:?}", String::from_utf8_lossy(b)),
        Value::Optional(None) => "optional.none()".into(),
        Value::Optional(Some(v)) => format!("optional.of({})", render(v)),
        Value::Quantity(q) => format!("quantity({})", q.to_canonical_string()),
        Value::Ip(ip) => format!("ip({ip})"),
        Value::Cidr(c) => format!("cidr({})", c.render()),
        Value::Semver(s) => format!("semver({}.{}.{})", s.major, s.minor, s.patch),
        Value::Type(t) => format!("type({t})"),
        Value::Duration(d) => format!("duration({d}ns)"),
        Value::Timestamp(t) => format!("timestamp({})", t.to_rfc3339()),
        v if v.is_list() => format!(
            "[{}]",
            v.list_iter()
                .into_iter()
                .flatten()
                .map(|e| render(&e))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        v if v.is_map() => {
            let mut entries: Vec<String> = v
                .map_iter()
                .into_iter()
                .flatten()
                .map(|(k, e)| format!("{}: {}", k.display(), render(&e)))
                .collect();
            entries.sort();
            format!("{{{}}}", entries.join(", "))
        }
        other => format!("<{}>", other.type_name()),
    }
}

fn eval_with(expr: &str, env: &Env<'_>) -> String {
    match Evaluator::new(env).eval_str(expr) {
        Ok(v) => render(&v),
        Err(e) => format!("error: {}", e.msg),
    }
}

fn eval(expr: &str) -> String {
    eval_with(expr, &Env::new(vec![]))
}

/// Every expression in upstream's k8s CEL library tests (quantity, url, ip, cidr, semver,
/// format) must evaluate to what upstream's tests assert: same values, same error text.
/// The expectations come from the tests' own `expectValue`/`expectedRuntimeErr` fields; an
/// expression upstream rejects at compile time (wrong argument type) is an eval error here.
#[test]
fn upstream_k8s_library_corpus_evaluates_to_upstream_results() {
    let exprs = include_str!("../../testdata/upstream_k8s_cel_library_exprs.txt");
    let results = include_str!("../../testdata/upstream_k8s_cel_library_results.txt");
    let exprs: Vec<&str> = exprs.lines().filter(|l| !l.is_empty()).collect();
    let results: Vec<&str> = results.lines().collect();
    assert_eq!(exprs.len(), results.len());
    for (expr, line) in exprs.iter().zip(results) {
        let (golden_expr, want) = line.split_once("\t=> ").expect("tab-separated golden line");
        assert_eq!(*expr, golden_expr, "golden file out of order");
        assert_eq!(eval(expr), want, "{expr}");
    }
}

#[test]
fn literals_cover_every_cel_form() {
    for (expr, want) in [
        ("1u", "1u"),
        ("0x10", "16"),
        ("0x1Fu", "31u"),
        ("1e3", "1000.0"),
        ("1.5e-2", "0.015"),
        (".5", "0.5"),
        ("2E+3", "2000.0"),
        (r#"r"raw\n""#, r#""raw\\n""#),
        (r#"R'raw\t'"#, r#""raw\\t""#),
        (r#"b"ab""#, r#"b"ab""#),
        (r#"B'\x41\xe2\x82\xac'"#, "b\"A\u{20ac}\""),
        ("'''x'y'''", r#""x'y""#),
        ("\"\"\"a\nb\"\"\"", r#""a\nb""#),
        (r#"'é\n'"#, r#""é\n""#),
        ("null", "null"),
        ("-9223372036854775808", "-9223372036854775808"),
        ("[1, 'a', [true]]", r#"[1, "a", [true]]"#),
        ("{'a': 1u, 2: false}", r#"{2: false, a: 1u}"#),
    ] {
        assert_eq!(eval(expr), want, "{expr}");
    }
}

#[test]
fn arithmetic_overflows_and_zero_division_use_cel_go_error_text() {
    for (expr, want) in [
        ("9223372036854775807 + 1", "error: integer overflow"),
        ("-9223372036854775807 - 2", "error: integer overflow"),
        ("9223372036854775807 * 2", "error: integer overflow"),
        ("-(-9223372036854775807 - 1)", "error: integer overflow"),
        ("(-9223372036854775807 - 1) / -1", "error: integer overflow"),
        ("1 / 0", "error: division by zero"),
        ("1 % 0", "error: modulus by zero"),
        ("1u - 2u", "error: unsigned integer overflow"),
        (
            "18446744073709551615u + 1u",
            "error: unsigned integer overflow",
        ),
        ("1u / 0u", "error: division by zero"),
        ("1.0 / 0.0", "inf"),
        ("7 % 3", "1"),
        ("-7 % 3", "-1"),
        ("1 + 1u", "error: no such overload"),
        ("'a' + 1", "error: no such overload"),
    ] {
        assert_eq!(eval(expr), want, "{expr}");
    }
}

#[test]
fn comparisons_and_equality_are_heterogeneous_for_numbers_only() {
    for (expr, want) in [
        ("1 == 1u", "true"),
        ("1 == 1.0", "true"),
        ("1u < 2", "true"),
        ("-1 < 1u", "true"),
        ("2.5 > 2", "true"),
        ("1 == '1'", "false"),
        ("null == null", "true"),
        ("[1, 2] == [1.0, 2u]", "true"),
        ("{'a': 1} == {'a': 1u}", "true"),
        ("'a' < 'b' && b'a' < b'b' && false < true", "true"),
        ("1 < 'a'", "error: no such overload"),
        ("0.0 / 0.0 < 1.0", "error: NaN values cannot be ordered"),
        ("0.0 / 0.0 == 0.0 / 0.0", "false"),
        ("1 in [1, 2] && 'a' in {'a': 1} && !(3 in [1, 2])", "true"),
        (
            "type(1) == int && type(1u) == uint && type(1.0) == double",
            "true",
        ),
        (
            "type(null) == null_type && type('a') == string && type(b'a') == bytes",
            "true",
        ),
        (
            "type([]) == list && type({}) == map && type(type(1)) == type",
            "true",
        ),
        (
            "type(timestamp(0)) == timestamp && type(duration('1s')) == duration",
            "true",
        ),
    ] {
        assert_eq!(eval(expr), want, "{expr}");
    }
}

#[test]
fn logical_operators_absorb_errors_exactly_as_cel_go() {
    for (expr, want) in [
        ("1 / 0 == 1 || true", "true"),
        ("true || 1 / 0 == 1", "true"),
        ("false && 1 / 0 == 1", "false"),
        ("1 / 0 == 1 && false", "false"),
        ("1 / 0 == 1 || false", "error: division by zero"),
        ("true && 1 / 0 == 1", "error: division by zero"),
        ("1 / 0 == 1 || 'x'", "error: division by zero"),
        ("'x' || false", "error: no such overload"),
        ("true ? 1 : 1 / 0", "1"),
        ("false ? 1 / 0 : 2", "2"),
        ("1 / 0 > 0 ? 1 : 2", "error: division by zero"),
        ("'x' ? 1 : 2", "error: no such overload"),
        ("[1, 0].all(x, 1 / x == 1)", "error: division by zero"),
        ("[0, 1, 2].all(x, 1 / x == 1)", "false"),
        ("[0, 1].exists(x, 1 / x == 1)", "true"),
        ("[0, 2].exists(x, 1 / x == 1)", "error: division by zero"),
    ] {
        assert_eq!(eval(expr), want, "{expr}");
    }
}

#[test]
fn string_library_matches_ext_strings() {
    for (expr, want) in [
        ("'hello'.startsWith('he') && 'hello'.endsWith('lo') && 'hello'.contains('ell')", "true"),
        ("'hello'.matches('^h.*o$') && !'hello'.matches('^x')", "true"),
        ("matches('hello', 'ell')", "true"),
        ("'héllo'.size()", "5"),
        ("size('héllo') + size(b'ab') + size([1]) + size({'a': 1})", "9"),
        ("'Hello'.lowerAscii() + 'Hello'.upperAscii()", r#""helloHELLO""#),
        ("'Ünï'.upperAscii()", r#""ÜNï""#),
        ("'a-b-c'.replace('-', '+')", r#""a+b+c""#),
        ("'a-b-c'.replace('-', '+', 1)", r#""a+b-c""#),
        ("'a-b-c'.replace('-', '+', 0)", r#""a-b-c""#),
        ("'abc'.replace('', '-')", r#""-a-b-c-""#),
        ("'a,b,c'.split(',')", r#"["a", "b", "c"]"#),
        ("'a,b,c'.split(',', 2)", r#"["a", "b,c"]"#),
        ("'a,b'.split(',', 0)", "[]"),
        ("'ab'.split('')", r#"["a", "b"]"#),
        ("'  x '.trim()", r#""x""#),
        ("['a', 'b'].join()", r#""ab""#),
        ("['a', 'b'].join('-')", r#""a-b""#),
        ("[1].join()", "error: join: invalid input: 1"),
        ("'hello'.substring(1)", r#""ello""#),
        ("'hello'.substring(1, 3)", r#""el""#),
        ("'hello'.substring(9)", "error: index out of range: 9"),
        ("'hello'.substring(3, 1)", "error: invalid substring range. start: 3, end: 1"),
        ("'hello'.charAt(1)", r#""e""#),
        ("'hello'.charAt(5)", r#""""#),
        ("'hello'.charAt(6)", "error: index out of range: 6"),
        ("'hello'.indexOf('l')", "2"),
        ("'hello'.indexOf('l', 3)", "3"),
        ("'hello'.indexOf('z')", "-1"),
        ("'hello'.lastIndexOf('l')", "3"),
        ("'hello'.lastIndexOf('l', 2)", "2"),
        ("strings.quote('a\"b')", r#""\"a\\\"b\"""#),
        ("'%s is %d years'.format(['Bob', 7])", r#""Bob is 7 years""#),
        ("'%.2f|%e'.format([1.5, 1234.5])", r#""1.50|1.234500e+03""#),
        ("'%x %X %o %b'.format([255, 255, 8, 5])", r#""ff FF 10 101""#),
        (
            "'%s %s'.format([[1, 'a'], {'k': true}])",
            r#""[1, \"a\"] {\"k\":true}""#,
        ),
        (
            "'%d'.format(['x'])",
            "error: error during formatting: decimal clause can only be used on integers, was given string",
        ),
        ("'%d %d'.format([1])", "error: index 1 out of range"),
        (
            "'%z'.format([1])",
            "error: could not parse formatting clause: unrecognized formatting clause \"z\"",
        ),
        ("'a.b'.find('[a-z]')", r#""a""#),
        ("'a1b22'.findAll('[0-9]+')", r#"["1", "22"]"#),
        ("'a1b22'.findAll('[0-9]+', 1)", r#"["1"]"#),
        (
            "string(1.5) + string(1e21) + string(100000.0)",
            r#""1.51e+21100000""#,
        ),
        ("string(true) + string(b'ab') + string(-1) + string(2u)", r#""trueab-12""#),
        ("int('12') + int(2.9) + int(2u)", "16"),
        ("int('x')", "error: type conversion error from 'string' to 'int'"),
        ("int(1e30)", "error: integer overflow"),
        ("uint(-1)", "error: unsigned integer overflow"),
        ("double('1.5') + double(2)", "3.5"),
        ("bool('true') && !bool('F')", "true"),
        ("bytes('abc') == b'abc'", "true"),
        ("dyn(1) == 1", "true"),
    ] {
        assert_eq!(eval(expr), want, "{expr}");
    }
}

#[test]
fn list_and_set_libraries() {
    for (expr, want) in [
        (
            "[1, 2, 3].isSorted() && ![3, 1].isSorted() && [].isSorted()",
            "true",
        ),
        ("['a', 'b'].isSorted()", "true"),
        ("[1, 2, 3].sum()", "6"),
        ("[1.5, 2.0].sum()", "3.5"),
        ("[].sum()", "0"),
        (
            "[duration('1s'), duration('2s')].sum() == duration('3s')",
            "true",
        ),
        ("[3, 1, 2].min() + [3, 1, 2].max()", "4"),
        ("[].min()", "error: min called on empty list"),
        ("[].max()", "error: max called on empty list"),
        ("[1, 2, 1].indexOf(1) + [1, 2, 1].lastIndexOf(1)", "2"),
        ("[1, 2].indexOf(5)", "-1"),
        ("[1, 2, 3].includes(2) && ![1].includes(5)", "true"),
        ("[1, 2, 3, 4].slice(1, 3)", "[2, 3]"),
        (
            "[1].slice(0, 5)",
            "error: cannot slice(0, 5), list is length 1",
        ),
        ("[1, [2, [3]]].flatten()", "[1, 2, [3]]"),
        ("[1, [2, [3]]].flatten(2)", "[1, 2, 3]"),
        ("[1, 2, 1, 3].distinct()", "[1, 2, 3]"),
        ("[1, 2, 3].reverse()", "[3, 2, 1]"),
        ("[3, 1, 2].sort()", "[1, 2, 3]"),
        ("['b', 'a'].sort()", r#"["a", "b"]"#),
        (
            "[1, 'a'].sort()",
            "error: list elements must have the same type",
        ),
        ("[{'n': 2}, {'n': 1}].sortBy(e, e.n)", "[{n: 1}, {n: 2}]"),
        ("lists.range(3)", "[0, 1, 2]"),
        ("[1, 2, 3].map(x, x * 2)", "[2, 4, 6]"),
        ("[1, 2, 3].filter(x, x > 1)", "[2, 3]"),
        ("[1, 2, 3].map(x, x > 1, x * 10)", "[20, 30]"),
        ("[1, 2, 3].exists_one(x, x > 2)", "true"),
        ("[1, 2, 3].all(i, v, i < v)", "true"),
        ("[1, 2, 3].exists(i, v, i == 2 && v == 3)", "true"),
        ("[1, 2].transformList(i, v, v * 10)", "[10, 20]"),
        ("[1, 2, 3].transformList(i, v, v > 1, v)", "[2, 3]"),
        ("{'a': 1}.transformMap(k, v, v + 1)", "{a: 2}"),
        ("{'a': 1}.all(k, v, v == 1)", "true"),
        (
            "sets.contains([1, 2, 3], [2, 3]) && !sets.contains([1], [2])",
            "true",
        ),
        ("sets.contains([1, 2.0, 3u], [1.0, 2u, 3])", "true"),
        ("sets.equivalent([1, 2], [2, 1, 1])", "true"),
        (
            "sets.intersects([1, 2], [2, 3]) && !sets.intersects([1], [2])",
            "true",
        ),
        ("cel.bind(x, 2, x * x)", "4"),
        ("[1, 2, 3][1] + [1, 2, 3][2u]", "5"),
        ("[1][5]", "error: index out of bounds: 5"),
        ("[1][-1]", "error: index out of bounds: -1"),
        ("{'a': 1}['b']", "error: no such key: b"),
        ("{'a': 1}['a']", "1"),
    ] {
        assert_eq!(eval(expr), want, "{expr}");
    }
}

#[test]
fn optionals() {
    for (expr, want) in [
        (
            "optional.of(1).hasValue() && !optional.none().hasValue()",
            "true",
        ),
        ("optional.of(1).value()", "1"),
        (
            "optional.none().value()",
            "error: optional.none() dereference",
        ),
        ("optional.none().orValue(5)", "5"),
        ("optional.of(1).orValue(5)", "1"),
        ("optional.none().or(optional.of(2)).value()", "2"),
        ("optional.ofNonZeroValue(0).hasValue()", "false"),
        ("optional.of(2).optMap(x, x + 1).value()", "3"),
        ("{'a': 1}.?a.orValue(0) + {'a': 1}.?b.orValue(7)", "8"),
        ("[1, 2][?1].orValue(0) + [1][?4].orValue(9)", "11"),
        ("[?optional.none(), 1]", "[1]"),
        ("{?'a': optional.of(1), ?'b': optional.none()}", "{a: 1}"),
    ] {
        assert_eq!(eval(expr), want, "{expr}");
    }
}

#[test]
fn time_functions() {
    for (expr, want) in [
        ("timestamp('2023-06-15T23:30:45.123Z').getFullYear()", "2023"),
        ("timestamp('2023-06-15T23:30:45Z').getMonth()", "5"),
        ("timestamp('2023-06-15T23:30:45Z').getDate()", "15"),
        ("timestamp('2023-06-15T23:30:45Z').getDayOfMonth()", "14"),
        ("timestamp('2023-06-15T23:30:45Z').getDayOfYear()", "165"),
        ("timestamp('2023-06-15T23:30:45Z').getDayOfWeek()", "4"),
        ("timestamp('2023-06-15T23:30:45Z').getHours()", "23"),
        ("timestamp('2023-06-15T23:30:45Z').getHours('+02:00')", "1"),
        ("timestamp('2023-06-15T23:30:45.123Z').getMilliseconds()", "123"),
        (
            "timestamp('2023-06-15T23:30:45Z') + duration('1h') == timestamp('2023-06-16T00:30:45Z')",
            "true",
        ),
        (
            "timestamp('2023-06-16T00:00:00Z') - timestamp('2023-06-15T00:00:00Z') == duration('24h')",
            "true",
        ),
        ("duration('1h30m').getMinutes()", "90"),
        ("duration('1.5s').getMilliseconds()", "1500"),
        ("duration('1s') < duration('2s')", "true"),
        ("string(duration('90s'))", r#""90s""#),
        ("int(timestamp('1970-01-02T00:00:00Z'))", "86400"),
        ("timestamp(86400) == timestamp('1970-01-02T00:00:00Z')", "true"),
        (
            "duration('bad')",
            "error: type conversion error from 'string' to 'google.protobuf.Duration'",
        ),
        (
            "timestamp('bad')",
            "error: type conversion error from 'string' to 'google.protobuf.Timestamp'",
        ),
    ] {
        assert_eq!(eval(expr), want, "{expr}");
    }
}

#[test]
fn unknown_names_are_compile_style_errors() {
    for (expr, want) in [
        (
            "nope",
            "error: compilation failed: undeclared reference to 'nope' (in container '')",
        ),
        (
            "nope(1)",
            "error: compilation failed: undeclared reference to 'nope' (in container '')",
        ),
        (
            "'a'.nope()",
            "error: compilation failed: undeclared reference to 'nope' (in container '')",
        ),
        (
            "math.greatest(1, 2)",
            "error: compilation failed: undeclared reference to 'math' (in container '')",
        ),
    ] {
        assert_eq!(eval(expr), want, "{expr}");
    }
}

#[test]
fn json_data_selects_index_and_presence() {
    let object = json!({
        "metadata": {"name": "n", "labels": {"a": "1"}},
        "spec": {"replicas": 3, "containers": [{"name": "c1"}, {"name": "c2"}], "none": null, "big": 18446744073709551615u64}
    });
    let env = Env::new(vec![("object", Value::from_json(&object))]);
    for (expr, want) in [
        ("object.spec.replicas", "3"),
        ("object.spec.big", "18446744073709551615u"),
        ("object.spec.containers[1].name", r#""c2""#),
        ("object.spec.containers.map(c, c.name)", r#"["c1", "c2"]"#),
        ("object.metadata.labels['a']", r#""1""#),
        ("has(object.metadata.labels.b)", "false"),
        ("has(object.spec.none)", "false"),
        ("has(object.spec.replicas)", "true"),
        ("object.spec.missing", "error: no such key: missing"),
        ("object.spec.containers[2]", "error: index out of bounds: 2"),
        ("object.metadata.labels['b']", "error: no such key: b"),
        ("object.spec.replicas.foo", "error: no such key: foo"),
        ("has(object.spec.replicas.foo)", "error: no such overload"),
        ("has(object.nope.x)", "error: no such key: nope"),
        ("object.?spec.?replicas.orValue(0)", "3"),
        ("object.?spec.?nope.orValue(0)", "0"),
        ("object.spec.containers.exists(c, c.name == 'c2')", "true"),
        (
            "object.spec.containers.size() == 2 && object.spec.replicas > 2",
            "true",
        ),
        (
            "oldObject",
            "error: compilation failed: undeclared reference to 'oldObject' (in container '')",
        ),
    ] {
        assert_eq!(eval_with(expr, &env), want, "{expr}");
    }
}

#[test]
fn policy_variables_are_lazy_and_only_see_earlier_variables() {
    let object = json!({"spec": {"a": 1}});
    let env = Env::new(vec![("object", Value::from_json(&object))]).with_variables(vec![
        ("one".into(), "object.spec.a".into()),
        ("two".into(), "variables.one + 1".into()),
        ("broken".into(), "object.spec.nope".into()),
        ("later".into(), "variables.after".into()),
        ("after".into(), "1".into()),
    ]);
    for (expr, want) in [
        ("variables.two", "2"),
        (
            "variables.two == 2 && has(variables.one) && !has(variables.zzz)",
            "true",
        ),
        ("false && variables.broken == 1", "false"),
        ("variables.broken", "error: no such key: nope"),
        ("variables.later", "error: no such key: after"),
        ("variables.after", "1"),
    ] {
        assert_eq!(eval_with(expr, &env), want, "{expr}");
    }
}

#[test]
fn cost_limit_aborts_quadratic_expressions_and_is_never_absorbed() {
    let big: Vec<serde_json::Value> = (0..2000).map(|i| json!(i)).collect();
    let object = json!({"l": big});
    let env = Env::new(vec![("object", Value::from_json(&object))]);
    let quadratic = "object.l.all(x, object.l.all(y, x + y >= 0))";
    assert_eq!(
        eval_with(quadratic, &env),
        "error: operation cancelled: actual cost limit exceeded"
    );
    assert_eq!(
        eval_with(&format!("{quadratic} || true"), &env),
        "error: operation cancelled: actual cost limit exceeded",
        "a cost abort must not be absorbed by `|| true`"
    );
    assert_eq!(
        eval_with("object.l.all(x, x >= 0)", &env),
        "true",
        "linear work over the same data stays within budget"
    );
}

#[test]
fn string_doubling_is_cost_bounded() {
    let doubling = (0..40).fold("'ab'".to_string(), |acc, _| {
        format!("cel.bind(s, {acc}, s + s)")
    });
    assert!(
        eval(&doubling).starts_with("error:"),
        "doubling a string 40 times must not allocate gigabytes"
    );
}

/// Each of these builds a result far larger than its inputs; the cost meter has to refuse
/// them before allocating, or one small policy expression can exhaust the apiserver's memory.
#[test]
fn allocation_amplifying_calls_are_refused_before_building_the_result() {
    let big = "x".repeat(1_000_000);
    let object = json!({"s": big, "l": (0..100_000).collect::<Vec<_>>()});
    let env = Env::new(vec![("object", Value::from_json(&object))]);
    let over = "error: operation cancelled: actual cost limit exceeded";
    for expr in [
        "object.s.replace('x', object.s)",
        "object.s.replace('', object.s)",
        "lists.range(5000000)",
        "object.l + object.l + object.l + object.l + object.l + object.l + object.l + object.l + object.l + object.l + object.l",
        "object.s.split('')",
        "cel.bind(l, object.l, cel.bind(m, l + l, cel.bind(n, m + m, cel.bind(o, n + n, o + o))))",
    ] {
        assert_eq!(eval_with(expr, &env), over, "{expr}");
    }
}

#[test]
fn reading_a_large_string_field_does_not_copy_it_per_use() {
    let object = json!({"s": "x".repeat(2_000_000), "l": (0..50_000).collect::<Vec<_>>()});
    let env = Env::new(vec![("object", Value::from_json(&object))]);
    let started = std::time::Instant::now();
    assert_eq!(
        eval_with("object.l.all(i, object.s.size() == 2000000)", &env),
        "true"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "50k reads of a 2MB string must borrow it (copying is ~100GB of memcpy)"
    );
}

#[test]
fn deeply_nested_expressions_error_instead_of_overflowing_the_stack() {
    let nested = format!("{}1{}", "[".repeat(300), "]".repeat(300));
    assert!(eval(&nested).starts_with("error: compilation failed"));
    let ok = format!("{}1{}", "(".repeat(60), ")".repeat(60));
    assert_eq!(eval(&ok), "1");
}

#[test]
fn maps_built_by_expressions_round_trip_to_json() {
    let env = Env::new(vec![]);
    let v = Evaluator::new(&env)
        .eval_str("{'a': 1u, 'b': [1.5, 'x'], 'c': b'hi', 'd': timestamp(0), 'e': null}")
        .unwrap();
    assert_eq!(
        v.to_json().unwrap(),
        json!({"a": 1, "b": [1.5, "x"], "c": "aGk=", "d": "1970-01-01T00:00:00Z", "e": null})
    );
}
