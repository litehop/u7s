//! The subset of `k8s.io/client-go/util/jsonpath` that CRD printer columns exercise: the parser
//! accepts everything upstream's parser accepts (so a CRD is never rejected for a path the
//! reference apiserver stores), and evaluation turns anything it cannot evaluate into "no
//! value" rather than an error.

use serde_json::Value;

const MAX_DEPTH: usize = 16;
const MAX_RESULTS: usize = 100_000;

#[derive(Debug, Clone)]
pub(crate) struct Param {
    known: bool,
    value: i64,
    derived: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum Node {
    Field(String),
    Wildcard,
    Recursive,
    Array([Param; 3]),
    Union(Vec<Vec<Node>>),
    Filter {
        left: Vec<Node>,
        op: String,
        right: Vec<Node>,
    },
    Literal(Value),
    Identifier,
}

type ParseResult<T> = Result<T, String>;

fn is_terminator(c: Option<char>) -> bool {
    match c {
        None => true,
        Some(c) => matches!(
            c,
            ' ' | '\t' | '\r' | '\n' | ',' | '.' | '[' | ']' | '$' | '@' | '{' | '}'
        ),
    }
}

fn is_alnum(c: Option<char>) -> bool {
    c.is_some_and(|c| c == '_' || c.is_alphanumeric())
}

/// Parse a printer-column `jsonPath` the way upstream does after wrapping it as `{<path>}`.
/// A literal `{` or `}` inside the path is rejected rather than starting a second action.
pub(crate) fn parse(path: &str) -> ParseResult<Vec<Node>> {
    parse_action(path, 0).map_err(|e| format!("invalid JSONPath {path:?}: {e}"))
}

struct Cursor<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Option<char> {
        self.s[self.pos..].chars().next()
    }
    fn next(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }
    fn rest(&self) -> &'a str {
        &self.s[self.pos..]
    }
}

fn parse_action(text: &str, depth: usize) -> ParseResult<Vec<Node>> {
    if depth > MAX_DEPTH {
        return Err("nesting too deep".to_string());
    }
    let mut cur = Cursor { s: text, pos: 0 };
    let mut nodes: Vec<Node> = Vec::new();
    loop {
        let rest = cur.rest();
        if rest.starts_with("[?(") {
            cur.pos += 3;
            nodes.push(parse_filter(&mut cur, depth)?);
            continue;
        }
        if rest.starts_with("..") {
            if matches!(nodes.last(), Some(Node::Recursive)) {
                return Err("invalid multiple recursive descent".to_string());
            }
            cur.pos += 2;
            nodes.push(Node::Recursive);
            if is_alnum(cur.peek()) {
                nodes.push(parse_field(&mut cur));
            }
            continue;
        }
        let Some(c) = cur.next() else {
            return Ok(nodes);
        };
        match c {
            '\r' | '\n' => return Err("unclosed action".to_string()),
            ' ' | '@' | '$' => {}
            '[' => parse_array(&mut cur, &mut nodes, depth)?,
            '"' | '\'' => nodes.push(parse_quote(&mut cur, c)?),
            '.' => nodes.push(parse_field(&mut cur)),
            '+' | '-' => {
                cur.pos -= 1;
                nodes.push(parse_number(&mut cur)?);
            }
            c if c.is_ascii_digit() => {
                cur.pos -= c.len_utf8();
                nodes.push(parse_number(&mut cur)?);
            }
            c if c == '_' || c.is_alphanumeric() => {
                cur.pos -= c.len_utf8();
                let start = cur.pos;
                while !is_terminator(cur.peek()) {
                    cur.next();
                }
                nodes.push(match &cur.s[start..cur.pos] {
                    "true" => Node::Literal(Value::Bool(true)),
                    "false" => Node::Literal(Value::Bool(false)),
                    _ => Node::Identifier,
                });
            }
            c => return Err(format!("unrecognized character in action: {c:?}")),
        }
    }
}

fn parse_field(cur: &mut Cursor) -> Node {
    let start = cur.pos;
    loop {
        match cur.next() {
            Some('\\') => {
                cur.next();
            }
            c if is_terminator(c) => {
                if c.is_some() {
                    cur.pos -= 1;
                }
                break;
            }
            _ => {}
        }
    }
    let value = &cur.s[start..cur.pos];
    if value == "*" {
        Node::Wildcard
    } else {
        Node::Field(value.replace('\\', ""))
    }
}

fn parse_number(cur: &mut Cursor) -> ParseResult<Node> {
    let start = cur.pos;
    if matches!(cur.peek(), Some('+' | '-')) {
        cur.next();
    }
    while matches!(cur.peek(), Some(c) if c == '.' || c.is_numeric()) {
        cur.next();
    }
    let value = &cur.s[start..cur.pos];
    if let Ok(i) = value.parse::<i64>() {
        return Ok(Node::Literal(Value::from(i)));
    }
    value
        .parse::<f64>()
        .ok()
        .and_then(serde_json::Number::from_f64)
        .map(|n| Node::Literal(Value::Number(n)))
        .ok_or_else(|| format!("cannot parse number {value}"))
}

fn parse_quote(cur: &mut Cursor, quote: char) -> ParseResult<Node> {
    let start = cur.pos - 1;
    loop {
        match cur.next() {
            None | Some('\n') => return Err("unterminated quoted string".to_string()),
            Some(c) if c == quote && cur.s.as_bytes()[cur.pos - 2] != b'\\' => break,
            _ => {}
        }
    }
    let raw = &cur.s[start + 1..cur.pos - 1];
    unquote(raw, quote).map(|s| Node::Literal(Value::String(s)))
}

fn unquote(raw: &str, quote: char) -> ParseResult<String> {
    let mut out = String::new();
    let mut it = raw.chars();
    let err = || format!("unquote string {raw:?} error invalid syntax");
    while let Some(c) = it.next() {
        if c == quote {
            return Err(err());
        }
        if c != '\\' {
            out.push(c);
            continue;
        }
        let esc = it.next().ok_or_else(err)?;
        let mut hex = |n: usize| -> ParseResult<char> {
            let mut v = 0u32;
            for _ in 0..n {
                v = v * 16 + it.next().and_then(|d| d.to_digit(16)).ok_or_else(err)?;
            }
            char::from_u32(v).ok_or_else(err)
        };
        out.push(match esc {
            'a' => '\u{7}',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\u{b}',
            '\\' => '\\',
            '\'' | '"' if esc == quote => esc,
            'x' => hex(2)?,
            'u' => hex(4)?,
            'U' => hex(8)?,
            _ => return Err(err()),
        });
    }
    Ok(out)
}

fn parse_array(cur: &mut Cursor, nodes: &mut Vec<Node>, depth: usize) -> ParseResult<()> {
    let start = cur.pos;
    loop {
        match cur.next() {
            None | Some('\n') => return Err("unterminated array".to_string()),
            Some(']') => break,
            _ => {}
        }
    }
    let text = &cur.s[start..cur.pos - 1];
    let text = if text == "*" { ":" } else { text };

    let parts: Vec<&str> = text.split(',').collect();
    if parts.len() > 1 {
        let mut union = Vec::new();
        for p in parts {
            union.push(parse_action(
                &format!("[{}]", p.trim_matches(' ')),
                depth + 1,
            )?);
        }
        nodes.push(Node::Union(union));
        return Ok(());
    }

    if let Some(key) = text
        .strip_prefix('\'')
        .and_then(|t| t.strip_suffix('\''))
        .filter(|k| !k.contains('\''))
    {
        nodes.extend(parse_action(&format!(".{key}"), depth + 1)?);
        return Ok(());
    }

    let segs: Vec<&str> = text.split(':').collect();
    let valid_num = |s: &str| {
        let d = s.strip_prefix('-').unwrap_or(s);
        d.bytes().all(|b| b.is_ascii_digit())
    };
    if segs.len() > 3 || !segs.iter().all(|s| valid_num(s)) {
        return Err(format!("invalid array index {text}"));
    }
    let mut params = [
        Param {
            known: false,
            value: 0,
            derived: false,
        },
        Param {
            known: false,
            value: 0,
            derived: false,
        },
        Param {
            known: false,
            value: 0,
            derived: false,
        },
    ];
    for i in 0..3 {
        match segs.get(i).copied() {
            Some(s) if !s.is_empty() => {
                params[i].known = true;
                params[i].value = s
                    .parse()
                    .map_err(|_| format!("array index {s} is not a number"))?;
            }
            Some(_) if i > 0 => {}
            _ if i == 1 && segs.len() == 1 => {
                params[1] = Param {
                    known: true,
                    value: params[0].value.wrapping_add(1),
                    derived: true,
                };
            }
            _ => {}
        }
    }
    nodes.push(Node::Array(params));
    Ok(())
}

fn parse_filter(cur: &mut Cursor, depth: usize) -> ParseResult<Node> {
    let start = cur.pos;
    let (mut begin, mut end) = (false, false);
    let mut pair = '\0';
    loop {
        match cur.next() {
            None | Some('\n') => return Err("unterminated filter".to_string()),
            Some(r @ ('"' | '\'')) => {
                if !begin {
                    begin = true;
                    pair = r;
                } else if cur.s.as_bytes()[cur.pos - 2] != b'\\' && r == pair {
                    end = true;
                }
            }
            Some(')') if begin == end => break,
            _ => {}
        }
    }
    if cur.next() != Some(']') {
        return Err("unclosed array expect ]".to_string());
    }
    let text = &cur.s[start..cur.pos - 2];

    let is_op = |c: char| matches!(c, '!' | '<' | '>' | '=');
    let split = text.find(is_op).filter(|&i| i > 0).and_then(|i| {
        let run = text[i..].find(|c| !is_op(c)).map_or(text.len(), |n| i + n);
        if run < text.len() {
            Some((i, run))
        } else {
            let last = text.char_indices().next_back()?.0;
            (last > i).then_some((i, last))
        }
    });
    match split {
        None => Ok(Node::Filter {
            left: parse_action(text, depth + 1)?,
            op: "exists".to_string(),
            right: Vec::new(),
        }),
        Some((i, j)) => Ok(Node::Filter {
            left: parse_action(&text[..i], depth + 1)?,
            op: text[i..j].to_string(),
            right: parse_action(&text[j..], depth + 1)?,
        }),
    }
}

#[derive(Clone)]
enum Val<'a> {
    Ref(&'a Value),
    Lit(Value),
}

impl<'a> Val<'a> {
    fn value(&self) -> &Value {
        match self {
            Val::Ref(v) => v,
            Val::Lit(v) => v,
        }
    }

    fn as_ref(&self) -> Option<&'a Value> {
        match self {
            Val::Ref(v) => Some(v),
            Val::Lit(_) => None,
        }
    }
}

type Eval<'a> = Result<Vec<Val<'a>>, ()>;

fn children(v: &Value) -> Vec<&Value> {
    match v {
        Value::Array(a) => a.iter().collect(),
        Value::Object(o) => o.values().collect(),
        _ => Vec::new(),
    }
}

fn capped<'a>(v: Vec<Val<'a>>) -> Eval<'a> {
    if v.len() > MAX_RESULTS {
        Err(())
    } else {
        Ok(v)
    }
}

fn eval_list<'a>(nodes: &[Node], input: Vec<Val<'a>>) -> Eval<'a> {
    let mut cur = input;
    for node in nodes {
        cur = eval_node(node, cur)?;
    }
    Ok(cur)
}

fn eval_node<'a>(node: &Node, input: Vec<Val<'a>>) -> Eval<'a> {
    match node {
        Node::Field(name) => Ok(input
            .iter()
            .filter_map(|v| match v {
                Val::Ref(Value::Object(o)) => o.get(name).filter(|c| !c.is_null()).map(Val::Ref),
                _ => None,
            })
            .collect()),
        Node::Wildcard => capped(
            input
                .iter()
                .filter_map(Val::as_ref)
                .flat_map(children)
                .map(Val::Ref)
                .collect(),
        ),
        Node::Recursive => {
            let mut out = Vec::new();
            for root in input.iter().filter_map(Val::as_ref) {
                let mut stack = vec![root];
                while let Some(n) = stack.pop() {
                    let kids = children(n);
                    if kids.is_empty() {
                        continue;
                    }
                    out.push(Val::Ref(n));
                    if out.len() > MAX_RESULTS {
                        return Err(());
                    }
                    stack.extend(kids.into_iter().rev());
                }
            }
            Ok(out)
        }
        Node::Array(params) => {
            let mut out = Vec::new();
            for v in &input {
                let arr = match v.as_ref() {
                    Some(Value::Null) => continue,
                    Some(Value::Array(a)) => a,
                    _ => return Err(()),
                };
                let len = arr.len() as i64;
                let mut p = params.clone();
                if !p[0].known {
                    p[0].value = 0;
                }
                if p[0].value < 0 {
                    p[0].value += len;
                }
                if !p[1].known {
                    p[1].value = len;
                }
                if p[1].value < 0 || (p[1].value == 0 && p[1].derived) {
                    p[1].value += len;
                }
                if p[1].value == p[0].value {
                    return capped(out);
                }
                if p[0].value >= len || p[0].value < 0 || p[1].value > len || p[1].value < 0 {
                    return Err(());
                }
                if p[0].value > p[1].value {
                    return Err(());
                }
                let step = if p[2].known {
                    if p[2].value <= 0 {
                        return Err(());
                    }
                    p[2].value as usize
                } else {
                    1
                };
                out.extend(
                    arr[p[0].value as usize..p[1].value as usize]
                        .iter()
                        .step_by(step)
                        .map(Val::Ref),
                );
                if out.len() > MAX_RESULTS {
                    return Err(());
                }
            }
            Ok(out)
        }
        Node::Union(lists) => {
            let mut out = Vec::new();
            for l in lists {
                out.extend(eval_list(l, input.clone())?);
                if out.len() > MAX_RESULTS {
                    return Err(());
                }
            }
            Ok(out)
        }
        Node::Filter { left, op, right } => {
            let mut out = Vec::new();
            for v in &input {
                let Some(Value::Array(arr)) = v.as_ref() else {
                    return Err(());
                };
                for item in arr {
                    let temp = vec![Val::Ref(item)];
                    let lefts = eval_list(left, temp.clone());
                    if op == "exists" {
                        if lefts.is_ok_and(|l| !l.is_empty()) {
                            out.push(Val::Ref(item));
                        }
                        continue;
                    }
                    let lefts = lefts?;
                    if lefts.len() > 1 {
                        return Err(());
                    }
                    let Some(l) = lefts.first() else { continue };
                    let rights = eval_list(right, temp)?;
                    if rights.len() > 1 {
                        return Err(());
                    }
                    let Some(r) = rights.first() else { continue };
                    if compare(op, l.value(), r.value())? {
                        out.push(Val::Ref(item));
                    }
                }
                if out.len() > MAX_RESULTS {
                    return Err(());
                }
            }
            Ok(out)
        }
        Node::Literal(lit) => {
            if matches!(lit, Value::String(_)) {
                Ok(vec![Val::Lit(lit.clone())])
            } else {
                Ok(input.iter().map(|_| Val::Lit(lit.clone())).collect())
            }
        }
        Node::Identifier => Err(()),
    }
}

enum Scalar<'a> {
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Str(&'a str),
}

fn scalar(v: &Value) -> Result<Scalar<'_>, ()> {
    match v {
        Value::Bool(b) => Ok(Scalar::Bool(*b)),
        Value::String(s) => Ok(Scalar::Str(s)),
        Value::Number(n) => Ok(if let Some(i) = n.as_i64() {
            Scalar::Int(i)
        } else if let Some(u) = n.as_u64() {
            Scalar::Uint(u)
        } else {
            Scalar::Float(n.as_f64().ok_or(())?)
        }),
        _ => Err(()),
    }
}

/// Mirrors the forked text/template comparison: operands of different kinds (other than
/// int/uint) and non-scalars are an error, as are ordering comparisons of bools.
fn equal(a: &Value, b: &Value) -> Result<bool, ()> {
    Ok(match (scalar(a)?, scalar(b)?) {
        (Scalar::Bool(x), Scalar::Bool(y)) => x == y,
        (Scalar::Int(x), Scalar::Int(y)) => x == y,
        (Scalar::Uint(x), Scalar::Uint(y)) => x == y,
        (Scalar::Int(x), Scalar::Uint(y)) | (Scalar::Uint(y), Scalar::Int(x)) => {
            x >= 0 && x as u64 == y
        }
        (Scalar::Float(x), Scalar::Float(y)) => x == y,
        (Scalar::Str(x), Scalar::Str(y)) => x == y,
        _ => return Err(()),
    })
}

fn less(a: &Value, b: &Value) -> Result<bool, ()> {
    Ok(match (scalar(a)?, scalar(b)?) {
        (Scalar::Int(x), Scalar::Int(y)) => x < y,
        (Scalar::Uint(x), Scalar::Uint(y)) => x < y,
        (Scalar::Int(x), Scalar::Uint(y)) => x < 0 || (x as u64) < y,
        (Scalar::Uint(x), Scalar::Int(y)) => y >= 0 && x < y as u64,
        (Scalar::Float(x), Scalar::Float(y)) => x < y,
        (Scalar::Str(x), Scalar::Str(y)) => x < y,
        _ => return Err(()),
    })
}

fn compare(op: &str, a: &Value, b: &Value) -> Result<bool, ()> {
    match op {
        "==" => equal(a, b),
        "!=" => equal(a, b).map(|e| !e),
        "<" => less(a, b),
        ">=" => less(a, b).map(|l| !l),
        "<=" => Ok(less(a, b)? || equal(a, b)?),
        ">" => Ok(!(less(a, b)? || equal(a, b)?)),
        _ => Err(()),
    }
}

/// First value the path selects in `root`, or `None` when it selects nothing or hits a
/// construct that cannot be evaluated (upstream treats both as a nil cell).
pub(crate) fn first_result<'a>(nodes: &[Node], root: &'a Value) -> Option<&'a Value> {
    match eval_list(nodes, vec![Val::Ref(root)])
        .ok()?
        .into_iter()
        .next()?
    {
        Val::Ref(v) => Some(v),
        Val::Lit(_) => None,
    }
}

/// Text for a selected value the way upstream `PrintResults` renders it: containers as
/// compact JSON, scalars as Go's `%v`.
pub(crate) fn print_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) if n.is_f64() => go_float(n.as_f64().unwrap_or_default()),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

fn go_float(f: f64) -> String {
    let exp = if f == 0.0 {
        0
    } else {
        f.abs().log10().floor() as i32
    };
    if !(-4..21).contains(&exp) {
        let s = format!("{f:e}");
        if let Some((mantissa, e)) = s.split_once('e') {
            let e: i32 = e.parse().unwrap_or(0);
            return format!("{mantissa}e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs());
        }
    }
    f.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn eval(path: &str, obj: &Value) -> Option<Value> {
        first_result(&parse(path).unwrap(), obj).cloned()
    }

    /// CRD authors copy these from upstream docs and operators; each must parse or the CRD
    /// cannot be created even though the reference apiserver accepts it.
    #[test]
    fn parser_accepts_every_construct_upstream_accepts() {
        for p in [
            ".a.b",
            ".",
            ".status.conditions[?(@.type==\"Ready\")].status",
            ".status.conditions[?(@.type=='Ready')].status",
            ".a[?(@.n>=2)].x",
            ".a[?(@.ok)].x",
            "..name",
            ".a..name",
            ".a[0:2]",
            ".a[:2]",
            ".a[1:]",
            ".a[::2]",
            ".a[-1]",
            ".a[-2:]",
            ".a[0,1]",
            ".a[*]",
            ".a.*",
            ".a['b.c']",
            ".metadata.labels.app\\.io/x",
            ".a[ 0 , 1 ]",
        ] {
            assert!(parse(p).is_ok(), "{p}");
        }
    }

    #[test]
    fn parser_rejects_what_upstream_rejects() {
        for p in [
            ".a[",
            ".a[0",
            ".a[?(@.x==1]",
            ".a[abc]",
            ".a[1:2:3:4]",
            "....a",
            ".a \"unterminated",
        ] {
            assert!(parse(p).is_err(), "{p}");
        }
    }

    #[test]
    fn deeply_nested_filters_are_rejected_not_a_stack_overflow() {
        let p = format!(".a{}", "[?(@.a".repeat(100_000));
        assert!(parse(&p).is_err());
    }

    /// The Ready condition lookup is the dominant printer column in real operators.
    #[test]
    fn filter_selects_the_condition_by_type() {
        let obj = json!({"status": {"conditions": [
            {"type": "Scheduled", "status": "True"},
            {"type": "Ready", "status": "False"},
            {"nope": 1}
        ]}});
        assert_eq!(
            eval(".status.conditions[?(@.type==\"Ready\")].status", &obj),
            Some(json!("False"))
        );
        assert_eq!(
            eval(".status.conditions[?(@.type!=\"Ready\")].status", &obj),
            Some(json!("True"))
        );
        assert_eq!(
            eval(".status.conditions[?(@.type==\"Gone\")].status", &obj),
            None
        );
        let nums = json!({"a": [{"n": 1, "ok": true}, {"n": 5, "ok": false}]});
        assert_eq!(eval(".a[?(@.n>2)].n", &nums), Some(json!(5)));
        assert_eq!(eval(".a[?(@.ok==false)].n", &nums), Some(json!(5)));
        assert_eq!(eval(".a[?(@.n==5)].n", &nums), Some(json!(5)));
    }

    #[test]
    fn slices_negative_indexes_wildcards_unions_and_recursion_evaluate() {
        let obj = json!({"a": ["x", "y", "z"], "m": {"k": {"name": "deep"}}, "l.b": 3});
        assert_eq!(eval(".a[-1]", &obj), Some(json!("z")));
        assert_eq!(eval(".a[1:]", &obj), Some(json!("y")));
        assert_eq!(eval(".a[::2]", &obj), Some(json!("x")));
        assert_eq!(eval(".a[*]", &obj), Some(json!("x")));
        assert_eq!(eval(".a[2,0]", &obj), Some(json!("z")));
        assert_eq!(eval("..name", &obj), Some(json!("deep")));
        assert_eq!(eval(".l\\.b", &obj), Some(json!(3)));
    }

    /// Upstream yields a nil cell (never an error) when evaluation fails.
    #[test]
    fn unevaluable_constructs_yield_no_value() {
        let obj = json!({"a": ["x"], "m": {"k": 1}});
        assert_eq!(eval(".a[5]", &obj), None, "out of bounds");
        assert_eq!(eval(".m[0]", &obj), None, "index on a map");
        assert_eq!(eval(".a[?(@.x==1)]", &obj), None, "filter over scalars");
        assert_eq!(eval(".a range", &obj), None, "identifier");
    }

    #[test]
    fn exploding_unions_hit_the_result_cap_instead_of_running_away() {
        let mut tree = json!(0);
        for _ in 0..10 {
            tree = json!([tree.clone(), tree]);
        }
        let obj = json!({ "t": tree });
        assert_eq!(eval(&format!(".t{}", "[*,*]".repeat(9)), &obj), None);
        assert!(eval(&format!(".t{}", "[*,*]".repeat(4)), &obj).is_some());
    }

    #[test]
    fn print_value_matches_go_formatting() {
        assert_eq!(print_value(&json!(1.5)), "1.5");
        assert_eq!(print_value(&json!(1e21)), "1e+21");
        assert_eq!(print_value(&json!(0.00001)), "1e-05");
        assert_eq!(print_value(&json!(true)), "true");
        assert_eq!(
            print_value(&json!({"b": 1, "a": [1, "x"]})),
            r#"{"a":[1,"x"],"b":1}"#
        );
    }
}
