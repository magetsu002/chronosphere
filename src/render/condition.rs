//! Tiny when-condition evaluator. Grammar:
//!
//! ```text
//! expr      := or_expr
//! or_expr   := and_expr ('or' and_expr)*
//! and_expr  := not_expr ('and' not_expr)*
//! not_expr  := 'not' not_expr | atom
//! atom      := '(' expr ')' | comparison | bool_ident
//! comparison := ident ( '==' | '!=' ) string_lit
//!             | ident 'in' '[' string_lit (',' string_lit)* ']'
//! ident     := dotted-path
//! string_lit := "'" non-quote-chars "'"
//! ```
//!
//! Anything we can't parse evaluates to `true` (fail-open) so that a typo doesn't hide commands;
//! the parser error is logged but doesn't crash rendering.

use super::context::RenderContext;

pub fn evaluate(expr: &str, ctx: &RenderContext) -> bool {
    match parse(expr) {
        Ok(node) => node.eval(ctx),
        Err(err) => {
            tracing::warn!(?err, expression = expr, "invalid when-condition; treating as false");
            false
        }
    }
}

pub fn validate(expr: &str) -> Result<(), String> {
    parse(expr).map(|_| ())
}

fn parse(expr: &str) -> Result<Node, String> {
    let tokens = tokenize(expr)?;
    let mut parser = Parser {
        tokens: &tokens,
        idx: 0,
    };
    let node = parser.parse_expr()?;
    if parser.idx != tokens.len() {
        return Err(format!("trailing tokens: {:?}", &tokens[parser.idx..]));
    }
    Ok(node)
}

#[derive(Debug, PartialEq, Eq)]

enum Tok {
    Ident(String),
    Str(String),
    Eq,
    Neq,
    In,
    And,
    Or,
    Not,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
}

fn tokenize(s: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '[' => {
                out.push(Tok::LBracket);
                i += 1;
            }
            ']' => {
                out.push(Tok::RBracket);
                i += 1;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            '=' if i + 1 < bytes.len() && bytes[i + 1] as char == '=' => {
                out.push(Tok::Eq);
                i += 2;
            }
'&' if i + 1 < bytes.len() && bytes[i + 1] as char == '&' => {
    out.push(Tok::And);
    i += 2;
}
'|' if i + 1 < bytes.len() && bytes[i + 1] as char == '|' => {
    out.push(Tok::Or);
    i += 2;
}
'!' if i + 1 < bytes.len() && bytes[i + 1] as char == '=' => {
                out.push(Tok::Neq);
                i += 2;
            }
            '\'' => {
                let end = s[i + 1..]
                    .find('\'')
                    .ok_or_else(|| format!("unterminated string at {}", i))?;
                out.push(Tok::Str(s[i + 1..i + 1 + end].to_string()));
                i += 1 + end + 1;
            }
            ch if ch.is_ascii_alphabetic() || ch == '_' => {
                let start = i;
                while i < bytes.len() {
                    let cur = bytes[i] as char;
                    if !(cur.is_ascii_alphanumeric() || cur == '_' || cur == '.') {
                        break;
                    }
                    i += 1;
                }
                let word = &s[start..i];
                match word {
                    "and" => out.push(Tok::And),
                    "or" => out.push(Tok::Or),
                    "not" => out.push(Tok::Not),
                    "in" => out.push(Tok::In),
                    "true" => out.push(Tok::Ident("__true__".into())),
                    "false" => out.push(Tok::Ident("__false__".into())),
                    other => out.push(Tok::Ident(other.to_string())),
                }
            }
            other => return Err(format!("unexpected char '{}' at {}", other, i)),
        }
    }
    Ok(out)
}

#[derive(Debug)]
enum Node {
    Or(Box<Node>, Box<Node>),
    And(Box<Node>, Box<Node>),
    Not(Box<Node>),
    Eq(String, String),
    Neq(String, String),
    In(String, Vec<String>),
    BoolIdent(String),
}

impl Node {
    fn eval(&self, ctx: &RenderContext) -> bool {
        match self {
            Node::Or(a, b) => a.eval(ctx) || b.eval(ctx),
            Node::And(a, b) => a.eval(ctx) && b.eval(ctx),
            Node::Not(a) => !a.eval(ctx),
            Node::Eq(id, val) => ctx.lookup_string(id).as_deref() == Some(val.as_str()),
            Node::Neq(id, val) => ctx.lookup_string(id).as_deref() != Some(val.as_str()),
            Node::In(id, opts) => match ctx.lookup_string(id) {
                Some(v) => opts.iter().any(|o| o == &v),
                None => opts.iter().any(|o| o == "none"),
            },
            Node::BoolIdent(name) => match name.as_str() {
                "__true__" => true,
                "__false__" => false,
                other => ctx.lookup_bool(other).unwrap_or(false),
            },
        }
    }
}

struct Parser<'a> {
    tokens: &'a [Tok],
    idx: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.idx)
    }
    fn bump(&mut self) -> Option<&Tok> {
        let t = self.tokens.get(self.idx);
        if t.is_some() {
            self.idx += 1;
        }
        t
    }
    fn parse_expr(&mut self) -> Result<Node, String> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.bump();
            let right = self.parse_and()?;
            left = Node::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    fn parse_and(&mut self) -> Result<Node, String> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.bump();
            let right = self.parse_not()?;
            left = Node::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    fn parse_not(&mut self) -> Result<Node, String> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.bump();
            let inner = self.parse_not()?;
            return Ok(Node::Not(Box::new(inner)));
        }
        self.parse_atom()
    }
    fn parse_atom(&mut self) -> Result<Node, String> {
        match self.peek() {
            Some(Tok::LParen) => {
                self.bump();
                let inner = self.parse_expr()?;
                match self.bump() {
                    Some(Tok::RParen) => Ok(inner),
                    other => Err(format!("expected ')', got {:?}", other)),
                }
            }
            Some(Tok::Ident(_)) => {
                let id = if let Some(Tok::Ident(s)) = self.bump() {
                    s.clone()
                } else {
                    unreachable!()
                };
                match self.peek() {
                    Some(Tok::Eq) => {
                        self.bump();
                        let s = self.expect_string()?;
                        Ok(Node::Eq(id, s))
                    }
                    Some(Tok::Neq) => {
                        self.bump();
                        let s = self.expect_string()?;
                        Ok(Node::Neq(id, s))
                    }
                    Some(Tok::In) => {
                        self.bump();
                        match self.bump() {
                            Some(Tok::LBracket) => {}
                            other => return Err(format!("expected '[', got {:?}", other)),
                        }
                        let mut items = Vec::new();
                        loop {
                            items.push(self.expect_string()?);
                            match self.peek() {
                                Some(Tok::Comma) => {
                                    self.bump();
                                }
                                Some(Tok::RBracket) => {
                                    self.bump();
                                    break;
                                }
                                other => return Err(format!("expected ',' or ']', got {:?}", other)),
                            }
                        }
                        Ok(Node::In(id, items))
                    }
                    _ => Ok(Node::BoolIdent(id)),
                }
            }
            other => Err(format!("unexpected token {:?}", other)),
        }
    }
    fn expect_string(&mut self) -> Result<String, String> {
        match self.bump() {
            Some(Tok::Str(s)) => Ok(s.clone()),
            other => Err(format!("expected string literal, got {:?}", other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engagement::{CredKind, CredentialProfile, Target};

    fn ctx_with(kind: CredKind, has_dc: bool) -> RenderContext {
        let mut c = RenderContext::default();
        c.target = Some(Target {
            name: "t".into(),
            ip: Some("1.1.1.1".into()),
            hostname: None,
            dc_name: if has_dc { Some("DC01".into()) } else { None },
            lhost: None,
            lport: None,
            notes: None,
        });
        c.profile = Some(CredentialProfile {
            name: "p".into(),
            username: "u".into(),
            domain: Some("D".into()),
            kind,
            password: Some("x".into()),
            nt_hash: None,
            ticket_path: None,
            notes: None,
        });
        c
    }

    #[test]
    fn simple_eq() {
        assert!(evaluate(
            "creds.kind == 'plaintext'",
            &ctx_with(CredKind::Plaintext, false)
        ));
        assert!(!evaluate(
            "creds.kind == 'plaintext'",
            &ctx_with(CredKind::Ntlm, false)
        ));
    }

    #[test]
    fn in_list() {
        let c = ctx_with(CredKind::Ntlm, false);
        assert!(evaluate("creds.kind in ['plaintext','ntlm']", &c));
        assert!(!evaluate("creds.kind in ['plaintext','kerberos']", &c));
    }

    #[test]
    fn boolean_logic() {
        let c = ctx_with(CredKind::Plaintext, true);
        assert!(evaluate("creds.kind == 'plaintext' and target.has_dc", &c));
        assert!(evaluate(
            "creds.kind == 'kerberos' or target.has_dc",
            &c
        ));
        assert!(!evaluate(
            "creds.kind == 'kerberos' and target.has_dc",
            &c
        ));
        assert!(evaluate("not (creds.kind == 'kerberos')", &c));
    }

    #[test]
    fn parse_errors_fail_closed() {
        assert!(!evaluate("blah blah blah", &ctx_with(CredKind::Plaintext, false)));
    }
}
