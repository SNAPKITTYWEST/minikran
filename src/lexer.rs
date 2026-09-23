// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
// CLONE_GATE:AES256:lex_minikran_v1
//
// lexer.rs — MINIKRAN tokenizer
// Turns .mkr source text into a flat token stream.

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    // Keywords
    Workroom, Ceiling, Task,
    Spawn, Schedule, Dispatch, Checkpoint,
    Verify, Commit, Fault, Recover, Restore, Retry,
    Abort, Suspend, Resume,
    // Attribute words
    License, Scope, Node, Expires, Key, Sig,
    Priority, Budget, Deadline, Input, Code,
    Cpu, Mem, Store, Power,
    Ok, Reject,
    Epoch,
    // Punctuation
    LBrace, RBrace, Colon, Arrow, BackArrow, At, Comma,
    // Literals
    Ident(String),
    Str(String),
    Int(u64),
    Hex(u64),
    Hash(String), // #sha256:...
    // Special
    Eof,
}

#[derive(Debug, Clone)]
pub struct Span {
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub tok: Tok,
    pub span: Span,
}

#[derive(Debug)]
pub struct LexError {
    pub msg: String,
    pub line: usize,
    pub col: usize,
}

impl std::fmt::Display for LexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lex error at {}:{}: {}", self.line, self.col, self.msg)
    }
}

pub struct Lexer<'s> {
    src: &'s [u8],
    pos: usize,
    line: usize,
    col: usize,
}

impl<'s> Lexer<'s> {
    pub fn new(src: &'s str) -> Self {
        Self { src: src.as_bytes(), pos: 0, line: 1, col: 1 }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let c = self.src.get(self.pos).copied()?;
        self.pos += 1;
        if c == b'\n' { self.line += 1; self.col = 1; }
        else { self.col += 1; }
        Some(c)
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                self.advance();
            }
            if self.src.get(self.pos..self.pos+2) == Some(b"--") {
                while !matches!(self.peek(), Some(b'\n') | None) {
                    self.advance();
                }
            } else {
                break;
            }
        }
    }

    fn span(&self) -> Span { Span { line: self.line, col: self.col } }

    fn read_ident(&mut self, first: u8) -> String {
        let mut s = vec![first];
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
            s.push(self.advance().unwrap());
        }
        String::from_utf8(s).unwrap()
    }

    fn read_string(&mut self) -> Result<String, LexError> {
        let mut s = Vec::new();
        loop {
            match self.advance() {
                None => return Err(LexError { msg: "unterminated string".into(), line: self.line, col: self.col }),
                Some(b'"') => break,
                Some(b'\\') => match self.advance() {
                    Some(b'n') => s.push(b'\n'),
                    Some(b't') => s.push(b'\t'),
                    Some(c) => s.push(c),
                    None => return Err(LexError { msg: "unterminated escape".into(), line: self.line, col: self.col }),
                },
                Some(c) => s.push(c),
            }
        }
        Ok(String::from_utf8_lossy(&s).into_owned())
    }

    fn read_int(&mut self, first: u8) -> Result<u64, LexError> {
        let mut s = vec![first];
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            s.push(self.advance().unwrap());
        }
        let text = String::from_utf8(s).unwrap();
        text.parse::<u64>().map_err(|_| LexError { msg: format!("invalid integer {text}"), line: self.line, col: self.col })
    }

    fn read_hex(&mut self) -> Result<u64, LexError> {
        // already consumed 0x
        let mut s = Vec::new();
        while matches!(self.peek(), Some(c) if c.is_ascii_hexdigit() || c == b'_') {
            let c = self.advance().unwrap();
            if c != b'_' { s.push(c); }
        }
        let text = String::from_utf8(s).unwrap();
        u64::from_str_radix(&text, 16).map_err(|_| LexError {
            msg: format!("invalid hex 0x{text}"), line: self.line, col: self.col
        })
    }

    fn read_hash(&mut self) -> String {
        // consumed '#', read until whitespace/special
        let mut s = Vec::new();
        while matches!(self.peek(), Some(c) if !c.is_ascii_whitespace() && c != b'}' && c != b',') {
            s.push(self.advance().unwrap());
        }
        String::from_utf8(s).unwrap()
    }

    fn keyword_or_ident(s: String) -> Tok {
        match s.as_str() {
            "workroom"   => Tok::Workroom,
            "ceiling"    => Tok::Ceiling,
            "task"       => Tok::Task,
            "spawn"      => Tok::Spawn,
            "schedule"   => Tok::Schedule,
            "dispatch"   => Tok::Dispatch,
            "checkpoint" => Tok::Checkpoint,
            "verify"     => Tok::Verify,
            "commit"     => Tok::Commit,
            "fault"      => Tok::Fault,
            "recover"    => Tok::Recover,
            "restore"    => Tok::Restore,
            "retry"      => Tok::Retry,
            "abort"      => Tok::Abort,
            "suspend"    => Tok::Suspend,
            "resume"     => Tok::Resume,
            "license"    => Tok::License,
            "scope"      => Tok::Scope,
            "node"       => Tok::Node,
            "expires"    => Tok::Expires,
            "key"        => Tok::Key,
            "sig"        => Tok::Sig,
            "priority"   => Tok::Priority,
            "budget"     => Tok::Budget,
            "deadline"   => Tok::Deadline,
            "input"      => Tok::Input,
            "code"       => Tok::Code,
            "cpu"        => Tok::Cpu,
            "mem"        => Tok::Mem,
            "store"      => Tok::Store,
            "power"      => Tok::Power,
            "ok"         => Tok::Ok,
            "reject"     => Tok::Reject,
            "epoch"      => Tok::Epoch,
            _            => Tok::Ident(s),
        }
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>, LexError> {
        let mut tokens = Vec::new();
        loop {
            self.skip_whitespace_and_comments();
            let span = self.span();
            let c = match self.peek() {
                None => { tokens.push(Token { tok: Tok::Eof, span }); break; }
                Some(c) => { self.advance(); c }
            };
            let tok = match c {
                b'{' => Tok::LBrace,
                b'}' => Tok::RBrace,
                b':' => Tok::Colon,
                b',' => Tok::Comma,
                b'@' => Tok::At,
                b'-' => {
                    if self.peek() == Some(b'>') { self.advance(); Tok::Arrow }
                    else { return Err(LexError { msg: "bare '-' — did you mean '->'?".into(), line: span.line, col: span.col }); }
                }
                b'<' => {
                    if self.peek() == Some(b'-') { self.advance(); Tok::BackArrow }
                    else { return Err(LexError { msg: "bare '<'".into(), line: span.line, col: span.col }); }
                }
                b'"' => Tok::Str(self.read_string()?),
                b'#' => Tok::Hash(self.read_hash()),
                b'0' if self.peek() == Some(b'x') || self.peek() == Some(b'X') => {
                    self.advance(); Tok::Hex(self.read_hex()?)
                }
                d if d.is_ascii_digit() => Tok::Int(self.read_int(d)?),
                a if a.is_ascii_alphabetic() || a == b'_' => {
                    let s = self.read_ident(a);
                    Self::keyword_or_ident(s)
                }
                other => return Err(LexError {
                    msg: format!("unexpected character '{}'", other as char),
                    line: span.line, col: span.col,
                }),
            };
            tokens.push(Token { tok, span });
        }
        Ok(tokens)
    }
}
