// SPDX-License-Identifier: AGPL-3.0-or-later OR Apache-2.0
// CLONE_GATE:AES256:parse_minikran_v1
//
// parser.rs — MINIKRAN AST + parser
// Turns a token stream into a program (Vec<Statement>).

use crate::lexer::{Tok, Token};

// ── AST TYPES ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BudgetLit {
    pub cpu: u64,
    pub mem: u64,
    pub store: u64,
    pub power: u64,
}

#[derive(Debug, Clone)]
pub struct WorkroomDecl {
    pub id: String,
    pub license: String,
    pub scope: String,
    pub node: String,
    pub expires: u64,
    pub key: u64,
    pub sig: u64,
}

#[derive(Debug, Clone)]
pub struct TaskDecl {
    pub name: String,
    pub id: u64,
    pub priority: u8,
    pub budget: BudgetLit,
    pub deadline: u64,
    pub input_tag: String,
    pub code_tag: String,
    pub verify_policy: String,
    pub recover_policy: String,
    pub parent: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum VerifyResult { Ok, Reject }

/// Every top-level statement in a .mkr file
#[derive(Debug, Clone)]
pub enum Statement {
    Workroom(WorkroomDecl),
    Ceiling(BudgetLit),
    Task(TaskDecl),
    Spawn    { task: String, at: u64 },
    Schedule { task: String, node: u64 },
    Dispatch { task: String, node: u64 },
    Checkpoint { task: String, epoch: u64, id: u64 },
    Verify   { task: String, result: VerifyResult },
    Commit   { task: String },
    Abort    { task: String },
    Fault    { task: String, epoch: u64 },
    Recover  { task: String },
    Restore  { task: String, checkpoint: u64 },
    Retry    { task: String, node: u64 },
    Suspend  { task: String, epoch: u64 },
    Resume   { task: String, epoch: u64 },
}

// ── PARSER ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ParseError {
    pub msg: String,
    pub line: usize,
    pub col: usize,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "parse error at {}:{}: {}", self.line, self.col, self.msg)
    }
}

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self { Self { tokens, pos: 0 } }

    fn peek(&self) -> &Tok { &self.tokens[self.pos].tok }
    fn span_line(&self) -> usize { self.tokens[self.pos].span.line }
    fn span_col(&self) -> usize { self.tokens[self.pos].span.col }

    fn advance(&mut self) -> &Tok {
        let t = &self.tokens[self.pos].tok;
        if self.pos + 1 < self.tokens.len() { self.pos += 1; }
        t
    }

    fn err(&self, msg: impl Into<String>) -> ParseError {
        ParseError { msg: msg.into(), line: self.span_line(), col: self.span_col() }
    }

    fn expect(&mut self, expected: &Tok) -> Result<(), ParseError> {
        if std::mem::discriminant(self.peek()) == std::mem::discriminant(expected) {
            self.advance();
            Ok(())
        } else {
            Err(self.err(format!("expected {expected:?}, got {:?}", self.peek())))
        }
    }

    fn expect_ident(&mut self) -> Result<String, ParseError> {
        match self.advance().clone() {
            Tok::Ident(s) => Ok(s),
            other => Err(self.err(format!("expected identifier, got {other:?}"))),
        }
    }

    fn expect_str(&mut self) -> Result<String, ParseError> {
        match self.advance().clone() {
            Tok::Str(s) => Ok(s),
            other => Err(self.err(format!("expected string literal, got {other:?}"))),
        }
    }

    fn expect_int(&mut self) -> Result<u64, ParseError> {
        match self.advance().clone() {
            Tok::Int(n) => Ok(n),
            Tok::Hex(n) => Ok(n),
            other => Err(self.err(format!("expected integer, got {other:?}"))),
        }
    }

    fn expect_int_or_hex(&mut self) -> Result<u64, ParseError> {
        match self.advance().clone() {
            Tok::Int(n) | Tok::Hex(n) => Ok(n),
            other => Err(self.err(format!("expected integer/hex, got {other:?}"))),
        }
    }

    fn task_name(&mut self) -> Result<String, ParseError> {
        match self.advance().clone() {
            Tok::Ident(s) => Ok(s),
            other => Err(self.err(format!("expected task name, got {other:?}"))),
        }
    }

    /// Parse key:value where value is int/hex/string/hash/ident
    fn parse_budget_block(&mut self) -> Result<BudgetLit, ParseError> {
        self.expect(&Tok::LBrace)?;
        let mut cpu=0u64; let mut mem=0u64; let mut store=0u64; let mut power=0u64;
        loop {
            if matches!(self.peek(), Tok::RBrace) { self.advance(); break; }
            match self.advance().clone() {
                Tok::Cpu   => { self.expect(&Tok::Colon)?; cpu   = self.expect_int()?; }
                Tok::Mem   => { self.expect(&Tok::Colon)?; mem   = self.expect_int()?; }
                Tok::Store => { self.expect(&Tok::Colon)?; store = self.expect_int()?; }
                Tok::Power => { self.expect(&Tok::Colon)?; power = self.expect_int()?; }
                Tok::Comma => {}
                other => return Err(self.err(format!("unexpected in budget block: {other:?}"))),
            }
        }
        Ok(BudgetLit { cpu, mem, store, power })
    }

    fn parse_workroom(&mut self) -> Result<WorkroomDecl, ParseError> {
        let id = self.expect_str()?;
        self.expect(&Tok::LBrace)?;
        let mut license=String::new(); let mut scope=String::new();
        let mut node=String::new(); let mut expires=0u64;
        let mut key=0u64; let mut sig=0u64;
        loop {
            if matches!(self.peek(), Tok::RBrace) { self.advance(); break; }
            match self.advance().clone() {
                Tok::License => { self.expect(&Tok::Colon)?; license = self.expect_str()?; }
                Tok::Scope   => { self.expect(&Tok::Colon)?; scope   = self.expect_str()?; }
                Tok::Node    => { self.expect(&Tok::Colon)?; node    = self.expect_str()?; }
                Tok::Expires => { self.expect(&Tok::Colon)?; expires = self.expect_int()?; }
                Tok::Key     => { self.expect(&Tok::Colon)?; key     = self.expect_int_or_hex()?; }
                Tok::Sig     => { self.expect(&Tok::Colon)?; sig     = self.expect_int_or_hex()?; }
                other => return Err(self.err(format!("unexpected in workroom block: {other:?}"))),
            }
        }
        Ok(WorkroomDecl { id, license, scope, node, expires, key, sig })
    }

    fn parse_task(&mut self) -> Result<TaskDecl, ParseError> {
        let name = self.expect_ident()?;
        self.expect(&Tok::LBrace)?;
        let mut id=0u64; let mut priority=1u8; let mut budget=BudgetLit{cpu:1,mem:1,store:1,power:1};
        let mut deadline=u64::MAX; let mut input_tag=String::new(); let mut code_tag=String::new();
        let mut verify_policy="proof".to_string(); let mut recover_policy="restore".to_string();
        let mut parent:Option<u64>=None;
        loop {
            if matches!(self.peek(), Tok::RBrace) { self.advance(); break; }
            match self.advance().clone() {
                Tok::Ident(k) if k=="id" => { self.expect(&Tok::Colon)?; id = self.expect_int()?; }
                Tok::Priority  => { self.expect(&Tok::Colon)?; priority = self.expect_int()? as u8; }
                Tok::Budget    => { budget = self.parse_budget_block()?; }
                Tok::Deadline  => { self.expect(&Tok::Colon)?; deadline = self.expect_int()?; }
                Tok::Input     => { self.expect(&Tok::Colon)?;
                    match self.advance().clone() {
                        Tok::Hash(s) | Tok::Str(s) | Tok::Ident(s) => input_tag = s,
                        other => return Err(self.err(format!("expected input tag, got {other:?}"))),
                    }
                }
                Tok::Code      => { self.expect(&Tok::Colon)?;
                    match self.advance().clone() {
                        Tok::Hash(s) | Tok::Str(s) | Tok::Ident(s) => code_tag = s,
                        other => return Err(self.err(format!("expected code tag, got {other:?}"))),
                    }
                }
                Tok::Verify    => { self.expect(&Tok::Colon)?; verify_policy = self.expect_ident()?; }
                Tok::Recover   => { self.expect(&Tok::Colon)?; recover_policy = self.expect_ident()?; }
                Tok::Ident(k) if k=="parent" => {
                    self.expect(&Tok::Colon)?;
                    match self.peek() {
                        Tok::Ident(n) if n=="none" => { self.advance(); }
                        _ => { parent = Some(self.expect_int()?); }
                    }
                }
                other => return Err(self.err(format!("unexpected in task block: {other:?}"))),
            }
        }
        Ok(TaskDecl { name, id, priority, budget, deadline, input_tag, code_tag, verify_policy, recover_policy, parent })
    }

    // Parse `key:value` pair after a command keyword
    fn kv_u64(&mut self, key: &Tok) -> Result<u64, ParseError> {
        self.expect(key)?;
        self.expect(&Tok::Colon)?;
        self.expect_int()
    }

    pub fn parse_program(&mut self) -> Result<Vec<Statement>, ParseError> {
        let mut stmts = Vec::new();
        loop {
            match self.peek().clone() {
                Tok::Eof => break,

                Tok::Workroom => { self.advance(); stmts.push(Statement::Workroom(self.parse_workroom()?)); }
                Tok::Ceiling  => { self.advance(); stmts.push(Statement::Ceiling(self.parse_budget_block()?)); }
                Tok::Task     => { self.advance(); stmts.push(Statement::Task(self.parse_task()?)); }

                // spawn task-name at TICK
                Tok::Spawn => {
                    self.advance();
                    let task = self.task_name()?;
                    self.expect(&Tok::Ident("at".to_string()))?;
                    let at = self.expect_int()?;
                    stmts.push(Statement::Spawn { task, at });
                }

                // schedule task-name -> node:NODE_ID
                Tok::Schedule => {
                    self.advance();
                    let task = self.task_name()?;
                    self.expect(&Tok::Arrow)?;
                    self.expect(&Tok::Node)?;
                    self.expect(&Tok::Colon)?;
                    let node = self.expect_int()?;
                    stmts.push(Statement::Schedule { task, node });
                }

                // dispatch task-name @ node:NODE_ID
                Tok::Dispatch => {
                    self.advance();
                    let task = self.task_name()?;
                    self.expect(&Tok::At)?;
                    self.expect(&Tok::Node)?;
                    self.expect(&Tok::Colon)?;
                    let node = self.expect_int()?;
                    stmts.push(Statement::Dispatch { task, node });
                }

                // checkpoint task-name epoch:E -> cp:ID
                Tok::Checkpoint => {
                    self.advance();
                    let task = self.task_name()?;
                    let epoch = self.kv_u64(&Tok::Epoch)?;
                    self.expect(&Tok::Arrow)?;
                    self.expect(&Tok::Ident("cp".to_string()))?;
                    self.expect(&Tok::Colon)?;
                    let id = self.expect_int()?;
                    stmts.push(Statement::Checkpoint { task, epoch, id });
                }

                // verify task-name ok | reject
                Tok::Verify => {
                    self.advance();
                    let task = self.task_name()?;
                    let result = match self.advance().clone() {
                        Tok::Ok     => VerifyResult::Ok,
                        Tok::Reject => VerifyResult::Reject,
                        other => return Err(self.err(format!("expected 'ok' or 'reject', got {other:?}"))),
                    };
                    stmts.push(Statement::Verify { task, result });
                }

                // commit task-name
                Tok::Commit  => { self.advance(); stmts.push(Statement::Commit  { task: self.task_name()? }); }

                // abort task-name
                Tok::Abort   => { self.advance(); stmts.push(Statement::Abort   { task: self.task_name()? }); }

                // fault task-name epoch:E
                Tok::Fault   => {
                    self.advance();
                    let task = self.task_name()?;
                    let epoch = self.kv_u64(&Tok::Epoch)?;
                    stmts.push(Statement::Fault { task, epoch });
                }

                // recover task-name
                Tok::Recover => { self.advance(); stmts.push(Statement::Recover { task: self.task_name()? }); }

                // restore task-name <- cp:ID
                Tok::Restore => {
                    self.advance();
                    let task = self.task_name()?;
                    self.expect(&Tok::BackArrow)?;
                    self.expect(&Tok::Ident("cp".to_string()))?;
                    self.expect(&Tok::Colon)?;
                    let checkpoint = self.expect_int()?;
                    stmts.push(Statement::Restore { task, checkpoint });
                }

                // retry task-name -> node:NODE_ID
                Tok::Retry => {
                    self.advance();
                    let task = self.task_name()?;
                    self.expect(&Tok::Arrow)?;
                    self.expect(&Tok::Node)?;
                    self.expect(&Tok::Colon)?;
                    let node = self.expect_int()?;
                    stmts.push(Statement::Retry { task, node });
                }

                // suspend task-name epoch:E
                Tok::Suspend => {
                    self.advance();
                    let task = self.task_name()?;
                    let epoch = self.kv_u64(&Tok::Epoch)?;
                    stmts.push(Statement::Suspend { task, epoch });
                }

                // resume task-name epoch:E
                Tok::Resume => {
                    self.advance();
                    let task = self.task_name()?;
                    let epoch = self.kv_u64(&Tok::Epoch)?;
                    stmts.push(Statement::Resume { task, epoch });
                }

                other => return Err(self.err(format!("unexpected top-level token: {other:?}"))),
            }
        }
        Ok(stmts)
    }
}
