#![allow(dead_code)]

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Option<Span>,
}

#[derive(Debug, Clone)]
pub enum ExprKind {
    Number(f64),
    Bool(bool),
    Text(String),
    Bytes(Vec<u8>),
    List(Vec<Expr>),
    Map(Vec<(String, Expr)>),
    Var(String),
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
    },
    Index {
        target: Box<Expr>,
        index: Box<Expr>,
    },
    Fn(Box<FnExpr>),
    Field {
        target: Box<Expr>,
        field: String,
    },
}

/// A refinement type annotation: `Num`, `{Num | v > 0}`, etc.
#[derive(Debug, Clone)]
pub struct TypeAnnotation {
    pub base: String,
    pub predicate: Option<String>,
}

/// A function parameter with optional type annotation.
#[derive(Debug, Clone)]
pub struct Param {
    pub name: String,
    pub annotation: Option<TypeAnnotation>,
}

impl Param {
    pub fn plain(name: String) -> Self {
        Self { name, annotation: None }
    }
}

impl std::fmt::Display for Param {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl From<&str> for Param {
    fn from(s: &str) -> Self {
        Self::plain(s.to_string())
    }
}

impl From<String> for Param {
    fn from(s: String) -> Self {
        Self::plain(s)
    }
}

#[derive(Debug, Clone)]
pub struct FnExpr {
    pub params: Vec<Param>,
    pub body: Vec<Stmt>,
    pub span: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Xor,
    Shl,
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Not,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Stmt {
    Rite {
        body: Vec<Stmt>,
        span: Option<Span>,
    },
    Unsafe {
        body: Vec<Stmt>,
        span: Option<Span>,
    },
    FnDef {
        name: String,
        params: Vec<Param>,
        body: Vec<Stmt>,
        return_type: Option<TypeAnnotation>,
        span: Option<Span>,
    },
    Assign {
        name: String,
        annotation: Option<TypeAnnotation>,
        expr: Expr,
        span: Option<Span>,
    },
    Expr {
        expr: Expr,
        span: Option<Span>,
    },
    If {
        cond: Expr,
        then_block: Vec<Stmt>,
        else_block: Vec<Stmt>,
        span: Option<Span>,
    },
    Loop {
        count: Expr,
        body: Vec<Stmt>,
        span: Option<Span>,
    },
    Each {
        var: String,
        iter: Expr,
        body: Vec<Stmt>,
        span: Option<Span>,
    },
    While {
        cond: Expr,
        body: Vec<Stmt>,
        span: Option<Span>,
    },
    Action {
        action: ActionKind,
        span: Option<Span>,
    },
    Return {
        value: Option<Expr>,
        span: Option<Span>,
    },
    Import {
        module: String,
        span: Option<Span>,
    },
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ActionKind {
    Say {
        value: Expr,
    },
    Ui {
        kind: String,
        props: Vec<(String, Expr)>,
    },
    Text {
        value: Expr,
    },
    Button {
        value: Expr,
    },
    Fetch {
        target: Expr,
    },
    Ask {
        prompt: Expr,
    },
    Syscall {
        number: Expr,
        args: Vec<Expr>,
        out: Option<String>,
    },
    Log {
        value: Expr,
    },
}

impl Expr {
    pub fn new(kind: ExprKind, span: Option<Span>) -> Self {
        Self { kind, span }
    }
}
