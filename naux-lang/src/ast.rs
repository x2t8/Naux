// TODO: AST definitions
// AST definitions for NAUX Core

#[derive(Debug, Clone)]
pub struct Span {
    pub line: usize,
    pub column: usize,
    // TODO: extend with file/offset for richer error reporting
}

#[derive(Debug, Clone)]
pub enum Expr {
    Number(f64),
    Bool(bool),
    Text(String),
    List(Vec<Expr>),
    Map(Vec<(String, Expr)>),
    Var(String),
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
    Field {
        target: Box<Expr>,
        field: String,
    },
    // TODO: future Call, function literals
}

#[derive(Debug, Clone)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    And,
    Or,
}

#[derive(Debug, Clone)]
pub enum UnaryOp {
    Neg,
    Not,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Rite {
        body: Vec<Stmt>,
        span: Option<Span>,
    },
    Assign {
        name: String,
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
    // TODO: function defs when needed
}

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
    Log {
        value: Expr,
    },
}
