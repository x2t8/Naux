use std::fmt;

pub const CORE_SCHEMA_NAME: &str = "core-n0";
pub const CORE_SCHEMA_VERSION: (u16, u16, u16) = (0, 1, 0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaVersion {
    pub name: String,
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl SchemaVersion {
    pub fn core_n0() -> Self {
        Self {
            name: CORE_SCHEMA_NAME.to_owned(),
            major: CORE_SCHEMA_VERSION.0,
            minor: CORE_SCHEMA_VERSION.1,
            patch: CORE_SCHEMA_VERSION.2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FunctionId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegionId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreProfile {
    /// The deliberately bounded subset accepted by the first Core-N0
    /// implementation and the P1 lighthouse.
    P1V0,
    /// A strict superset of P1V0 with invocation-local logical stores,
    /// lexical regions, and non-escaping shared scalar references.
    P1V1,
    /// A strict superset of P1V1 with typed local-only existential closures
    /// and ordered tuple environments.
    P1V2,
    /// A strict superset of P1V2 with typed operations and affine implicit
    /// lexical handlers.
    P1V3,
    /// A strict superset of P1V3 with verifier-owned affine direct Unique
    /// references and ownership transfer.
    P1V4,
    /// A strict superset of P1V4 with one anchored direct Unique owner
    /// returned across an internal direct-call boundary.
    P1V5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mutability {
    Read,
    Unique,
    Shared,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConstructorType {
    pub name: String,
    pub fields: Vec<Type>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SumType {
    pub name: String,
    pub constructors: Vec<ConstructorType>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Type {
    Unit,
    Bool,
    I64,
    F64,
    Text,
    Bytes,
    Tuple(Vec<Type>),
    Sum(SumType),
    Array {
        region: RegionId,
        mutability: Mutability,
        element: Box<Type>,
    },
    Ref {
        region: RegionId,
        mutability: Mutability,
        element: Box<Type>,
    },
    Function {
        parameters: Vec<Type>,
        effects: EffectRow,
        result: Box<Type>,
    },
    Closure {
        parameters: Vec<Type>,
        effects: EffectRow,
        result: Box<Type>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OperationSignature {
    pub id: OperationId,
    pub parameters: Vec<Type>,
    pub result: Box<Type>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorKind {
    Overflow,
    Bounds,
    DivisionByZero,
    User(u32),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effect {
    State(RegionId),
    Alloc(RegionId),
    Error(ErrorKind),
    Io,
    Ffi([u8; 32]),
    UnsafeMemory([u8; 32]),
    Operation(OperationSignature),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct EffectRow {
    pub effects: Vec<Effect>,
}

impl EffectRow {
    pub fn pure() -> Self {
        Self::default()
    }

    pub fn canonical(mut effects: Vec<Effect>) -> Self {
        effects.sort();
        effects.dedup();
        Self { effects }
    }

    pub fn contains(&self, effect: &Effect) -> bool {
        self.effects.contains(effect)
    }

    pub fn contains_all(&self, other: &Self) -> bool {
        other.effects.iter().all(|effect| self.contains(effect))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumericMode {
    Checked,
    Wrapping,
    Saturating,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Primitive {
    I64Add(NumericMode),
    I64Sub(NumericMode),
    I64Mul(NumericMode),
    F64Add,
    F64Sub,
    I64CmpLt,
    I64CmpGe,
    ArrayLenF64,
    ArrayGetF64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Operand {
    Unit,
    Bool(bool),
    I64(i64),
    F64(f64),
    Local(LocalId),
}

#[derive(Clone, Debug, PartialEq)]
pub enum RValue {
    Use(Operand),
    Tuple(Vec<Operand>),
    Project {
        tuple: Operand,
        index: u32,
    },
    Construct {
        sum: SumType,
        constructor: u32,
        fields: Vec<Operand>,
    },
    Primitive {
        operation: Primitive,
        arguments: Vec<Operand>,
    },
    Call {
        function: FunctionId,
        arguments: Vec<Operand>,
    },
    RefAlloc {
        region: RegionId,
        mutability: Mutability,
        value: Operand,
    },
    RefLoad {
        reference: Operand,
    },
    RefStore {
        reference: Operand,
        value: Operand,
    },
    PackClosure {
        function: FunctionId,
        captures: Vec<Operand>,
    },
    CallClosure {
        closure: Operand,
        arguments: Vec<Operand>,
    },
    Perform {
        operation: OperationSignature,
        arguments: Vec<Operand>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct HandlerClause {
    pub operation: OperationSignature,
    pub parameters: Vec<LocalId>,
    pub body: Box<Term>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CaseArm {
    pub constructor: u32,
    pub bindings: Vec<LocalId>,
    pub body: Term,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Term {
    Let {
        binder: LocalId,
        ty: Type,
        value: RValue,
        next: Box<Term>,
    },
    If {
        condition: Operand,
        then_term: Box<Term>,
        else_term: Box<Term>,
    },
    Case {
        scrutinee: Operand,
        arms: Vec<CaseArm>,
    },
    TailCall {
        function: FunctionId,
        arguments: Vec<Operand>,
    },
    Return(Operand),
    Region {
        region: RegionId,
        body: Box<Term>,
    },
    Handle {
        captures: Vec<Operand>,
        capture_parameters: Vec<Parameter>,
        clauses: Vec<HandlerClause>,
        body: Box<Term>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    pub local: LocalId,
    pub ty: Type,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Function {
    pub id: FunctionId,
    pub region_parameters: Vec<RegionId>,
    pub parameters: Vec<Parameter>,
    pub effects: EffectRow,
    pub result: Type,
    pub body: Term,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Program {
    pub schema: SchemaVersion,
    pub profile: CoreProfile,
    pub entry: FunctionId,
    /// Canonical artifacts store functions in strictly increasing ID order.
    pub functions: Vec<Function>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticHash(pub [u8; 32]);

impl SemanticHash {
    pub const ZERO: Self = Self([0; 32]);

    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut result = String::with_capacity(64);
        for byte in self.0 {
            result.push(HEX[(byte >> 4) as usize] as char);
            result.push(HEX[(byte & 0x0f) as usize] as char);
        }
        result
    }
}

impl fmt::Display for SemanticHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CoreArtifact {
    pub program: Program,
    pub semantic_hash: SemanticHash,
}
