//! Untimed candidate carrier for the frozen Scope 4 NAUX corpus.
//!
//! This module is intentionally not a benchmark runner. It observes semantic
//! results and execution-path facts only, then fails closed if any accepted
//! kernel element falls back to interpreter indexing.

use crate::core::encoding::sha256;
use crate::core::SemanticHash;
use crate::runtime::value::Value;
use crate::vm::bytecode::{disasm_block, Program};
use crate::vm::compiler::compile_script;
use crate::vm::typed::{is_supported_program, TraceSummary, TypedRunner, UntimedRunObservation};
use crate::{lexer, parser, typecheck};
use std::fmt;

pub const S4_NATIVE_CANDIDATE_SCHEMA_VERSION: (u16, u16, u16) = (0, 1, 0);
pub const S4_NATIVE_CANDIDATE_POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
pub const S4_NATIVE_CANDIDATE_KERNELS: usize = 4;

const CORPUS: &str = include_str!("../../distribution/s4-performance/CORPUS.tsv");
const SOURCES: [(&str, &str); S4_NATIVE_CANDIDATE_KERNELS] = [
    (
        "benchmarks/s4/naux/sum_dense.nx",
        include_str!("../../benchmarks/s4/naux/sum_dense.nx"),
    ),
    (
        "benchmarks/s4/naux/branch_mix.nx",
        include_str!("../../benchmarks/s4/naux/branch_mix.nx"),
    ),
    (
        "benchmarks/s4/naux/dot_product.nx",
        include_str!("../../benchmarks/s4/naux/dot_product.nx"),
    ),
    (
        "benchmarks/s4/naux/list_update.nx",
        include_str!("../../benchmarks/s4/naux/list_update.nx"),
    ),
];

const SOURCE_DOMAIN: &[u8] = b"NAUX:s4:native-candidate:source:v1\0";
const PROGRAM_DOMAIN: &[u8] = b"NAUX:s4:native-candidate:program:v1\0";
const RECORD_DOMAIN: &[u8] = b"NAUX:s4:native-candidate:record:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:s4:native-candidate:evidence:v1\0";
const CORPUS_AUTHORITY_DOMAIN: &[u8] = b"NAUX:s4-benchmark:corpus:v1\0";
const CORPUS_MAGIC: &str = "NAUX-S4-BENCHMARK-CORPUS\t1";
const CORPUS_METADATA: [&str; 3] = [
    "meta\tdataset\tn16384-r50-v1",
    "meta\tnumeric-domain\tbinary64-exact-integer-v1",
    "meta\tkernel-count\t4",
];
const KERNEL_IDENTITIES: [(&str, &str, &str, &str, &str, &str, &str); S4_NATIVE_CANDIDATE_KERNELS] = [
    (
        "01",
        "sum-dense",
        "throughput",
        "dense-iteration",
        "benchmarks/s4/naux/sum_dense.nx",
        "benchmarks/c/bench_sum_dense.c",
        "benchmarks/rust/src/bin/bench_sum_dense.rs",
    ),
    (
        "02",
        "branch-mix",
        "control-flow",
        "stateful-branch",
        "benchmarks/s4/naux/branch_mix.nx",
        "benchmarks/c/bench_branch_mix.c",
        "benchmarks/rust/src/bin/bench_branch_mix.rs",
    ),
    (
        "03",
        "dot-product",
        "arithmetic",
        "quadratic-reduction",
        "benchmarks/s4/naux/dot_product.nx",
        "benchmarks/c/bench_dot_product.c",
        "benchmarks/rust/src/bin/bench_dot_product.rs",
    ),
    (
        "04",
        "list-update",
        "allocation-mutation",
        "stateful-list-update",
        "benchmarks/s4/naux/list_update.nx",
        "benchmarks/c/bench_list_update.c",
        "benchmarks/rust/src/bin/bench_list_update.rs",
    ),
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct KernelSpec {
    ordinal: u32,
    name: String,
    source_path: String,
    oracle: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S4NativeCandidateRecord {
    ordinal: u32,
    name: String,
    source_hash: SemanticHash,
    program_hash: SemanticHash,
    result: i64,
    trace_count: u32,
    native_trace_hits: u64,
    static_branches: u64,
    code_bytes: u64,
    hot_code_bytes: u64,
    deopts: u64,
    internal_side_exits: u64,
    guard_failures: u64,
    interpreter_index_elements: u64,
    list_range_calls: u64,
    record_hash: SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S4NativeCandidateEvidence {
    schema_version: (u16, u16, u16),
    policy_version: (u16, u16, u16),
    corpus_hash: SemanticHash,
    records: Vec<S4NativeCandidateRecord>,
    evidence_hash: SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum S4NativeCandidateError {
    UnsupportedHost,
    InvalidCorpus(String),
    Frontend {
        kernel: String,
        message: String,
    },
    UnsupportedProgram(String),
    Execution {
        kernel: String,
        message: String,
    },
    ObservableEvents(String),
    NonIntegralResult(String),
    SemanticMismatch {
        kernel: String,
        expected: i64,
        actual: i64,
    },
    MissingNativeTrace(String),
    NativePathViolation {
        kernel: String,
        field: &'static str,
    },
    EvidenceMismatch,
}

impl fmt::Display for S4NativeCandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost => formatter
                .write_str("S4 native candidate requires the admitted Linux x86-64 trace runner"),
            Self::InvalidCorpus(message) => write!(formatter, "invalid S4 corpus: {message}"),
            Self::Frontend { kernel, message } => {
                write!(formatter, "S4 kernel `{kernel}` frontend failed: {message}")
            }
            Self::UnsupportedProgram(kernel) => {
                write!(
                    formatter,
                    "S4 kernel `{kernel}` is outside the typed native subset"
                )
            }
            Self::Execution { kernel, message } => {
                write!(
                    formatter,
                    "S4 kernel `{kernel}` execution failed: {message}"
                )
            }
            Self::ObservableEvents(kernel) => {
                write!(
                    formatter,
                    "S4 kernel `{kernel}` emitted an observable event"
                )
            }
            Self::NonIntegralResult(kernel) => {
                write!(
                    formatter,
                    "S4 kernel `{kernel}` did not return an exact i64"
                )
            }
            Self::SemanticMismatch {
                kernel,
                expected,
                actual,
            } => write!(
                formatter,
                "S4 kernel `{kernel}` returned {actual}, expected {expected}"
            ),
            Self::MissingNativeTrace(kernel) => {
                write!(formatter, "S4 kernel `{kernel}` produced no native trace")
            }
            Self::NativePathViolation { kernel, field } => {
                write!(
                    formatter,
                    "S4 kernel `{kernel}` violated native path `{field}`"
                )
            }
            Self::EvidenceMismatch => {
                formatter.write_str("S4 native candidate differs from regenerative replay")
            }
        }
    }
}

impl std::error::Error for S4NativeCandidateError {}

pub fn emit_s4_native_candidate() -> Result<S4NativeCandidateEvidence, S4NativeCandidateError> {
    if !cfg!(all(target_arch = "x86_64", target_os = "linux")) {
        return Err(S4NativeCandidateError::UnsupportedHost);
    }
    let specs = parse_corpus()?;
    let mut records = Vec::with_capacity(specs.len());
    for spec in specs {
        records.push(execute_kernel(&spec)?);
    }
    let corpus_hash = hash_domain(SOURCE_DOMAIN, CORPUS.as_bytes());
    let mut evidence = S4NativeCandidateEvidence {
        schema_version: S4_NATIVE_CANDIDATE_SCHEMA_VERSION,
        policy_version: S4_NATIVE_CANDIDATE_POLICY_VERSION,
        corpus_hash,
        records,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = evidence_hash(&evidence);
    Ok(evidence)
}

pub fn verify_s4_native_candidate(
    evidence: &S4NativeCandidateEvidence,
) -> Result<(), S4NativeCandidateError> {
    let regenerated = emit_s4_native_candidate()?;
    if &regenerated == evidence {
        Ok(())
    } else {
        Err(S4NativeCandidateError::EvidenceMismatch)
    }
}

pub fn render_s4_native_candidate(evidence: &S4NativeCandidateEvidence) -> String {
    let mut output = String::new();
    output.push_str("NAUX-S4-NATIVE-CANDIDATE\t1\n");
    output.push_str(&format!(
        "meta\tschema\t{}.{}.{}\nmeta\tpolicy\t{}.{}.{}\nmeta\tcorpus\t{}\n",
        evidence.schema_version.0,
        evidence.schema_version.1,
        evidence.schema_version.2,
        evidence.policy_version.0,
        evidence.policy_version.1,
        evidence.policy_version.2,
        evidence.corpus_hash.to_hex(),
    ));
    output.push_str("columns\tordinal\tkernel\tresult\tsource\tprogram\ttraces\thits\tstatic-branches\tcode-bytes\thot-code-bytes\tdeopts\tside-exits\tguard-failures\tinterpreter-index-elements\tlist-range-calls\trecord\n");
    for record in &evidence.records {
        output.push_str(&format!(
            "kernel\t{:02}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            record.ordinal,
            record.name,
            record.result,
            record.source_hash.to_hex(),
            record.program_hash.to_hex(),
            record.trace_count,
            record.native_trace_hits,
            record.static_branches,
            record.code_bytes,
            record.hot_code_bytes,
            record.deopts,
            record.internal_side_exits,
            record.guard_failures,
            record.interpreter_index_elements,
            record.list_range_calls,
            record.record_hash.to_hex(),
        ));
    }
    output.push_str(&format!(
        "evidence\t{}\nverification\tregenerated\n",
        evidence.evidence_hash.to_hex()
    ));
    output
}

fn parse_corpus() -> Result<Vec<KernelSpec>, S4NativeCandidateError> {
    if !CORPUS.ends_with('\n') || CORPUS.contains(['\r', '\0']) {
        return Err(S4NativeCandidateError::InvalidCorpus(
            "corpus text is not canonical LF UTF-8".into(),
        ));
    }
    let lines: Vec<&str> = CORPUS.lines().collect();
    let expected_line_count = 1 + CORPUS_METADATA.len() + S4_NATIVE_CANDIDATE_KERNELS + 1;
    if lines.len() != expected_line_count
        || lines.first() != Some(&CORPUS_MAGIC)
        || lines[1..=CORPUS_METADATA.len()] != CORPUS_METADATA
    {
        return Err(S4NativeCandidateError::InvalidCorpus(
            "corpus schema or metadata drifted".into(),
        ));
    }
    let seal_fields: Vec<&str> = lines[expected_line_count - 1].split('\t').collect();
    if seal_fields.len() != 2
        || seal_fields[0] != "seal"
        || seal_fields[1].len() != 64
        || !seal_fields[1]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(S4NativeCandidateError::InvalidCorpus(
            "corpus seal is not canonical SHA-256".into(),
        ));
    }
    let seal_line_bytes = lines[expected_line_count - 1].len() + 1;
    let body_len = CORPUS.len().checked_sub(seal_line_bytes).ok_or_else(|| {
        S4NativeCandidateError::InvalidCorpus("corpus seal extent underflowed".into())
    })?;
    let expected_seal = hash_domain(CORPUS_AUTHORITY_DOMAIN, &CORPUS.as_bytes()[..body_len]);
    if expected_seal.to_hex() != seal_fields[1] {
        return Err(S4NativeCandidateError::InvalidCorpus(
            "corpus seal mismatch".into(),
        ));
    }

    let mut specs = Vec::new();
    for (index, line) in lines[1 + CORPUS_METADATA.len()..expected_line_count - 1]
        .iter()
        .enumerate()
    {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 11 || fields.first() != Some(&"kernel") {
            return Err(S4NativeCandidateError::InvalidCorpus(format!(
                "kernel row has {} fields",
                fields.len()
            )));
        }
        let identity = KERNEL_IDENTITIES[index];
        if (
            fields[1], fields[2], fields[3], fields[4], fields[8], fields[9], fields[10],
        ) != identity
        {
            return Err(S4NativeCandidateError::InvalidCorpus(
                "kernel identity or source path drifted".into(),
            ));
        }
        let ordinal = fields[1]
            .parse::<u32>()
            .map_err(|_| S4NativeCandidateError::InvalidCorpus("invalid ordinal".into()))?;
        let oracle = fields[7]
            .parse::<i64>()
            .map_err(|_| S4NativeCandidateError::InvalidCorpus("invalid oracle".into()))?;
        if fields[5] != "16384" || fields[6] != "50" {
            return Err(S4NativeCandidateError::InvalidCorpus(
                "dataset differs from n=16384, reps=50".into(),
            ));
        }
        if specs.len() as u32 + 1 != ordinal {
            return Err(S4NativeCandidateError::InvalidCorpus(
                "kernel ordinals are not canonical".into(),
            ));
        }
        specs.push(KernelSpec {
            ordinal,
            name: fields[2].to_string(),
            source_path: fields[8].to_string(),
            oracle,
        });
    }
    if specs.len() != S4_NATIVE_CANDIDATE_KERNELS {
        return Err(S4NativeCandidateError::InvalidCorpus(format!(
            "expected {S4_NATIVE_CANDIDATE_KERNELS} kernels, found {}",
            specs.len()
        )));
    }
    Ok(specs)
}

fn execute_kernel(spec: &KernelSpec) -> Result<S4NativeCandidateRecord, S4NativeCandidateError> {
    let source = source_for(&spec.source_path)?;
    let tokens = lexer::lex(source).map_err(|error| S4NativeCandidateError::Frontend {
        kernel: spec.name.clone(),
        message: error.message,
    })?;
    let statements =
        parser::parse_script(&tokens).map_err(|error| S4NativeCandidateError::Frontend {
            kernel: spec.name.clone(),
            message: error.message,
        })?;
    typecheck::check_program(&statements).map_err(|error| S4NativeCandidateError::Frontend {
        kernel: spec.name.clone(),
        message: error.message,
    })?;
    let program = compile_script(&statements);
    if !is_supported_program(&program) {
        return Err(S4NativeCandidateError::UnsupportedProgram(
            spec.name.clone(),
        ));
    }

    let mut runner = TypedRunner::new(&program);
    let (warm_value, warm_events, _) =
        runner
            .run_untimed(&program)
            .map_err(|message| S4NativeCandidateError::Execution {
                kernel: spec.name.clone(),
                message,
            })?;
    require_result(spec, &warm_value, &warm_events)?;
    let before = runner.trace_summary();
    if before.trace_count == 0 {
        return Err(S4NativeCandidateError::MissingNativeTrace(
            spec.name.clone(),
        ));
    }

    runner.reset_runtime_path_totals();
    let (value, events, path) =
        runner
            .run_untimed(&program)
            .map_err(|message| S4NativeCandidateError::Execution {
                kernel: spec.name.clone(),
                message,
            })?;
    let result = require_result(spec, &value, &events)?;
    let after = runner.trace_summary();
    let record = record_from(spec, source, &program, result, path, &before, &after)?;
    runner.cleanup();
    Ok(record)
}

fn record_from(
    spec: &KernelSpec,
    source: &str,
    program: &Program,
    result: i64,
    path: UntimedRunObservation,
    before: &TraceSummary,
    after: &TraceSummary,
) -> Result<S4NativeCandidateRecord, S4NativeCandidateError> {
    let trace_count = u32::try_from(after.trace_count).map_err(|_| {
        S4NativeCandidateError::NativePathViolation {
            kernel: spec.name.clone(),
            field: "trace-count-overflow",
        }
    })?;
    let native_trace_hits = after.total_hits.saturating_sub(before.total_hits);
    let deopts = after.total_deopts.saturating_sub(before.total_deopts);
    let internal_side_exits = after
        .total_internal_side_exits
        .saturating_sub(before.total_internal_side_exits);
    let guard_failures = after
        .guard_fail_total
        .saturating_sub(before.guard_fail_total);
    let checks = [
        (native_trace_hits == 0, "native-trace-hits"),
        (after.total_static_branches == 0, "static-branches"),
        (after.max_code_bytes == 0, "code-bytes"),
        (after.max_hot_code_bytes == 0, "hot-code-bytes"),
        (
            after.max_hot_code_bytes > after.max_code_bytes,
            "hot-code-extent",
        ),
        (deopts != 0, "deopts"),
        (internal_side_exits != 0, "internal-side-exits"),
        (guard_failures != 0, "guard-failures"),
        (
            path.interp_index_elements != 0,
            "interpreter-index-elements",
        ),
        (path.list_range_calls != 1, "list-range-calls"),
    ];
    if let Some((_, field)) = checks.into_iter().find(|(failed, _)| *failed) {
        return Err(S4NativeCandidateError::NativePathViolation {
            kernel: spec.name.clone(),
            field,
        });
    }

    let mut record = S4NativeCandidateRecord {
        ordinal: spec.ordinal,
        name: spec.name.clone(),
        source_hash: hash_domain(SOURCE_DOMAIN, source.as_bytes()),
        program_hash: program_hash(program),
        result,
        trace_count,
        native_trace_hits,
        static_branches: after.total_static_branches,
        code_bytes: after.max_code_bytes as u64,
        hot_code_bytes: after.max_hot_code_bytes as u64,
        deopts,
        internal_side_exits,
        guard_failures,
        interpreter_index_elements: path.interp_index_elements,
        list_range_calls: path.list_range_calls,
        record_hash: SemanticHash::ZERO,
    };
    record.record_hash = record_hash(&record);
    Ok(record)
}

fn require_result(
    spec: &KernelSpec,
    value: &Value,
    events: &[crate::runtime::events::RuntimeEvent],
) -> Result<i64, S4NativeCandidateError> {
    if !events.is_empty() {
        return Err(S4NativeCandidateError::ObservableEvents(spec.name.clone()));
    }
    let number = value
        .as_f64()
        .filter(|value| value.is_finite() && value.fract() == 0.0)
        .ok_or_else(|| S4NativeCandidateError::NonIntegralResult(spec.name.clone()))?;
    if number < i64::MIN as f64 || number > i64::MAX as f64 {
        return Err(S4NativeCandidateError::NonIntegralResult(spec.name.clone()));
    }
    let actual = number as i64;
    if actual != spec.oracle {
        return Err(S4NativeCandidateError::SemanticMismatch {
            kernel: spec.name.clone(),
            expected: spec.oracle,
            actual,
        });
    }
    Ok(actual)
}

fn source_for(path: &str) -> Result<&'static str, S4NativeCandidateError> {
    SOURCES
        .iter()
        .find_map(|(candidate, source)| (*candidate == path).then_some(*source))
        .ok_or_else(|| {
            S4NativeCandidateError::InvalidCorpus(format!("unknown NAUX source `{path}`"))
        })
}

fn program_hash(program: &Program) -> SemanticHash {
    let mut bytes = Vec::new();
    put_string(&mut bytes, &disasm_block(&program.main));
    put_strings(&mut bytes, &program.main_locals);
    put_string(&mut bytes, &format!("{:?}", program.main_return));
    let mut functions: Vec<_> = program.functions.iter().collect();
    functions.sort_by_key(|(name, _)| *name);
    put_u32(&mut bytes, functions.len() as u32);
    for (name, function) in functions {
        put_string(&mut bytes, name);
        put_strings(&mut bytes, &function.params);
        put_strings(&mut bytes, &function.locals);
        put_string(&mut bytes, &disasm_block(&function.code));
        put_string(&mut bytes, &format!("{:?}", function.return_type));
    }
    hash_domain(PROGRAM_DOMAIN, &bytes)
}

fn record_hash(record: &S4NativeCandidateRecord) -> SemanticHash {
    let mut bytes = Vec::new();
    put_u32(&mut bytes, record.ordinal);
    put_string(&mut bytes, &record.name);
    put_hash(&mut bytes, record.source_hash);
    put_hash(&mut bytes, record.program_hash);
    put_i64(&mut bytes, record.result);
    put_u32(&mut bytes, record.trace_count);
    for value in [
        record.native_trace_hits,
        record.static_branches,
        record.code_bytes,
        record.hot_code_bytes,
        record.deopts,
        record.internal_side_exits,
        record.guard_failures,
        record.interpreter_index_elements,
        record.list_range_calls,
    ] {
        put_u64(&mut bytes, value);
    }
    hash_domain(RECORD_DOMAIN, &bytes)
}

fn evidence_hash(evidence: &S4NativeCandidateEvidence) -> SemanticHash {
    let mut bytes = Vec::new();
    for value in [
        evidence.schema_version.0,
        evidence.schema_version.1,
        evidence.schema_version.2,
        evidence.policy_version.0,
        evidence.policy_version.1,
        evidence.policy_version.2,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    put_hash(&mut bytes, evidence.corpus_hash);
    put_u32(&mut bytes, evidence.records.len() as u32);
    for record in &evidence.records {
        put_hash(&mut bytes, record.record_hash);
    }
    hash_domain(EVIDENCE_DOMAIN, &bytes)
}

fn hash_domain(domain: &[u8], payload: &[u8]) -> SemanticHash {
    let mut bytes = Vec::with_capacity(domain.len() + payload.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(payload);
    SemanticHash(sha256(&bytes))
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_i64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_hash(bytes: &mut Vec<u8>, value: SemanticHash) {
    bytes.extend_from_slice(&value.0);
}

fn put_string(bytes: &mut Vec<u8>, value: &str) {
    put_u32(bytes, value.len() as u32);
    bytes.extend_from_slice(value.as_bytes());
}

fn put_strings(bytes: &mut Vec<u8>, values: &[String]) {
    put_u32(bytes, values.len() as u32);
    for value in values {
        put_string(bytes, value);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        emit_s4_native_candidate, render_s4_native_candidate, verify_s4_native_candidate,
        S4_NATIVE_CANDIDATE_KERNELS,
    };

    #[cfg_attr(
        any(not(target_arch = "x86_64"), not(target_os = "linux")),
        ignore = "S4 native candidate requires Linux x86-64"
    )]
    #[test]
    fn frozen_corpus_replays_without_interpreter_indexing() {
        let evidence = emit_s4_native_candidate().expect("frozen S4 carrier should emit");
        assert_eq!(evidence.records.len(), S4_NATIVE_CANDIDATE_KERNELS);
        for record in &evidence.records {
            assert!(record.native_trace_hits > 0);
            assert_eq!(record.deopts, 0);
            assert_eq!(record.internal_side_exits, 0);
            assert_eq!(record.guard_failures, 0);
            assert_eq!(record.interpreter_index_elements, 0);
            assert_eq!(record.list_range_calls, 1);
        }
        verify_s4_native_candidate(&evidence).expect("regenerative replay should match");
        let report = render_s4_native_candidate(&evidence);
        assert!(report.starts_with("NAUX-S4-NATIVE-CANDIDATE\t1\n"));
        assert!(report.ends_with("verification\tregenerated\n"));
    }
}
