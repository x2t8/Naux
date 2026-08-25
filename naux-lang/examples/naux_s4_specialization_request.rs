//! Clock-free, deterministic specialization-request emitter for S4-WP5A.
//!
//! This executable stops before residual generation. It proves that one
//! ordinary frontend path can identify the exact four accepted NAUX programs
//! and bind their static dataset plus work-preservation obligations.

use naux::core::SemanticHash;
use naux::vm::bytecode::{disasm_block, Program};
use naux::vm::compiler::compile_script;
use naux::{lexer, parser, typecheck};
use std::fmt;

const CONTRACT: &str = include_str!("../../distribution/s4-performance/WP5A-REQUEST.tsv");
const CORPUS: &str = include_str!("../../distribution/s4-performance/CORPUS.tsv");
const SOURCES: [(&str, &str); 4] = [
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

const CONTRACT_MAGIC: &str = "NAUX-S4-SPECIALIZATION-REQUEST-CONTRACT\t1";
const REQUEST_MAGIC: &str = "NAUX-S4-SPECIALIZATION-REQUEST\t1";
const CONTRACT_DOMAIN: &[u8] = b"NAUX:s4-specialization-request:contract:v1\0";
const CORPUS_DOMAIN: &[u8] = b"NAUX:s4-benchmark:corpus:v1\0";
const SOURCE_DOMAIN: &[u8] = b"NAUX:s4-specialization-request:source:v1\0";
const PROGRAM_DOMAIN: &[u8] = b"NAUX:s4-specialization-request:program:v1\0";
const WORK_DOMAIN: &[u8] = b"NAUX:s4-specialization-request:work:v1\0";
const RECORD_DOMAIN: &[u8] = b"NAUX:s4-specialization-request:record:v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"NAUX:s4-specialization-request:evidence:v1\0";
const SCHEMA_VERSION: (u16, u16, u16) = (0, 1, 0);
const POLICY_VERSION: (u16, u16, u16) = (1, 0, 0);
const STATIC_N: u64 = 16_384;
const STATIC_REPS: u64 = 50;
const KERNEL_COUNT: usize = 4;
const WORK: [&str; 5] = [
    "owned-runtime-list",
    "range-zero-through-n-minus-one",
    "reps-times-full-n-source-semantics",
    "exact-corpus-oracle-after-dynamic-work",
    "release-owned-list-before-completion",
];
const IDENTITIES: [(&str, &str); KERNEL_COUNT] = [
    ("01", "sum-dense"),
    ("02", "branch-mix"),
    ("03", "dot-product"),
    ("04", "list-update"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct ContractRecord {
    ordinal: u32,
    name: String,
    source_path: String,
    source_sha256: SemanticHash,
    n: u64,
    reps: u64,
    oracle: i64,
    work: [String; 5],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestRecord {
    contract: ContractRecord,
    source_hash: SemanticHash,
    program_hash: SemanticHash,
    work_hash: SemanticHash,
    record_hash: SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RequestEvidence {
    contract_seal: SemanticHash,
    corpus_seal: SemanticHash,
    records: Vec<RequestRecord>,
    evidence_hash: SemanticHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RequestError {
    InvalidContract(String),
    InvalidCorpus(String),
    Frontend { kernel: String, message: String },
    ReplayMismatch,
}

impl fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract(message) => {
                write!(formatter, "invalid request contract: {message}")
            }
            Self::InvalidCorpus(message) => write!(formatter, "invalid parent corpus: {message}"),
            Self::Frontend { kernel, message } => {
                write!(
                    formatter,
                    "ordinary frontend rejected `{kernel}`: {message}"
                )
            }
            Self::ReplayMismatch => formatter.write_str("regenerated request evidence differs"),
        }
    }
}

impl std::error::Error for RequestError {}

fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("usage: naux-s4-specialization-request");
        std::process::exit(2);
    }
    let evidence = emit_request().unwrap_or_else(|error| {
        eprintln!("S4 specialization request emission failed: {error}");
        std::process::exit(1);
    });
    verify_request(&evidence).unwrap_or_else(|error| {
        eprintln!("S4 specialization request replay failed: {error}");
        std::process::exit(1);
    });
    print!("{}", render_request(&evidence));
}

fn emit_request() -> Result<RequestEvidence, RequestError> {
    let (contract_seal, records) = parse_contract(CONTRACT)?;
    let corpus_seal = verify_corpus(CORPUS, &records)?;
    let mut requests = Vec::with_capacity(records.len());
    for (record, (expected_path, source)) in records.into_iter().zip(SOURCES) {
        if record.source_path != expected_path {
            return Err(RequestError::InvalidContract(
                "source order differs from the frozen corpus".into(),
            ));
        }
        requests.push(build_request(record, source)?);
    }
    let mut evidence = RequestEvidence {
        contract_seal,
        corpus_seal,
        records: requests,
        evidence_hash: SemanticHash::ZERO,
    };
    evidence.evidence_hash = evidence_hash(&evidence);
    Ok(evidence)
}

fn verify_request(evidence: &RequestEvidence) -> Result<(), RequestError> {
    if emit_request()? == *evidence {
        Ok(())
    } else {
        Err(RequestError::ReplayMismatch)
    }
}

fn build_request(record: ContractRecord, source: &str) -> Result<RequestRecord, RequestError> {
    if SemanticHash(sha256(source.as_bytes())) != record.source_sha256 {
        return Err(RequestError::InvalidContract(format!(
            "source hash drifted for `{}`",
            record.name
        )));
    }
    let tokens = lexer::lex(source).map_err(|error| RequestError::Frontend {
        kernel: record.name.clone(),
        message: error.message,
    })?;
    let statements = parser::parse_script(&tokens).map_err(|error| RequestError::Frontend {
        kernel: record.name.clone(),
        message: error.message,
    })?;
    typecheck::check_program(&statements).map_err(|error| RequestError::Frontend {
        kernel: record.name.clone(),
        message: error.message,
    })?;
    let program = compile_script(&statements);
    let source_hash = hash_domain(SOURCE_DOMAIN, source.as_bytes());
    let program_hash = program_hash(&program);
    let work_hash = work_hash(&record.work);
    let mut request = RequestRecord {
        contract: record,
        source_hash,
        program_hash,
        work_hash,
        record_hash: SemanticHash::ZERO,
    };
    request.record_hash = record_hash(&request);
    Ok(request)
}

fn parse_contract(text: &str) -> Result<(SemanticHash, Vec<ContractRecord>), RequestError> {
    let lines = canonical_lines(text, "request contract").map_err(RequestError::InvalidContract)?;
    if lines.first() != Some(&CONTRACT_MAGIC) || lines.len() != 18 {
        return Err(RequestError::InvalidContract(
            "schema or row count drifted".into(),
        ));
    }
    let expected_metadata = [
        "meta\tpolicy-version\t1.0.0",
        "meta\trequest-status\tadmitted",
        "meta\tresidual-status\tunavailable",
        "meta\tclaim-status\tnot-admitted",
        "meta\ttiming-status\tforbidden",
        "meta\ttarget\tx86_64-unknown-linux-gnu",
        "meta\tdataset\tstatic-n16384-r50",
        "meta\tfrontend\tordinary-naux-frontend",
        "meta\tpipeline\tsingle-general-future-residual-pipeline",
        "meta\tkernel-count\t4",
        "meta\tcorpus-seal\t793fdac34e1b0536365208a745ad59edaf6dbb94eabcede88d273292861dffa5",
        "meta\twork-obligations\tallocation-initialization-kernel-checksum-teardown",
    ];
    if lines[1..13] != expected_metadata {
        return Err(RequestError::InvalidContract("metadata drifted".into()));
    }
    let seal = verify_terminal_seal(&lines, CONTRACT_DOMAIN, "request contract")
        .map_err(RequestError::InvalidContract)?;
    let mut records = Vec::with_capacity(KERNEL_COUNT);
    for (index, line) in lines[13..17].iter().enumerate() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 13 || fields[0] != "kernel" {
            return Err(RequestError::InvalidContract(
                "kernel row has invalid shape".into(),
            ));
        }
        if (fields[1], fields[2]) != IDENTITIES[index]
            || fields[3] != SOURCES[index].0
            || fields[5] != "16384"
            || fields[6] != "50"
            || fields[8..13] != WORK
        {
            return Err(RequestError::InvalidContract(
                "kernel identity, dataset, or work obligations drifted".into(),
            ));
        }
        let ordinal = fields[1]
            .parse::<u32>()
            .map_err(|_| RequestError::InvalidContract("invalid ordinal".into()))?;
        let source_sha256 =
            parse_hash(fields[4], "source SHA-256").map_err(RequestError::InvalidContract)?;
        let oracle = fields[7]
            .parse::<i64>()
            .map_err(|_| RequestError::InvalidContract("invalid corpus oracle".into()))?;
        records.push(ContractRecord {
            ordinal,
            name: fields[2].to_string(),
            source_path: fields[3].to_string(),
            source_sha256,
            n: STATIC_N,
            reps: STATIC_REPS,
            oracle,
            work: WORK.map(str::to_string),
        });
    }
    Ok((seal, records))
}

fn verify_corpus(text: &str, records: &[ContractRecord]) -> Result<SemanticHash, RequestError> {
    let lines = canonical_lines(text, "corpus").map_err(RequestError::InvalidCorpus)?;
    if lines.len() != 9 || lines.first() != Some(&"NAUX-S4-BENCHMARK-CORPUS\t1") {
        return Err(RequestError::InvalidCorpus(
            "schema or row count drifted".into(),
        ));
    }
    let seal = verify_terminal_seal(&lines, CORPUS_DOMAIN, "corpus")
        .map_err(RequestError::InvalidCorpus)?;
    for (record, line) in records.iter().zip(&lines[4..8]) {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() != 11
            || fields[0] != "kernel"
            || fields[1] != format!("{:02}", record.ordinal)
            || fields[2] != record.name
            || fields[5] != record.n.to_string()
            || fields[6] != record.reps.to_string()
            || fields[7] != record.oracle.to_string()
            || fields[8] != record.source_path
        {
            return Err(RequestError::InvalidCorpus(format!(
                "kernel `{}` differs from the specialization request",
                record.name
            )));
        }
    }
    Ok(seal)
}

fn canonical_lines<'a>(text: &'a str, label: &str) -> Result<Vec<&'a str>, String> {
    if !text.ends_with('\n') || text.contains(['\r', '\0']) {
        return Err(format!("{label} is not canonical LF UTF-8"));
    }
    let lines: Vec<&str> = text.lines().collect();
    if lines.iter().any(|line| line.is_empty()) {
        return Err(format!("{label} contains a blank row"));
    }
    Ok(lines)
}

fn verify_terminal_seal(
    lines: &[&str],
    domain: &[u8],
    label: &str,
) -> Result<SemanticHash, String> {
    let fields: Vec<&str> = lines
        .last()
        .ok_or_else(|| format!("{label} is empty"))?
        .split('\t')
        .collect();
    if fields.len() != 2 || fields[0] != "seal" {
        return Err(format!("{label} has no terminal seal"));
    }
    let seal = parse_hash(fields[1], "seal")?;
    let mut body = String::new();
    for line in &lines[..lines.len() - 1] {
        body.push_str(line);
        body.push('\n');
    }
    if hash_domain(domain, body.as_bytes()) != seal {
        return Err(format!("{label} seal mismatch"));
    }
    Ok(seal)
}

fn parse_hash(value: &str, label: &str) -> Result<SemanticHash, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("{label} is not canonical SHA-256"));
    }
    let mut bytes = [0_u8; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        *output = (hex(value.as_bytes()[index * 2])? << 4) | hex(value.as_bytes()[index * 2 + 1])?;
    }
    Ok(SemanticHash(bytes))
}

fn hex(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("invalid lowercase hex digit".into()),
    }
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

fn work_hash(work: &[String; 5]) -> SemanticHash {
    let mut bytes = Vec::new();
    put_u32(&mut bytes, work.len() as u32);
    for item in work {
        put_string(&mut bytes, item);
    }
    hash_domain(WORK_DOMAIN, &bytes)
}

fn record_hash(record: &RequestRecord) -> SemanticHash {
    let mut bytes = Vec::new();
    put_u32(&mut bytes, record.contract.ordinal);
    put_string(&mut bytes, &record.contract.name);
    put_string(&mut bytes, &record.contract.source_path);
    put_u64(&mut bytes, record.contract.n);
    put_u64(&mut bytes, record.contract.reps);
    put_i64(&mut bytes, record.contract.oracle);
    put_hash(&mut bytes, record.source_hash);
    put_hash(&mut bytes, record.program_hash);
    put_hash(&mut bytes, record.work_hash);
    hash_domain(RECORD_DOMAIN, &bytes)
}

fn evidence_hash(evidence: &RequestEvidence) -> SemanticHash {
    let mut bytes = Vec::new();
    for version in [
        SCHEMA_VERSION.0,
        SCHEMA_VERSION.1,
        SCHEMA_VERSION.2,
        POLICY_VERSION.0,
        POLICY_VERSION.1,
        POLICY_VERSION.2,
    ] {
        bytes.extend_from_slice(&version.to_le_bytes());
    }
    put_hash(&mut bytes, evidence.contract_seal);
    put_hash(&mut bytes, evidence.corpus_seal);
    put_u32(&mut bytes, evidence.records.len() as u32);
    for record in &evidence.records {
        put_hash(&mut bytes, record.record_hash);
    }
    hash_domain(EVIDENCE_DOMAIN, &bytes)
}

fn render_request(evidence: &RequestEvidence) -> String {
    let mut output = String::new();
    output.push_str(REQUEST_MAGIC);
    output.push('\n');
    output.push_str("meta\tschema\t0.1.0\n");
    output.push_str("meta\tpolicy\t1.0.0\n");
    output.push_str(&format!("meta\tcontract\t{}\n", evidence.contract_seal));
    output.push_str(&format!("meta\tcorpus\t{}\n", evidence.corpus_seal));
    output.push_str("meta\tfrontend\tordinary-naux-frontend\n");
    output.push_str("meta\tresidual\tunavailable\n");
    output.push_str("columns\tordinal\tkernel\tn\treps\toracle\tsource-path\tsource-hash\tprogram-hash\twork-hash\trecord-hash\n");
    for record in &evidence.records {
        output.push_str(&format!(
            "kernel\t{:02}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            record.contract.ordinal,
            record.contract.name,
            record.contract.n,
            record.contract.reps,
            record.contract.oracle,
            record.contract.source_path,
            record.source_hash,
            record.program_hash,
            record.work_hash,
            record.record_hash,
        ));
    }
    output.push_str(&format!("evidence\t{}\n", evidence.evidence_hash));
    output.push_str("verification\tregenerated\n");
    output
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

fn sha256(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    let mut state = INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, word) in words[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes(chunk[index * 4..index * 4 + 4].try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let big1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(big1)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let big0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = big0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut output = [0_u8; 32];
    for (chunk, value) in output.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_standard_vectors() {
        assert_eq!(
            SemanticHash(sha256(b"")).to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            SemanticHash(sha256(b"abc")).to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn exact_request_is_deterministic_and_regenerative() {
        let first = emit_request().expect("request should emit");
        let second = emit_request().expect("request should regenerate");
        assert_eq!(first, second);
        assert_eq!(first.records.len(), KERNEL_COUNT);
        verify_request(&first).expect("request replay should match");
        let rendered = render_request(&first);
        assert!(rendered.starts_with(REQUEST_MAGIC));
        assert!(rendered.ends_with("verification\tregenerated\n"));
    }

    #[test]
    fn reseal_is_not_optional() {
        let mutated = CONTRACT.replacen(
            "meta\ttiming-status\tforbidden",
            "meta\ttiming-status\toptional",
            1,
        );
        assert!(parse_contract(&mutated).is_err());
    }
}
