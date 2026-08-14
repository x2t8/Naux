use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::lexer;
use crate::token::TokenKind;

pub const S1_LEARN_CORPUS_VERSION: u16 = 1;
pub const S1_LEARN_CORPUS_CASE_COUNT: usize = 30;
pub const S1_LEARN_CORPUS_MIN_SOURCE_ALGORITHMS: usize = 10;
pub const S1_LEARN_MANIFEST_MAX_BYTES: usize = 64 * 1024;
pub const S1_LEARN_SOURCE_MAX_BYTES: usize = 128 * 1024;
pub const S1_LEARN_INPUT_MAX_BYTES: usize = 64 * 1024;
pub const S1_LEARN_OUTPUT_MAX_BYTES: usize = 64 * 1024;

const MANIFEST_MAGIC: &str = "naux-learn-corpus-v1";
const MANIFEST_HEADER: &str = "id\ttopic\tdifficulty\timplementation\tsource\tinput\texpected";
const MAX_ID_BYTES: usize = 48;
const MAX_RELATIVE_PATH_BYTES: usize = 160;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LearnTopic {
    Basics,
    Math,
    Search,
    Sorting,
    Graph,
    Greedy,
    DynamicProgramming,
}

impl LearnTopic {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "basics" => Some(Self::Basics),
            "math" => Some(Self::Math),
            "search" => Some(Self::Search),
            "sorting" => Some(Self::Sorting),
            "graph" => Some(Self::Graph),
            "greedy" => Some(Self::Greedy),
            "dynamic-programming" => Some(Self::DynamicProgramming),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearnDifficulty {
    Intro,
    Intermediate,
    Advanced,
}

impl LearnDifficulty {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "intro" => Some(Self::Intro),
            "intermediate" => Some(Self::Intermediate),
            "advanced" => Some(Self::Advanced),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearnImplementation {
    SourceBasic,
    SourceAlgorithm,
}

impl LearnImplementation {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "source-basic" => Some(Self::SourceBasic),
            "source-algorithm" => Some(Self::SourceAlgorithm),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnCorpusEntry {
    pub id: String,
    pub topic: LearnTopic,
    pub difficulty: LearnDifficulty,
    pub implementation: LearnImplementation,
    pub source: PathBuf,
    pub input: PathBuf,
    pub expected: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnCorpusCase {
    pub entry: LearnCorpusEntry,
    pub source_path: PathBuf,
    pub input_path: PathBuf,
    pub expected_path: PathBuf,
    pub source: String,
    pub input: String,
    pub expected_output: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnCorpus {
    pub version: u16,
    pub root: PathBuf,
    pub cases: Vec<LearnCorpusCase>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnCorpusError {
    message: String,
}

impl LearnCorpusError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for LearnCorpusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LearnCorpusError {}

pub fn load_learn_corpus_v1(manifest_path: &Path) -> Result<LearnCorpus, LearnCorpusError> {
    let manifest = read_utf8_bounded(
        manifest_path,
        S1_LEARN_MANIFEST_MAX_BYTES,
        "learn corpus manifest",
    )?;
    let entries = parse_learn_manifest_v1(&manifest)?;
    if entries.len() != S1_LEARN_CORPUS_CASE_COUNT {
        return Err(LearnCorpusError::new(format!(
            "learn corpus v1 requires exactly {} cases, found {}",
            S1_LEARN_CORPUS_CASE_COUNT,
            entries.len()
        )));
    }

    let root = manifest_path
        .parent()
        .ok_or_else(|| LearnCorpusError::new("learn corpus manifest has no parent directory"))?
        .canonicalize()
        .map_err(|error| {
            LearnCorpusError::new(format!("cannot resolve learn corpus root: {error}"))
        })?;
    let mut cases = Vec::with_capacity(entries.len());
    let mut source_algorithms = 0usize;
    let mut topics = BTreeSet::new();

    for entry in entries {
        let source_path = resolve_corpus_file(&root, &entry.source, "source")?;
        let input_path = resolve_corpus_file(&root, &entry.input, "input")?;
        let expected_path = resolve_corpus_file(&root, &entry.expected, "expected output")?;
        let source = read_utf8_bounded(
            &source_path,
            S1_LEARN_SOURCE_MAX_BYTES,
            "learn exercise source",
        )?;
        let input = read_utf8_bounded(
            &input_path,
            S1_LEARN_INPUT_MAX_BYTES,
            "learn exercise input",
        )?;
        let expected_output = read_utf8_bounded(
            &expected_path,
            S1_LEARN_OUTPUT_MAX_BYTES,
            "learn exercise expected output",
        )?;

        reject_nul(&source, "learn exercise source")?;
        reject_nul(&input, "learn exercise input")?;
        reject_nul(&expected_output, "learn exercise expected output")?;
        if expected_output.contains('\r') || !expected_output.ends_with('\n') {
            return Err(LearnCorpusError::new(format!(
                "case `{}` expected output must use LF and end with one newline",
                entry.id
            )));
        }
        if entry.implementation == LearnImplementation::SourceAlgorithm {
            reject_algorithm_builtin_calls(&entry.id, &source)?;
            source_algorithms += 1;
        }
        topics.insert(entry.topic);
        cases.push(LearnCorpusCase {
            entry,
            source_path,
            input_path,
            expected_path,
            source,
            input,
            expected_output,
        });
    }

    if source_algorithms < S1_LEARN_CORPUS_MIN_SOURCE_ALGORITHMS {
        return Err(LearnCorpusError::new(format!(
            "learn corpus v1 requires at least {} source algorithms, found {source_algorithms}",
            S1_LEARN_CORPUS_MIN_SOURCE_ALGORITHMS
        )));
    }
    for required in [
        LearnTopic::Search,
        LearnTopic::Sorting,
        LearnTopic::Graph,
        LearnTopic::Greedy,
        LearnTopic::DynamicProgramming,
    ] {
        if !topics.contains(&required) {
            return Err(LearnCorpusError::new(format!(
                "learn corpus v1 is missing required topic {required:?}"
            )));
        }
    }

    Ok(LearnCorpus {
        version: S1_LEARN_CORPUS_VERSION,
        root,
        cases,
    })
}

pub fn parse_learn_manifest_v1(manifest: &str) -> Result<Vec<LearnCorpusEntry>, LearnCorpusError> {
    if manifest.len() > S1_LEARN_MANIFEST_MAX_BYTES {
        return Err(LearnCorpusError::new(
            "learn corpus manifest exceeds byte cap",
        ));
    }
    reject_nul(manifest, "learn corpus manifest")?;
    if manifest.contains('\r') {
        return Err(LearnCorpusError::new(
            "learn corpus manifest must use canonical LF line endings",
        ));
    }
    if !manifest.ends_with('\n') {
        return Err(LearnCorpusError::new(
            "learn corpus manifest must end with LF",
        ));
    }

    let mut lines = manifest.lines();
    if lines.next() != Some(MANIFEST_MAGIC) {
        return Err(LearnCorpusError::new(
            "learn corpus manifest magic/version mismatch",
        ));
    }
    if lines.next() != Some(MANIFEST_HEADER) {
        return Err(LearnCorpusError::new(
            "learn corpus manifest header mismatch",
        ));
    }

    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut entries = Vec::new();
    for (offset, line) in lines.enumerate() {
        let line_number = offset + 3;
        if line.is_empty() {
            return Err(LearnCorpusError::new(format!(
                "learn corpus manifest line {line_number} is empty"
            )));
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 7 {
            return Err(LearnCorpusError::new(format!(
                "learn corpus manifest line {line_number} has {} fields, expected 7",
                fields.len()
            )));
        }

        let id = fields[0];
        validate_id(id, line_number)?;
        if !ids.insert(id.to_string()) {
            return Err(LearnCorpusError::new(format!(
                "learn corpus manifest duplicates id `{id}`"
            )));
        }
        let topic = LearnTopic::parse(fields[1]).ok_or_else(|| {
            LearnCorpusError::new(format!(
                "learn corpus manifest line {line_number} has unknown topic `{}`",
                fields[1]
            ))
        })?;
        let difficulty = LearnDifficulty::parse(fields[2]).ok_or_else(|| {
            LearnCorpusError::new(format!(
                "learn corpus manifest line {line_number} has unknown difficulty `{}`",
                fields[2]
            ))
        })?;
        let implementation = LearnImplementation::parse(fields[3]).ok_or_else(|| {
            LearnCorpusError::new(format!(
                "learn corpus manifest line {line_number} has unknown implementation `{}`",
                fields[3]
            ))
        })?;
        let source = validate_relative_path(fields[4], "source", line_number, "nx")?;
        let input = validate_relative_path(fields[5], "input", line_number, "in")?;
        let expected = validate_relative_path(fields[6], "expected output", line_number, "out")?;
        for path in [&source, &input, &expected] {
            if !paths.insert(path.clone()) {
                return Err(LearnCorpusError::new(format!(
                    "learn corpus manifest reuses path `{}`",
                    path.display()
                )));
            }
        }
        entries.push(LearnCorpusEntry {
            id: id.to_string(),
            topic,
            difficulty,
            implementation,
            source,
            input,
            expected,
        });
    }
    if entries.is_empty() {
        return Err(LearnCorpusError::new("learn corpus manifest has no cases"));
    }
    Ok(entries)
}

pub fn admit_learn_case_result(
    case_id: &str,
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
    expected_output: &str,
) -> Result<(), LearnCorpusError> {
    if stdout.len() > S1_LEARN_OUTPUT_MAX_BYTES {
        return Err(LearnCorpusError::new(format!(
            "learn case `{case_id}` stdout exceeds the {}-byte cap",
            S1_LEARN_OUTPUT_MAX_BYTES
        )));
    }
    if stderr.len() > S1_LEARN_OUTPUT_MAX_BYTES {
        return Err(LearnCorpusError::new(format!(
            "learn case `{case_id}` stderr exceeds the {}-byte cap",
            S1_LEARN_OUTPUT_MAX_BYTES
        )));
    }
    let stdout = std::str::from_utf8(stdout).map_err(|_| {
        LearnCorpusError::new(format!("learn case `{case_id}` stdout is not valid UTF-8"))
    })?;
    let stderr = std::str::from_utf8(stderr).map_err(|_| {
        LearnCorpusError::new(format!("learn case `{case_id}` stderr is not valid UTF-8"))
    })?;
    if !success {
        return Err(LearnCorpusError::new(format!(
            "learn case `{case_id}` exited unsuccessfully: {stderr}"
        )));
    }
    if !stderr.is_empty() {
        return Err(LearnCorpusError::new(format!(
            "learn case `{case_id}` emitted unexpected diagnostics: {stderr}"
        )));
    }
    if stdout != expected_output {
        return Err(LearnCorpusError::new(format!(
            "learn case `{case_id}` output differs from its exact fixture"
        )));
    }
    Ok(())
}

fn validate_id(id: &str, line_number: usize) -> Result<(), LearnCorpusError> {
    if id.is_empty()
        || id.len() > MAX_ID_BYTES
        || !id.as_bytes()[0].is_ascii_lowercase()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(LearnCorpusError::new(format!(
            "learn corpus manifest line {line_number} has invalid id `{id}`"
        )));
    }
    Ok(())
}

fn validate_relative_path(
    value: &str,
    field: &str,
    line_number: usize,
    extension: &str,
) -> Result<PathBuf, LearnCorpusError> {
    if value.is_empty()
        || value.len() > MAX_RELATIVE_PATH_BYTES
        || value.contains('\\')
        || value.contains(':')
    {
        return Err(LearnCorpusError::new(format!(
            "learn corpus manifest line {line_number} has invalid {field} path"
        )));
    }
    let path = PathBuf::from(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.extension().and_then(|value| value.to_str()) != Some(extension)
    {
        return Err(LearnCorpusError::new(format!(
            "learn corpus manifest line {line_number} has unsafe {field} path `{value}`"
        )));
    }
    Ok(path)
}

fn resolve_corpus_file(
    root: &Path,
    relative: &Path,
    field: &str,
) -> Result<PathBuf, LearnCorpusError> {
    let resolved = root.join(relative).canonicalize().map_err(|error| {
        LearnCorpusError::new(format!(
            "cannot resolve learn corpus {field} `{}`: {error}",
            relative.display()
        ))
    })?;
    if !resolved.starts_with(root) || !resolved.is_file() {
        return Err(LearnCorpusError::new(format!(
            "learn corpus {field} escapes its root or is not a file: `{}`",
            relative.display()
        )));
    }
    Ok(resolved)
}

fn read_utf8_bounded(path: &Path, limit: usize, label: &str) -> Result<String, LearnCorpusError> {
    let file = File::open(path).map_err(|error| {
        LearnCorpusError::new(format!("cannot open {label} `{}`: {error}", path.display()))
    })?;
    let byte_limit = u64::try_from(limit)
        .map_err(|_| LearnCorpusError::new(format!("{label} byte cap does not fit u64")))?;
    let mut bytes = Vec::new();
    file.take(byte_limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            LearnCorpusError::new(format!("cannot read {label} `{}`: {error}", path.display()))
        })?;
    if bytes.len() > limit {
        return Err(LearnCorpusError::new(format!(
            "{label} `{}` exceeds the {limit}-byte cap",
            path.display()
        )));
    }
    String::from_utf8(bytes).map_err(|_| {
        LearnCorpusError::new(format!("{label} `{}` must be valid UTF-8", path.display()))
    })
}

fn reject_nul(value: &str, label: &str) -> Result<(), LearnCorpusError> {
    if value.contains('\0') {
        Err(LearnCorpusError::new(format!(
            "{label} contains a forbidden NUL byte"
        )))
    } else {
        Ok(())
    }
}

fn reject_algorithm_builtin_calls(id: &str, source: &str) -> Result<(), LearnCorpusError> {
    let tokens = lexer::lex(source).map_err(|error| {
        LearnCorpusError::new(format!(
            "source-algorithm case `{id}` does not lex at {}:{}: {}",
            error.span.line, error.span.column, error.message
        ))
    })?;
    if tokens
        .iter()
        .any(|token| matches!(token.kind, TokenKind::Import))
    {
        return Err(LearnCorpusError::new(format!(
            "source-algorithm case `{id}` may not import uninspected implementation code"
        )));
    }
    for pair in tokens.windows(2) {
        let TokenKind::Ident(name) = &pair[0].kind else {
            continue;
        };
        if matches!(pair[1].kind, TokenKind::LParen) && is_algorithm_builtin(name) {
            return Err(LearnCorpusError::new(format!(
                "source-algorithm case `{id}` delegates to forbidden host builtin `{name}`"
            )));
        }
    }
    Ok(())
}

fn is_algorithm_builtin(name: &str) -> bool {
    matches!(
        name,
        "gcd"
            | "lcm"
            | "pow_mod"
            | "is_prime"
            | "sieve"
            | "lis_length"
            | "knapsack_01"
            | "window_sum_fixed"
            | "window_max"
            | "window_min"
            | "lower_bound"
            | "upper_bound"
            | "kmp_search"
            | "z_function"
            | "suffix_array"
            | "rolling_hash_table"
            | "rolling_hash_sub"
            | "rabin_karp"
            | "manacher_lps"
            | "fft_convolve"
            | "ntt_convolve"
            | "pollard_rho"
            | "sparse_table_new"
            | "sparse_table_query"
            | "lichao_new"
            | "lichao_add"
            | "lichao_query"
            | "dsu_new"
            | "dsu_union"
            | "dsu_find"
            | "segtree_new"
            | "segtree_query"
            | "segtree_update"
            | "segtree_lazy_new"
            | "segtree_lazy_add"
            | "segtree_lazy_query"
            | "segtree_dynamic_new"
            | "segtree_dynamic_add"
            | "segtree_dynamic_query"
            | "graph_new"
            | "graph_add_edge"
            | "graph_neighbors"
            | "graph_bfs"
            | "graph_dijkstra"
            | "graph_zero_one_bfs"
            | "graph_dials"
            | "graph_astar"
            | "graph_bridges"
            | "graph_articulation_points"
            | "graph_scc"
            | "graph_toposort"
            | "graph_floyd_warshall"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestFile {
        path: PathBuf,
    }

    impl TestFile {
        fn new(contents: &[u8]) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let ordinal = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "naux-learn-corpus-test-{}-{ordinal}",
                std::process::id()
            ));
            fs::write(&path, contents).expect("write bounded corpus test file");
            Self { path }
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn row(id: &str) -> String {
        format!(
            "{id}\tsearch\tintro\tsource-basic\tsolutions/{id}.nx\tfixtures/{id}.in\tfixtures/{id}.out"
        )
    }

    fn manifest(rows: &[String]) -> String {
        format!("{MANIFEST_MAGIC}\n{MANIFEST_HEADER}\n{}\n", rows.join("\n"))
    }

    #[test]
    fn manifest_parser_accepts_one_canonical_row() {
        let parsed = parse_learn_manifest_v1(&manifest(&[row("linear-search")])).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "linear-search");
        assert_eq!(parsed[0].topic, LearnTopic::Search);
    }

    #[test]
    fn manifest_parser_rejects_duplicates_traversal_and_taxonomy_drift() {
        let duplicate = manifest(&[row("same"), row("same")]);
        assert!(parse_learn_manifest_v1(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicates id"));

        let traversal = format!(
            "{MANIFEST_MAGIC}\n{MANIFEST_HEADER}\ncase\tsearch\tintro\tsource-basic\t../case.nx\tfixtures/case.in\tfixtures/case.out\n"
        );
        assert!(parse_learn_manifest_v1(&traversal)
            .unwrap_err()
            .to_string()
            .contains("unsafe source path"));

        let taxonomy = row("case").replace("\tsearch\t", "\tmagic\t");
        assert!(parse_learn_manifest_v1(&manifest(&[taxonomy]))
            .unwrap_err()
            .to_string()
            .contains("unknown topic"));
    }

    #[test]
    fn manifest_parser_rejects_noncanonical_bytes_and_shapes() {
        assert!(
            parse_learn_manifest_v1(&manifest(&[row("bad")]).replace('\n', "\r\n"))
                .unwrap_err()
                .to_string()
                .contains("canonical LF")
        );
        assert!(parse_learn_manifest_v1(&format!(
            "{MANIFEST_MAGIC}\n{MANIFEST_HEADER}\n{}\0\n",
            row("bad")
        ))
        .unwrap_err()
        .to_string()
        .contains("NUL"));
        assert!(parse_learn_manifest_v1(manifest(&[row("bad")]).trim_end())
            .unwrap_err()
            .to_string()
            .contains("end with LF"));
        assert!(parse_learn_manifest_v1(&format!(
            "{MANIFEST_MAGIC}\n{MANIFEST_HEADER}\nmissing\tsearch\tintro\n"
        ))
        .unwrap_err()
        .to_string()
        .contains("expected 7"));
    }

    #[test]
    fn source_algorithm_gate_rejects_host_solver_calls_but_not_text_or_comments() {
        reject_algorithm_builtin_calls(
            "honest",
            "# lis_length($a)\n~ rite\n    !say \"knapsack_01($w)\"\n~ end\n",
        )
        .unwrap();
        let error = reject_algorithm_builtin_calls(
            "delegated",
            "~ rite\n    !say lis_length([1, 2])\n~ end\n",
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("forbidden host builtin `lis_length`"));

        let imported = reject_algorithm_builtin_calls(
            "imported",
            "~ import \"hidden-solver.nx\"\n~ rite\n~ end\n",
        )
        .unwrap_err();
        assert!(imported
            .to_string()
            .contains("may not import uninspected implementation code"));
    }

    #[test]
    fn bounded_file_admission_rejects_missing_oversized_and_non_utf8_files() {
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("resolve temporary directory");
        let missing = PathBuf::from(format!(
            "naux-learn-missing-{}-{}.nx",
            std::process::id(),
            918_273_u64
        ));
        assert!(resolve_corpus_file(&root, &missing, "source")
            .unwrap_err()
            .to_string()
            .contains("cannot resolve"));

        let oversized = TestFile::new(b"12345");
        assert!(read_utf8_bounded(&oversized.path, 4, "fixture")
            .unwrap_err()
            .to_string()
            .contains("exceeds the 4-byte cap"));

        let non_utf8 = TestFile::new(&[0xff]);
        assert!(read_utf8_bounded(&non_utf8.path, 4, "fixture")
            .unwrap_err()
            .to_string()
            .contains("must be valid UTF-8"));
    }

    #[test]
    fn result_admission_rejects_status_diagnostics_drift_and_size() {
        admit_learn_case_result("ok", true, b"42\n", b"", "42\n").unwrap();
        assert!(admit_learn_case_result("status", false, b"", b"boom", "")
            .unwrap_err()
            .to_string()
            .contains("unsuccessfully"));
        assert!(
            admit_learn_case_result("stderr", true, b"42\n", b"noise", "42\n")
                .unwrap_err()
                .to_string()
                .contains("unexpected diagnostics")
        );
        assert!(admit_learn_case_result("drift", true, b"41\n", b"", "42\n")
            .unwrap_err()
            .to_string()
            .contains("differs"));
        assert!(admit_learn_case_result(
            "large",
            true,
            &vec![b'x'; S1_LEARN_OUTPUT_MAX_BYTES + 1],
            b"",
            ""
        )
        .unwrap_err()
        .to_string()
        .contains("stdout exceeds"));
    }
}
