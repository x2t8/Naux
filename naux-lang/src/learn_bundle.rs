//! Fail-closed admission and installation for the bounded NAUX Learn bundle.
//!
//! The producer is the repository packaging script. This module is the
//! independent consumer: it accepts one exact directory inventory, verifies
//! a sealed canonical manifest, then installs through a separately verified
//! staging directory.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::core::encoding::sha256;
use crate::install_locale::validate_packaged_catalogs;

pub const S1_BUNDLE_VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const S1_BUNDLE_TARGET: &str = "linux-x86_64-gnu";
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub const S1_BUNDLE_TARGET: &str = "windows-x86_64-gnu";
#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "windows", target_arch = "x86_64")
)))]
pub const S1_BUNDLE_TARGET: &str = "unsupported-host";
pub const S1_BUNDLE_MANIFEST: &str = "MANIFEST.tsv";

const MANIFEST_MAGIC: &str = "NAUX-S1-LEARN-BUNDLE\t1";
const MANIFEST_SEAL_DOMAIN: &[u8] = b"NAUX:s1-learn-bundle:manifest:v1\0";
const MANIFEST_MAX_BYTES: u64 = 16 * 1024;
const INVENTORY_MAX_ENTRIES: usize = 40;
const INVENTORY_MAX_PATH_BYTES: usize = 160;
const BUNDLE_MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RequiredFile {
    path: &'static str,
    mode: u32,
    max_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LearnBundleTarget {
    LinuxX86_64Gnu,
    WindowsX86_64Gnu,
}

impl LearnBundleTarget {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxX86_64Gnu => "linux-x86_64-gnu",
            Self::WindowsX86_64Gnu => "windows-x86_64-gnu",
        }
    }

    fn parse(value: &str) -> Result<Self, LearnBundleError> {
        match value {
            "linux-x86_64-gnu" => Ok(Self::LinuxX86_64Gnu),
            "windows-x86_64-gnu" => Ok(Self::WindowsX86_64Gnu),
            _ => Err(LearnBundleError::new(format!(
                "bundle manifest target `{value}` is unsupported"
            ))),
        }
    }
}

const LINUX_REQUIRED_FILES: &[RequiredFile] = &[
    RequiredFile {
        path: "BUILD-SEED.tsv",
        mode: 0o644,
        max_bytes: 16 * 1024,
    },
    RequiredFile {
        path: "HOST-DEPENDENCIES.tsv",
        mode: 0o644,
        max_bytes: 16 * 1024,
    },
    RequiredFile {
        path: "LICENSE",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "README.md",
        mode: 0o644,
        max_bytes: 256 * 1024,
    },
    RequiredFile {
        path: "naux-learn-setup",
        mode: 0o755,
        max_bytes: 16 * 1024 * 1024,
    },
    RequiredFile {
        path: "assets/langnaux-learn.png",
        mode: 0o644,
        max_bytes: 512 * 1024,
    },
    RequiredFile {
        path: "bin/naux",
        mode: 0o755,
        max_bytes: 16 * 1024 * 1024,
    },
    RequiredFile {
        path: "docs/LIMITATIONS.md",
        mode: 0o644,
        max_bytes: 256 * 1024,
    },
    RequiredFile {
        path: "docs/RELEASE_DISCLOSURE.md",
        mode: 0o644,
        max_bytes: 256 * 1024,
    },
    RequiredFile {
        path: "docs/s1_learn_batch_io.md",
        mode: 0o644,
        max_bytes: 256 * 1024,
    },
    RequiredFile {
        path: "docs/s1_learn_diagnostics.md",
        mode: 0o644,
        max_bytes: 256 * 1024,
    },
    RequiredFile {
        path: "docs/s1_learn_execution_envelope.md",
        mode: 0o644,
        max_bytes: 256 * 1024,
    },
    RequiredFile {
        path: "docs/s1_learn_quick_reference_v0_1.md",
        mode: 0o644,
        max_bytes: 1024 * 1024,
    },
    RequiredFile {
        path: "examples/hello.nx",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "examples/hello.out",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/SUPPORTED_LOCALES.tsv",
        mode: 0o644,
        max_bytes: 16 * 1024,
    },
    RequiredFile {
        path: "locales/de.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/en-US.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/es.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/fr.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/ja-JP.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/ko-KR.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/pt-BR.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/vi-VN.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/zh-CN.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
];

const WINDOWS_REQUIRED_FILES: &[RequiredFile] = &[
    RequiredFile {
        path: "BUILD-SEED.tsv",
        mode: 0o644,
        max_bytes: 16 * 1024,
    },
    RequiredFile {
        path: "HOST-DEPENDENCIES.tsv",
        mode: 0o644,
        max_bytes: 16 * 1024,
    },
    RequiredFile {
        path: "LICENSE",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "README.md",
        mode: 0o644,
        max_bytes: 256 * 1024,
    },
    RequiredFile {
        path: "NAUX-Learn-Setup.exe",
        mode: 0o755,
        max_bytes: 16 * 1024 * 1024,
    },
    RequiredFile {
        path: "assets/langnaux-learn.ico",
        mode: 0o644,
        max_bytes: 512 * 1024,
    },
    RequiredFile {
        path: "assets/langnaux-learn.png",
        mode: 0o644,
        max_bytes: 512 * 1024,
    },
    RequiredFile {
        path: "bin/naux.exe",
        mode: 0o755,
        max_bytes: 16 * 1024 * 1024,
    },
    RequiredFile {
        path: "docs/LIMITATIONS.md",
        mode: 0o644,
        max_bytes: 256 * 1024,
    },
    RequiredFile {
        path: "docs/RELEASE_DISCLOSURE.md",
        mode: 0o644,
        max_bytes: 256 * 1024,
    },
    RequiredFile {
        path: "docs/s1_learn_batch_io.md",
        mode: 0o644,
        max_bytes: 256 * 1024,
    },
    RequiredFile {
        path: "docs/s1_learn_diagnostics.md",
        mode: 0o644,
        max_bytes: 256 * 1024,
    },
    RequiredFile {
        path: "docs/s1_learn_execution_envelope.md",
        mode: 0o644,
        max_bytes: 256 * 1024,
    },
    RequiredFile {
        path: "docs/s1_learn_quick_reference_v0_1.md",
        mode: 0o644,
        max_bytes: 1024 * 1024,
    },
    RequiredFile {
        path: "examples/hello.nx",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "examples/hello.out",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/SUPPORTED_LOCALES.tsv",
        mode: 0o644,
        max_bytes: 16 * 1024,
    },
    RequiredFile {
        path: "locales/de.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/en-US.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/es.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/fr.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/ja-JP.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/ko-KR.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/pt-BR.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/vi-VN.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
    RequiredFile {
        path: "locales/zh-CN.tsv",
        mode: 0o644,
        max_bytes: 64 * 1024,
    },
];

fn required_files(target: LearnBundleTarget) -> &'static [RequiredFile] {
    match target {
        LearnBundleTarget::LinuxX86_64Gnu => LINUX_REQUIRED_FILES,
        LearnBundleTarget::WindowsX86_64Gnu => WINDOWS_REQUIRED_FILES,
    }
}

const REQUIRED_DIRECTORIES: &[&str] = &["assets", "bin", "docs", "examples", "locales"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearnBundleError {
    message: String,
}

impl LearnBundleError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for LearnBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LearnBundleError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLearnBundle {
    root: PathBuf,
    target: LearnBundleTarget,
    manifest_seal: [u8; 32],
    file_count: usize,
    total_bytes: u64,
}

impl VerifiedLearnBundle {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub const fn target(&self) -> &'static str {
        self.target.as_str()
    }

    pub fn manifest_seal_hex(&self) -> String {
        hex_encode(&self.manifest_seal)
    }

    pub const fn file_count(&self) -> usize {
        self.file_count
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Return the complete canonical owned-file set, including the manifest.
    ///
    /// Installation lifecycle code uses this only after full bundle admission;
    /// it never discovers ownership by scanning outside the admitted root.
    pub fn owned_relative_files(&self) -> Vec<&'static str> {
        required_files(self.target)
            .iter()
            .map(|file| file.path)
            .chain(std::iter::once(S1_BUNDLE_MANIFEST))
            .collect()
    }

    /// Return the exact owned directory set in parent-before-child order.
    pub fn owned_relative_directories(&self) -> &'static [&'static str] {
        REQUIRED_DIRECTORIES
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearnBundleInstallReceipt {
    prefix: PathBuf,
    target: LearnBundleTarget,
    manifest_seal: [u8; 32],
    file_count: usize,
    total_bytes: u64,
}

impl LearnBundleInstallReceipt {
    pub fn prefix(&self) -> &Path {
        &self.prefix
    }

    pub const fn target(&self) -> &'static str {
        self.target.as_str()
    }

    pub fn manifest_seal_hex(&self) -> String {
        hex_encode(&self.manifest_seal)
    }

    pub const fn file_count(&self) -> usize {
        self.file_count
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ManifestEntry {
    path: String,
    mode: u32,
    size: u64,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedManifest {
    target: LearnBundleTarget,
    entries: Vec<ManifestEntry>,
    seal: [u8; 32],
}

/// Verify the complete bounded S1 directory artifact without executing it.
pub fn verify_learn_bundle(root: &Path) -> Result<VerifiedLearnBundle, LearnBundleError> {
    require_existing_directory(root, "bundle root")?;
    let manifest_path = root.join(S1_BUNDLE_MANIFEST);
    let manifest_bytes =
        read_regular_file_bounded(&manifest_path, MANIFEST_MAX_BYTES, S1_BUNDLE_MANIFEST)?;
    require_mode(&manifest_path, 0o644, S1_BUNDLE_MANIFEST)?;
    let parsed = parse_manifest(&manifest_bytes)?;
    let required_files = required_files(parsed.target);
    let inventory = inspect_inventory(root)?;

    let expected_paths: Vec<_> = required_files.iter().map(|file| file.path).collect();
    let manifest_paths: Vec<_> = parsed
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    if manifest_paths != expected_paths {
        return Err(LearnBundleError::new(
            "bundle manifest file rows do not match the canonical ordered inventory",
        ));
    }

    let mut total_bytes = manifest_bytes.len() as u64;
    for (entry, required) in parsed.entries.iter().zip(required_files) {
        if entry.mode != required.mode {
            return Err(LearnBundleError::new(format!(
                "bundle manifest mode for `{}` is {:04o}, expected {:04o}",
                entry.path, entry.mode, required.mode
            )));
        }
        if entry.size > required.max_bytes {
            return Err(LearnBundleError::new(format!(
                "bundle member `{}` exceeds its {} byte cap",
                entry.path, required.max_bytes
            )));
        }
        let path = root.join(required.path);
        require_mode(&path, required.mode, required.path)?;
        let bytes = read_regular_file_bounded(&path, required.max_bytes, required.path)?;
        if bytes.len() as u64 != entry.size {
            return Err(LearnBundleError::new(format!(
                "bundle member `{}` size mismatch: manifest {}, actual {}",
                entry.path,
                entry.size,
                bytes.len()
            )));
        }
        let actual_digest = sha256(&bytes);
        if actual_digest != entry.digest {
            return Err(LearnBundleError::new(format!(
                "bundle member `{}` SHA-256 mismatch",
                entry.path
            )));
        }
        total_bytes = total_bytes
            .checked_add(entry.size)
            .ok_or_else(|| LearnBundleError::new("bundle total byte count overflow"))?;
        if total_bytes > BUNDLE_MAX_TOTAL_BYTES {
            return Err(LearnBundleError::new(format!(
                "bundle exceeds the {} byte total cap",
                BUNDLE_MAX_TOTAL_BYTES
            )));
        }
    }

    let expected_inventory: BTreeSet<_> = required_files
        .iter()
        .map(|file| file.path.to_string())
        .chain(std::iter::once(S1_BUNDLE_MANIFEST.to_string()))
        .collect();
    if inventory.files != expected_inventory {
        return Err(LearnBundleError::new(
            "bundle filesystem inventory differs from its canonical file set",
        ));
    }
    validate_packaged_catalogs(&root.join("locales")).map_err(|error| {
        LearnBundleError::new(format!("bundle installer locale admission failed: {error}"))
    })?;

    Ok(VerifiedLearnBundle {
        root: root.to_path_buf(),
        target: parsed.target,
        manifest_seal: parsed.seal,
        file_count: required_files.len() + 1,
        total_bytes,
    })
}

/// Install only a fully admitted bundle into a new prefix.
///
/// The prefix must not exist. Files are copied into a sibling staging
/// directory, the staged copy is independently re-verified, and only then is
/// it atomically renamed into place.
pub fn install_learn_bundle(
    bundle_root: &Path,
    prefix: &Path,
) -> Result<LearnBundleInstallReceipt, LearnBundleError> {
    let source = verify_learn_bundle(bundle_root)?;
    require_install_target(source.target)?;
    let absolute_prefix = absolute_new_prefix(prefix)?;
    let parent = absolute_prefix
        .parent()
        .ok_or_else(|| LearnBundleError::new("install prefix has no parent directory"))?;
    require_existing_directory(parent, "install-prefix parent")?;
    if fs::symlink_metadata(&absolute_prefix).is_ok() {
        return Err(LearnBundleError::new(format!(
            "install prefix `{}` already exists",
            absolute_prefix.display()
        )));
    }

    let leaf = absolute_prefix
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| LearnBundleError::new("install prefix has a non-UTF-8 final component"))?;
    let staging = parent.join(format!(".{leaf}.naux-staging-{}", std::process::id()));
    if fs::symlink_metadata(&staging).is_ok() {
        return Err(LearnBundleError::new(format!(
            "install staging path `{}` already exists",
            staging.display()
        )));
    }

    if let Err(error) = copy_bundle_to_staging(bundle_root, &staging, source.target) {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    let staged = match verify_learn_bundle(&staging) {
        Ok(staged) => staged,
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(LearnBundleError::new(format!(
                "staged bundle verification failed: {error}"
            )));
        }
    };
    if staged.manifest_seal != source.manifest_seal
        || staged.total_bytes != source.total_bytes
        || staged.file_count != source.file_count
    {
        let _ = fs::remove_dir_all(&staging);
        return Err(LearnBundleError::new(
            "staged bundle receipt differs from the admitted source receipt",
        ));
    }
    if let Err(error) = fs::rename(&staging, &absolute_prefix) {
        let _ = fs::remove_dir_all(&staging);
        return Err(LearnBundleError::new(format!(
            "cannot publish install prefix `{}`: {error}",
            absolute_prefix.display()
        )));
    }

    Ok(LearnBundleInstallReceipt {
        prefix: absolute_prefix,
        target: source.target,
        manifest_seal: source.manifest_seal,
        file_count: source.file_count,
        total_bytes: source.total_bytes,
    })
}

fn require_install_target(target: LearnBundleTarget) -> Result<(), LearnBundleError> {
    if target.as_str() == S1_BUNDLE_TARGET {
        return Ok(());
    }
    Err(LearnBundleError::new(format!(
        "NAUX Learn bundle target `{}` cannot be installed on host `{S1_BUNDLE_TARGET}`",
        target.as_str()
    )))
}

fn parse_manifest(bytes: &[u8]) -> Result<ParsedManifest, LearnBundleError> {
    let manifest = std::str::from_utf8(bytes)
        .map_err(|_| LearnBundleError::new("bundle manifest is not valid UTF-8"))?;
    if manifest.contains('\0') {
        return Err(LearnBundleError::new("bundle manifest contains NUL"));
    }
    if manifest.contains('\r') {
        return Err(LearnBundleError::new(
            "bundle manifest must use canonical LF line endings",
        ));
    }
    if !manifest.ends_with('\n') {
        return Err(LearnBundleError::new(
            "bundle manifest must end with one LF",
        ));
    }

    let without_final_lf = &manifest[..manifest.len() - 1];
    let seal_line_start = without_final_lf
        .rfind('\n')
        .map(|position| position + 1)
        .ok_or_else(|| LearnBundleError::new("bundle manifest is missing its seal row"))?;
    let body = &manifest.as_bytes()[..seal_line_start];
    let seal_line = &without_final_lf[seal_line_start..];
    let seal_fields: Vec<_> = seal_line.split('\t').collect();
    if seal_fields.len() != 2 || seal_fields[0] != "seal" {
        return Err(LearnBundleError::new(
            "bundle manifest has a malformed terminal seal row",
        ));
    }
    let declared_seal = parse_lower_hex_32(seal_fields[1], "manifest seal")?;
    let mut seal_preimage = Vec::with_capacity(MANIFEST_SEAL_DOMAIN.len() + body.len());
    seal_preimage.extend_from_slice(MANIFEST_SEAL_DOMAIN);
    seal_preimage.extend_from_slice(body);
    let actual_seal = sha256(&seal_preimage);
    if declared_seal != actual_seal {
        return Err(LearnBundleError::new("bundle manifest seal mismatch"));
    }

    let body_text = std::str::from_utf8(body)
        .map_err(|_| LearnBundleError::new("bundle manifest body is not valid UTF-8"))?;
    let mut lines = body_text.lines();
    if lines.next() != Some(MANIFEST_MAGIC) {
        return Err(LearnBundleError::new(
            "bundle manifest magic/version mismatch",
        ));
    }
    if lines.next() != Some(&format!("bundle\t{S1_BUNDLE_VERSION}")) {
        return Err(LearnBundleError::new(
            "bundle manifest product version mismatch",
        ));
    }
    let target_line = lines
        .next()
        .ok_or_else(|| LearnBundleError::new("bundle manifest target row is missing"))?;
    let target_value = target_line
        .strip_prefix("target\t")
        .ok_or_else(|| LearnBundleError::new("bundle manifest target row is malformed"))?;
    if target_value.contains('\t') {
        return Err(LearnBundleError::new(
            "bundle manifest target row is malformed",
        ));
    }
    let target = LearnBundleTarget::parse(target_value)?;
    let required_files = required_files(target);

    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    for (offset, line) in lines.enumerate() {
        let line_number = offset + 4;
        if line.is_empty() {
            return Err(LearnBundleError::new(format!(
                "bundle manifest line {line_number} is empty"
            )));
        }
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 5 || fields[0] != "file" {
            return Err(LearnBundleError::new(format!(
                "bundle manifest line {line_number} is not a canonical file row"
            )));
        }
        let mode = parse_mode(fields[1], line_number)?;
        let size = parse_canonical_u64(fields[2], line_number)?;
        let digest = parse_lower_hex_32(fields[3], "member digest")?;
        require_safe_relative_path(fields[4])?;
        if !seen.insert(fields[4].to_string()) {
            return Err(LearnBundleError::new(format!(
                "bundle manifest duplicates member `{}`",
                fields[4]
            )));
        }
        entries.push(ManifestEntry {
            path: fields[4].to_string(),
            mode,
            size,
            digest,
        });
        if entries.len() > required_files.len() {
            return Err(LearnBundleError::new(
                "bundle manifest contains too many file rows",
            ));
        }
    }
    if entries.len() != required_files.len() {
        return Err(LearnBundleError::new(format!(
            "bundle manifest contains {} file rows, expected {}",
            entries.len(),
            required_files.len()
        )));
    }
    Ok(ParsedManifest {
        target,
        entries,
        seal: actual_seal,
    })
}

fn parse_mode(value: &str, line_number: usize) -> Result<u32, LearnBundleError> {
    if value.len() != 4 || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(LearnBundleError::new(format!(
            "bundle manifest line {line_number} has a noncanonical mode"
        )));
    }
    u32::from_str_radix(value, 8).map_err(|_| {
        LearnBundleError::new(format!(
            "bundle manifest line {line_number} has an invalid mode"
        ))
    })
}

fn parse_canonical_u64(value: &str, line_number: usize) -> Result<u64, LearnBundleError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(LearnBundleError::new(format!(
            "bundle manifest line {line_number} has a noncanonical size"
        )));
    }
    value.parse::<u64>().map_err(|_| {
        LearnBundleError::new(format!(
            "bundle manifest line {line_number} size exceeds u64"
        ))
    })
}

fn parse_lower_hex_32(value: &str, field: &str) -> Result<[u8; 32], LearnBundleError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(LearnBundleError::new(format!(
            "bundle {field} is not 64 lowercase hexadecimal digits"
        )));
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0]);
        let low = hex_nibble(chunk[1]);
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("hex input was validated"),
    }
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn require_safe_relative_path(path: &str) -> Result<(), LearnBundleError> {
    if path.is_empty()
        || path.len() > INVENTORY_MAX_PATH_BYTES
        || path.contains('\\')
        || Path::new(path).is_absolute()
        || Path::new(path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(LearnBundleError::new(format!(
            "bundle manifest contains unsafe path `{path}`"
        )));
    }
    Ok(())
}

#[derive(Debug)]
struct Inventory {
    files: BTreeSet<String>,
}

fn inspect_inventory(root: &Path) -> Result<Inventory, LearnBundleError> {
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    walk_inventory(root, Path::new(""), &mut files, &mut directories)?;
    let expected_directories: BTreeSet<_> = REQUIRED_DIRECTORIES
        .iter()
        .map(|path| path.to_string())
        .collect();
    if directories != expected_directories {
        return Err(LearnBundleError::new(
            "bundle directory inventory differs from the canonical directory set",
        ));
    }
    if files.len() + directories.len() > INVENTORY_MAX_ENTRIES {
        return Err(LearnBundleError::new(format!(
            "bundle inventory exceeds the {INVENTORY_MAX_ENTRIES} entry cap"
        )));
    }
    Ok(Inventory { files })
}

fn walk_inventory(
    root: &Path,
    relative: &Path,
    files: &mut BTreeSet<String>,
    directories: &mut BTreeSet<String>,
) -> Result<(), LearnBundleError> {
    let directory = root.join(relative);
    let entries = fs::read_dir(&directory).map_err(|error| {
        LearnBundleError::new(format!(
            "cannot read bundle directory `{}`: {error}",
            directory.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            LearnBundleError::new(format!(
                "cannot inspect bundle directory `{}`: {error}",
                directory.display()
            ))
        })?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| LearnBundleError::new("bundle contains a non-UTF-8 path component"))?;
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
            return Err(LearnBundleError::new(
                "bundle contains an unsafe filesystem path component",
            ));
        }
        let (child_relative, child_text) = canonical_inventory_child(relative, &name)?;
        require_safe_relative_path(&child_text)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            LearnBundleError::new(format!(
                "cannot inspect bundle member `{child_text}`: {error}"
            ))
        })?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(LearnBundleError::new(format!(
                "bundle member `{child_text}` is a symlink"
            )));
        }
        if file_type.is_dir() {
            if !directories.insert(child_text.clone()) {
                return Err(LearnBundleError::new(format!(
                    "bundle repeats directory `{child_text}`"
                )));
            }
            walk_inventory(root, &child_relative, files, directories)?;
        } else if file_type.is_file() {
            if !files.insert(child_text.clone()) {
                return Err(LearnBundleError::new(format!(
                    "bundle repeats file `{child_text}`"
                )));
            }
        } else {
            return Err(LearnBundleError::new(format!(
                "bundle member `{child_text}` is not a regular file or directory"
            )));
        }
        if files.len() + directories.len() > INVENTORY_MAX_ENTRIES {
            return Err(LearnBundleError::new(format!(
                "bundle inventory exceeds the {INVENTORY_MAX_ENTRIES} entry cap"
            )));
        }
    }
    Ok(())
}

fn canonical_inventory_child(
    relative: &Path,
    name: &str,
) -> Result<(PathBuf, String), LearnBundleError> {
    let parent_text = relative
        .to_str()
        .ok_or_else(|| LearnBundleError::new("bundle contains a non-UTF-8 path"))?
        .replace('\\', "/");
    let child_text = if parent_text.is_empty() {
        name.to_string()
    } else {
        format!("{parent_text}/{name}")
    };
    Ok((PathBuf::from(&child_text), child_text))
}

fn read_regular_file_bounded(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, LearnBundleError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LearnBundleError::new(format!("cannot inspect bundle member `{label}`: {error}"))
    })?;
    if !metadata.file_type().is_file() {
        return Err(LearnBundleError::new(format!(
            "bundle member `{label}` is not a regular file"
        )));
    }
    if metadata.len() > max_bytes {
        return Err(LearnBundleError::new(format!(
            "bundle member `{label}` exceeds its {max_bytes} byte cap"
        )));
    }
    let mut file = File::open(path).map_err(|error| {
        LearnBundleError::new(format!("cannot open bundle member `{label}`: {error}"))
    })?;
    let capacity = usize::try_from(metadata.len())
        .map_err(|_| LearnBundleError::new(format!("bundle member `{label}` is too large")))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            LearnBundleError::new(format!("cannot read bundle member `{label}`: {error}"))
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(LearnBundleError::new(format!(
            "bundle member `{label}` exceeds its {max_bytes} byte cap"
        )));
    }
    Ok(bytes)
}

fn require_existing_directory(path: &Path, label: &str) -> Result<(), LearnBundleError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LearnBundleError::new(format!(
            "cannot inspect {label} `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(LearnBundleError::new(format!(
            "{label} `{}` is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn require_mode(path: &Path, expected: u32, label: &str) -> Result<(), LearnBundleError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LearnBundleError::new(format!("cannot inspect bundle member `{label}`: {error}"))
    })?;
    let actual = metadata.permissions().mode() & 0o777;
    if actual != expected {
        return Err(LearnBundleError::new(format!(
            "bundle member `{label}` mode is {actual:04o}, expected {expected:04o}"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn require_mode(path: &Path, expected: u32, label: &str) -> Result<(), LearnBundleError> {
    if !matches!(expected, 0o644 | 0o755) {
        return Err(LearnBundleError::new(format!(
            "bundle member `{label}` has unsupported Windows transport mode {expected:04o}"
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LearnBundleError::new(format!("cannot inspect bundle member `{label}`: {error}"))
    })?;
    if metadata.permissions().readonly() {
        return Err(LearnBundleError::new(format!(
            "bundle member `{label}` is unexpectedly read-only"
        )));
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn require_mode(_path: &Path, _expected: u32, _label: &str) -> Result<(), LearnBundleError> {
    Err(LearnBundleError::new(
        "NAUX Learn bundle mode verification requires a Unix host",
    ))
}

fn absolute_new_prefix(prefix: &Path) -> Result<PathBuf, LearnBundleError> {
    if prefix.as_os_str().is_empty()
        || prefix.parent().is_none()
        || prefix.file_name().is_none()
        || prefix
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(LearnBundleError::new(
            "install prefix must name a new non-root path without `..`",
        ));
    }
    if prefix.is_absolute() {
        Ok(prefix.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|current| current.join(prefix))
            .map_err(|error| {
                LearnBundleError::new(format!("cannot resolve current directory: {error}"))
            })
    }
}

fn copy_bundle_to_staging(
    source: &Path,
    staging: &Path,
    target: LearnBundleTarget,
) -> Result<(), LearnBundleError> {
    fs::create_dir(staging).map_err(|error| {
        LearnBundleError::new(format!(
            "cannot create install staging directory `{}`: {error}",
            staging.display()
        ))
    })?;
    for directory in REQUIRED_DIRECTORIES {
        fs::create_dir(staging.join(directory)).map_err(|error| {
            LearnBundleError::new(format!(
                "cannot create staged directory `{directory}`: {error}"
            ))
        })?;
    }
    for required in required_files(target) {
        copy_regular_member(source, staging, required.path, required.mode)?;
    }
    copy_regular_member(source, staging, S1_BUNDLE_MANIFEST, 0o644)?;
    Ok(())
}

fn copy_regular_member(
    source: &Path,
    destination: &Path,
    relative: &str,
    mode: u32,
) -> Result<(), LearnBundleError> {
    let destination_path = destination.join(relative);
    fs::copy(source.join(relative), &destination_path).map_err(|error| {
        LearnBundleError::new(format!("cannot stage bundle member `{relative}`: {error}"))
    })?;
    set_mode(&destination_path, mode, relative)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32, label: &str) -> Result<(), LearnBundleError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| {
        LearnBundleError::new(format!(
            "cannot set staged bundle member `{label}` mode: {error}"
        ))
    })
}

#[cfg(windows)]
fn set_mode(path: &Path, mode: u32, label: &str) -> Result<(), LearnBundleError> {
    if !matches!(mode, 0o644 | 0o755) {
        return Err(LearnBundleError::new(format!(
            "cannot set staged bundle member `{label}` unsupported Windows transport mode {mode:04o}"
        )));
    }
    let mut permissions = fs::metadata(path)
        .map_err(|error| {
            LearnBundleError::new(format!(
                "cannot inspect staged bundle member `{label}` permissions: {error}"
            ))
        })?
        .permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions).map_err(|error| {
        LearnBundleError::new(format!(
            "cannot set staged bundle member `{label}` permissions: {error}"
        ))
    })
}

#[cfg(all(not(unix), not(windows)))]
fn set_mode(_path: &Path, _mode: u32, _label: &str) -> Result<(), LearnBundleError> {
    Err(LearnBundleError::new(
        "NAUX Learn bundle installation requires a Unix host",
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_inventory_child, parse_manifest, require_safe_relative_path, LearnBundleTarget,
        MANIFEST_MAGIC, MANIFEST_SEAL_DOMAIN, S1_BUNDLE_TARGET, S1_BUNDLE_VERSION,
    };
    use crate::core::encoding::sha256;

    fn one_entry_manifest(path: &str) -> String {
        let body = format!(
            "{MANIFEST_MAGIC}\nbundle\t{S1_BUNDLE_VERSION}\ntarget\t{S1_BUNDLE_TARGET}\nfile\t0644\t1\t{}\t{path}\n",
            "00".repeat(32)
        );
        let mut preimage = MANIFEST_SEAL_DOMAIN.to_vec();
        preimage.extend_from_slice(body.as_bytes());
        let seal = super::hex_encode(&sha256(&preimage));
        format!("{body}seal\t{seal}\n")
    }

    #[test]
    fn safe_relative_path_rejects_traversal_and_platform_aliases() {
        assert!(require_safe_relative_path("bin/naux").is_ok());
        assert!(require_safe_relative_path("bin/naux.exe").is_ok());
        for path in ["../naux", "bin/../naux", "/bin/naux", "bin\\naux", ""] {
            assert!(
                require_safe_relative_path(path).is_err(),
                "accepted {path:?}"
            );
        }
    }

    #[test]
    fn bundle_targets_are_an_exact_two_member_set() {
        assert_eq!(
            LearnBundleTarget::parse("linux-x86_64-gnu")
                .unwrap()
                .as_str(),
            "linux-x86_64-gnu"
        );
        assert_eq!(
            LearnBundleTarget::parse("windows-x86_64-gnu")
                .unwrap()
                .as_str(),
            "windows-x86_64-gnu"
        );
        assert!(LearnBundleTarget::parse("windows-x86_64-msvc").is_err());
        assert!(LearnBundleTarget::parse("linux-aarch64-gnu").is_err());
    }

    #[test]
    fn inventory_paths_are_canonical_across_host_separators() {
        let (_, root) = canonical_inventory_child(std::path::Path::new(""), "bin").unwrap();
        let (_, nested) =
            canonical_inventory_child(std::path::Path::new(r"docs\nested"), "file.md").unwrap();
        assert_eq!(root, "bin");
        assert_eq!(nested, "docs/nested/file.md");
    }

    #[test]
    fn manifest_seal_is_checked_before_inventory_shape() {
        let mut manifest = one_entry_manifest("LICENSE");
        manifest = manifest.replace("file\t0644\t1", "file\t0644\t2");
        assert!(parse_manifest(manifest.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("seal mismatch"));
    }

    #[test]
    fn manifest_rejects_noncanonical_lines() {
        let manifest = one_entry_manifest("../LICENSE");
        assert!(parse_manifest(manifest.as_bytes()).is_err());
        let crlf = one_entry_manifest("LICENSE").replace('\n', "\r\n");
        assert!(parse_manifest(crlf.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("canonical LF"));
    }
}
