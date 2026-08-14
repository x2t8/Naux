//! Proof-oriented installation receipt and bounded uninstall foundation.
//!
//! The immutable installed prefix remains an ordinary verified Learn bundle.
//! Mutable lifecycle state is held in a sibling/central state directory chosen
//! by the native installer. The receipt binds that prefix and its bundle seal;
//! uninstall never scans for guessed ownership.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use crate::core::encoding::sha256;
use crate::install_locale::catalog_for;
use crate::learn_bundle::{
    install_learn_bundle, verify_learn_bundle, LearnBundleInstallReceipt, S1_BUNDLE_VERSION,
};

const RECEIPT_MAGIC: &str = "NAUX-LEARN-INSTALLATION\t1";
const RECEIPT_SEAL_DOMAIN: &[u8] = b"NAUX:learn-installation-receipt:v1\0";
const INSTALLATION_ID_DOMAIN: &[u8] = b"NAUX:learn-installation-id:v1\0";
const RECEIPT_MAX_BYTES: u64 = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallationReceipt {
    installation_id: String,
    receipt_path: PathBuf,
    prefix: PathBuf,
    locale: String,
    target: String,
    bundle_manifest_seal: String,
    file_count: usize,
    total_bytes: u64,
}

impl InstallationReceipt {
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    pub fn receipt_path(&self) -> &Path {
        &self.receipt_path
    }

    pub fn prefix(&self) -> &Path {
        &self.prefix
    }

    pub fn locale(&self) -> &str {
        &self.locale
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn bundle_manifest_seal(&self) -> &str {
        &self.bundle_manifest_seal
    }

    pub const fn file_count(&self) -> usize {
        self.file_count
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UninstallPlan {
    receipt: InstallationReceipt,
    files: Vec<PathBuf>,
    directories: Vec<PathBuf>,
}

impl UninstallPlan {
    pub fn receipt(&self) -> &InstallationReceipt {
        &self.receipt
    }

    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    pub fn directories(&self) -> &[PathBuf] {
        &self.directories
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleError {
    message: String,
}

impl LifecycleError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LifecycleError {}

/// Install an admitted bundle and publish one sealed ownership receipt.
///
/// The state directory must already exist and must not be a symlink. Native
/// carriers create that directory using their OS-specific user-local policy.
pub fn install_with_receipt(
    bundle_root: &Path,
    prefix: &Path,
    state_directory: &Path,
    locale: &str,
) -> Result<InstallationReceipt, LifecycleError> {
    let catalog = catalog_for(locale).map_err(|error| LifecycleError::new(error.to_string()))?;
    require_state_directory(state_directory)?;
    let installed = install_learn_bundle(bundle_root, prefix)
        .map_err(|error| LifecycleError::new(error.to_string()))?;
    let receipt = receipt_from_install(&installed, state_directory, catalog.locale())?;
    if let Err(error) = publish_receipt(&receipt) {
        rollback_exact_install(&installed)?;
        return Err(error);
    }
    read_installation_receipt(receipt.receipt_path())
}

/// Admit a receipt and the exact installed bundle, then build an uninstall
/// plan without mutating either location.
pub fn plan_uninstall(receipt_path: &Path) -> Result<UninstallPlan, LifecycleError> {
    let receipt = read_installation_receipt(receipt_path)?;
    let verified = verify_learn_bundle(receipt.prefix())
        .map_err(|error| LifecycleError::new(format!("installed bundle is not intact: {error}")))?;
    if verified.target() != receipt.target
        || verified.manifest_seal_hex() != receipt.bundle_manifest_seal
        || verified.file_count() != receipt.file_count
        || verified.total_bytes() != receipt.total_bytes
    {
        return Err(LifecycleError::new(
            "installation receipt differs from the verified installed bundle",
        ));
    }

    let files = verified
        .owned_relative_files()
        .into_iter()
        .map(|relative| receipt.prefix.join(relative))
        .collect();
    let directories = verified
        .owned_relative_directories()
        .iter()
        .rev()
        .map(|relative| receipt.prefix.join(relative))
        .chain(std::iter::once(receipt.prefix.clone()))
        .collect();
    Ok(UninstallPlan {
        receipt,
        files,
        directories,
    })
}

/// Execute only a previously re-admitted exact uninstall plan.
///
/// Windows native setup uses a separate helper because a running PE cannot
/// reliably remove itself. The dry-run planner remains portable.
#[cfg(not(windows))]
pub fn execute_uninstall(receipt_path: &Path) -> Result<UninstallPlan, LifecycleError> {
    let plan = plan_uninstall(receipt_path)?;
    for path in &plan.files {
        fs::remove_file(path).map_err(|error| {
            LifecycleError::new(format!(
                "cannot remove owned file `{}`: {error}",
                path.display()
            ))
        })?;
    }
    for path in &plan.directories {
        fs::remove_dir(path).map_err(|error| {
            LifecycleError::new(format!(
                "cannot remove owned directory `{}`: {error}",
                path.display()
            ))
        })?;
    }
    fs::remove_file(receipt_path).map_err(|error| {
        LifecycleError::new(format!(
            "installation payload was removed but receipt `{}` could not be removed: {error}",
            receipt_path.display()
        ))
    })?;
    Ok(plan)
}

#[cfg(windows)]
pub fn execute_uninstall(_receipt_path: &Path) -> Result<UninstallPlan, LifecycleError> {
    Err(LifecycleError::new(
        "Windows uninstall execution requires the detached NAUX Setup helper; use dry-run planning from naux.exe",
    ))
}

pub fn read_installation_receipt(
    receipt_path: &Path,
) -> Result<InstallationReceipt, LifecycleError> {
    require_regular_file(receipt_path, "installation receipt")?;
    let metadata = fs::metadata(receipt_path).map_err(|error| {
        LifecycleError::new(format!(
            "cannot inspect installation receipt `{}`: {error}",
            receipt_path.display()
        ))
    })?;
    if metadata.len() > RECEIPT_MAX_BYTES {
        return Err(LifecycleError::new(format!(
            "installation receipt exceeds {RECEIPT_MAX_BYTES} bytes"
        )));
    }
    let bytes = fs::read(receipt_path).map_err(|error| {
        LifecycleError::new(format!(
            "cannot read installation receipt `{}`: {error}",
            receipt_path.display()
        ))
    })?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| LifecycleError::new("installation receipt is not valid UTF-8"))?;
    if text.contains(['\0', '\r']) || !text.ends_with('\n') {
        return Err(LifecycleError::new(
            "installation receipt must use canonical UTF-8/LF text",
        ));
    }
    let without_lf = &text[..text.len() - 1];
    let seal_start = without_lf
        .rfind('\n')
        .map(|position| position + 1)
        .ok_or_else(|| LifecycleError::new("installation receipt is missing its seal row"))?;
    let body = &text.as_bytes()[..seal_start];
    let seal_line = &without_lf[seal_start..];
    let declared_seal = seal_line
        .strip_prefix("seal\t")
        .filter(|seal| is_lower_hex_64(seal))
        .ok_or_else(|| LifecycleError::new("installation receipt seal row is malformed"))?;
    let mut preimage = Vec::with_capacity(RECEIPT_SEAL_DOMAIN.len() + body.len());
    preimage.extend_from_slice(RECEIPT_SEAL_DOMAIN);
    preimage.extend_from_slice(body);
    if hex_encode(&sha256(&preimage)) != declared_seal {
        return Err(LifecycleError::new("installation receipt seal mismatch"));
    }

    let body_text =
        std::str::from_utf8(body).expect("receipt body is a slice of previously admitted UTF-8");
    let mut lines = body_text.lines();
    if lines.next() != Some(RECEIPT_MAGIC) {
        return Err(LifecycleError::new(
            "installation receipt magic/version mismatch",
        ));
    }
    let installation_id = receipt_field(&mut lines, "installation-id")?.to_string();
    if !is_lower_hex_64(&installation_id) {
        return Err(LifecycleError::new(
            "installation receipt contains an invalid installation ID",
        ));
    }
    require_receipt_value(&mut lines, "product", "naux-learn")?;
    require_receipt_value(&mut lines, "version", S1_BUNDLE_VERSION)?;
    let target = receipt_field(&mut lines, "target")?.to_string();
    let prefix_text = receipt_field(&mut lines, "prefix")?;
    let prefix = PathBuf::from(prefix_text);
    require_safe_absolute_prefix(&prefix)?;
    let locale = receipt_field(&mut lines, "locale")?.to_string();
    catalog_for(&locale).map_err(|error| LifecycleError::new(error.to_string()))?;
    let bundle_manifest_seal = receipt_field(&mut lines, "bundle-manifest-seal")?.to_string();
    if !is_lower_hex_64(&bundle_manifest_seal) {
        return Err(LifecycleError::new(
            "installation receipt contains an invalid bundle seal",
        ));
    }
    let file_count = parse_canonical_usize(receipt_field(&mut lines, "files")?, "files")?;
    let total_bytes = parse_canonical_u64(receipt_field(&mut lines, "bytes")?, "bytes")?;
    if lines.next().is_some() {
        return Err(LifecycleError::new(
            "installation receipt contains extra rows",
        ));
    }

    let expected_id = installation_id_for(&prefix, &target, &bundle_manifest_seal, &locale)?;
    if installation_id != expected_id {
        return Err(LifecycleError::new(
            "installation receipt ID does not bind its declared installation",
        ));
    }
    let expected_name = format!("{installation_id}.tsv");
    if receipt_path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
        return Err(LifecycleError::new(
            "installation receipt filename does not match its installation ID",
        ));
    }

    Ok(InstallationReceipt {
        installation_id,
        receipt_path: receipt_path.to_path_buf(),
        prefix,
        locale,
        target,
        bundle_manifest_seal,
        file_count,
        total_bytes,
    })
}

fn receipt_from_install(
    installed: &LearnBundleInstallReceipt,
    state_directory: &Path,
    locale: &str,
) -> Result<InstallationReceipt, LifecycleError> {
    require_safe_absolute_prefix(installed.prefix())?;
    let bundle_manifest_seal = installed.manifest_seal_hex();
    let installation_id = installation_id_for(
        installed.prefix(),
        installed.target(),
        &bundle_manifest_seal,
        locale,
    )?;
    Ok(InstallationReceipt {
        receipt_path: state_directory.join(format!("{installation_id}.tsv")),
        installation_id,
        prefix: installed.prefix().to_path_buf(),
        locale: locale.to_string(),
        target: installed.target().to_string(),
        bundle_manifest_seal,
        file_count: installed.file_count(),
        total_bytes: installed.total_bytes(),
    })
}

fn publish_receipt(receipt: &InstallationReceipt) -> Result<(), LifecycleError> {
    if fs::symlink_metadata(receipt.receipt_path()).is_ok() {
        return Err(LifecycleError::new(format!(
            "installation receipt `{}` already exists",
            receipt.receipt_path().display()
        )));
    }
    let body = receipt_body(receipt)?;
    let mut preimage = Vec::with_capacity(RECEIPT_SEAL_DOMAIN.len() + body.len());
    preimage.extend_from_slice(RECEIPT_SEAL_DOMAIN);
    preimage.extend_from_slice(body.as_bytes());
    let contents = format!("{body}seal\t{}\n", hex_encode(&sha256(&preimage)));
    let staging = receipt
        .receipt_path()
        .with_extension(format!("tsv.staging-{}", std::process::id()));
    if fs::symlink_metadata(&staging).is_ok() {
        return Err(LifecycleError::new(format!(
            "installation receipt staging path `{}` already exists",
            staging.display()
        )));
    }

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)
            .map_err(|error| {
                LifecycleError::new(format!(
                    "cannot create installation receipt staging file `{}`: {error}",
                    staging.display()
                ))
            })?;
        set_private_permissions(&file, &staging)?;
        file.write_all(contents.as_bytes()).map_err(|error| {
            LifecycleError::new(format!("cannot write installation receipt: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            LifecycleError::new(format!("cannot sync installation receipt: {error}"))
        })?;
        drop(file);
        fs::rename(&staging, receipt.receipt_path()).map_err(|error| {
            LifecycleError::new(format!(
                "cannot publish installation receipt `{}`: {error}",
                receipt.receipt_path().display()
            ))
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staging);
    }
    result
}

fn receipt_body(receipt: &InstallationReceipt) -> Result<String, LifecycleError> {
    let prefix = receipt
        .prefix
        .to_str()
        .ok_or_else(|| LifecycleError::new("installation prefix must be valid UTF-8"))?;
    Ok(format!(
        "{RECEIPT_MAGIC}\ninstallation-id\t{}\nproduct\tnaux-learn\nversion\t{S1_BUNDLE_VERSION}\ntarget\t{}\nprefix\t{prefix}\nlocale\t{}\nbundle-manifest-seal\t{}\nfiles\t{}\nbytes\t{}\n",
        receipt.installation_id,
        receipt.target,
        receipt.locale,
        receipt.bundle_manifest_seal,
        receipt.file_count,
        receipt.total_bytes,
    ))
}

fn installation_id_for(
    prefix: &Path,
    target: &str,
    manifest_seal: &str,
    locale: &str,
) -> Result<String, LifecycleError> {
    let prefix = prefix
        .to_str()
        .ok_or_else(|| LifecycleError::new("installation prefix must be valid UTF-8"))?;
    let mut preimage = Vec::new();
    preimage.extend_from_slice(INSTALLATION_ID_DOMAIN);
    for field in [S1_BUNDLE_VERSION, target, prefix, locale, manifest_seal] {
        preimage.extend_from_slice(field.as_bytes());
        preimage.push(0);
    }
    Ok(hex_encode(&sha256(&preimage)))
}

fn rollback_exact_install(installed: &LearnBundleInstallReceipt) -> Result<(), LifecycleError> {
    let verified = verify_learn_bundle(installed.prefix()).map_err(|error| {
        LifecycleError::new(format!(
            "receipt publication failed and exact install rollback was refused: {error}"
        ))
    })?;
    if verified.manifest_seal_hex() != installed.manifest_seal_hex() {
        return Err(LifecycleError::new(
            "receipt publication failed and install changed before rollback",
        ));
    }
    fs::remove_dir_all(installed.prefix()).map_err(|error| {
        LifecycleError::new(format!(
            "receipt publication failed and exact install rollback failed: {error}"
        ))
    })
}

fn require_state_directory(path: &Path) -> Result<(), LifecycleError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LifecycleError::new(format!(
            "lifecycle state directory `{}` must already exist: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LifecycleError::new(
            "lifecycle state path must be an existing non-symlink directory",
        ));
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<(), LifecycleError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LifecycleError::new(format!(
            "cannot inspect {label} `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LifecycleError::new(format!(
            "{label} must be a regular non-symlink file"
        )));
    }
    Ok(())
}

fn require_safe_absolute_prefix(prefix: &Path) -> Result<(), LifecycleError> {
    let text = prefix
        .to_str()
        .ok_or_else(|| LifecycleError::new("installation prefix must be valid UTF-8"))?;
    if !prefix.is_absolute()
        || prefix.parent().is_none()
        || prefix.file_name().is_none()
        || text.chars().any(char::is_control)
        || prefix
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(LifecycleError::new(
            "installation receipt requires a safe absolute non-root prefix",
        ));
    }
    Ok(())
}

fn receipt_field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
) -> Result<&'a str, LifecycleError> {
    let line = lines
        .next()
        .ok_or_else(|| LifecycleError::new(format!("installation receipt is missing `{key}`")))?;
    let value = line
        .strip_prefix(key)
        .and_then(|rest| rest.strip_prefix('\t'))
        .filter(|value| !value.is_empty() && !value.contains('\t'))
        .ok_or_else(|| {
            LifecycleError::new(format!("installation receipt `{key}` row is malformed"))
        })?;
    Ok(value)
}

fn require_receipt_value<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
    expected: &str,
) -> Result<(), LifecycleError> {
    if receipt_field(lines, key)? != expected {
        return Err(LifecycleError::new(format!(
            "installation receipt `{key}` value is unsupported"
        )));
    }
    Ok(())
}

fn parse_canonical_usize(value: &str, key: &str) -> Result<usize, LifecycleError> {
    if !is_canonical_decimal(value) {
        return Err(LifecycleError::new(format!(
            "installation receipt `{key}` is noncanonical"
        )));
    }
    value
        .parse()
        .map_err(|_| LifecycleError::new(format!("installation receipt `{key}` exceeds usize")))
}

fn parse_canonical_u64(value: &str, key: &str) -> Result<u64, LifecycleError> {
    if !is_canonical_decimal(value) {
        return Err(LifecycleError::new(format!(
            "installation receipt `{key}` is noncanonical"
        )));
    }
    value
        .parse()
        .map_err(|_| LifecycleError::new(format!("installation receipt `{key}` exceeds u64")))
}

fn is_canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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

#[cfg(unix)]
fn set_private_permissions(file: &File, path: &Path) -> Result<(), LifecycleError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| {
            LifecycleError::new(format!(
                "cannot set installation receipt `{}` permissions: {error}",
                path.display()
            ))
        })
}

#[cfg(windows)]
fn set_private_permissions(file: &File, path: &Path) -> Result<(), LifecycleError> {
    let mut permissions = file
        .metadata()
        .map_err(|error| {
            LifecycleError::new(format!(
                "cannot inspect installation receipt `{}` permissions: {error}",
                path.display()
            ))
        })?
        .permissions();
    permissions.set_readonly(false);
    file.set_permissions(permissions).map_err(|error| {
        LifecycleError::new(format!(
            "cannot set installation receipt `{}` permissions: {error}",
            path.display()
        ))
    })
}

#[cfg(all(not(unix), not(windows)))]
fn set_private_permissions(_file: &File, _path: &Path) -> Result<(), LifecycleError> {
    Err(LifecycleError::new(
        "installation receipt permissions are unsupported on this host",
    ))
}
