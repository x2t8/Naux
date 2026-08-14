//! Linux user-local activation for an immutable NAUX Learn bundle.
//!
//! The bundle receipt owns the versioned toolchain. This second, sealed
//! receipt owns only the Linux activation surface around that toolchain:
//! stable launchers and directories created by Setup. Uninstall therefore
//! operates from declared ownership and never scans the user's machine.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use crate::core::encoding::sha256;
use crate::install_lifecycle::{
    execute_uninstall, install_with_receipt, plan_uninstall, InstallationReceipt, UninstallPlan,
};
use crate::install_locale::catalog_for;
use crate::learn_bundle::S1_BUNDLE_VERSION;

const ACTIVATION_MAGIC: &str = "NAUX-LEARN-LINUX-ACTIVATION\t1";
const ACTIVATION_SEAL_DOMAIN: &[u8] = b"NAUX:learn-linux-activation-receipt:v1\0";
const ACTIVATION_ID_DOMAIN: &[u8] = b"NAUX:learn-linux-activation-id:v1\0";
const ACTIVATION_MAX_BYTES: u64 = 16 * 1024;
const MAX_CREATED_DIRECTORIES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxInstallLayout {
    prefix: PathBuf,
    state_directory: PathBuf,
    bin_directory: PathBuf,
}

impl LinuxInstallLayout {
    pub fn new(prefix: PathBuf, state_directory: PathBuf, bin_directory: PathBuf) -> Self {
        Self {
            prefix,
            state_directory,
            bin_directory,
        }
    }

    pub fn prefix(&self) -> &Path {
        &self.prefix
    }

    pub fn state_directory(&self) -> &Path {
        &self.state_directory
    }

    pub fn bin_directory(&self) -> &Path {
        &self.bin_directory
    }

    pub fn activation_receipt_path(&self) -> PathBuf {
        self.state_directory
            .join(format!("learn-{S1_BUNDLE_VERSION}.tsv"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxActivationReceipt {
    installation_id: String,
    receipt_path: PathBuf,
    core_receipt_path: PathBuf,
    core_installation_id: String,
    prefix: PathBuf,
    locale: String,
    naux_launcher: PathBuf,
    naux_target: PathBuf,
    nauxup_launcher: PathBuf,
    nauxup_target: PathBuf,
    created_directories: Vec<PathBuf>,
}

impl LinuxActivationReceipt {
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    pub fn receipt_path(&self) -> &Path {
        &self.receipt_path
    }

    pub fn core_receipt_path(&self) -> &Path {
        &self.core_receipt_path
    }

    pub fn prefix(&self) -> &Path {
        &self.prefix
    }

    pub fn locale(&self) -> &str {
        &self.locale
    }

    pub fn naux_launcher(&self) -> &Path {
        &self.naux_launcher
    }

    pub fn nauxup_launcher(&self) -> &Path {
        &self.nauxup_launcher
    }

    pub fn created_directories(&self) -> &[PathBuf] {
        &self.created_directories
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxUninstallPlan {
    activation: LinuxActivationReceipt,
    core: UninstallPlan,
}

impl LinuxUninstallPlan {
    pub fn activation(&self) -> &LinuxActivationReceipt {
        &self.activation
    }

    pub fn core(&self) -> &UninstallPlan {
        &self.core
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxDistributionError {
    message: String,
}

impl LinuxDistributionError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for LinuxDistributionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LinuxDistributionError {}

/// Install a versioned bundle and activate stable `naux`/`nauxup` commands.
///
/// Existing launchers are never overwritten. Any failure before activation
/// publication rolls back only paths created by this invocation.
pub fn install_linux_distribution(
    bundle_root: &Path,
    layout: &LinuxInstallLayout,
    locale: &str,
) -> Result<LinuxActivationReceipt, LinuxDistributionError> {
    validate_layout(layout)?;
    catalog_for(locale).map_err(|error| LinuxDistributionError::new(error.to_string()))?;

    let activation_path = layout.activation_receipt_path();
    require_absent(&activation_path, "Linux activation receipt")?;
    let naux_launcher = layout.bin_directory.join("naux");
    let nauxup_launcher = layout.bin_directory.join("nauxup");
    require_absent(&naux_launcher, "naux launcher")?;
    require_absent(&nauxup_launcher, "nauxup launcher")?;

    let mut created_directories = Vec::new();
    let preparation = (|| {
        let prefix_parent = layout.prefix.parent().ok_or_else(|| {
            LinuxDistributionError::new("Linux installation prefix has no parent")
        })?;
        ensure_directory_chain(prefix_parent, 0o755, &mut created_directories)?;
        ensure_directory_chain(&layout.state_directory, 0o700, &mut created_directories)?;
        ensure_directory_chain(&layout.bin_directory, 0o755, &mut created_directories)
    })();
    if let Err(error) = preparation {
        cleanup_created_directories(&created_directories);
        return Err(error);
    }

    let core =
        match install_with_receipt(bundle_root, &layout.prefix, &layout.state_directory, locale) {
            Ok(receipt) => receipt,
            Err(error) => {
                cleanup_created_directories(&created_directories);
                return Err(LinuxDistributionError::new(error.to_string()));
            }
        };

    let naux_target = layout.prefix.join("bin/naux");
    let nauxup_target = layout.prefix.join("bin/nauxup");
    let mut published_launchers = Vec::new();
    let activation = (|| {
        require_regular_executable(&naux_target, "installed naux")?;
        require_regular_executable(&nauxup_target, "installed nauxup")?;
        publish_launcher(&naux_target, &naux_launcher)?;
        published_launchers.push(naux_launcher.clone());
        publish_launcher(&nauxup_target, &nauxup_launcher)?;
        published_launchers.push(nauxup_launcher.clone());

        let receipt = activation_from_install(
            &activation_path,
            &core,
            locale,
            naux_launcher,
            naux_target,
            nauxup_launcher,
            nauxup_target,
            created_directories.clone(),
        )?;
        publish_activation_receipt(&receipt)?;
        read_linux_activation_receipt(&activation_path)
    })();

    match activation {
        Ok(receipt) => Ok(receipt),
        Err(error) => {
            for launcher in published_launchers.iter().rev() {
                let _ = fs::remove_file(launcher);
            }
            let rollback = execute_uninstall(core.receipt_path());
            cleanup_created_directories(&created_directories);
            match rollback {
                Ok(_) => Err(error),
                Err(rollback_error) => Err(LinuxDistributionError::new(format!(
                    "{error}; exact bundle rollback also failed: {rollback_error}"
                ))),
            }
        }
    }
}

/// Re-admit the activation receipt, immutable bundle and exact launchers.
pub fn plan_linux_uninstall(
    activation_path: &Path,
) -> Result<LinuxUninstallPlan, LinuxDistributionError> {
    let activation = read_linux_activation_receipt(activation_path)?;
    let core = plan_uninstall(activation.core_receipt_path())
        .map_err(|error| LinuxDistributionError::new(error.to_string()))?;
    let core_receipt = core.receipt();
    if core_receipt.installation_id() != activation.core_installation_id
        || core_receipt.prefix() != activation.prefix
        || core_receipt.locale() != activation.locale
    {
        return Err(LinuxDistributionError::new(
            "Linux activation receipt differs from the admitted bundle receipt",
        ));
    }
    verify_launcher(&activation.naux_launcher, &activation.naux_target)?;
    verify_launcher(&activation.nauxup_launcher, &activation.nauxup_target)?;
    for directory in &activation.created_directories {
        require_existing_directory(directory, "created installation directory")?;
    }
    Ok(LinuxUninstallPlan { activation, core })
}

/// Remove only the exact launchers, bundle, receipts and still-empty
/// directories admitted by `plan_linux_uninstall`.
pub fn execute_linux_uninstall(
    activation_path: &Path,
) -> Result<LinuxUninstallPlan, LinuxDistributionError> {
    let plan = plan_linux_uninstall(activation_path)?;
    remove_verified_launcher(&plan.activation.naux_launcher, &plan.activation.naux_target)?;
    remove_verified_launcher(
        &plan.activation.nauxup_launcher,
        &plan.activation.nauxup_target,
    )?;
    execute_uninstall(plan.activation.core_receipt_path()).map_err(|error| {
        LinuxDistributionError::new(format!(
            "Linux launchers were removed but bundle uninstall failed: {error}"
        ))
    })?;
    fs::remove_file(plan.activation.receipt_path()).map_err(|error| {
        LinuxDistributionError::new(format!(
            "bundle was removed but activation receipt `{}` could not be removed: {error}",
            plan.activation.receipt_path().display()
        ))
    })?;
    cleanup_created_directories(&plan.activation.created_directories);
    Ok(plan)
}

pub fn read_linux_activation_receipt(
    activation_path: &Path,
) -> Result<LinuxActivationReceipt, LinuxDistributionError> {
    require_regular_file(activation_path, "Linux activation receipt")?;
    let metadata = fs::metadata(activation_path).map_err(|error| {
        LinuxDistributionError::new(format!(
            "cannot inspect Linux activation receipt `{}`: {error}",
            activation_path.display()
        ))
    })?;
    if metadata.len() > ACTIVATION_MAX_BYTES {
        return Err(LinuxDistributionError::new(format!(
            "Linux activation receipt exceeds {ACTIVATION_MAX_BYTES} bytes"
        )));
    }
    let bytes = fs::read(activation_path).map_err(|error| {
        LinuxDistributionError::new(format!(
            "cannot read Linux activation receipt `{}`: {error}",
            activation_path.display()
        ))
    })?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| LinuxDistributionError::new("Linux activation receipt is not valid UTF-8"))?;
    if text.contains(['\0', '\r']) || !text.ends_with('\n') {
        return Err(LinuxDistributionError::new(
            "Linux activation receipt must use canonical UTF-8/LF text",
        ));
    }
    let without_lf = &text[..text.len() - 1];
    let seal_start = without_lf
        .rfind('\n')
        .map(|position| position + 1)
        .ok_or_else(|| LinuxDistributionError::new("Linux activation receipt has no seal row"))?;
    let body = &text.as_bytes()[..seal_start];
    let declared_seal = without_lf[seal_start..]
        .strip_prefix("seal\t")
        .filter(|seal| is_lower_hex_64(seal))
        .ok_or_else(|| LinuxDistributionError::new("Linux activation seal row is malformed"))?;
    let mut preimage = Vec::with_capacity(ACTIVATION_SEAL_DOMAIN.len() + body.len());
    preimage.extend_from_slice(ACTIVATION_SEAL_DOMAIN);
    preimage.extend_from_slice(body);
    if hex_encode(&sha256(&preimage)) != declared_seal {
        return Err(LinuxDistributionError::new(
            "Linux activation receipt seal mismatch",
        ));
    }

    let body_text =
        std::str::from_utf8(body).expect("activation body was sliced from admitted UTF-8");
    let mut lines = body_text.lines();
    if lines.next() != Some(ACTIVATION_MAGIC) {
        return Err(LinuxDistributionError::new(
            "Linux activation receipt magic/version mismatch",
        ));
    }
    let installation_id = receipt_field(&mut lines, "installation-id")?.to_string();
    if !is_lower_hex_64(&installation_id) {
        return Err(LinuxDistributionError::new(
            "Linux activation receipt has an invalid installation ID",
        ));
    }
    require_receipt_value(&mut lines, "product", "naux-learn")?;
    require_receipt_value(&mut lines, "version", S1_BUNDLE_VERSION)?;
    let core_receipt_path = absolute_receipt_path(&mut lines, "core-receipt")?;
    let core_installation_id = receipt_field(&mut lines, "core-installation-id")?.to_string();
    if !is_lower_hex_64(&core_installation_id) {
        return Err(LinuxDistributionError::new(
            "Linux activation receipt has an invalid core installation ID",
        ));
    }
    let prefix = absolute_receipt_path(&mut lines, "prefix")?;
    let locale = receipt_field(&mut lines, "locale")?.to_string();
    catalog_for(&locale).map_err(|error| LinuxDistributionError::new(error.to_string()))?;
    let naux_launcher = absolute_receipt_path(&mut lines, "naux-launcher")?;
    let naux_target = absolute_receipt_path(&mut lines, "naux-target")?;
    let nauxup_launcher = absolute_receipt_path(&mut lines, "nauxup-launcher")?;
    let nauxup_target = absolute_receipt_path(&mut lines, "nauxup-target")?;
    if naux_launcher == nauxup_launcher
        || naux_target != prefix.join("bin/naux")
        || nauxup_target != prefix.join("bin/nauxup")
        || naux_launcher.starts_with(&prefix)
        || nauxup_launcher.starts_with(&prefix)
    {
        return Err(LinuxDistributionError::new(
            "Linux activation receipt contains an invalid launcher topology",
        ));
    }
    let created_count = parse_canonical_usize(
        receipt_field(&mut lines, "created-directories")?,
        "created-directories",
    )?;
    if created_count > MAX_CREATED_DIRECTORIES {
        return Err(LinuxDistributionError::new(
            "Linux activation receipt declares too many created directories",
        ));
    }
    let mut created_directories = Vec::with_capacity(created_count);
    let mut unique = BTreeSet::new();
    for _ in 0..created_count {
        let directory = absolute_receipt_path(&mut lines, "created-directory")?;
        if !unique.insert(directory.clone()) {
            return Err(LinuxDistributionError::new(
                "Linux activation receipt repeats a created directory",
            ));
        }
        if !owns_created_directory(
            &directory,
            &prefix,
            activation_path,
            &naux_launcher,
            &nauxup_launcher,
        ) {
            return Err(LinuxDistributionError::new(
                "Linux activation receipt declares a directory outside its installation roots",
            ));
        }
        created_directories.push(directory);
    }
    if lines.next().is_some() {
        return Err(LinuxDistributionError::new(
            "Linux activation receipt contains extra rows",
        ));
    }

    let expected_id = activation_id_for(
        &core_installation_id,
        &core_receipt_path,
        &prefix,
        &locale,
        &naux_launcher,
        &naux_target,
        &nauxup_launcher,
        &nauxup_target,
        &created_directories,
    )?;
    if installation_id != expected_id {
        return Err(LinuxDistributionError::new(
            "Linux activation ID does not bind its declared installation",
        ));
    }

    Ok(LinuxActivationReceipt {
        installation_id,
        receipt_path: activation_path.to_path_buf(),
        core_receipt_path,
        core_installation_id,
        prefix,
        locale,
        naux_launcher,
        naux_target,
        nauxup_launcher,
        nauxup_target,
        created_directories,
    })
}

#[allow(clippy::too_many_arguments)]
fn activation_from_install(
    receipt_path: &Path,
    core: &InstallationReceipt,
    locale: &str,
    naux_launcher: PathBuf,
    naux_target: PathBuf,
    nauxup_launcher: PathBuf,
    nauxup_target: PathBuf,
    created_directories: Vec<PathBuf>,
) -> Result<LinuxActivationReceipt, LinuxDistributionError> {
    let installation_id = activation_id_for(
        core.installation_id(),
        core.receipt_path(),
        core.prefix(),
        locale,
        &naux_launcher,
        &naux_target,
        &nauxup_launcher,
        &nauxup_target,
        &created_directories,
    )?;
    Ok(LinuxActivationReceipt {
        installation_id,
        receipt_path: receipt_path.to_path_buf(),
        core_receipt_path: core.receipt_path().to_path_buf(),
        core_installation_id: core.installation_id().to_string(),
        prefix: core.prefix().to_path_buf(),
        locale: locale.to_string(),
        naux_launcher,
        naux_target,
        nauxup_launcher,
        nauxup_target,
        created_directories,
    })
}

fn publish_activation_receipt(
    receipt: &LinuxActivationReceipt,
) -> Result<(), LinuxDistributionError> {
    require_absent(receipt.receipt_path(), "Linux activation receipt")?;
    let body = activation_body(receipt)?;
    let mut preimage = Vec::with_capacity(ACTIVATION_SEAL_DOMAIN.len() + body.len());
    preimage.extend_from_slice(ACTIVATION_SEAL_DOMAIN);
    preimage.extend_from_slice(body.as_bytes());
    let contents = format!("{body}seal\t{}\n", hex_encode(&sha256(&preimage)));
    let staging = receipt
        .receipt_path()
        .with_extension(format!("tsv.staging-{}", std::process::id()));
    require_absent(&staging, "Linux activation staging receipt")?;

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)
            .map_err(|error| {
                LinuxDistributionError::new(format!(
                    "cannot create Linux activation staging receipt `{}`: {error}",
                    staging.display()
                ))
            })?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                LinuxDistributionError::new(format!(
                    "cannot protect Linux activation staging receipt: {error}"
                ))
            })?;
        file.write_all(contents.as_bytes()).map_err(|error| {
            LinuxDistributionError::new(format!(
                "cannot write Linux activation staging receipt: {error}"
            ))
        })?;
        file.sync_all().map_err(|error| {
            LinuxDistributionError::new(format!(
                "cannot sync Linux activation staging receipt: {error}"
            ))
        })?;
        drop(file);
        fs::hard_link(&staging, receipt.receipt_path()).map_err(|error| {
            LinuxDistributionError::new(format!(
                "cannot publish Linux activation receipt `{}`: {error}",
                receipt.receipt_path().display()
            ))
        })?;
        fs::remove_file(&staging).map_err(|error| {
            LinuxDistributionError::new(format!(
                "cannot retire Linux activation staging receipt: {error}"
            ))
        })?;
        File::open(
            receipt
                .receipt_path()
                .parent()
                .expect("validated receipt parent"),
        )
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            LinuxDistributionError::new(format!(
                "cannot sync Linux activation receipt directory: {error}"
            ))
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staging);
    }
    result
}

fn activation_body(receipt: &LinuxActivationReceipt) -> Result<String, LinuxDistributionError> {
    let mut body = format!(
        "{ACTIVATION_MAGIC}\ninstallation-id\t{}\nproduct\tnaux-learn\nversion\t{S1_BUNDLE_VERSION}\ncore-receipt\t{}\ncore-installation-id\t{}\nprefix\t{}\nlocale\t{}\nnaux-launcher\t{}\nnaux-target\t{}\nnauxup-launcher\t{}\nnauxup-target\t{}\ncreated-directories\t{}\n",
        receipt.installation_id,
        path_text(&receipt.core_receipt_path)?,
        receipt.core_installation_id,
        path_text(&receipt.prefix)?,
        receipt.locale,
        path_text(&receipt.naux_launcher)?,
        path_text(&receipt.naux_target)?,
        path_text(&receipt.nauxup_launcher)?,
        path_text(&receipt.nauxup_target)?,
        receipt.created_directories.len(),
    );
    for directory in &receipt.created_directories {
        body.push_str("created-directory\t");
        body.push_str(path_text(directory)?);
        body.push('\n');
    }
    Ok(body)
}

#[allow(clippy::too_many_arguments)]
fn activation_id_for(
    core_installation_id: &str,
    core_receipt_path: &Path,
    prefix: &Path,
    locale: &str,
    naux_launcher: &Path,
    naux_target: &Path,
    nauxup_launcher: &Path,
    nauxup_target: &Path,
    created_directories: &[PathBuf],
) -> Result<String, LinuxDistributionError> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(ACTIVATION_ID_DOMAIN);
    for field in [
        core_installation_id,
        path_text(core_receipt_path)?,
        path_text(prefix)?,
        locale,
        path_text(naux_launcher)?,
        path_text(naux_target)?,
        path_text(nauxup_launcher)?,
        path_text(nauxup_target)?,
    ] {
        preimage.extend_from_slice(field.as_bytes());
        preimage.push(0);
    }
    for directory in created_directories {
        preimage.extend_from_slice(path_text(directory)?.as_bytes());
        preimage.push(0);
    }
    Ok(hex_encode(&sha256(&preimage)))
}

fn validate_layout(layout: &LinuxInstallLayout) -> Result<(), LinuxDistributionError> {
    require_safe_absolute_path(&layout.prefix, "Linux installation prefix")?;
    require_safe_absolute_path(&layout.state_directory, "Linux state directory")?;
    require_safe_absolute_path(&layout.bin_directory, "Linux command directory")?;
    if overlaps(&layout.prefix, &layout.state_directory)
        || overlaps(&layout.prefix, &layout.bin_directory)
        || overlaps(&layout.state_directory, &layout.bin_directory)
    {
        return Err(LinuxDistributionError::new(
            "Linux prefix, state and command directories must not contain one another",
        ));
    }
    Ok(())
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn ensure_directory_chain(
    path: &Path,
    mode: u32,
    created: &mut Vec<PathBuf>,
) -> Result<(), LinuxDistributionError> {
    require_safe_absolute_path(path, "installation directory")?;
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(LinuxDistributionError::new(format!(
                        "installation directory component `{}` is not a non-symlink directory",
                        current.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.mode(mode);
                builder.create(&current).map_err(|create_error| {
                    LinuxDistributionError::new(format!(
                        "cannot create installation directory `{}`: {create_error}",
                        current.display()
                    ))
                })?;
                created.push(current.clone());
            }
            Err(error) => {
                return Err(LinuxDistributionError::new(format!(
                    "cannot inspect installation directory `{}`: {error}",
                    current.display()
                )));
            }
        }
    }
    Ok(())
}

fn publish_launcher(target: &Path, launcher: &Path) -> Result<(), LinuxDistributionError> {
    require_absent(launcher, "Linux launcher")?;
    symlink(target, launcher).map_err(|error| {
        LinuxDistributionError::new(format!(
            "cannot create Linux launcher `{}` -> `{}`: {error}",
            launcher.display(),
            target.display()
        ))
    })
}

fn verify_launcher(launcher: &Path, expected_target: &Path) -> Result<(), LinuxDistributionError> {
    let metadata = fs::symlink_metadata(launcher).map_err(|error| {
        LinuxDistributionError::new(format!(
            "cannot inspect managed launcher `{}`: {error}",
            launcher.display()
        ))
    })?;
    if !metadata.file_type().is_symlink() {
        return Err(LinuxDistributionError::new(format!(
            "managed launcher `{}` is no longer a symbolic link",
            launcher.display()
        )));
    }
    let target = fs::read_link(launcher).map_err(|error| {
        LinuxDistributionError::new(format!(
            "cannot read managed launcher `{}`: {error}",
            launcher.display()
        ))
    })?;
    if target != expected_target {
        return Err(LinuxDistributionError::new(format!(
            "managed launcher `{}` no longer targets its admitted toolchain",
            launcher.display()
        )));
    }
    Ok(())
}

fn remove_verified_launcher(
    launcher: &Path,
    expected_target: &Path,
) -> Result<(), LinuxDistributionError> {
    verify_launcher(launcher, expected_target)?;
    fs::remove_file(launcher).map_err(|error| {
        LinuxDistributionError::new(format!(
            "cannot remove managed launcher `{}`: {error}",
            launcher.display()
        ))
    })
}

fn require_regular_executable(path: &Path, label: &str) -> Result<(), LinuxDistributionError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LinuxDistributionError::new(format!(
            "cannot inspect {label} `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(LinuxDistributionError::new(format!(
            "{label} must be a regular executable file"
        )));
    }
    Ok(())
}

fn require_existing_directory(path: &Path, label: &str) -> Result<(), LinuxDistributionError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LinuxDistributionError::new(format!(
            "cannot inspect {label} `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LinuxDistributionError::new(format!(
            "{label} must remain a non-symlink directory"
        )));
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<(), LinuxDistributionError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LinuxDistributionError::new(format!(
            "cannot inspect {label} `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LinuxDistributionError::new(format!(
            "{label} must be a regular non-symlink file"
        )));
    }
    Ok(())
}

fn require_absent(path: &Path, label: &str) -> Result<(), LinuxDistributionError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(LinuxDistributionError::new(format!(
            "{label} `{}` already exists; refusing to overwrite it",
            path.display()
        ))),
        Err(error) => Err(LinuxDistributionError::new(format!(
            "cannot inspect {label} `{}`: {error}",
            path.display()
        ))),
    }
}

fn require_safe_absolute_path(path: &Path, label: &str) -> Result<(), LinuxDistributionError> {
    let text = path
        .to_str()
        .ok_or_else(|| LinuxDistributionError::new(format!("{label} must be valid UTF-8")))?;
    if !path.is_absolute()
        || path.parent().is_none()
        || path.file_name().is_none()
        || text.chars().any(char::is_control)
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(LinuxDistributionError::new(format!(
            "{label} must be a safe absolute non-root path"
        )));
    }
    Ok(())
}

fn owns_created_directory(
    directory: &Path,
    prefix: &Path,
    activation_path: &Path,
    naux_launcher: &Path,
    nauxup_launcher: &Path,
) -> bool {
    [
        prefix.parent(),
        activation_path.parent(),
        naux_launcher.parent(),
        nauxup_launcher.parent(),
    ]
    .into_iter()
    .flatten()
    .any(|root| root == directory || root.starts_with(directory))
}

fn cleanup_created_directories(directories: &[PathBuf]) {
    for directory in directories.iter().rev() {
        match fs::remove_dir(directory) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(_) => {}
        }
    }
}

fn absolute_receipt_path<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
) -> Result<PathBuf, LinuxDistributionError> {
    let path = PathBuf::from(receipt_field(lines, key)?);
    require_safe_absolute_path(&path, key)?;
    Ok(path)
}

fn receipt_field<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
) -> Result<&'a str, LinuxDistributionError> {
    let line = lines.next().ok_or_else(|| {
        LinuxDistributionError::new(format!("Linux activation receipt is missing `{key}`"))
    })?;
    line.strip_prefix(key)
        .and_then(|rest| rest.strip_prefix('\t'))
        .filter(|value| !value.is_empty() && !value.contains('\t'))
        .ok_or_else(|| {
            LinuxDistributionError::new(format!(
                "Linux activation receipt `{key}` row is malformed"
            ))
        })
}

fn require_receipt_value<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
    expected: &str,
) -> Result<(), LinuxDistributionError> {
    if receipt_field(lines, key)? != expected {
        return Err(LinuxDistributionError::new(format!(
            "Linux activation receipt `{key}` value is unsupported"
        )));
    }
    Ok(())
}

fn parse_canonical_usize(value: &str, key: &str) -> Result<usize, LinuxDistributionError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(LinuxDistributionError::new(format!(
            "Linux activation receipt `{key}` is noncanonical"
        )));
    }
    value.parse().map_err(|_| {
        LinuxDistributionError::new(format!("Linux activation receipt `{key}` exceeds usize"))
    })
}

fn path_text(path: &Path) -> Result<&str, LinuxDistributionError> {
    path.to_str()
        .filter(|text| !text.contains(['\t', '\n', '\r', '\0']))
        .ok_or_else(|| {
            LinuxDistributionError::new("Linux activation paths must be canonical UTF-8 text")
        })
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
