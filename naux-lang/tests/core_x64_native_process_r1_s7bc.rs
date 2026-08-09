#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    admit_x64_gate_b_measurement_claim, authorize_x64_standalone_seed_r1_s8,
    build_x64_standalone_artifact_r1_s8, decode_x64_native_ipc_record,
    decode_x64_standalone_output_for_profile, emit_x64_gate_b_baseline_admission,
    emit_x64_gate_b_measurement_observation, emit_x64_native_process_evidence_r1_s7bc,
    emit_x64_standalone_process_evidence_r1_s8c, encode_x64_standalone_input,
    execute_x64_native_worker_case_r1_s7bc, verify_x64_gate_b_baseline_admission,
    verify_x64_gate_b_measurement_observation, verify_x64_native_process_evidence_r1_s7bc,
    verify_x64_standalone_artifact_r1_s8, verify_x64_standalone_process_evidence_r1_s8c,
    x64_native_ipc_record_bytes, X64NativeIpcError, X64StandaloneInput, X64StandaloneOutcome,
    X64StandaloneProfile, X64_NATIVE_IPC_RECORD_DOMAIN, X64_NATIVE_MAX_RECORD_BYTES,
    X64_STANDALONE_PROCESS_EXECUTABLE_MODE,
};
#[cfg(debug_assertions)]
use naux::core::{
    probe_x64_native_worker_debug_r1_s7bc, X64NativeProcessError, X64_NATIVE_MAX_DIAGNOSTICS,
};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static TEMP_EXECUTABLE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn elf_u16(image: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(image[offset..offset + 2].try_into().expect("ELF u16"))
}

fn elf_u32(image: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(image[offset..offset + 4].try_into().expect("ELF u32"))
}

fn elf_u64(image: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(image[offset..offset + 8].try_into().expect("ELF u64"))
}

fn assert_canonical_direct_elf(image: &[u8], startup_bytes: usize) {
    let image_bytes = image.len() as u64;
    assert_eq!(&image[..16], b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
    assert_eq!(elf_u16(image, 16), 2);
    assert_eq!(elf_u16(image, 18), 62);
    assert_eq!(elf_u32(image, 20), 1);
    assert_eq!(elf_u64(image, 24), 0x0040_0100);
    assert_eq!(elf_u64(image, 32), 64);
    assert_eq!(elf_u64(image, 40), 0);
    assert_eq!(elf_u32(image, 48), 0);
    assert_eq!(elf_u16(image, 52), 64);
    assert_eq!(elf_u16(image, 54), 56);
    assert_eq!(elf_u16(image, 56), 2);
    assert_eq!(
        (elf_u16(image, 58), elf_u16(image, 60), elf_u16(image, 62)),
        (0, 0, 0)
    );

    assert_eq!((elf_u32(image, 64), elf_u32(image, 68)), (1, 5));
    assert_eq!(elf_u64(image, 72), 0);
    assert_eq!(
        (elf_u64(image, 80), elf_u64(image, 88)),
        (0x0040_0000, 0x0040_0000)
    );
    assert_eq!(
        (elf_u64(image, 96), elf_u64(image, 104)),
        (image_bytes, image_bytes)
    );
    assert_eq!(elf_u64(image, 112), 0x1000);

    assert_eq!((elf_u32(image, 120), elf_u32(image, 124)), (0x6474_e551, 6));
    for offset in [128, 136, 144, 152, 160] {
        assert_eq!(elf_u64(image, offset), 0);
    }
    assert_eq!(elf_u64(image, 168), 16);
    assert!(image[176..256].iter().all(|byte| *byte == 0));
    assert!(image[256 + startup_bytes..0x510]
        .iter()
        .all(|byte| *byte == 0));
    assert!(image.len() > 0x510);
}

struct TemporaryExecutable {
    path: PathBuf,
}

impl TemporaryExecutable {
    fn create(image: &[u8]) -> Self {
        let sequence = TEMP_EXECUTABLE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("naux-r1-s8-{}-{sequence}.elf", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("standalone smoke image path must be unique");
        file.write_all(image)
            .expect("standalone smoke image must be written exactly");
        file.sync_all()
            .expect("standalone smoke image must reach the filesystem");
        drop(file);
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(X64_STANDALONE_PROCESS_EXECUTABLE_MODE),
        )
        .expect("standalone smoke image must have the frozen executable mode");
        Self { path }
    }
}

impl Drop for TemporaryExecutable {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn execute_standalone_smoke(image: &[u8], input: &[u8]) -> (ExitStatus, Vec<u8>, Vec<u8>) {
    execute_standalone_smoke_with_args(image, input, &[])
}

fn execute_standalone_smoke_with_args(
    image: &[u8],
    input: &[u8],
    arguments: &[&str],
) -> (ExitStatus, Vec<u8>, Vec<u8>) {
    let executable = TemporaryExecutable::create(image);
    let mut child = Command::new(&executable.path)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("direct standalone ELF must spawn");
    let input_write = child.stdin.take().expect("piped stdin").write_all(input);
    if let Err(error) = input_write {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "standalone input write failed unexpectedly: {error}"
        );
        // Rejection paths such as forbidden argv or a wrong profile may exit
        // before the parent has copied the complete input frame. Their exit
        // status and empty output remain asserted by the caller below.
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("standalone wait must succeed") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("timed-out standalone child must stop");
            panic!("direct standalone ELF exceeded the five-second smoke timeout");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_end(&mut stdout)
        .expect("standalone stdout must be readable");
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_end(&mut stderr)
        .expect("standalone stderr must be readable");
    (status, stdout, stderr)
}

fn worker() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_naux-r1-s7b-worker"))
}

fn current_mxcsr() -> u32 {
    let mut value = 0_u32;
    // SAFETY: `value` is valid writable u32 storage for `stmxcsr`.
    unsafe {
        std::arch::asm!(
            "stmxcsr [{pointer}]",
            pointer = in(reg) &mut value,
            options(nostack, preserves_flags),
        );
    }
    value
}

fn install_mxcsr(value: u32) {
    // SAFETY: callers derive `value` from `stmxcsr` and change only the
    // architecturally defined rounding-control bits.
    unsafe {
        std::arch::asm!(
            "ldmxcsr [{pointer}]",
            pointer = in(reg) &value,
            options(nostack, preserves_flags),
        );
    }
}

#[test]
fn canonical_ipc_roundtrip_is_bounded_and_fail_closed() {
    let original_mxcsr = current_mxcsr();
    let altered_rounding = if original_mxcsr & 0x0000_6000 == 0x0000_6000 {
        0
    } else {
        0x0000_6000
    };
    let altered_mxcsr = (original_mxcsr & !0x0000_6000) | altered_rounding;
    assert_ne!(altered_mxcsr, original_mxcsr);
    install_mxcsr(altered_mxcsr);
    let case_zero = execute_x64_native_worker_case_r1_s7bc(worker(), 0);
    let restored_mxcsr = current_mxcsr();
    install_mxcsr(original_mxcsr);
    assert_eq!(restored_mxcsr, altered_mxcsr);
    let case_zero = case_zero.expect("one canonical child must emit one complete frame");
    let frame = x64_native_ipc_record_bytes(&case_zero)
        .expect("the admitted child record must re-encode canonically");
    assert_eq!(frame.len(), 518);
    assert_eq!(
        decode_x64_native_ipc_record(&frame, 0).expect("the canonical frame must round-trip"),
        case_zero
    );

    for end in [0, X64_NATIVE_IPC_RECORD_DOMAIN.len(), frame.len() - 1] {
        assert!(
            decode_x64_native_ipc_record(&frame[..end], 0).is_err(),
            "truncation at byte {end} must fail"
        );
    }
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(matches!(
        decode_x64_native_ipc_record(&trailing, 0),
        Err(X64NativeIpcError::TrailingBytes { .. })
    ));
    let mut changed_seal = frame.clone();
    let last = changed_seal.len() - 1;
    changed_seal[last] ^= 1;
    assert!(matches!(
        decode_x64_native_ipc_record(&changed_seal, 0),
        Err(X64NativeIpcError::FrameHashMismatch)
    ));
    let oversized = vec![0_u8; X64_NATIVE_MAX_RECORD_BYTES as usize + 1];
    assert!(matches!(
        decode_x64_native_ipc_record(&oversized, 0),
        Err(X64NativeIpcError::RecordByteLimit {
            limit: 16_384,
            actual: 16_385
        })
    ));
}

#[cfg(debug_assertions)]
#[test]
fn debug_worker_failures_are_rejected() {
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "abort", 30_000),
        Err(X64NativeProcessError::NativeFault { case_ordinal: 0 })
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "abnormal", 30_000),
        Err(X64NativeProcessError::AbnormalExit {
            case_ordinal: 0,
            ..
        })
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "timeout", 25),
        Err(X64NativeProcessError::NativeTimeout {
            case_ordinal: 0,
            timeout_millis: 25
        })
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "descendant-pipe", 30_000),
        Err(X64NativeProcessError::MissingRecord { case_ordinal: 0 })
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "missing", 30_000),
        Err(X64NativeProcessError::MissingRecord { case_ordinal: 0 })
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "malformed", 30_000),
        Err(X64NativeProcessError::Ipc(_))
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "oversized", 30_000),
        Err(X64NativeProcessError::RecordByteLimit {
            case_ordinal: 0,
            limit: 16_384,
            actual: 16_385
        })
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(
            worker(),
            0,
            "diagnostics-one-over",
            30_000
        ),
        Err(X64NativeProcessError::DiagnosticLimit {
            case_ordinal: 0,
            limit,
            actual: 129
        }) if limit == X64_NATIVE_MAX_DIAGNOSTICS
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "diagnostics-limit", 30_000),
        Err(X64NativeProcessError::UnexpectedDiagnostics {
            case_ordinal: 0,
            actual: 128
        })
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "diagnostic-bytes-limit", 30_000),
        Err(X64NativeProcessError::UnexpectedDiagnostics {
            case_ordinal: 0,
            actual: 1
        })
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "diagnostic-bytes-one-over", 30_000),
        Err(X64NativeProcessError::DiagnosticByteLimit {
            case_ordinal: 0,
            limit: 16_384,
            actual: 16_385
        })
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "record-limit", 30_000),
        Err(X64NativeProcessError::Ipc(X64NativeIpcError::InvalidDomain))
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "trailing", 30_000),
        Err(X64NativeProcessError::Ipc(
            X64NativeIpcError::TrailingBytes { .. }
        ))
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "truncated", 30_000),
        Err(X64NativeProcessError::Ipc(
            X64NativeIpcError::Truncated { .. }
        ))
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "double-frame", 30_000),
        Err(X64NativeProcessError::Ipc(
            X64NativeIpcError::TrailingBytes { .. }
        ))
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "valid-abnormal", 30_000),
        Err(X64NativeProcessError::AbnormalExit {
            case_ordinal: 0,
            ..
        })
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "valid-abort", 30_000),
        Err(X64NativeProcessError::NativeFault { case_ordinal: 0 })
    ));
    assert!(matches!(
        probe_x64_native_worker_debug_r1_s7bc(worker(), 0, "wrong-case", 30_000),
        Err(X64NativeProcessError::Ipc(
            X64NativeIpcError::WrongCaseOrdinal {
                expected: 0,
                actual: 1
            }
        ))
    ));
}

#[test]
fn process_isolated_fixed_corpus_has_locked_identity() {
    let evidence = emit_x64_native_process_evidence_r1_s7bc(worker())
        .expect("all 51 canonical cases must complete in isolated children");
    let verified = verify_x64_native_process_evidence_r1_s7bc(&evidence)
        .expect("the isolated evidence package must verify");
    assert_eq!(verified.evidence(), &evidence);
    assert_eq!(
        verified.semantic_results_hash(),
        evidence.semantic_results_hash()
    );
    assert_eq!(verified.process_results_hash(), evidence.results_hash());

    let branch_authority =
        authorize_x64_standalone_seed_r1_s8(verified, X64StandaloneProfile::BranchMix)
            .expect("verified process evidence must authorize BranchMix R1-S8 seed");
    assert_eq!(branch_authority.canonical_case_count(), 46);
    assert_eq!(branch_authority.input_lanes(), 3);
    assert_eq!(branch_authority.entry_offset(), 0);
    assert_eq!(
        branch_authority.target_artifact_hash().to_hex(),
        "a642bcc02f2ea3566b0d5f275780e5cbbefe007b46a0eaa5578f3f680f838e95"
    );
    assert_eq!(
        branch_authority.target_code_hash().to_hex(),
        "ef32051c5c7af81365eee82664636f0a82bef5b1de3a8e3dcc07c2c207d7ce54"
    );

    let bounds_authority =
        authorize_x64_standalone_seed_r1_s8(verified, X64StandaloneProfile::Bounds)
            .expect("verified process evidence must authorize Bounds R1-S8 seed");
    assert_eq!(bounds_authority.canonical_case_count(), 5);
    assert_eq!(bounds_authority.input_lanes(), 2);
    assert_eq!(bounds_authority.entry_offset(), 0);
    assert_eq!(
        bounds_authority.target_artifact_hash().to_hex(),
        "06e8a4cd6d1a7df57229180248c9f0040c9aa7781e1f38dea60e3f6a8f1c6251"
    );
    assert_eq!(
        bounds_authority.target_code_hash().to_hex(),
        "c80220666bc16c99bd2c2a0570e418cc47462e0cdf8c7483530a8c7c149fee19"
    );
    assert_eq!(
        branch_authority.manifest_hash(),
        bounds_authority.manifest_hash()
    );
    assert_eq!(
        branch_authority.semantic_results_hash(),
        bounds_authority.semantic_results_hash()
    );
    assert_eq!(
        branch_authority.process_results_hash(),
        bounds_authority.process_results_hash()
    );

    let branch_artifact = build_x64_standalone_artifact_r1_s8(&branch_authority)
        .expect("BranchMix authority must deterministically compose a direct ELF64 image");
    let branch_repeat = build_x64_standalone_artifact_r1_s8(&branch_authority)
        .expect("BranchMix artifact composition must reproduce");
    assert_eq!(branch_artifact.image_bytes(), branch_repeat.image_bytes());
    let verified_branch =
        verify_x64_standalone_artifact_r1_s8(&branch_authority, branch_artifact.image_bytes())
            .expect("raw BranchMix ELF bytes must verify against live authority");
    let verified_branch_repeat =
        verify_x64_standalone_artifact_r1_s8(&branch_authority, branch_repeat.image_bytes())
            .expect("reproduced BranchMix ELF bytes must verify against live authority");
    assert_eq!(
        verified_branch.artifact_hash(),
        verified_branch_repeat.artifact_hash()
    );
    assert_eq!(verified_branch.layout().target_offset(), 0x510);
    assert_eq!(verified_branch.layout().startup_bytes(), 1_032);
    assert_eq!(verified_branch.layout().target_entry_vaddr(), 0x0040_0510);
    assert_canonical_direct_elf(verified_branch.image_bytes(), 1_032);
    assert!(!verified_branch.interpreter_dependency());
    assert!(!verified_branch.external_symbol_dependency());
    assert!(!verified_branch.dynamic_loader_dependency());
    assert!(!verified_branch.system_linker_dependency());
    assert!(!verified_branch.fallback());

    let bounds_artifact = build_x64_standalone_artifact_r1_s8(&bounds_authority)
        .expect("Bounds authority must deterministically compose a direct ELF64 image");
    let bounds_repeat = build_x64_standalone_artifact_r1_s8(&bounds_authority)
        .expect("Bounds artifact composition must reproduce");
    assert_eq!(bounds_artifact.image_bytes(), bounds_repeat.image_bytes());
    let verified_bounds =
        verify_x64_standalone_artifact_r1_s8(&bounds_authority, bounds_artifact.image_bytes())
            .expect("raw Bounds ELF bytes must verify against live authority");
    let verified_bounds_repeat =
        verify_x64_standalone_artifact_r1_s8(&bounds_authority, bounds_repeat.image_bytes())
            .expect("reproduced Bounds ELF bytes must verify against live authority");
    assert_eq!(
        verified_bounds.artifact_hash(),
        verified_bounds_repeat.artifact_hash()
    );
    assert_eq!(verified_bounds.layout().target_offset(), 0x510);
    assert_eq!(verified_bounds.layout().startup_bytes(), 1_038);
    assert_eq!(verified_bounds.layout().target_entry_vaddr(), 0x0040_0510);
    assert_canonical_direct_elf(verified_bounds.image_bytes(), 1_038);
    assert_ne!(
        verified_branch.artifact_hash(),
        verified_bounds.artifact_hash()
    );
    assert!(
        verify_x64_standalone_artifact_r1_s8(&bounds_authority, branch_artifact.image_bytes())
            .is_err(),
        "cross-profile authority substitution must fail"
    );
    assert!(
        verify_x64_standalone_artifact_r1_s8(&branch_authority, bounds_artifact.image_bytes())
            .is_err(),
        "cross-profile image substitution must fail"
    );

    for mutation_offset in [
        0,
        0x100,
        verified_branch.layout().target_offset() as usize,
        branch_artifact.image_bytes().len() - 1,
    ] {
        let mut mutated = branch_artifact.image_bytes().to_vec();
        mutated[mutation_offset] ^= 1;
        assert!(
            verify_x64_standalone_artifact_r1_s8(&branch_authority, &mutated).is_err(),
            "artifact mutation at byte {mutation_offset:#x} must fail"
        );
    }
    let mut trailing = branch_artifact.image_bytes().to_vec();
    trailing.push(0);
    assert!(
        verify_x64_standalone_artifact_r1_s8(&branch_authority, &trailing).is_err(),
        "artifact trailing bytes must fail"
    );

    let branch_input = encode_x64_standalone_input(
        &X64StandaloneInput::new(X64StandaloneProfile::BranchMix, vec![1.0_f64.to_bits()], 1)
            .expect("BranchMix smoke input"),
    )
    .expect("BranchMix smoke frame");
    let (branch_status, branch_stdout, branch_stderr) =
        execute_standalone_smoke(verified_branch.image_bytes(), &branch_input);
    assert_eq!(branch_status.code(), Some(0));
    assert!(branch_stderr.is_empty());
    let branch_output =
        decode_x64_standalone_output_for_profile(&branch_stdout, X64StandaloneProfile::BranchMix)
            .expect("direct BranchMix ELF must emit one canonical output");
    assert_eq!(branch_output.profile(), X64StandaloneProfile::BranchMix);

    let bounds_input = encode_x64_standalone_input(
        &X64StandaloneInput::new(X64StandaloneProfile::Bounds, Vec::new(), 0)
            .expect("Bounds smoke input"),
    )
    .expect("Bounds smoke frame");
    let (bounds_status, bounds_stdout, bounds_stderr) =
        execute_standalone_smoke(verified_bounds.image_bytes(), &bounds_input);
    assert_eq!(bounds_status.code(), Some(0));
    assert!(bounds_stderr.is_empty());
    let bounds_output =
        decode_x64_standalone_output_for_profile(&bounds_stdout, X64StandaloneProfile::Bounds)
            .expect("direct Bounds ELF must emit one canonical output");
    assert_eq!(bounds_output.outcome(), X64StandaloneOutcome::Bounds);

    let (wrong_profile_status, wrong_profile_stdout, wrong_profile_stderr) =
        execute_standalone_smoke(verified_branch.image_bytes(), &bounds_input);
    assert_eq!(wrong_profile_status.code(), Some(64));
    assert!(wrong_profile_stdout.is_empty());
    assert!(wrong_profile_stderr.is_empty());

    let (extra_argv_status, extra_argv_stdout, extra_argv_stderr) =
        execute_standalone_smoke_with_args(
            verified_branch.image_bytes(),
            &branch_input,
            &["forbidden-extra-argv"],
        );
    assert_eq!(extra_argv_status.code(), Some(64));
    assert!(extra_argv_stdout.is_empty());
    assert!(extra_argv_stderr.is_empty());

    let standalone_evidence = emit_x64_standalone_process_evidence_r1_s8c(
        &branch_authority,
        &verified_branch,
        &bounds_authority,
        &verified_bounds,
    )
    .expect("all 51 canonical cases must execute as fresh direct ELF processes");
    let verified_standalone = verify_x64_standalone_process_evidence_r1_s8c(
        &standalone_evidence,
        &branch_authority,
        &verified_branch,
        &bounds_authority,
        &verified_bounds,
    )
    .expect("the ordered direct-process package must independently replay");
    assert_eq!(verified_standalone.evidence(), &standalone_evidence);
    assert_eq!(standalone_evidence.records().len(), 51);
    for (ordinal, record) in standalone_evidence.records().iter().enumerate() {
        assert_eq!(record.case_ordinal() as usize, ordinal);
        assert_eq!(record.total_cases(), 51);
        assert_eq!(record.stdout_bytes(), 40);
        assert_eq!(record.stderr_bytes(), 0);
        assert_eq!(record.normal_exit_code(), 0);
        assert!(!record.timeout());
        assert!(!record.fault());
        assert!(!record.abnormal_status());
        assert!(!record.interpreter_dependency());
        assert!(!record.external_symbol_dependency());
        assert!(!record.dynamic_loader_dependency());
        assert!(!record.system_linker_dependency());
        assert!(!record.fallback());
        assert_eq!(
            record.standalone_observation(),
            record.machine_ir_observation()
        );
        let expected_profile = if ordinal < 46 {
            X64StandaloneProfile::BranchMix
        } else {
            X64StandaloneProfile::Bounds
        };
        assert_eq!(record.profile(), expected_profile);
    }
    assert_eq!(
        standalone_evidence.branch_artifact_hash(),
        verified_branch.artifact_hash()
    );
    assert_eq!(
        standalone_evidence.bounds_artifact_hash(),
        verified_bounds.artifact_hash()
    );
    assert_eq!(
        verified_branch.artifact_hash().to_hex(),
        "f1951da3deafa4119c56cec8a91721bc83630ff5f3c48c60d6f4f56cadd19a47"
    );
    assert_eq!(
        verified_branch.startup_plan_hash().to_hex(),
        "e840dbe52923d4ba45a897ebe1b65444c9ea650fca39f183ff92349737637f51"
    );
    assert_eq!(
        verified_branch.startup_code_hash().to_hex(),
        "0c53ab21bb128e2932104f100f2492aa972451395b9ee539175ffb4aba00dbca"
    );
    assert_eq!(
        verified_branch.io_contract_hash().to_hex(),
        "18831bcbc18700638ef3027404f094df399be151bb93e1f58880557b75910561"
    );
    assert_eq!(
        verified_branch.elf_image_hash().to_hex(),
        "b1a1544a8e96f1741295e4da897b17f3b7bc8436bc57df8335b9a3ef38046f4d"
    );
    assert_eq!(
        verified_bounds.artifact_hash().to_hex(),
        "f6271787b782f0177ac067086db9525f985b2eb2b87b4a60ce031974454ee664"
    );
    assert_eq!(
        verified_bounds.startup_plan_hash().to_hex(),
        "2bb1c60f26559aebb400b14d17aebfa28319f0430ee5f9e0f36519e6d6c8210b"
    );
    assert_eq!(
        verified_bounds.startup_code_hash().to_hex(),
        "7887484fcb4c3702f296c581cde0a6e6c63d4cb33ec18ccaf64a21c4c43888a7"
    );
    assert_eq!(
        verified_bounds.io_contract_hash().to_hex(),
        "f8abed533402d1b3694525002a681813ee83dcb056bf36ea0e2078bd1c236d20"
    );
    assert_eq!(
        verified_bounds.elf_image_hash().to_hex(),
        "1b3b6e92b5e0091fdb15b2e77bdd824fbcb495754e581da185b093202f22e3c3"
    );
    assert_eq!(
        standalone_evidence.records()[0].record_hash().to_hex(),
        "13400cca5de36dd388bdd03c99e66fae78c79d927e168f4fd2d00c55f00cfb5f"
    );
    assert_eq!(
        standalone_evidence.records()[46].record_hash().to_hex(),
        "e99e7fd0513ce35b6497cf0fc9e10d6a68c23dd1624b2daa07b2be36949ed387"
    );
    assert_eq!(
        standalone_evidence.results_hash().to_hex(),
        "22897dc524804625751f027a820bb75f4da3f7e77afca5183bc1522542418b85"
    );

    let baseline_admission = emit_x64_gate_b_baseline_admission()
        .expect("the independent hand baseline must pass all 46 BranchMix process cases");
    let verified_baseline_admission = verify_x64_gate_b_baseline_admission(&baseline_admission)
        .expect("the hand-baseline admission package must replay");
    let gate_b_observation =
        emit_x64_gate_b_measurement_observation(&verified_branch, verified_baseline_admission)
            .expect("the fixed alternating Gate B sampler must complete");
    let verified_gate_b = verify_x64_gate_b_measurement_observation(
        &gate_b_observation,
        &verified_branch,
        verified_baseline_admission,
    )
    .expect("the local Gate B observation must replay exactly");
    assert_eq!(verified_gate_b.observation(), &gate_b_observation);
    assert_eq!(gate_b_observation.samples().len(), 30);
    assert!(
        admit_x64_gate_b_measurement_claim(verified_gate_b).is_err(),
        "the deliberately local-only observation must not close Gate B"
    );
    println!(
        "Gate B local observation: naux median*2={}ns baseline median*2={}ns \
         naux_p95={}ns baseline_p95={}ns naux_cv_ok={} baseline_cv_ok={} threshold_ok={}",
        gate_b_observation
            .naux_statistics()
            .median_twice_nanoseconds(),
        gate_b_observation
            .baseline_statistics()
            .median_twice_nanoseconds(),
        gate_b_observation.naux_statistics().p95_nanoseconds(),
        gate_b_observation.baseline_statistics().p95_nanoseconds(),
        gate_b_observation.naux_statistics().cv_within_limit(),
        gate_b_observation.baseline_statistics().cv_within_limit(),
        gate_b_observation.performance_threshold_met(),
    );

    assert_eq!(evidence.receipts().len(), 51);
    assert_eq!(
        evidence.semantic_results_hash().to_hex(),
        "73ecf90e2fff7a36a6011e447c0982ca317f591aea45486f55c330d8dc12d22c"
    );
    assert_eq!(
        evidence.receipts()[0].ipc_frame_hash().to_hex(),
        "73656da5263d0b2f948af0d65b70e62ef9a2de784c5007418fbeec806dd02511"
    );
    assert_eq!(
        evidence.receipts()[0].receipt_hash().to_hex(),
        "649f8a0dcfde3ef8241a6c088c2be699b00ff9b3d4288dd197e1d02333f38c36"
    );
    assert_eq!(
        evidence.receipts()[46].ipc_frame_hash().to_hex(),
        "bac6b841c3df6343b81e31254c09ebfb4b5683eabbed89b1d282dfbff2803a58"
    );
    assert_eq!(
        evidence.receipts()[46].receipt_hash().to_hex(),
        "7e573ecb93cd365c966232c402059de1431e5cd815c24e2de7f647a350496fa1"
    );
    assert_eq!(
        evidence.results_hash().to_hex(),
        "7700c126528db9bbe810f5396129d155da407d365e1dfa12e346adfbd5df37e1"
    );
}
