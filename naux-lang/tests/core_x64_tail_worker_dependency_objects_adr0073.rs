#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use naux::core::{
    admit_x64_tail_worker_artifact, admit_x64_tail_worker_dependency_closure,
    admit_x64_tail_worker_dependency_compatibility, admit_x64_tail_worker_dependency_declarations,
    admit_x64_tail_worker_dependency_objects, admit_x64_tail_worker_root_compatibility,
    admit_x64_tail_worker_root_scope, emit_x64_tail_worker_dependency_definition_evidence,
    emit_x64_tail_worker_dependency_dynamic_evidence,
    emit_x64_tail_worker_dependency_symbol_evidence,
    emit_x64_tail_worker_dependency_version_evidence, emit_x64_tail_worker_elf_evidence,
    emit_x64_tail_worker_root_relocation_evidence, emit_x64_tail_worker_root_selection_evidence,
    emit_x64_tail_worker_root_symbol_evidence, emit_x64_tail_worker_root_version_evidence,
    probe_x64_tail_worker_dependency_closure_mutations,
    probe_x64_tail_worker_dependency_compatibility_join_edges,
    probe_x64_tail_worker_dependency_compatibility_mutations,
    probe_x64_tail_worker_dependency_definition_decoder_mutations,
    probe_x64_tail_worker_dependency_definition_mutations,
    probe_x64_tail_worker_dependency_dynamic_decoder_mutations,
    probe_x64_tail_worker_dependency_dynamic_mutations,
    probe_x64_tail_worker_dependency_object_elf_mutations,
    probe_x64_tail_worker_dependency_object_mutations,
    probe_x64_tail_worker_dependency_symbol_decoder_mutations,
    probe_x64_tail_worker_dependency_symbol_mutations,
    probe_x64_tail_worker_dependency_version_decoder_mutations,
    probe_x64_tail_worker_dependency_version_mutations,
    probe_x64_tail_worker_root_compatibility_join_edges,
    probe_x64_tail_worker_root_compatibility_mutations,
    probe_x64_tail_worker_root_relocation_decoder_mutations,
    probe_x64_tail_worker_root_relocation_mutations, probe_x64_tail_worker_root_scope_mutations,
    probe_x64_tail_worker_root_selection_mutations,
    probe_x64_tail_worker_root_symbol_decoder_mutations,
    probe_x64_tail_worker_root_symbol_mutations,
    probe_x64_tail_worker_root_version_decoder_mutations,
    probe_x64_tail_worker_root_version_mutations, verify_x64_tail_worker_dependency_closure,
    verify_x64_tail_worker_dependency_compatibility,
    verify_x64_tail_worker_dependency_definition_evidence,
    verify_x64_tail_worker_dependency_dynamic_evidence,
    verify_x64_tail_worker_dependency_symbol_evidence,
    verify_x64_tail_worker_dependency_version_evidence, verify_x64_tail_worker_elf_evidence,
    verify_x64_tail_worker_root_compatibility, verify_x64_tail_worker_root_relocation_evidence,
    verify_x64_tail_worker_root_scope, verify_x64_tail_worker_root_selection_evidence,
    verify_x64_tail_worker_root_symbol_evidence, verify_x64_tail_worker_root_version_evidence,
    x64_tail_worker_dependency_closure_policy_hash,
    x64_tail_worker_dependency_compatibility_policy_hash,
    x64_tail_worker_dependency_definition_policy_hash,
    x64_tail_worker_dependency_dynamic_policy_hash, x64_tail_worker_dependency_object_policy_hash,
    x64_tail_worker_dependency_symbol_policy_hash, x64_tail_worker_dependency_version_policy_hash,
    x64_tail_worker_expectation_from_reviewed_bytes,
    x64_tail_worker_root_compatibility_policy_hash, x64_tail_worker_root_relocation_policy_hash,
    x64_tail_worker_root_scope_policy_hash, x64_tail_worker_root_selection_policy_hash,
    x64_tail_worker_root_symbol_policy_hash, x64_tail_worker_root_version_policy_hash,
    SemanticHash, X64TailWorkerArtifact, X64TailWorkerDependencyAdmissionEvidence,
    X64TailWorkerDependencyClosureExpectation, X64TailWorkerDependencyClosureProviderExpectation,
    X64TailWorkerDependencyDefinitionObjectEvidence, X64TailWorkerDependencyExpectation,
    X64TailWorkerDependencyObjectExpectation, X64TailWorkerDependencyObjectKind,
    X64TailWorkerDependencyObjectManifest, X64TailWorkerElfEvidence,
    X64TailWorkerRootRelocationClass, X64TailWorkerRootRelocationTableKind,
    X64TailWorkerRootScopeEntryExpectation, X64TailWorkerRootScopeExpectation,
    X64TailWorkerRootSelectionDecisionKind, X64TailWorkerRootSymbolNamespaceKind,
    X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT,
    X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_POLICY_ROOT,
    X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT,
    X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_POLICY_ROOT, X64_TAIL_WORKER_DEPENDENCY_OBJECT_POLICY_ROOT,
    X64_TAIL_WORKER_DEPENDENCY_OBJECT_REQUIRED_SEALS, X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS,
    X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS_1, X64_TAIL_WORKER_DEPENDENCY_SYMBOL_POLICY_ROOT,
    X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT, X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT,
    X64_TAIL_WORKER_ROOT_RELOCATION_POLICY_ROOT, X64_TAIL_WORKER_ROOT_SCOPE_POLICY_ROOT,
    X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_IFUNC_REFUSALS,
    X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_REQUESTS,
    X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_ROOT_SYMBOLS,
    X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_SELECTED, X64_TAIL_WORKER_ROOT_SELECTION_POLICY_ROOT,
    X64_TAIL_WORKER_ROOT_SELECTION_TOPOLOGY_ROOT, X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT,
    X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT,
};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const ELF64_RELA_BYTES: u64 = 24;
const DT_PLTRELSZ: i64 = 2;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_PLTREL: i64 = 20;
const DT_RELACOUNT: i64 = 0x6fff_fff9;

fn worker() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_naux-tail-enveloped-worker"))
}

fn exact_dynamic_value(inventory: &X64TailWorkerElfEvidence, tag: i64) -> u64 {
    let mut matches = inventory
        .dynamic_entries()
        .iter()
        .filter(|entry| entry.tag() == tag);
    let value = matches
        .next()
        .unwrap_or_else(|| panic!("missing reviewed dynamic tag {tag}"))
        .value();
    assert!(
        matches.next().is_none(),
        "duplicate reviewed dynamic tag {tag}"
    );
    value
}

fn reviewed_declarations() -> X64TailWorkerDependencyExpectation {
    X64TailWorkerDependencyExpectation::new(
        "/lib64/ld-linux-x86-64.so.2".to_owned(),
        vec![
            "libgcc_s.so.1".to_owned(),
            "libc.so.6".to_owned(),
            "ld-linux-x86-64.so.2".to_owned(),
        ],
        X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS,
        X64_TAIL_WORKER_DEPENDENCY_REQUIRED_FLAGS_1,
    )
    .expect("the ADR-0072 declaration authority is frozen")
}

fn declaration_authorities() -> (
    X64TailWorkerArtifact,
    X64TailWorkerElfEvidence,
    X64TailWorkerDependencyExpectation,
    X64TailWorkerDependencyAdmissionEvidence,
) {
    let worker_bytes = fs::read(worker()).expect("read reviewed worker");
    let worker_expectation =
        x64_tail_worker_expectation_from_reviewed_bytes(&worker_bytes).unwrap();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root_source = PathBuf::from(format!(
        "/tmp/naux-adr0080-root-{}-{nonce}.elf",
        std::process::id()
    ));
    fs::write(&root_source, &worker_bytes).expect("create reviewed root-worker source");
    let artifact = admit_x64_tail_worker_artifact(&root_source, worker_expectation)
        .expect("seal worker from reviewed source");
    fs::write(&root_source, b"replaced-after-sealing")
        .expect("replace root-worker source after descriptor admission");
    fs::remove_file(&root_source).expect("remove replaced root-worker source");
    let inventory = emit_x64_tail_worker_elf_evidence(&artifact).expect("replay ADR-0071");
    let declarations = reviewed_declarations();
    let declaration_evidence =
        admit_x64_tail_worker_dependency_declarations(&artifact, &inventory, &declarations)
            .expect("replay ADR-0072");
    (artifact, inventory, declarations, declaration_evidence)
}

fn first_readable(candidates: &[&str]) -> Vec<u8> {
    candidates
        .iter()
        .find_map(|path| fs::read(path).ok())
        .unwrap_or_else(|| panic!("none of the reviewed fixture paths exist: {candidates:?}"))
}

struct ObjectFixture {
    root: PathBuf,
    loader_path: String,
    libgcc_path: String,
    libc_path: String,
    loader_bytes: Vec<u8>,
    libgcc_bytes: Vec<u8>,
    libc_bytes: Vec<u8>,
}

impl ObjectFixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = PathBuf::from(format!("/tmp/naux-adr0073-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).expect("create isolated ADR-0073 fixture");

        // These bytes stand in for an out-of-band reviewed deployment bundle.
        // Production admission never performs this candidate search.
        let loader_bytes = first_readable(&[
            "/usr/lib/ld-linux-x86-64.so.2",
            "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        ]);
        let libgcc_bytes = first_readable(&[
            "/usr/lib/libgcc_s.so.1",
            "/lib/x86_64-linux-gnu/libgcc_s.so.1",
            "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
        ]);
        let libc_bytes = first_readable(&[
            "/usr/lib/libc.so.6",
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
        ]);
        let loader = root.join("loader.elf");
        let libgcc = root.join("libgcc.elf");
        let libc = root.join("libc.elf");
        fs::write(&loader, &loader_bytes).expect("copy reviewed loader bytes");
        fs::write(&libgcc, &libgcc_bytes).expect("copy reviewed libgcc bytes");
        fs::write(&libc, &libc_bytes).expect("copy reviewed libc bytes");
        Self {
            root,
            loader_path: loader.to_string_lossy().into_owned(),
            libgcc_path: libgcc.to_string_lossy().into_owned(),
            libc_path: libc.to_string_lossy().into_owned(),
            loader_bytes,
            libgcc_bytes,
            libc_bytes,
        }
    }

    fn manifest(
        &self,
        declarations: &X64TailWorkerDependencyExpectation,
    ) -> X64TailWorkerDependencyObjectManifest {
        let interpreter =
            X64TailWorkerDependencyObjectExpectation::interpreter_from_reviewed_bytes(
                declarations.interpreter().to_owned(),
                self.loader_path.clone(),
                &self.loader_bytes,
            )
            .unwrap();
        let dependencies = vec![
            X64TailWorkerDependencyObjectExpectation::direct_dependency_from_reviewed_bytes(
                declarations.dependencies()[0].clone(),
                self.libgcc_path.clone(),
                &self.libgcc_bytes,
            )
            .unwrap(),
            X64TailWorkerDependencyObjectExpectation::direct_dependency_from_reviewed_bytes(
                declarations.dependencies()[1].clone(),
                self.libc_path.clone(),
                &self.libc_bytes,
            )
            .unwrap(),
            X64TailWorkerDependencyObjectExpectation::direct_dependency_from_reviewed_bytes(
                declarations.dependencies()[2].clone(),
                self.loader_path.clone(),
                &self.loader_bytes,
            )
            .unwrap(),
        ];
        X64TailWorkerDependencyObjectManifest::new(declarations, interpreter, dependencies)
            .expect("exact ordered reviewed object manifest")
    }

    fn remove_sources(&self) {
        fs::remove_dir_all(&self.root).expect("remove admitted source bundle");
    }
}

impl Drop for ObjectFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn hash_hex(hash: SemanticHash) -> String {
    hash.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn assert_definition_namespace(
    object: &X64TailWorkerDependencyDefinitionObjectEvidence,
    primaries: &[&str],
    parented_end_exclusive: usize,
) {
    assert_eq!(usize::from(object.definition_count()), primaries.len());
    assert_eq!(
        object
            .definitions()
            .iter()
            .map(|definition| definition.primary_name())
            .collect::<Vec<_>>(),
        primaries
    );
    for (ordinal, definition) in object.definitions().iter().enumerate() {
        assert_eq!(
            definition.version_index(),
            u16::try_from(ordinal + 1).unwrap()
        );
        assert_eq!(definition.flags(), if ordinal == 0 { 1 } else { 0 });
        let names = definition
            .auxiliaries()
            .iter()
            .map(|auxiliary| auxiliary.name())
            .collect::<Vec<_>>();
        if ordinal >= 2 && ordinal < parented_end_exclusive {
            assert_eq!(names, vec![primaries[ordinal], primaries[ordinal - 1]]);
        } else {
            assert_eq!(names, vec![primaries[ordinal]]);
        }
    }
}

fn reviewed_closure(
    manifest: &X64TailWorkerDependencyObjectManifest,
) -> X64TailWorkerDependencyClosureExpectation {
    X64TailWorkerDependencyClosureExpectation::new(vec![
        X64TailWorkerDependencyClosureProviderExpectation::new(
            "ld-linux-x86-64.so.2".to_owned(),
            manifest.objects()[0].object_hash(),
            vec![],
        )
        .unwrap(),
        X64TailWorkerDependencyClosureProviderExpectation::new(
            "libgcc_s.so.1".to_owned(),
            manifest.objects()[1].object_hash(),
            vec!["libc.so.6".to_owned(), "ld-linux-x86-64.so.2".to_owned()],
        )
        .unwrap(),
        X64TailWorkerDependencyClosureProviderExpectation::new(
            "libc.so.6".to_owned(),
            manifest.objects()[2].object_hash(),
            vec!["ld-linux-x86-64.so.2".to_owned()],
        )
        .unwrap(),
    ])
    .expect("externally reviewed canonical closure graph")
}

#[test]
fn adr0073_seals_exact_reviewed_objects_and_replays_without_paths() {
    let admission_source = include_str!("../src/core/x64_tail_worker_dependency_objects.rs");
    let imports = admission_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::process",
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "decode_x64_tail_worker_elf",
        "libloading",
    ] {
        assert!(
            !imports.contains(forbidden),
            "object admission imports forbidden authority {forbidden}"
        );
    }
    let root_version_source = include_str!("../src/core/x64_tail_worker_root_versions.rs");
    let root_version_imports = root_version_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "std::path",
        "std::process",
        "x64_tail_worker_dependency_definitions",
        "x64_tail_worker_dependency_symbols",
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "decode_x64_tail_worker_elf",
        "libloading",
    ] {
        assert!(
            !root_version_imports.contains(forbidden),
            "root-version inventory imports forbidden authority {forbidden}"
        );
    }
    let version_source = include_str!("../src/core/x64_tail_worker_dependency_versions.rs");
    let version_imports = version_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "std::path",
        "std::process",
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "decode_x64_tail_worker_elf",
        "libloading",
    ] {
        assert!(
            !version_imports.contains(forbidden),
            "version inventory imports forbidden authority {forbidden}"
        );
    }
    let definition_source = include_str!("../src/core/x64_tail_worker_dependency_definitions.rs");
    let definition_imports = definition_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "std::path",
        "std::process",
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "decode_x64_tail_worker_elf",
        "libloading",
    ] {
        assert!(
            !definition_imports.contains(forbidden),
            "definition inventory imports forbidden authority {forbidden}"
        );
    }
    let compatibility_source =
        include_str!("../src/core/x64_tail_worker_dependency_compatibility.rs");
    let compatibility_imports = compatibility_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "std::path",
        "std::process",
        "x64_tail_worker_dependency_object_bytes",
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "decode_x64_tail_worker_elf",
        "libloading",
    ] {
        assert!(
            !compatibility_imports.contains(forbidden),
            "compatibility admission imports forbidden authority {forbidden}"
        );
    }
    let root_compatibility_source =
        include_str!("../src/core/x64_tail_worker_root_compatibility.rs");
    let root_compatibility_imports = root_compatibility_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "std::path",
        "std::process",
        "x64_tail_worker_dependency_object_bytes",
        "x64_tail_worker_dependency_symbols",
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "decode_x64_tail_worker_elf",
        "object::",
        "goblin",
        "libloading",
    ] {
        assert!(
            !root_compatibility_imports.contains(forbidden),
            "root compatibility admission imports forbidden authority {forbidden}"
        );
    }
    let root_symbol_source = include_str!("../src/core/x64_tail_worker_root_symbols.rs");
    let root_symbol_imports = root_symbol_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "std::path",
        "std::process",
        "x64_tail_worker_dependency_object_bytes",
        "x64_tail_worker_dependency_symbols",
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "decode_x64_tail_worker_elf",
        "object::",
        "goblin",
        "libloading",
    ] {
        assert!(
            !root_symbol_imports.contains(forbidden),
            "root symbol inventory imports forbidden authority {forbidden}"
        );
    }
    let closure_source = include_str!("../src/core/x64_tail_worker_dependency_closure.rs");
    let closure_imports = closure_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "std::path",
        "std::process",
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "decode_x64_tail_worker_elf",
        "libloading",
    ] {
        assert!(
            !closure_imports.contains(forbidden),
            "closure admission imports forbidden authority {forbidden}"
        );
    }
    let dynamic_source = include_str!("../src/core/x64_tail_worker_dependency_dynamic.rs");
    let dynamic_imports = dynamic_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "std::process",
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "decode_x64_tail_worker_elf",
        "libloading",
    ] {
        assert!(
            !dynamic_imports.contains(forbidden),
            "dynamic inventory imports forbidden authority {forbidden}"
        );
    }

    let (artifact, inventory, declarations, declaration_evidence) = declaration_authorities();
    let fixture = ObjectFixture::new();
    let manifest = fixture.manifest(&declarations);
    let object_set = admit_x64_tail_worker_dependency_objects(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
    )
    .expect("exact reviewed object bytes must admit");
    // Admission performs one complete independent replay before returning.
    assert_eq!(object_set.object_count(), 4);
    assert_eq!(object_set.evidence().object_count(), 4);
    assert_eq!(
        object_set.evidence().manifest_hash(),
        manifest.manifest_hash()
    );
    assert_eq!(
        object_set.evidence().declaration_evidence_hash(),
        declaration_evidence.evidence_hash()
    );
    assert_eq!(
        object_set.evidence().worker_artifact_hash(),
        declaration_evidence.artifact_hash()
    );
    assert_eq!(
        object_set.evidence().objects()[0].kind(),
        X64TailWorkerDependencyObjectKind::Interpreter
    );
    assert!(object_set.evidence().objects()[1..]
        .iter()
        .all(|object| object.kind() == X64TailWorkerDependencyObjectKind::DirectDependency));
    assert!(object_set.evidence().objects().iter().all(|object| {
        object.seals() == X64_TAIL_WORKER_DEPENDENCY_OBJECT_REQUIRED_SEALS
            && object.elf().program_header_count() > 0
            && object.elf().load_segment_count() > 0
    }));
    assert_eq!(
        object_set.evidence().total_bytes(),
        u64::try_from(
            fixture.loader_bytes.len() * 2 + fixture.libgcc_bytes.len() + fixture.libc_bytes.len()
        )
        .unwrap()
    );
    assert!(probe_x64_tail_worker_dependency_object_mutations(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
    ));

    let policy = x64_tail_worker_dependency_object_policy_hash();
    eprintln!("ADR-0073 policy root: {}", hash_hex(policy));
    assert_eq!(policy, X64_TAIL_WORKER_DEPENDENCY_OBJECT_POLICY_ROOT);

    assert!(probe_x64_tail_worker_dependency_dynamic_decoder_mutations(
        &fixture.libgcc_bytes,
        "libgcc_s.so.1",
    ));
    let dynamic = emit_x64_tail_worker_dependency_dynamic_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
    )
    .expect("ADR-0074 must decode every opaque sealed object");
    assert_eq!(dynamic.object_count(), 4);
    assert_eq!(dynamic.total_needed(), 3);
    assert_eq!(
        dynamic
            .objects()
            .iter()
            .map(|object| object.soname())
            .collect::<Vec<_>>(),
        vec![
            "ld-linux-x86-64.so.2",
            "libgcc_s.so.1",
            "libc.so.6",
            "ld-linux-x86-64.so.2",
        ]
    );
    assert!(dynamic.objects()[0].needed().is_empty());
    assert_eq!(
        dynamic.objects()[1]
            .needed()
            .iter()
            .map(|needed| needed.name())
            .collect::<Vec<_>>(),
        vec!["libc.so.6", "ld-linux-x86-64.so.2"]
    );
    assert_eq!(
        dynamic.objects()[2]
            .needed()
            .iter()
            .map(|needed| needed.name())
            .collect::<Vec<_>>(),
        vec!["ld-linux-x86-64.so.2"]
    );
    assert!(dynamic.objects()[3].needed().is_empty());
    assert_eq!(
        dynamic.policy_hash(),
        x64_tail_worker_dependency_dynamic_policy_hash()
    );
    assert_eq!(
        dynamic.policy_hash(),
        X64_TAIL_WORKER_DEPENDENCY_DYNAMIC_POLICY_ROOT
    );
    assert!(probe_x64_tail_worker_dependency_dynamic_mutations(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
    ));

    let closure_policy = x64_tail_worker_dependency_closure_policy_hash();
    eprintln!("ADR-0075 policy root: {}", hash_hex(closure_policy));
    assert_eq!(
        closure_policy,
        X64_TAIL_WORKER_DEPENDENCY_CLOSURE_POLICY_ROOT
    );
    let closure_expectation = reviewed_closure(&manifest);
    let closure = admit_x64_tail_worker_dependency_closure(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
    )
    .expect("the exact reviewed transitive graph must close inside the sealed set");
    assert_eq!(closure.provider_count(), 3);
    assert_eq!(closure.appearance_count(), 4);
    assert_eq!(closure.edge_count(), 3);
    assert_eq!(closure.providers()[0].source_object_ordinals(), &[0, 3]);
    assert!(closure.providers()[0].needed().is_empty());
    assert_eq!(closure.providers()[1].edge_provider_ordinals(), &[2, 0]);
    assert_eq!(closure.providers()[2].edge_provider_ordinals(), &[0]);
    assert!(probe_x64_tail_worker_dependency_closure_mutations(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
    ));

    let root_version_policy = x64_tail_worker_root_version_policy_hash();
    eprintln!("ADR-0080 policy root: {}", hash_hex(root_version_policy));
    assert_eq!(
        root_version_policy,
        X64_TAIL_WORKER_ROOT_VERSION_POLICY_ROOT
    );
    let root_versions = emit_x64_tail_worker_root_version_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
    )
    .expect("root GNU version requirements must decode from exact sealed worker bytes");
    assert_eq!(root_versions.requirement_count(), 3);
    assert_eq!(root_versions.auxiliary_count(), 20);
    assert_eq!(
        root_versions
            .requirements()
            .iter()
            .map(|requirement| requirement.file_name())
            .collect::<Vec<_>>(),
        vec!["libgcc_s.so.1", "libc.so.6", "ld-linux-x86-64.so.2"]
    );
    assert_eq!(
        root_versions
            .requirements()
            .iter()
            .map(|requirement| requirement.declaration_ordinal())
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(
        root_versions
            .requirements()
            .iter()
            .map(|requirement| requirement.provider_ordinal())
            .collect::<Vec<_>>(),
        vec![1, 2, 0]
    );
    assert_eq!(
        root_versions.requirements()[0]
            .auxiliaries()
            .iter()
            .map(|auxiliary| auxiliary.name())
            .collect::<Vec<_>>(),
        vec!["GCC_3.0", "GCC_3.3", "GCC_4.2.0"]
    );
    assert_eq!(
        root_versions.requirements()[1]
            .auxiliaries()
            .iter()
            .map(|auxiliary| auxiliary.name())
            .collect::<Vec<_>>(),
        vec![
            "GLIBC_2.2.5",
            "GLIBC_2.3",
            "GLIBC_2.3.4",
            "GLIBC_2.9",
            "GLIBC_2.14",
            "GLIBC_2.15",
            "GLIBC_2.16",
            "GLIBC_2.17",
            "GLIBC_2.18",
            "GLIBC_2.28",
            "GLIBC_2.29",
            "GLIBC_2.30",
            "GLIBC_2.32",
            "GLIBC_2.33",
            "GLIBC_2.34",
            "GLIBC_2.39",
        ]
    );
    assert_eq!(
        root_versions.requirements()[2]
            .auxiliaries()
            .iter()
            .map(|auxiliary| auxiliary.name())
            .collect::<Vec<_>>(),
        vec!["GLIBC_2.3"]
    );
    let version_indices = root_versions
        .requirements()
        .iter()
        .flat_map(|requirement| requirement.auxiliaries())
        .map(|auxiliary| auxiliary.version_index())
        .collect::<Vec<_>>();
    let mut unique_version_indices = version_indices.clone();
    unique_version_indices.sort_unstable();
    unique_version_indices.dedup();
    assert_eq!(unique_version_indices.len(), version_indices.len());
    assert!(version_indices
        .iter()
        .all(|index| (2..=0x7fff).contains(index)));
    assert!(root_versions
        .requirements()
        .iter()
        .flat_map(|requirement| requirement.auxiliaries())
        .all(|auxiliary| auxiliary.flags() == 0));
    let exact_worker_bytes = fs::read(worker()).expect("read exact root-worker mutation fixture");
    assert!(probe_x64_tail_worker_root_version_decoder_mutations(
        &exact_worker_bytes,
        &declarations,
        &closure,
    ));
    assert!(probe_x64_tail_worker_root_version_mutations(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &root_versions,
    ));

    let version_policy = x64_tail_worker_dependency_version_policy_hash();
    eprintln!("ADR-0076 policy root: {}", hash_hex(version_policy));
    assert_eq!(
        version_policy,
        X64_TAIL_WORKER_DEPENDENCY_VERSION_POLICY_ROOT
    );
    let versions = emit_x64_tail_worker_dependency_version_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
    )
    .expect("GNU version requirements must decode from exact sealed bytes");
    assert_eq!(versions.provider_count(), 3);
    assert_eq!(versions.total_requirements(), 3);
    assert_eq!(versions.total_auxiliaries(), 12);
    assert_eq!(versions.objects()[0].requirement_count(), 0);
    assert_eq!(versions.objects()[0].auxiliary_count(), 0);
    assert_eq!(versions.objects()[1].requirement_count(), 2);
    assert_eq!(versions.objects()[1].auxiliary_count(), 8);
    assert_eq!(
        versions.objects()[1]
            .requirements()
            .iter()
            .map(|requirement| requirement.file_name())
            .collect::<Vec<_>>(),
        vec!["ld-linux-x86-64.so.2", "libc.so.6"]
    );
    assert_eq!(
        versions.objects()[1]
            .requirements()
            .iter()
            .map(|requirement| requirement.provider_ordinal())
            .collect::<Vec<_>>(),
        vec![0, 2]
    );
    assert_eq!(
        versions.objects()[1].requirements()[0]
            .auxiliaries()
            .iter()
            .map(|auxiliary| auxiliary.name())
            .collect::<Vec<_>>(),
        vec!["GLIBC_2.3"]
    );
    assert_eq!(
        versions.objects()[1].requirements()[1]
            .auxiliaries()
            .iter()
            .map(|auxiliary| auxiliary.name())
            .collect::<Vec<_>>(),
        vec![
            "GLIBC_ABI_DT_RELR",
            "GLIBC_2.3.4",
            "GLIBC_2.35",
            "GLIBC_2.14",
            "GLIBC_2.34",
            "GLIBC_2.3.2",
            "GLIBC_2.2.5",
        ]
    );
    assert_eq!(versions.objects()[2].requirement_count(), 1);
    assert_eq!(versions.objects()[2].auxiliary_count(), 4);
    assert_eq!(
        versions.objects()[2].requirements()[0].file_name(),
        "ld-linux-x86-64.so.2"
    );
    assert_eq!(
        versions.objects()[2].requirements()[0].provider_ordinal(),
        0
    );
    assert_eq!(
        versions.objects()[2].requirements()[0]
            .auxiliaries()
            .iter()
            .map(|auxiliary| auxiliary.name())
            .collect::<Vec<_>>(),
        vec!["GLIBC_2.2.5", "GLIBC_2.3", "GLIBC_2.35", "GLIBC_PRIVATE"]
    );
    assert!(probe_x64_tail_worker_dependency_version_decoder_mutations(
        &fixture.libgcc_bytes,
        1,
        &closure,
    ));
    assert!(probe_x64_tail_worker_dependency_version_mutations(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
    ));

    let definition_policy = x64_tail_worker_dependency_definition_policy_hash();
    eprintln!("ADR-0077 policy root: {}", hash_hex(definition_policy));
    assert_eq!(
        definition_policy,
        X64_TAIL_WORKER_DEPENDENCY_DEFINITION_POLICY_ROOT
    );
    let definitions = emit_x64_tail_worker_dependency_definition_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
    )
    .expect("GNU version definitions must decode from exact sealed bytes");
    assert_eq!(definitions.provider_count(), 3);
    assert_eq!(definitions.total_definitions(), 70);
    assert_eq!(definitions.total_auxiliaries(), 131);
    assert_eq!(definitions.objects()[0].auxiliary_count(), 12);
    assert_definition_namespace(
        &definitions.objects()[0],
        &[
            "ld-linux-x86-64.so.2",
            "GLIBC_2.2.5",
            "GLIBC_2.3",
            "GLIBC_2.4",
            "GLIBC_2.34",
            "GLIBC_2.35",
            "GLIBC_PRIVATE",
        ],
        7,
    );
    assert_eq!(definitions.objects()[1].auxiliary_count(), 30);
    assert_definition_namespace(
        &definitions.objects()[1],
        &[
            "libgcc_s.so.1",
            "GCC_3.0",
            "GCC_3.3",
            "GCC_3.3.1",
            "GCC_3.4",
            "GCC_3.4.2",
            "GCC_3.4.4",
            "GCC_4.0.0",
            "GCC_4.2.0",
            "GCC_4.3.0",
            "GCC_4.7.0",
            "GCC_4.8.0",
            "GCC_7.0.0",
            "GCC_12.0.0",
            "GCC_13.0.0",
            "GCC_14.0.0",
        ],
        16,
    );
    assert_eq!(definitions.objects()[2].auxiliary_count(), 89);
    assert_definition_namespace(
        &definitions.objects()[2],
        &[
            "libc.so.6",
            "GLIBC_2.2.5",
            "GLIBC_2.2.6",
            "GLIBC_2.3",
            "GLIBC_2.3.2",
            "GLIBC_2.3.3",
            "GLIBC_2.3.4",
            "GLIBC_2.4",
            "GLIBC_2.5",
            "GLIBC_2.6",
            "GLIBC_2.7",
            "GLIBC_2.8",
            "GLIBC_2.9",
            "GLIBC_2.10",
            "GLIBC_2.11",
            "GLIBC_2.12",
            "GLIBC_2.13",
            "GLIBC_2.14",
            "GLIBC_2.15",
            "GLIBC_2.16",
            "GLIBC_2.17",
            "GLIBC_2.18",
            "GLIBC_2.22",
            "GLIBC_2.23",
            "GLIBC_2.24",
            "GLIBC_2.25",
            "GLIBC_2.26",
            "GLIBC_2.27",
            "GLIBC_2.28",
            "GLIBC_2.29",
            "GLIBC_2.30",
            "GLIBC_2.31",
            "GLIBC_2.32",
            "GLIBC_2.33",
            "GLIBC_2.34",
            "GLIBC_2.35",
            "GLIBC_2.36",
            "GLIBC_2.38",
            "GLIBC_2.39",
            "GLIBC_2.41",
            "GLIBC_2.42",
            "GLIBC_2.43",
            "GLIBC_2.44",
            "GLIBC_ABI_DT_RELR",
            "GLIBC_ABI_DT_X86_64_PLT",
            "GLIBC_ABI_GNU2_TLS",
            "GLIBC_PRIVATE",
        ],
        44,
    );
    assert!(
        probe_x64_tail_worker_dependency_definition_decoder_mutations(
            &fixture.libgcc_bytes,
            1,
            &closure,
        )
    );
    assert!(probe_x64_tail_worker_dependency_definition_mutations(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
    ));

    let root_compatibility_policy = x64_tail_worker_root_compatibility_policy_hash();
    eprintln!(
        "ADR-0081 policy root: {}",
        hash_hex(root_compatibility_policy)
    );
    assert_eq!(
        root_compatibility_policy,
        X64_TAIL_WORKER_ROOT_COMPATIBILITY_POLICY_ROOT
    );
    let root_compatibility = admit_x64_tail_worker_root_compatibility(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &root_versions,
    )
    .expect("every strong root version requirement must bind its exact sealed provider");
    assert_eq!(root_compatibility.provider_count(), 3);
    assert_eq!(root_compatibility.requirement_count(), 3);
    assert_eq!(root_compatibility.binding_count(), 20);
    assert_eq!(
        root_compatibility
            .bindings()
            .iter()
            .map(|binding| binding.root_requirement_ordinal())
            .collect::<Vec<_>>(),
        [vec![0; 3], vec![1; 16], vec![2; 1]].concat()
    );
    assert_eq!(
        root_compatibility
            .bindings()
            .iter()
            .map(|binding| binding.provider_ordinal())
            .collect::<Vec<_>>(),
        [vec![1; 3], vec![2; 16], vec![0; 1]].concat()
    );
    assert_eq!(
        root_compatibility
            .bindings()
            .iter()
            .map(|binding| binding.requirement_name())
            .collect::<Vec<_>>(),
        root_versions
            .requirements()
            .iter()
            .flat_map(|requirement| requirement.auxiliaries())
            .map(|auxiliary| auxiliary.name())
            .collect::<Vec<_>>()
    );
    assert!(root_compatibility
        .bindings()
        .iter()
        .enumerate()
        .all(|(ordinal, binding)| {
            binding.ordinal() == u16::try_from(ordinal).unwrap()
                && binding.requirement_flags() == 0
                && binding.definition_flags() == 0
        }));
    let glibc_23_bindings = root_compatibility
        .bindings()
        .iter()
        .filter(|binding| binding.requirement_name() == "GLIBC_2.3")
        .collect::<Vec<_>>();
    assert_eq!(glibc_23_bindings.len(), 2);
    assert_eq!(
        glibc_23_bindings
            .iter()
            .map(|binding| binding.provider_ordinal())
            .collect::<Vec<_>>(),
        vec![2, 0]
    );
    assert_eq!(
        glibc_23_bindings
            .iter()
            .map(|binding| binding.definition_version_index())
            .collect::<Vec<_>>(),
        vec![4, 3]
    );
    assert_ne!(
        glibc_23_bindings[0].provider_definition_object_evidence_hash(),
        glibc_23_bindings[1].provider_definition_object_evidence_hash()
    );
    assert!(probe_x64_tail_worker_root_compatibility_join_edges(
        &root_versions,
        &definitions,
    ));
    assert!(probe_x64_tail_worker_root_compatibility_mutations(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &root_versions,
        &root_compatibility,
    ));

    let root_symbol_policy = x64_tail_worker_root_symbol_policy_hash();
    eprintln!("ADR-0082 policy root: {}", hash_hex(root_symbol_policy));
    assert_eq!(root_symbol_policy, X64_TAIL_WORKER_ROOT_SYMBOL_POLICY_ROOT);
    let root_symbols = emit_x64_tail_worker_root_symbol_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &root_versions,
        &root_compatibility,
    )
    .expect("sealed root dynsym and versym topology must replay independently");
    let root_symbol_object = root_symbols.object();
    eprintln!(
        "ADR-0082 root shape: symbols={} sysv_buckets={} sysv_chains={} gnu_offset={} gnu_shift={} gnu_bloom={} gnu_buckets={} gnu_chains={}",
        root_symbols.symbol_count(),
        root_symbol_object.sysv_buckets().len(),
        root_symbol_object.sysv_chains().len(),
        root_symbol_object.gnu_symbol_offset(),
        root_symbol_object.gnu_bloom_shift(),
        root_symbol_object.gnu_bloom().len(),
        root_symbol_object.gnu_buckets().len(),
        root_symbol_object.gnu_chains().len(),
    );
    assert_eq!(
        root_symbols.symbol_count(),
        root_symbol_object.symbol_count()
    );
    assert_eq!(
        usize::from(root_symbols.symbol_count()),
        root_symbol_object.symbols().len()
    );
    assert!(!root_symbol_object.symbols().is_empty());
    assert_eq!(root_symbol_object.symbols()[0].ordinal(), 0);
    assert_eq!(root_symbol_object.symbols()[0].name(), "");
    assert_eq!(root_symbol_object.symbols()[0].version_word(), 0);
    assert_eq!(
        root_symbol_object.symbols()[0].namespace_kind(),
        X64TailWorkerRootSymbolNamespaceKind::Local
    );
    assert!(root_symbol_object
        .symbols()
        .iter()
        .enumerate()
        .all(|(ordinal, symbol)| symbol.ordinal() == u16::try_from(ordinal).unwrap()));
    let versioned_requirements = root_symbol_object
        .symbols()
        .iter()
        .filter(|symbol| symbol.version_index() >= 2)
        .collect::<Vec<_>>();
    assert!(!versioned_requirements.is_empty());
    assert!(versioned_requirements.iter().all(|symbol| {
        !symbol.is_defined()
            && symbol.namespace_kind() == X64TailWorkerRootSymbolNamespaceKind::Requirement
            && symbol.namespace_provider_ordinal() < root_compatibility.provider_count()
            && symbol.namespace_record_ordinal() < root_versions.requirement_count()
            && symbol.namespace_auxiliary_ordinal() < 20
            && symbol.namespace_evidence_hash() != SemanticHash::ZERO
            && symbol.compatibility_binding_evidence_hash() != SemanticHash::ZERO
    }));
    assert!(root_symbol_object
        .symbols()
        .iter()
        .filter(|symbol| symbol.version_index() < 2)
        .all(|symbol| {
            matches!(
                symbol.namespace_kind(),
                X64TailWorkerRootSymbolNamespaceKind::Local
                    | X64TailWorkerRootSymbolNamespaceKind::Global
            ) && symbol.namespace_evidence_hash() == SemanticHash::ZERO
                && symbol.compatibility_binding_evidence_hash() == SemanticHash::ZERO
        }));
    assert!(probe_x64_tail_worker_root_symbol_decoder_mutations(
        &exact_worker_bytes,
        root_symbol_object.artifact_hash(),
        &inventory,
        &root_versions,
        &root_compatibility,
    ));
    assert!(probe_x64_tail_worker_root_symbol_mutations(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &root_versions,
        &root_compatibility,
        &root_symbols,
    ));

    let compatibility_policy = x64_tail_worker_dependency_compatibility_policy_hash();
    eprintln!("ADR-0078 policy root: {}", hash_hex(compatibility_policy));
    assert_eq!(
        compatibility_policy,
        X64_TAIL_WORKER_DEPENDENCY_COMPATIBILITY_POLICY_ROOT
    );
    let compatibility = admit_x64_tail_worker_dependency_compatibility(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
    )
    .expect("all strong GNU version requirements must exist in their exact providers");
    assert_eq!(compatibility.provider_count(), 3);
    assert_eq!(compatibility.total_bindings(), 12);
    assert_eq!(compatibility.objects()[0].binding_count(), 0);
    assert_eq!(compatibility.objects()[1].binding_count(), 8);
    assert_eq!(compatibility.objects()[2].binding_count(), 4);
    let libgcc_bindings = compatibility.objects()[1].bindings();
    assert_eq!(
        libgcc_bindings
            .iter()
            .map(|binding| binding.requirement_name())
            .collect::<Vec<_>>(),
        vec![
            "GLIBC_2.3",
            "GLIBC_ABI_DT_RELR",
            "GLIBC_2.3.4",
            "GLIBC_2.35",
            "GLIBC_2.14",
            "GLIBC_2.34",
            "GLIBC_2.3.2",
            "GLIBC_2.2.5",
        ]
    );
    assert_eq!(
        libgcc_bindings
            .iter()
            .map(|binding| binding.provider_ordinal())
            .collect::<Vec<_>>(),
        vec![0, 2, 2, 2, 2, 2, 2, 2]
    );
    assert_eq!(
        libgcc_bindings
            .iter()
            .map(|binding| binding.definition_version_index())
            .collect::<Vec<_>>(),
        vec![3, 44, 7, 36, 18, 35, 5, 2]
    );
    assert_eq!(
        libgcc_bindings
            .iter()
            .map(|binding| binding.requirement_ordinal())
            .collect::<Vec<_>>(),
        vec![0, 1, 1, 1, 1, 1, 1, 1]
    );
    assert_eq!(
        libgcc_bindings
            .iter()
            .map(|binding| binding.auxiliary_ordinal())
            .collect::<Vec<_>>(),
        vec![0, 0, 1, 2, 3, 4, 5, 6]
    );
    let libc_bindings = compatibility.objects()[2].bindings();
    assert_eq!(
        libc_bindings
            .iter()
            .map(|binding| binding.requirement_name())
            .collect::<Vec<_>>(),
        vec!["GLIBC_2.2.5", "GLIBC_2.3", "GLIBC_2.35", "GLIBC_PRIVATE"]
    );
    assert_eq!(
        libc_bindings
            .iter()
            .map(|binding| binding.provider_ordinal())
            .collect::<Vec<_>>(),
        vec![0, 0, 0, 0]
    );
    assert_eq!(
        libc_bindings
            .iter()
            .map(|binding| binding.definition_version_index())
            .collect::<Vec<_>>(),
        vec![2, 3, 6, 7]
    );
    assert!(compatibility.objects().iter().all(|object| {
        object
            .bindings()
            .iter()
            .enumerate()
            .all(|(ordinal, binding)| {
                binding.ordinal() == u16::try_from(ordinal).unwrap()
                    && binding.definition_flags() == 0
            })
    }));
    assert!(probe_x64_tail_worker_dependency_compatibility_join_edges(
        &versions,
        &definitions,
    ));
    assert!(probe_x64_tail_worker_dependency_compatibility_mutations(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &compatibility,
    ));

    let symbol_source = include_str!("../src/core/x64_tail_worker_dependency_symbols.rs");
    let symbol_imports = symbol_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "std::path",
        "std::process",
        "object::",
        "goblin",
        "libloading",
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
    ] {
        assert!(
            !symbol_imports.contains(forbidden),
            "symbol inventory imports forbidden authority {forbidden}"
        );
    }
    let symbol_policy = x64_tail_worker_dependency_symbol_policy_hash();
    eprintln!("ADR-0079 policy root: {}", hash_hex(symbol_policy));
    assert_eq!(symbol_policy, X64_TAIL_WORKER_DEPENDENCY_SYMBOL_POLICY_ROOT);
    let symbols = emit_x64_tail_worker_dependency_symbol_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &compatibility,
    )
    .expect("exact dynsym extent and parallel versym inventory must replay independently");
    assert_eq!(symbols.provider_count(), 3);
    assert_eq!(symbols.total_symbols(), 3_455);
    assert_eq!(
        symbols
            .objects()
            .iter()
            .map(|object| object.symbol_count())
            .collect::<Vec<_>>(),
        vec![40, 226, 3_189]
    );
    for object in symbols.objects() {
        assert!(object.sysv_buckets().is_empty());
        assert!(!object.gnu_bloom().is_empty());
        assert!(!object.gnu_buckets().is_empty());
        assert_eq!(
            object.gnu_chains().len(),
            usize::from(object.symbol_count())
                .checked_sub(usize::try_from(object.gnu_symbol_offset()).unwrap())
                .unwrap()
        );
        assert_eq!(object.symbols()[0].name(), "");
        assert_eq!(object.symbols()[0].version_word(), 0);
    }
    assert!(probe_x64_tail_worker_dependency_symbol_decoder_mutations(
        &fixture.libgcc_bytes,
        &closure.providers()[1],
        &versions.objects()[1],
        &definitions.objects()[1],
    ));
    assert!(probe_x64_tail_worker_dependency_symbol_mutations(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &compatibility,
        &symbols,
    ));

    let root_scope_source = include_str!("../src/core/x64_tail_worker_root_scope.rs");
    let root_scope_imports = root_scope_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "std::path",
        "std::process",
        "x64_tail_worker_dependency_object_bytes",
        "readelf",
        "object::",
        "goblin",
        "libloading",
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
    ] {
        assert!(
            !root_scope_imports.contains(forbidden),
            "root scope admission imports forbidden authority {forbidden}"
        );
    }
    let root_scope_policy = x64_tail_worker_root_scope_policy_hash();
    eprintln!("ADR-0083 policy root: {}", hash_hex(root_scope_policy));
    assert_eq!(root_scope_policy, X64_TAIL_WORKER_ROOT_SCOPE_POLICY_ROOT);
    let reviewed_scope_entries = [1usize, 2, 0]
        .into_iter()
        .map(|provider_ordinal| {
            let provider = &closure.providers()[provider_ordinal];
            let symbol_object = &symbols.objects()[provider_ordinal];
            X64TailWorkerRootScopeEntryExpectation::new(
                u16::try_from(provider_ordinal).unwrap(),
                provider.soname().to_owned(),
                provider.object_hash(),
                provider.evidence_hash(),
                symbol_object.evidence_hash(),
            )
            .expect("reviewed scope entry must bind one exact sealed provider")
        })
        .collect::<Vec<_>>();
    let root_scope_expectation = X64TailWorkerRootScopeExpectation::new(
        symbols.evidence_hash(),
        root_symbols.evidence_hash(),
        reviewed_scope_entries,
    )
    .expect("reviewed root scope must be canonical and complete");
    let root_scope = admit_x64_tail_worker_root_scope(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &compatibility,
        &symbols,
        &root_versions,
        &root_compatibility,
        &root_symbols,
        &root_scope_expectation,
    )
    .expect("the complete reviewed provider precedence must admit without lookup");
    assert_eq!(root_scope.scope_count(), 3);
    assert_eq!(
        root_scope
            .entries()
            .iter()
            .map(|entry| entry.provider_ordinal())
            .collect::<Vec<_>>(),
        vec![1, 2, 0]
    );
    assert_eq!(
        root_scope
            .entries()
            .iter()
            .map(|entry| entry.soname())
            .collect::<Vec<_>>(),
        vec!["libgcc_s.so.1", "libc.so.6", "ld-linux-x86-64.so.2"]
    );
    assert!(root_scope
        .entries()
        .iter()
        .enumerate()
        .all(|(ordinal, entry)| {
            let provider = &closure.providers()[usize::from(entry.provider_ordinal())];
            let symbol_object = &symbols.objects()[usize::from(entry.provider_ordinal())];
            entry.ordinal() == u16::try_from(ordinal).unwrap()
                && entry.object_hash() == provider.object_hash()
                && entry.closure_provider_evidence_hash() == provider.evidence_hash()
                && entry.provider_symbol_object_evidence_hash() == symbol_object.evidence_hash()
        }));
    assert!(probe_x64_tail_worker_root_scope_mutations(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &compatibility,
        &symbols,
        &root_versions,
        &root_compatibility,
        &root_symbols,
        &root_scope_expectation,
        &root_scope,
    ));

    let root_selection_source = include_str!("../src/core/x64_tail_worker_root_selection.rs");
    let root_selection_imports = root_selection_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "std::path",
        "std::process",
        "x64_tail_worker_dependency_object_bytes",
        "decode_x64_tail_worker",
        "readelf",
        "dlsym",
        "libloading",
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "Instant",
        "SystemTime",
    ] {
        assert!(
            !root_selection_imports.contains(forbidden),
            "root selection imports forbidden authority {forbidden}"
        );
    }

    let root_relocation_source = include_str!("../src/core/x64_tail_worker_root_relocations.rs");
    let root_relocation_imports = root_relocation_source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "std::fs",
        "std::path",
        "std::process",
        "x64_tail_worker_dependency_object_bytes",
        "readelf",
        "dlsym",
        "libloading",
        "x64_tail_enveloped_native",
        "x64_native_process",
        "x64_standalone",
        "x64_target::raw",
        "Instant",
        "SystemTime",
    ] {
        assert!(
            !root_relocation_imports.contains(forbidden),
            "root relocation inventory imports forbidden authority {forbidden}"
        );
    }
    let root_relocation_policy = x64_tail_worker_root_relocation_policy_hash();
    eprintln!("ADR-0085 policy root: {}", hash_hex(root_relocation_policy));
    assert_eq!(
        root_relocation_policy,
        X64_TAIL_WORKER_ROOT_RELOCATION_POLICY_ROOT
    );

    let root_selection_policy = x64_tail_worker_root_selection_policy_hash();
    eprintln!("ADR-0084 policy root: {}", hash_hex(root_selection_policy));
    assert_eq!(
        root_selection_policy,
        X64_TAIL_WORKER_ROOT_SELECTION_POLICY_ROOT
    );
    let root_selection = emit_x64_tail_worker_root_selection_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &compatibility,
        &symbols,
        &root_versions,
        &root_compatibility,
        &root_symbols,
        &root_scope_expectation,
        &root_scope,
    )
    .expect("exact strong versioned candidate selection must replay sealed hash tables");
    eprintln!(
        "ADR-0084 evidence root: {}",
        hash_hex(root_selection.evidence_hash())
    );
    eprintln!(
        "ADR-0084 topology root: {}",
        hash_hex(root_selection.topology_hash())
    );
    assert_eq!(
        root_selection.topology_hash(),
        X64_TAIL_WORKER_ROOT_SELECTION_TOPOLOGY_ROOT
    );
    assert_eq!(
        root_selection.root_symbol_count(),
        X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_ROOT_SYMBOLS
    );
    assert_eq!(
        root_selection.request_count(),
        X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_REQUESTS
    );
    assert_eq!(
        root_selection.selected_count(),
        X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_SELECTED
    );
    assert_eq!(
        root_selection.ifunc_refusal_count(),
        X64_TAIL_WORKER_ROOT_SELECTION_FROZEN_IFUNC_REFUSALS
    );
    assert_eq!(
        root_selection
            .decisions()
            .iter()
            .filter(|decision| {
                decision.decision_kind() == X64TailWorkerRootSelectionDecisionKind::Selected
                    && decision.selected_binding() == 1
            })
            .count(),
        40
    );
    assert_eq!(
        root_selection
            .decisions()
            .iter()
            .filter(|decision| {
                decision.decision_kind() == X64TailWorkerRootSelectionDecisionKind::Selected
                    && decision.selected_binding() == 2
            })
            .count(),
        50
    );
    assert_eq!(
        root_selection
            .decisions()
            .iter()
            .filter(|decision| {
                decision.decision_kind() == X64TailWorkerRootSelectionDecisionKind::Selected
                    && decision.selected_symbol_type() == 2
            })
            .count(),
        89
    );
    assert_eq!(
        root_selection
            .decisions()
            .iter()
            .filter(|decision| {
                decision.decision_kind() == X64TailWorkerRootSelectionDecisionKind::Selected
                    && decision.selected_symbol_type() == 1
            })
            .count(),
        1
    );
    let mut refused_ifunc_names = root_selection
        .decisions()
        .iter()
        .filter(|decision| {
            decision.decision_kind() == X64TailWorkerRootSelectionDecisionKind::RefusedIfunc
        })
        .map(|decision| decision.name())
        .collect::<Vec<_>>();
    refused_ifunc_names.sort_unstable();
    assert_eq!(
        refused_ifunc_names,
        vec!["bcmp", "memcmp", "memcpy", "memmove", "memset", "strlen"]
    );
    assert_eq!(
        root_selection
            .decisions()
            .iter()
            .map(|decision| decision.probes().len())
            .sum::<usize>(),
        181
    );
    assert!(probe_x64_tail_worker_root_selection_mutations(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &compatibility,
        &symbols,
        &root_versions,
        &root_compatibility,
        &root_symbols,
        &root_scope_expectation,
        &root_scope,
        &root_selection,
    ));

    fixture.remove_sources();
    let verified_inventory = verify_x64_tail_worker_elf_evidence(&artifact, &inventory)
        .expect("source deletion cannot alter sealed root ELF authority");
    verify_x64_tail_worker_dependency_dynamic_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
    )
    .expect("source deletion cannot alter sealed dynamic inventory authority");
    verify_x64_tail_worker_dependency_closure(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
    )
    .expect("source deletion cannot alter reviewed closure authority");
    verify_x64_tail_worker_dependency_version_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
    )
    .expect("source deletion cannot alter GNU version requirement authority");
    verify_x64_tail_worker_dependency_definition_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
    )
    .expect("source deletion cannot alter GNU version definition authority");
    verify_x64_tail_worker_dependency_compatibility(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &compatibility,
    )
    .expect("source deletion cannot alter exact GNU version compatibility authority");
    verify_x64_tail_worker_dependency_symbol_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &compatibility,
        &symbols,
    )
    .expect("source deletion cannot alter exact dynsym/versym inventory authority");
    verify_x64_tail_worker_root_version_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &root_versions,
    )
    .expect("source deletion cannot alter sealed root-version inventory authority");
    verify_x64_tail_worker_root_compatibility(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &root_versions,
        &root_compatibility,
    )
    .expect("source deletion cannot alter exact root-version compatibility authority");
    let verified_root_symbols = verify_x64_tail_worker_root_symbol_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &root_versions,
        &root_compatibility,
        &root_symbols,
    )
    .expect("source deletion cannot alter sealed root dynsym/versym authority");
    verify_x64_tail_worker_root_scope(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &compatibility,
        &symbols,
        &root_versions,
        &root_compatibility,
        &root_symbols,
        &root_scope_expectation,
        &root_scope,
    )
    .expect("source deletion cannot alter reviewed root lookup-scope authority");
    let verified_root_selection = verify_x64_tail_worker_root_selection_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &manifest,
        &object_set,
        &dynamic,
        &closure_expectation,
        &closure,
        &versions,
        &definitions,
        &compatibility,
        &symbols,
        &root_versions,
        &root_compatibility,
        &root_symbols,
        &root_scope_expectation,
        &root_scope,
        &root_selection,
    )
    .expect("source deletion cannot alter exact root candidate-selection authority");

    let root_relocations = emit_x64_tail_worker_root_relocation_evidence(
        &artifact,
        &verified_inventory,
        &verified_root_symbols,
        &verified_root_selection,
    )
    .expect("sealed root relocation inventory must join exact symbol selection evidence");
    eprintln!(
        "ADR-0085 evidence root: {}",
        hash_hex(root_relocations.evidence_hash())
    );
    let rela_bytes = exact_dynamic_value(&inventory, DT_RELASZ);
    let rela_entry_bytes = exact_dynamic_value(&inventory, DT_RELAENT);
    let relative_prefix = exact_dynamic_value(&inventory, DT_RELACOUNT);
    let jmprel_bytes = exact_dynamic_value(&inventory, DT_PLTRELSZ);
    let pltrel_kind = exact_dynamic_value(&inventory, DT_PLTREL);
    assert_eq!(rela_entry_bytes, ELF64_RELA_BYTES);
    assert_eq!(pltrel_kind, DT_RELA as u64);
    assert_eq!(rela_bytes % ELF64_RELA_BYTES, 0);
    assert_eq!(jmprel_bytes % ELF64_RELA_BYTES, 0);
    let expected_rela = u32::try_from(rela_bytes / ELF64_RELA_BYTES).unwrap();
    let expected_relative = u32::try_from(relative_prefix).unwrap();
    let expected_jump_slot = u32::try_from(jmprel_bytes / ELF64_RELA_BYTES).unwrap();
    let expected_glob_dat = expected_rela.checked_sub(expected_relative).unwrap();
    let expected_total = expected_rela + expected_jump_slot;
    let expected_selected = 89;
    let expected_ifunc_refused = 8;
    let expected_unsupported = 11;
    assert_eq!(expected_glob_dat, 105);
    assert_eq!(expected_jump_slot, 3);
    assert_eq!(
        expected_selected + expected_ifunc_refused + expected_unsupported,
        expected_glob_dat + expected_jump_slot
    );
    assert_eq!(
        root_relocations.records().len(),
        usize::try_from(expected_total).unwrap()
    );
    assert_eq!(root_relocations.rela_count(), expected_rela);
    assert_eq!(root_relocations.jmprel_count(), expected_jump_slot);
    assert_eq!(root_relocations.relative_prefix_count(), expected_relative);
    assert_eq!(root_relocations.relative_count(), expected_relative);
    assert_eq!(root_relocations.glob_dat_count(), expected_glob_dat);
    assert_eq!(root_relocations.jump_slot_count(), expected_jump_slot);
    assert_eq!(root_relocations.selected_count(), expected_selected);
    assert_eq!(
        root_relocations.ifunc_refused_count(),
        expected_ifunc_refused
    );
    assert_eq!(root_relocations.unsupported_count(), expected_unsupported);
    let relocated_symbols = root_relocations
        .records()
        .iter()
        .filter_map(|record| (record.symbol_ordinal() != 0).then_some(record.symbol_ordinal()))
        .collect::<BTreeSet<_>>();
    let selected_without_relocation = root_selection
        .decisions()
        .iter()
        .filter(|decision| {
            decision.decision_kind() == X64TailWorkerRootSelectionDecisionKind::Selected
                && !relocated_symbols.contains(&decision.requester_symbol_ordinal())
        })
        .map(|decision| decision.name())
        .collect::<Vec<_>>();
    eprintln!("ADR-0085 selected decisions without relocation: {selected_without_relocation:?}");
    assert_eq!(selected_without_relocation.len(), 1);
    assert!(root_relocations
        .records()
        .iter()
        .take(usize::try_from(root_relocations.rela_count()).unwrap())
        .all(|record| record.table_kind() == X64TailWorkerRootRelocationTableKind::Rela));
    assert!(root_relocations
        .records()
        .iter()
        .skip(usize::try_from(root_relocations.rela_count()).unwrap())
        .all(|record| record.table_kind() == X64TailWorkerRootRelocationTableKind::JumpRel));
    for (class, expected) in [
        (
            X64TailWorkerRootRelocationClass::Relative,
            expected_relative,
        ),
        (
            X64TailWorkerRootRelocationClass::Selected,
            expected_selected,
        ),
        (
            X64TailWorkerRootRelocationClass::RefusedIfunc,
            expected_ifunc_refused,
        ),
        (
            X64TailWorkerRootRelocationClass::UnsupportedRequester,
            expected_unsupported,
        ),
    ] {
        assert_eq!(
            root_relocations
                .records()
                .iter()
                .filter(|record| record.class() == class)
                .count(),
            usize::try_from(expected).unwrap()
        );
    }
    verify_x64_tail_worker_root_relocation_evidence(
        &artifact,
        &verified_inventory,
        &verified_root_symbols,
        &verified_root_selection,
        &root_relocations,
    )
    .expect("source deletion cannot alter sealed root relocation authority");
    assert!(probe_x64_tail_worker_root_relocation_decoder_mutations(
        &artifact,
        &verified_inventory,
        &verified_root_symbols,
        &verified_root_selection,
        &root_relocations,
    ));
    assert!(probe_x64_tail_worker_root_relocation_mutations(
        &artifact,
        &verified_inventory,
        &verified_root_symbols,
        &verified_root_selection,
        &root_relocations,
    ));
}

#[test]
fn adr0073_rejects_locator_identity_and_elf_drift() {
    let (artifact, inventory, declarations, declaration_evidence) = declaration_authorities();
    let fixture = ObjectFixture::new();
    assert!(probe_x64_tail_worker_dependency_object_elf_mutations(
        &fixture.loader_bytes
    ));

    for invalid_path in [
        "relative/libc.so.6",
        "/",
        "/tmp/../libc.so.6",
        "/tmp//libc.so.6",
        "/tmp/./libc.so.6",
        "/tmp/libc so.6",
        "/tmp/libc.so.6/",
    ] {
        assert!(
            X64TailWorkerDependencyObjectExpectation::direct_dependency_from_reviewed_bytes(
                "libc.so.6".to_owned(),
                invalid_path.to_owned(),
                &fixture.libc_bytes,
            )
            .is_err()
        );
    }

    let wrong_hash_path = fixture.root.join("wrong-hash.elf");
    fs::write(&wrong_hash_path, &fixture.loader_bytes).unwrap();
    let wrong_hash_interpreter = X64TailWorkerDependencyObjectExpectation::interpreter(
        declarations.interpreter().to_owned(),
        wrong_hash_path.to_string_lossy().into_owned(),
        u64::try_from(fixture.loader_bytes.len()).unwrap(),
        SemanticHash([0x55; 32]),
    )
    .unwrap();
    let exact = fixture.manifest(&declarations);
    let wrong_hash_manifest = X64TailWorkerDependencyObjectManifest::new(
        &declarations,
        wrong_hash_interpreter,
        exact.objects()[1..].to_vec(),
    )
    .unwrap();
    assert!(admit_x64_tail_worker_dependency_objects(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &wrong_hash_manifest,
    )
    .is_err());

    let symlink_path = fixture.root.join("loader-link.elf");
    symlink(&fixture.loader_path, &symlink_path).expect("create adversarial final symlink");
    let symlink_interpreter =
        X64TailWorkerDependencyObjectExpectation::interpreter_from_reviewed_bytes(
            declarations.interpreter().to_owned(),
            symlink_path.to_string_lossy().into_owned(),
            &fixture.loader_bytes,
        )
        .unwrap();
    let symlink_manifest = X64TailWorkerDependencyObjectManifest::new(
        &declarations,
        symlink_interpreter,
        exact.objects()[1..].to_vec(),
    )
    .unwrap();
    assert!(admit_x64_tail_worker_dependency_objects(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &symlink_manifest,
    )
    .is_err());

    let mut invalid_elf = fixture.loader_bytes.clone();
    invalid_elf[0] ^= 1;
    let invalid_path = fixture.root.join("invalid-magic.elf");
    fs::write(&invalid_path, &invalid_elf).unwrap();
    let invalid_interpreter =
        X64TailWorkerDependencyObjectExpectation::interpreter_from_reviewed_bytes(
            declarations.interpreter().to_owned(),
            invalid_path.to_string_lossy().into_owned(),
            &invalid_elf,
        )
        .unwrap();
    let invalid_manifest = X64TailWorkerDependencyObjectManifest::new(
        &declarations,
        invalid_interpreter,
        exact.objects()[1..].to_vec(),
    )
    .unwrap();
    assert!(admit_x64_tail_worker_dependency_objects(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &invalid_manifest,
    )
    .is_err());

    // A second individually valid object may claim the same SONAME, but ADR-0075
    // must not collapse it when its exact byte identity differs.
    let mut conflicting_loader_bytes = fixture.loader_bytes.clone();
    let last = conflicting_loader_bytes
        .last_mut()
        .expect("reviewed loader is nonempty");
    *last ^= 1;
    let conflicting_loader_path = fixture.root.join("conflicting-loader.elf");
    fs::write(&conflicting_loader_path, &conflicting_loader_bytes).unwrap();
    let conflicting_manifest = X64TailWorkerDependencyObjectManifest::new(
        &declarations,
        X64TailWorkerDependencyObjectExpectation::interpreter_from_reviewed_bytes(
            declarations.interpreter().to_owned(),
            fixture.loader_path.clone(),
            &fixture.loader_bytes,
        )
        .unwrap(),
        vec![
            X64TailWorkerDependencyObjectExpectation::direct_dependency_from_reviewed_bytes(
                declarations.dependencies()[0].clone(),
                fixture.libgcc_path.clone(),
                &fixture.libgcc_bytes,
            )
            .unwrap(),
            X64TailWorkerDependencyObjectExpectation::direct_dependency_from_reviewed_bytes(
                declarations.dependencies()[1].clone(),
                fixture.libc_path.clone(),
                &fixture.libc_bytes,
            )
            .unwrap(),
            X64TailWorkerDependencyObjectExpectation::direct_dependency_from_reviewed_bytes(
                declarations.dependencies()[2].clone(),
                conflicting_loader_path.to_string_lossy().into_owned(),
                &conflicting_loader_bytes,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let conflicting_set = admit_x64_tail_worker_dependency_objects(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &conflicting_manifest,
    )
    .expect("both exact ELF objects are individually admissible");
    let conflicting_dynamic = emit_x64_tail_worker_dependency_dynamic_evidence(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &conflicting_manifest,
        &conflicting_set,
    )
    .expect("both objects retain the same valid internal SONAME");
    assert!(admit_x64_tail_worker_dependency_closure(
        &artifact,
        &inventory,
        &declarations,
        &declaration_evidence,
        &conflicting_manifest,
        &conflicting_set,
        &conflicting_dynamic,
        &reviewed_closure(&conflicting_manifest),
    )
    .is_err());
}
