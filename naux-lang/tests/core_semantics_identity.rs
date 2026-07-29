use naux::core::{interpreter_semantics_bytes, interpreter_semantics_hash, CoreProfile};
use std::collections::BTreeSet;

const PROFILES: [CoreProfile; 6] = [
    CoreProfile::P1V0,
    CoreProfile::P1V1,
    CoreProfile::P1V2,
    CoreProfile::P1V3,
    CoreProfile::P1V4,
    CoreProfile::P1V5,
];

const LOCKED_HASHES: [&str; 6] = [
    "d9911cf60e5afa54e271cdff274cde41b522a4a0c9855ccd6efbcd4e981909cc",
    "b2390469cf843ac941ae66b8c10d118adb4395075567e9f7e297c1f59428733a",
    "f42c66951eadbdc4112f94ae79c4a6bd62bdeadf898ab174a8d034b24179e025",
    "2e0cab2ae5f57ee90a6a90475b5f4948db0ce768ce54777748ea11fed6d0d30f",
    "9553993aab31235ac0998b48e0ffbe46342c5110df939605ad8579710db0d38b",
    "29559c4cfe514c4f22ef01e66feaff5cfad6b2728944dfc1f72da12382b4c1cc",
];

#[test]
fn interpreter_semantics_identity_is_deterministic_and_domain_separated() {
    const DOMAIN: &[u8] = b"NAUX:core-n0:interpreter-semantics:v1\0";

    for profile in PROFILES {
        let first = interpreter_semantics_bytes(profile).expect("semantics must encode");
        let second = interpreter_semantics_bytes(profile).expect("semantics must re-encode");
        assert_eq!(first, second);
        assert!(first.starts_with(DOMAIN));

        let first_hash = interpreter_semantics_hash(profile).expect("semantics must hash");
        let second_hash = interpreter_semantics_hash(profile).expect("semantics must re-hash");
        assert_eq!(first_hash, second_hash);
    }
}

#[test]
fn every_profile_has_a_distinct_interpreter_semantics_identity() {
    let hashes = PROFILES
        .into_iter()
        .map(|profile| {
            interpreter_semantics_hash(profile)
                .expect("semantics must hash")
                .to_hex()
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(hashes.len(), PROFILES.len());
}

#[test]
fn interpreter_semantics_hashes_match_locked_vectors() {
    let actual = PROFILES.map(|profile| {
        interpreter_semantics_hash(profile)
            .expect("semantics must hash")
            .to_hex()
    });

    assert_eq!(actual, LOCKED_HASHES);
}
