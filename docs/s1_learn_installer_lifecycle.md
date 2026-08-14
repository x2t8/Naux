# NAUX Learn installer lifecycle contract v0.1

Status: lifecycle foundation and native console install carriers accepted\
Date: 2026-08-13\
Scope: S1-INSTALL1 / one-click installation foundation

## 1. Product boundary

The installer presents NAUX Learn as an experimental learning profile, not as
the complete future NAUX system. Installation must remain offline-capable and
must not require Rust, Cargo, LLVM, MinGW, a compiler, an assembler, or a
linker on the learner host.

The lifecycle is:

```text
select language -> disclose -> verify -> stage -> publish
                -> use -> verify/repair -> upgrade/rollback -> uninstall
```

Every mutating step must have an ownership record. No lifecycle operation may
discover removal targets by scanning an unrestricted filesystem tree.

## 2. Supported installer locales

The bounded v0.1 locale set is `en-US`, `vi-VN`, `zh-CN`, `ja-JP`, `ko-KR`,
`es`, `pt-BR`, `fr`, and `de`. `en-US` is the canonical authority and the
mandatory fallback. Locale names are shown in their own language; country
flags are not used.

The selected locale applies to installer, disclosure, repair, rollback, and
uninstall surfaces. Compiler diagnostics and program stdout remain canonical
and are not localized by this contract.

## 3. Release disclosure

Before publication, every locale must communicate all of the following:

- this is an experimental NAUX Learn release;
- the intended use is guided programming and algorithm study;
- production, security-critical, safety-critical, and performance-leadership
  uses are excluded;
- syntax, semantics, library, project, and installation behavior may change;
- execution budgets are not a security sandbox;
- the learner host does not need Rust/Cargo, but the current artifact still
  has Rust/Cargo and `egg` seed debt;
- future NAUX directions are not delivery promises;
- warranty limitations are governed by the bundled license and limitations.

Disclosure is explicitly requested through `naux welcome` or `naux about`.
It must never contaminate `naux run`, `naux check`, version output, program
stdout, machine-readable output, or noninteractive package transactions.

## 4. Installation ownership

Each installed prefix remains an immutable, ordinarily verifiable Learn
bundle. A separate user-local state directory contains one sealed receipt per
installation. The receipt binds the product/version/target, absolute prefix,
selected locale, bundle manifest seal, exact file and byte counts, and a
derived installation identity. Keeping mutable state outside the prefix
prevents lifecycle metadata from weakening the bundle inventory. OS
integration actions are a later layer over the same receipt semantics.

Uninstall may remove only paths admitted by the bundle manifest or explicitly
recorded integration actions. Changed, ambiguous, traversing, linked, or
unowned paths fail closed. User `.nx` projects are never installation-owned.

## 5. Host carriers

The intended Windows carrier is a native, user-local `NAUX-Learn-Setup.exe`.
The intended Linux carriers are native Arch and Debian packages plus a
user-local fallback installer. Native package managers retain authority over
system-package removal; NAUX retains authority over its own admitted payload
and user-local integration receipt.

## 6. Acceptance gates

- all nine catalogs parse as canonical UTF-8/LF and contain the exact required
  ordered key set;
- locale selection is explicit, bounded, and falls back to `en-US`;
- every localized disclosure renders without changing program execution;
- a clean install is independently verifiable without the seed toolchain;
- a staged receipt is verified before publication;
- dry-run uninstall enumerates exact owned paths and performs no mutation;
- mutation, missing-key, duplicate-key, unsafe-prefix, moved-installation, and
  receipt-seal cases fail closed;
- real Windows and supported Linux host carriers pass before promotion.

This contract does not yet grant GUI-installer completion, package-manager
publication, code signing, update service, production safety, compatibility
stability, seed independence, self-generation, or compiler generation.

## 7. Current evidence

The executable and both bundles contain the same nine exact catalogs and
reject packaged catalog drift even after a hostile manifest reseal. Linux
no-toolchain installation, receipt publication, dry-run, exact uninstall, and
receipt-collision rollback pass. Windows cross-builds are byte-identical; Wine
passes locale validation, direct native Setup installation in German, `pt-BR`
receipt installation, first-program execution, and uninstall planning, while
actual in-process removal fails closed as required. An interactive Linux PTY
carrier selects Vietnamese, renders the complete Vietnamese disclosure, and
cancels without mutation.

Default and all-feature focused S1 groups each pass 30 tests plus two native
Setup tests. The all-feature
library gate reports 454 passed, zero failed, and six intentionally ignored.
Strict all-target/all-feature Clippy, deterministic Linux/Windows archive
replay, checksum/extra-member/PE/icon mutation rejection, and semantic PE icon
verification pass. A graphical Setup UI, detached Windows remover, OS
shortcuts/registration, Linux native packages, and real Windows 10/11 carrier
are still required for full one-click completion.
