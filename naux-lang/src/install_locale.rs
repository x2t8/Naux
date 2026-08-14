//! Bounded localization surface for the NAUX Learn installer lifecycle.
//!
//! Catalogs are embedded, canonical UTF-8 TSV inputs. The parser deliberately
//! accepts one exact schema and ordered key set so a missing disclosure cannot
//! silently disappear from one language.

use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs;
use std::path::Path;

const CATALOG_MAGIC: &str = "NAUX-INSTALLER-LOCALE\t1";
const SUPPORTED_MAGIC: &str = "NAUX-SUPPORTED-LOCALES\t1";
const CATALOG_VERSION: &str = "1";
const DEFAULT_LOCALE: &str = "en-US";
const CATALOG_MAX_BYTES: usize = 64 * 1024;
const TEXT_MAX_BYTES: usize = 2 * 1024;

const REQUIRED_TEXT_KEYS: &[&str] = &[
    "installer_title",
    "action_install",
    "action_cancel",
    "action_finish",
    "welcome_title",
    "release_badge",
    "summary",
    "intended_heading",
    "intended_1",
    "intended_2",
    "intended_3",
    "excluded_heading",
    "excluded_1",
    "excluded_2",
    "excluded_3",
    "change_warning",
    "sandbox_warning",
    "seed_warning",
    "future_warning",
    "warranty_warning",
    "action_start",
    "action_limitations",
    "action_release_notes",
    "action_close",
    "uninstall_title",
    "repair_title",
    "rollback_title",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupportedLocale {
    pub code: &'static str,
    pub language_name: &'static str,
}

pub const SUPPORTED_LOCALES: &[SupportedLocale] = &[
    SupportedLocale {
        code: "en-US",
        language_name: "English",
    },
    SupportedLocale {
        code: "vi-VN",
        language_name: "Tiếng Việt",
    },
    SupportedLocale {
        code: "zh-CN",
        language_name: "简体中文",
    },
    SupportedLocale {
        code: "ja-JP",
        language_name: "日本語",
    },
    SupportedLocale {
        code: "ko-KR",
        language_name: "한국어",
    },
    SupportedLocale {
        code: "es",
        language_name: "Español",
    },
    SupportedLocale {
        code: "pt-BR",
        language_name: "Português do Brasil",
    },
    SupportedLocale {
        code: "fr",
        language_name: "Français",
    },
    SupportedLocale {
        code: "de",
        language_name: "Deutsch",
    },
];

const SUPPORTED_LOCALE_BYTES: &[u8] = include_bytes!("../locales/SUPPORTED_LOCALES.tsv");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallerCatalog {
    locale: String,
    language_name: String,
    texts: BTreeMap<String, String>,
}

impl InstallerCatalog {
    pub fn locale(&self) -> &str {
        &self.locale
    }

    pub fn language_name(&self) -> &str {
        &self.language_name
    }

    pub fn text(&self, key: &str) -> &str {
        self.texts
            .get(key)
            .map(String::as_str)
            .expect("catalog was admitted with every required key")
    }

    pub fn render_release_disclosure(&self, version: &str) -> String {
        let title = self.text("welcome_title").replace("{version}", version);
        format!(
            "{title}\n{}\n\n{}\n\n{}:\n- {}\n- {}\n- {}\n\n{}:\n- {}\n- {}\n- {}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n",
            self.text("release_badge"),
            self.text("summary"),
            self.text("intended_heading"),
            self.text("intended_1"),
            self.text("intended_2"),
            self.text("intended_3"),
            self.text("excluded_heading"),
            self.text("excluded_1"),
            self.text("excluded_2"),
            self.text("excluded_3"),
            self.text("change_warning"),
            self.text("sandbox_warning"),
            self.text("seed_warning"),
            self.text("future_warning"),
            self.text("warranty_warning"),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocaleError {
    message: String,
}

impl LocaleError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for LocaleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LocaleError {}

pub fn catalog_for(locale: &str) -> Result<InstallerCatalog, LocaleError> {
    let descriptor = exact_supported_locale(locale).ok_or_else(|| {
        LocaleError::new(format!(
            "unsupported NAUX installer locale `{locale}`; run `naux welcome --list-languages`"
        ))
    })?;
    parse_catalog(catalog_bytes(descriptor.code), descriptor)
}

pub fn selected_catalog(explicit: Option<&str>) -> Result<InstallerCatalog, LocaleError> {
    if let Some(locale) = explicit {
        let matched = match_locale_candidate(locale).ok_or_else(|| {
            LocaleError::new(format!(
                "unsupported NAUX installer locale `{locale}`; run `naux welcome --list-languages`"
            ))
        })?;
        return catalog_for(matched.code);
    }

    for variable in ["NAUX_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(candidate) = env::var(variable) {
            if let Some(matched) = match_locale_candidate(&candidate) {
                return catalog_for(matched.code);
            }
        }
    }
    catalog_for(DEFAULT_LOCALE)
}

pub fn validate_embedded_catalogs() -> Result<(), LocaleError> {
    validate_supported_locale_file(SUPPORTED_LOCALE_BYTES)?;
    for descriptor in SUPPORTED_LOCALES {
        parse_catalog(catalog_bytes(descriptor.code), descriptor)?;
    }
    Ok(())
}

/// Require a packaged locale directory to be byte-identical to the embedded
/// catalogs used by the executable.
pub fn validate_packaged_catalogs(directory: &Path) -> Result<(), LocaleError> {
    validate_embedded_catalogs()?;
    let files = std::iter::once(("SUPPORTED_LOCALES.tsv", SUPPORTED_LOCALE_BYTES)).chain(
        SUPPORTED_LOCALES.iter().map(|descriptor| {
            (
                match descriptor.code {
                    "en-US" => "en-US.tsv",
                    "vi-VN" => "vi-VN.tsv",
                    "zh-CN" => "zh-CN.tsv",
                    "ja-JP" => "ja-JP.tsv",
                    "ko-KR" => "ko-KR.tsv",
                    "es" => "es.tsv",
                    "pt-BR" => "pt-BR.tsv",
                    "fr" => "fr.tsv",
                    "de" => "de.tsv",
                    _ => unreachable!("supported locale has a catalog filename"),
                },
                catalog_bytes(descriptor.code),
            )
        }),
    );
    for (filename, expected) in files {
        let path = directory.join(filename);
        let actual = fs::read(&path).map_err(|error| {
            LocaleError::new(format!(
                "cannot read packaged installer locale `{}`: {error}",
                path.display()
            ))
        })?;
        if actual != expected {
            return Err(LocaleError::new(format!(
                "packaged installer locale `{filename}` differs from the executable catalog"
            )));
        }
    }
    Ok(())
}

fn exact_supported_locale(locale: &str) -> Option<&'static SupportedLocale> {
    SUPPORTED_LOCALES
        .iter()
        .find(|descriptor| descriptor.code.eq_ignore_ascii_case(locale))
}

fn match_locale_candidate(candidate: &str) -> Option<&'static SupportedLocale> {
    let canonical = candidate
        .trim()
        .split(['.', '@'])
        .next()
        .unwrap_or_default()
        .replace('_', "-");
    if canonical.is_empty()
        || canonical.eq_ignore_ascii_case("C")
        || canonical.eq_ignore_ascii_case("POSIX")
    {
        return None;
    }
    if let Some(exact) = exact_supported_locale(&canonical) {
        return Some(exact);
    }

    let lower = canonical.to_ascii_lowercase();
    let language = lower.split('-').next().unwrap_or_default();
    let code = match language {
        "en" => "en-US",
        "vi" => "vi-VN",
        "ja" => "ja-JP",
        "ko" => "ko-KR",
        "es" => "es",
        "fr" => "fr",
        "de" => "de",
        "pt" if lower == "pt" || lower == "pt-br" => "pt-BR",
        "zh" if matches!(lower.as_str(), "zh" | "zh-cn" | "zh-hans" | "zh-hans-cn") => "zh-CN",
        _ => return None,
    };
    exact_supported_locale(code)
}

fn catalog_bytes(locale: &str) -> &'static [u8] {
    match locale {
        "en-US" => include_bytes!("../locales/en-US.tsv"),
        "vi-VN" => include_bytes!("../locales/vi-VN.tsv"),
        "zh-CN" => include_bytes!("../locales/zh-CN.tsv"),
        "ja-JP" => include_bytes!("../locales/ja-JP.tsv"),
        "ko-KR" => include_bytes!("../locales/ko-KR.tsv"),
        "es" => include_bytes!("../locales/es.tsv"),
        "pt-BR" => include_bytes!("../locales/pt-BR.tsv"),
        "fr" => include_bytes!("../locales/fr.tsv"),
        "de" => include_bytes!("../locales/de.tsv"),
        _ => unreachable!("caller resolved a supported locale"),
    }
}

fn parse_catalog(
    bytes: &[u8],
    expected: &SupportedLocale,
) -> Result<InstallerCatalog, LocaleError> {
    let text = canonical_text(bytes, "installer locale catalog")?;
    let mut lines = text[..text.len() - 1].split('\n');
    if lines.next() != Some(CATALOG_MAGIC) {
        return Err(LocaleError::new(format!(
            "installer locale `{}` has invalid magic/version",
            expected.code
        )));
    }
    require_pair(lines.next(), "locale", expected.code, expected.code)?;
    require_pair(
        lines.next(),
        "language-name",
        expected.language_name,
        expected.code,
    )?;
    require_pair(
        lines.next(),
        "catalog-version",
        CATALOG_VERSION,
        expected.code,
    )?;

    let mut texts = BTreeMap::new();
    for required_key in REQUIRED_TEXT_KEYS {
        let line = lines.next().ok_or_else(|| {
            LocaleError::new(format!(
                "installer locale `{}` is missing text key `{required_key}`",
                expected.code
            ))
        })?;
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 3 || fields[0] != "text" || fields[1] != *required_key {
            return Err(LocaleError::new(format!(
                "installer locale `{}` expected ordered text key `{required_key}`",
                expected.code
            )));
        }
        validate_text_value(fields[2], required_key, expected.code)?;
        if texts
            .insert(required_key.to_string(), fields[2].to_string())
            .is_some()
        {
            return Err(LocaleError::new(format!(
                "installer locale `{}` duplicates text key `{required_key}`",
                expected.code
            )));
        }
    }
    if lines.next().is_some() {
        return Err(LocaleError::new(format!(
            "installer locale `{}` contains extra rows",
            expected.code
        )));
    }
    let welcome = texts
        .get("welcome_title")
        .expect("required welcome key was inserted");
    if welcome.matches("{version}").count() != 1 {
        return Err(LocaleError::new(format!(
            "installer locale `{}` welcome title must contain one `{{version}}` placeholder",
            expected.code
        )));
    }

    Ok(InstallerCatalog {
        locale: expected.code.to_string(),
        language_name: expected.language_name.to_string(),
        texts,
    })
}

fn validate_supported_locale_file(bytes: &[u8]) -> Result<(), LocaleError> {
    let text = canonical_text(bytes, "supported locale inventory")?;
    let mut lines = text[..text.len() - 1].split('\n');
    if lines.next() != Some(SUPPORTED_MAGIC) {
        return Err(LocaleError::new(
            "supported locale inventory has invalid magic/version",
        ));
    }
    require_pair(lines.next(), "default", DEFAULT_LOCALE, "inventory")?;
    for descriptor in SUPPORTED_LOCALES {
        let expected = format!("locale\t{}\t{}", descriptor.code, descriptor.language_name);
        if lines.next() != Some(expected.as_str()) {
            return Err(LocaleError::new(format!(
                "supported locale inventory differs at `{}`",
                descriptor.code
            )));
        }
    }
    if lines.next().is_some() {
        return Err(LocaleError::new(
            "supported locale inventory contains extra rows",
        ));
    }
    Ok(())
}

fn canonical_text<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str, LocaleError> {
    if bytes.is_empty() || bytes.len() > CATALOG_MAX_BYTES {
        return Err(LocaleError::new(format!(
            "{label} must contain 1..={CATALOG_MAX_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| LocaleError::new(format!("{label} is not valid UTF-8")))?;
    if text.contains(['\0', '\r']) || !text.ends_with('\n') {
        return Err(LocaleError::new(format!(
            "{label} must use canonical LF text with one terminal LF"
        )));
    }
    Ok(text)
}

fn require_pair(
    line: Option<&str>,
    key: &str,
    value: &str,
    locale: &str,
) -> Result<(), LocaleError> {
    let expected = format!("{key}\t{value}");
    if line != Some(expected.as_str()) {
        return Err(LocaleError::new(format!(
            "installer locale `{locale}` has invalid `{key}` metadata"
        )));
    }
    Ok(())
}

fn validate_text_value(value: &str, key: &str, locale: &str) -> Result<(), LocaleError> {
    if value.is_empty()
        || value.len() > TEXT_MAX_BYTES
        || value.chars().any(char::is_control)
        || (value.contains('{') && key != "welcome_title")
        || (value.contains('}') && key != "welcome_title")
    {
        return Err(LocaleError::new(format!(
            "installer locale `{locale}` has invalid text value for `{key}`"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        catalog_for, match_locale_candidate, selected_catalog, validate_embedded_catalogs,
        SUPPORTED_LOCALES,
    };

    #[test]
    fn all_embedded_catalogs_are_exact_and_complete() {
        validate_embedded_catalogs().unwrap();
        assert_eq!(SUPPORTED_LOCALES.len(), 9);
        for descriptor in SUPPORTED_LOCALES {
            let catalog = catalog_for(descriptor.code).unwrap();
            assert_eq!(catalog.locale(), descriptor.code);
            assert_eq!(catalog.language_name(), descriptor.language_name);
            let disclosure = catalog.render_release_disclosure("9.8.7");
            assert!(disclosure.contains("9.8.7"));
            assert!(!disclosure.contains("{version}"));
        }
    }

    #[test]
    fn locale_matching_is_bounded_and_script_aware() {
        assert_eq!(match_locale_candidate("vi_VN.UTF-8").unwrap().code, "vi-VN");
        assert_eq!(match_locale_candidate("fr_CA").unwrap().code, "fr");
        assert_eq!(match_locale_candidate("zh-Hans").unwrap().code, "zh-CN");
        assert!(match_locale_candidate("zh-TW").is_none());
        assert!(match_locale_candidate("ar-SA").is_none());
    }

    #[test]
    fn explicit_selection_rejects_unknown_instead_of_silent_fallback() {
        assert_eq!(selected_catalog(Some("de-DE")).unwrap().locale(), "de");
        assert!(selected_catalog(Some("xx-YY"))
            .unwrap_err()
            .to_string()
            .contains("unsupported"));
    }
}
