use crate::cli::NAUX_VERSION;
use crate::install_locale::{selected_catalog, validate_embedded_catalogs, SUPPORTED_LOCALES};

pub fn handle_welcome(
    language: Option<String>,
    list_languages: bool,
    validate_locales: bool,
) -> Result<(), String> {
    if validate_locales {
        validate_embedded_catalogs().map_err(|error| error.to_string())?;
        println!("NAUX installer locales: verified");
        println!("catalogs: {}", SUPPORTED_LOCALES.len());
        return Ok(());
    }
    if list_languages {
        for locale in SUPPORTED_LOCALES {
            println!("{}\t{}", locale.code, locale.language_name);
        }
        return Ok(());
    }

    let catalog = selected_catalog(language.as_deref()).map_err(|error| error.to_string())?;
    print!("{}", catalog.render_release_disclosure(NAUX_VERSION));
    Ok(())
}
