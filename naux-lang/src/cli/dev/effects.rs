use std::path::Path;

use crate::cli::util;
use crate::effects;

pub fn effects_core(path: &Path) -> Result<(), String> {
    let (_, ast) = util::load_ast(path)?;

    println!("~ NAUX EFFECT ANALYSIS ~");
    println!("path: {}", path.display());
    println!();

    let result = effects::handle_effects(&ast);

    println!("[SIGNATURE] {}", result.signature);
    println!();

    if result.unhandled.is_empty() {
        println!("[EFFECTS] Pure — no side effects detected");
    } else {
        println!("[EFFECTS] {} operations:", result.unhandled.len());
        for (i, effect) in result.unhandled.iter().enumerate() {
            let args_str = effect
                .args
                .iter()
                .map(|a| format!("{}", a))
                .collect::<Vec<_>>()
                .join(", ");
            println!("  E{}: !{}({}) [{}]", i, effect.op, args_str, effect.name);
        }
    }
    println!();

    let registry = effects::types::EffectRegistry::with_builtins();
    println!("[REGISTRY] {} built-in effects:", registry.effects.len());
    let mut names: Vec<_> = registry.effects.keys().collect();
    names.sort();
    for name in &names {
        let decl = registry.lookup(name).unwrap();
        let ops: Vec<_> = decl
            .operations
            .iter()
            .map(|o| {
                format!(
                    "!{}({}) → {}",
                    o.name,
                    o.params
                        .iter()
                        .map(|p| format!("{}: {}", p.name, p.ty))
                        .collect::<Vec<_>>()
                        .join(", "),
                    o.return_type
                )
            })
            .collect();
        println!("  effect {} {{ {} }}", name, ops.join(", "));
    }
    println!();

    println!("[RESULT] signature={}, {} effect operations", result.signature, result.unhandled.len());
    Ok(())
}
