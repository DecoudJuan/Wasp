//! Recorrido del repositorio respetando `.gitignore`.

use anyhow::Result;
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

/// Recorre `root` y devuelve los archivos (no directorios), respetando reglas
/// de `.gitignore`/`.ignore` aunque el directorio no sea un repo git.
///
/// Los archivos ocultos (p.ej. `.git/`, `.gitignore`) quedan excluidos: no son
/// código fuente a auditar.
pub fn walk(root: &Path) -> Result<Vec<PathBuf>> {
    let mut archivos = Vec::new();
    let walker = WalkBuilder::new(root)
        .hidden(true) // omite dotfiles y dotdirs (.git, .gitignore, ...)
        .git_ignore(true)
        .ignore(true)
        .require_git(false) // aplicar .gitignore aunque no haya repo git
        .build();

    for entry in walker {
        let entry = entry?;
        if entry.file_type().is_some_and(|t| t.is_file()) {
            archivos.push(entry.into_path());
        }
    }
    Ok(archivos)
}

/// Como [`walk`], pero **incluye archivos ocultos** (dotfiles/dotdirs como
/// `.github`, `.agents`) porque los escáneres también los revisan. Nunca desciende
/// al directorio `.git/`. Se usa para calcular huellas del cache incremental.
pub fn walk_all(root: &Path) -> Result<Vec<PathBuf>> {
    let mut archivos = Vec::new();
    let walker = WalkBuilder::new(root)
        .hidden(false) // incluir dotfiles/dotdirs
        .git_ignore(true)
        .ignore(true)
        .require_git(false)
        .filter_entry(|e| e.file_name() != ".git") // nunca entrar a .git/
        .build();

    for entry in walker {
        let entry = entry?;
        if entry.file_type().is_some_and(|t| t.is_file()) {
            archivos.push(entry.into_path());
        }
    }
    Ok(archivos)
}
