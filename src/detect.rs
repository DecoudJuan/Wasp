//! Detección de stack tecnológico y disponibilidad de escáneres externos.

use crate::model::Tool;
use anyhow::Result;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Stack tecnológico detectado por sus manifiestos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stack {
    Npm,
    Python,
    Java,
    Go,
    Php,
}

/// Manifiestos que delatan cada stack.
const MANIFIESTOS: &[(&str, Stack)] = &[
    ("package.json", Stack::Npm),
    ("requirements.txt", Stack::Python),
    ("pyproject.toml", Stack::Python),
    ("pom.xml", Stack::Java),
    ("build.gradle", Stack::Java),
    ("go.mod", Stack::Go),
    ("composer.json", Stack::Php),
];

/// Detecta los stacks presentes buscando manifiestos en la raíz del repo.
pub fn detect_stacks(root: &Path) -> Result<Vec<Stack>> {
    let mut stacks = Vec::new();
    for (archivo, stack) in MANIFIESTOS {
        if root.join(archivo).is_file() && !stacks.contains(stack) {
            stacks.push(*stack);
        }
    }
    Ok(stacks)
}

/// Estado de disponibilidad de un escáner externo.
#[derive(Debug, Clone)]
pub struct ToolStatus {
    pub tool: Tool,
    pub available: bool,
    /// Ruta al binario si se encontró.
    pub path: Option<PathBuf>,
}

/// Reporta la disponibilidad de los tres escáneres que Wasp orquesta.
pub fn doctor() -> Vec<ToolStatus> {
    [Tool::Semgrep, Tool::Gitleaks, Tool::Trivy]
        .into_iter()
        .map(|tool| {
            let path = find_in_paths(tool.as_str(), std::env::var_os("PATH").as_deref());
            ToolStatus {
                tool,
                available: path.is_some(),
                path,
            }
        })
        .collect()
}

/// ¿Está `name` disponible como ejecutable en el `PATH` del sistema?
pub fn tool_available(name: &str) -> bool {
    find_in_paths(name, std::env::var_os("PATH").as_deref()).is_some()
}

/// Busca `name` como ejecutable dentro de un `PATH` dado (inyectable para tests).
/// En Windows considera las extensiones de `PATHEXT`.
pub fn find_in_paths(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    let path = path?;
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_string())
            .split(';')
            .map(|s| s.to_string())
            .collect()
    } else {
        vec![String::new()]
    };

    for dir in std::env::split_paths(path) {
        let directo = dir.join(name);
        if directo.is_file() {
            return Some(directo);
        }
        for ext in &exts {
            if ext.is_empty() {
                continue;
            }
            let candidato = dir.join(format!("{name}{ext}"));
            if candidato.is_file() {
                return Some(candidato);
            }
        }
    }
    None
}
