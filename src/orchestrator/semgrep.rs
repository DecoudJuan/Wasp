//! Invocación de Semgrep y normalización de su salida.

use crate::model::Finding;
use crate::normalize;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Construye el comando de Semgrep para escanear `root` con reglas de seguridad.
///
/// `--config auto` selecciona reglas relevantes (incluye OWASP); `--json` emite a
/// stdout; `--quiet` silencia el progreso para no contaminar el JSON.
pub fn build_command(root: &Path) -> Command {
    let mut cmd = Command::new("semgrep");
    cmd.arg("scan")
        .arg("--config")
        .arg("auto")
        .arg("--json")
        .arg("--quiet")
        .arg("--no-git-ignore") // el walker ya decide el alcance; aquí escaneamos lo dado
        .arg(root);
    cmd
}

/// Ejecuta Semgrep sobre `root` y devuelve los hallazgos normalizados.
pub fn run(root: &Path) -> Result<Vec<Finding>> {
    let output = build_command(root).output().context("ejecutando semgrep")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    normalize::from_semgrep(&stdout)
}
