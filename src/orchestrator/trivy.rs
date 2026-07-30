//! Invocación de Trivy y normalización de su salida.

use crate::model::Finding;
use crate::normalize;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Construye el comando de Trivy para escanear dependencias del filesystem en `root`.
///
/// `fs` escanea manifiestos/lockfiles; `--format json` emite a stdout; `--quiet`
/// silencia el progreso.
pub fn build_command(root: &Path) -> Command {
    let mut cmd = Command::new("trivy");
    cmd.arg("fs")
        .arg("--format")
        .arg("json")
        .arg("--quiet")
        .arg("--scanners")
        .arg("vuln")
        .arg(root);
    cmd
}

/// Ejecuta Trivy sobre `root` y devuelve los hallazgos normalizados.
pub fn run(root: &Path) -> Result<Vec<Finding>> {
    let output = build_command(root).output().context("ejecutando trivy")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    normalize::from_trivy(&stdout)
}
