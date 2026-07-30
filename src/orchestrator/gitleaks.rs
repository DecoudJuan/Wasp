//! Invocación de Gitleaks y normalización de su salida.

use crate::model::Finding;
use crate::normalize;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Construye el comando de Gitleaks para detectar secretos en `root`.
///
/// Gitleaks escribe el reporte JSON en `report_path` (no a stdout). Usamos
/// `--no-git` para poder escanear carpetas que no son repositorios git.
pub fn build_command(root: &Path, report_path: &Path) -> Command {
    let mut cmd = Command::new("gitleaks");
    cmd.arg("detect")
        .arg("--source")
        .arg(root)
        .arg("--no-git")
        .arg("--report-format")
        .arg("json")
        .arg("--report-path")
        .arg(report_path)
        .arg("--no-banner")
        .arg("--exit-code")
        .arg("0"); // que encontrar secretos no sea un "fallo" del proceso
    cmd
}

/// Ejecuta Gitleaks sobre `root` y devuelve los hallazgos normalizados.
pub fn run(root: &Path) -> Result<Vec<Finding>> {
    // Gitleaks reporta a archivo; usamos uno temporal y lo leemos.
    let tmp = tempfile_path()?;
    let status = build_command(root, &tmp)
        .status()
        .context("ejecutando gitleaks")?;
    let _ = status;
    let json = std::fs::read_to_string(&tmp).unwrap_or_else(|_| "[]".to_string());
    let _ = std::fs::remove_file(&tmp);
    normalize::from_gitleaks(&json)
}

/// Genera una ruta temporal única para el reporte de gitleaks.
fn tempfile_path() -> Result<std::path::PathBuf> {
    let file = tempfile::Builder::new()
        .prefix("wasp-gitleaks-")
        .suffix(".json")
        .tempfile()
        .context("creando archivo temporal para gitleaks")?;
    // Conservamos solo la ruta; gitleaks (re)escribe el archivo.
    let (_f, path) = file.keep().context("persistiendo ruta temporal")?;
    Ok(path)
}
