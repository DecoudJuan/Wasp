//! Orquestación de escáneres: corre los disponibles y degrada con gracia.

pub mod gitleaks;
pub mod semgrep;
pub mod trivy;

use crate::detect;
use crate::model::{Finding, Tool};
use std::collections::HashSet;
use std::path::Path;

/// Resultado de una corrida de escaneo. Cada herramienta cae en exactamente una
/// categoría: ejecutada, omitida (no instalada) o con error.
#[derive(Debug, Default)]
pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    /// Herramientas que corrieron correctamente.
    pub ran: Vec<Tool>,
    /// Herramientas omitidas por no estar instaladas.
    pub skipped: Vec<Tool>,
    /// Herramientas que fallaron en ejecución, con el motivo.
    pub errors: Vec<(Tool, String)>,
}

/// Ejecuta todos los escáneres disponibles sobre `root`.
///
/// Nunca falla globalmente: la ausencia o el error de una herramienta se registra
/// en el `ScanOutcome` sin abortar el resto del escaneo.
pub fn scan(root: &Path) -> ScanOutcome {
    let mut outcome = ScanOutcome::default();

    run_one(&mut outcome, Tool::Semgrep, || semgrep::run(root));
    run_one(&mut outcome, Tool::Gitleaks, || gitleaks::run(root));
    run_one(&mut outcome, Tool::Trivy, || trivy::run(root));

    // Normalizar rutas a relativas a `root` (para consistencia y cache incremental).
    let base = root.to_string_lossy();
    for f in &mut outcome.findings {
        f.location.file = crate::cache::relativize(&f.location.file, &base);
    }

    // Deduplicar y ordenar por severidad para una salida consistente.
    outcome.findings = crate::dedupe::dedupe(std::mem::take(&mut outcome.findings));
    crate::dedupe::sort_by_severity(&mut outcome.findings);

    outcome
}

/// Re-escanea únicamente `changed` (rutas relativas a `root`) usando un directorio
/// temporal de staging. Los hallazgos vuelven con rutas relativas al staging (= las
/// mismas rutas relativas del repo). Si `changed` está vacío, no escanea nada.
pub fn scan_changed(root: &Path, changed: &HashSet<String>) -> ScanOutcome {
    if changed.is_empty() {
        return ScanOutcome::default();
    }
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(_) => return scan(root), // fallback conservador: escaneo completo
    };
    for rel in changed {
        let src = root.join(rel);
        if !src.is_file() {
            continue;
        }
        let dst = tmp.path().join(rel);
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::copy(&src, &dst);
    }
    scan(tmp.path())
}

/// Corre una herramienta si está disponible, clasificando el resultado.
fn run_one<F>(outcome: &mut ScanOutcome, tool: Tool, ejecutar: F)
where
    F: FnOnce() -> anyhow::Result<Vec<Finding>>,
{
    if !detect::tool_available(tool.as_str()) {
        outcome.skipped.push(tool);
        return;
    }
    match ejecutar() {
        Ok(mut findings) => {
            outcome.findings.append(&mut findings);
            outcome.ran.push(tool);
        }
        Err(e) => outcome.errors.push((tool, e.to_string())),
    }
}
