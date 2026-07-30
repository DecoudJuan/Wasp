//! Orquestación de escáneres: corre los disponibles y degrada con gracia.

pub mod gitleaks;
pub mod semgrep;
pub mod trivy;

use crate::detect;
use crate::model::{Finding, Tool};
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

    outcome
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
