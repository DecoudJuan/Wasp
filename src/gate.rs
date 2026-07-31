//! Puerta de severidad para modo CI: decide si el escaneo debe fallar el build.

use crate::model::{Finding, Severity};

/// La severidad más alta presente en los hallazgos, o `None` si no hay ninguno.
pub fn max_severity(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}

/// ¿Hay al menos un hallazgo con severidad igual o superior al umbral?
pub fn fails(findings: &[Finding], threshold: Severity) -> bool {
    findings.iter().any(|f| f.severity >= threshold)
}

/// Cantidad de hallazgos con severidad igual o superior al umbral.
pub fn count_at_or_above(findings: &[Finding], threshold: Severity) -> usize {
    findings.iter().filter(|f| f.severity >= threshold).count()
}
