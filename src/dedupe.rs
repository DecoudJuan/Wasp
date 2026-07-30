//! Deduplicación idempotente de hallazgos y ordenamiento por severidad.

use crate::model::Finding;
use std::collections::HashSet;

/// Elimina hallazgos con la misma huella (`fingerprint`), conservando la primera
/// aparición. Es idempotente: `dedupe(dedupe(x)) == dedupe(x)`.
pub fn dedupe(findings: Vec<Finding>) -> Vec<Finding> {
    let mut vistos = HashSet::new();
    findings
        .into_iter()
        .filter(|f| vistos.insert(f.fingerprint()))
        .collect()
}

/// Ordena los hallazgos por severidad descendente (Critical primero).
/// El orden relativo de severidades iguales se mantiene estable.
pub fn sort_by_severity(findings: &mut [Finding]) {
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
}
