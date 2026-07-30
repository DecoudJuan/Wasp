//! Fase 5 (TDD): deduplicación idempotente y orden por severidad.

use wasp::dedupe;
use wasp::model::{Confidence, Finding, Location, Severity, Tool};

fn finding(file: &str, line: u32, rule: &str, sev: Severity) -> Finding {
    Finding {
        tool: Tool::Semgrep,
        rule_id: rule.to_string(),
        title: rule.to_string(),
        severity: sev,
        confidence: Confidence::Medium,
        owasp: None,
        cwe: vec![],
        location: Location {
            file: file.to_string(),
            start_line: line,
            end_line: line,
            snippet: None,
        },
        message: String::new(),
        remediation: None,
    }
}

#[test]
fn dedupe_elimina_huellas_repetidas() {
    let entrada = vec![
        finding("a.py", 1, "r1", Severity::High),
        finding("a.py", 1, "r1", Severity::High), // duplicado exacto
        finding("b.py", 2, "r2", Severity::Low),
    ];
    let salida = dedupe::dedupe(entrada);
    assert_eq!(salida.len(), 2);
}

#[test]
fn dedupe_es_idempotente() {
    let entrada = vec![
        finding("a.py", 1, "r1", Severity::High),
        finding("a.py", 1, "r1", Severity::High),
        finding("b.py", 2, "r2", Severity::Low),
    ];
    let una = dedupe::dedupe(entrada);
    let dos = dedupe::dedupe(una.clone());
    assert_eq!(una, dos);
}

#[test]
fn no_deduplica_findings_distintos() {
    let entrada = vec![
        finding("a.py", 1, "r1", Severity::High),
        finding("a.py", 2, "r1", Severity::High), // otra línea
        finding("a.py", 1, "r2", Severity::High), // otra regla
    ];
    assert_eq!(dedupe::dedupe(entrada).len(), 3);
}

#[test]
fn ordena_por_severidad_descendente() {
    let mut v = vec![
        finding("a.py", 1, "r1", Severity::Low),
        finding("b.py", 2, "r2", Severity::Critical),
        finding("c.py", 3, "r3", Severity::Medium),
    ];
    dedupe::sort_by_severity(&mut v);
    assert_eq!(v[0].severity, Severity::Critical);
    assert_eq!(v[1].severity, Severity::Medium);
    assert_eq!(v[2].severity, Severity::Low);
}
