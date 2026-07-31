//! TDD: puerta de severidad para modo CI (fallar el build según umbral).

use wasp::gate;
use wasp::model::{Confidence, Finding, Location, Severity, Tool};

fn finding(sev: Severity) -> Finding {
    Finding {
        tool: Tool::Semgrep,
        rule_id: "r".to_string(),
        title: "t".to_string(),
        severity: sev,
        confidence: Confidence::Medium,
        owasp: None,
        cwe: vec![],
        location: Location {
            file: "a.rs".to_string(),
            start_line: 1,
            end_line: 1,
            snippet: None,
        },
        message: String::new(),
        remediation: None,
    }
}

#[test]
fn max_severity_devuelve_la_mas_alta() {
    let v = vec![
        finding(Severity::Low),
        finding(Severity::High),
        finding(Severity::Medium),
    ];
    assert_eq!(gate::max_severity(&v), Some(Severity::High));
    assert_eq!(gate::max_severity(&[]), None);
}

#[test]
fn fails_cuando_hay_algo_en_o_sobre_el_umbral() {
    let v = vec![finding(Severity::Medium), finding(Severity::Low)];
    assert!(gate::fails(&v, Severity::Medium)); // hay un medium
    assert!(gate::fails(&v, Severity::Low)); // umbral más bajo
    assert!(!gate::fails(&v, Severity::High)); // nada alcanza high
    assert!(!gate::fails(&[], Severity::Info)); // sin hallazgos no falla
}

#[test]
fn cuenta_en_o_sobre_el_umbral() {
    let v = vec![
        finding(Severity::Critical),
        finding(Severity::High),
        finding(Severity::Low),
    ];
    assert_eq!(gate::count_at_or_above(&v, Severity::High), 2);
    assert_eq!(gate::count_at_or_above(&v, Severity::Critical), 1);
    assert_eq!(gate::count_at_or_above(&v, Severity::Info), 3);
}
