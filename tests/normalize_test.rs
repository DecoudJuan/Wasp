//! Fase 1 (TDD): las salidas crudas de cada escáner se normalizan a `Vec<Finding>`.

use wasp::model::{Severity, Tool};
use wasp::normalize;

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read_to_string(path).expect("fixture legible")
}

#[test]
fn normaliza_semgrep() {
    let findings = normalize::from_semgrep(&fixture("semgrep_sample.json")).unwrap();
    assert_eq!(findings.len(), 2);

    let inj = &findings[0];
    assert_eq!(inj.tool, Tool::Semgrep);
    assert_eq!(inj.location.file, "app/main.py");
    assert_eq!(inj.location.start_line, 12);
    assert_eq!(inj.severity, Severity::High); // ERROR -> High
    assert_eq!(inj.cwe, vec![78]);
    assert_eq!(inj.owasp.as_deref(), Some("A03:2021 - Injection"));
    assert!(inj.location.snippet.is_some());

    let crypto = &findings[1];
    assert_eq!(crypto.severity, Severity::Medium); // WARNING -> Medium
    assert_eq!(crypto.cwe, vec![327]);
}

#[test]
fn normaliza_semgrep_con_metadata_escalar_o_nula() {
    // Semgrep emite `cwe`/`owasp` como string, lista o null indistintamente.
    // El parser debe tolerar las tres formas sin romper todo el documento.
    let findings = normalize::from_semgrep(&fixture("semgrep_scalar_meta.json")).unwrap();
    assert_eq!(findings.len(), 2);

    // Primer hallazgo: cwe y owasp como string escalar.
    assert_eq!(findings[0].cwe, vec![327]);
    assert_eq!(
        findings[0].owasp.as_deref(),
        Some("A02:2021 - Cryptographic Failures")
    );

    // Segundo: cwe como lista, owasp null.
    assert_eq!(findings[1].cwe, vec![89]);
    assert_eq!(findings[1].owasp, None);
}

#[test]
fn normaliza_gitleaks() {
    let findings = normalize::from_gitleaks(&fixture("gitleaks_sample.json")).unwrap();
    assert_eq!(findings.len(), 2);

    let aws = &findings[0];
    assert_eq!(aws.tool, Tool::Gitleaks);
    assert_eq!(aws.rule_id, "aws-access-token");
    assert_eq!(aws.location.file, "config/prod.env");
    assert_eq!(aws.location.start_line, 3);
    assert_eq!(aws.severity, Severity::High); // secretos = High
                                              // Secretos mapean a A07 (fallas de identificación/autenticación) por convención del proyecto.
    assert_eq!(aws.cwe, vec![798]); // CWE-798: Use of Hard-coded Credentials
                                    // El secreto en claro NO debe aparecer en el mensaje ni el snippet (no filtrar credenciales).
    assert!(!aws.message.contains("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn normaliza_trivy() {
    let findings = normalize::from_trivy(&fixture("trivy_sample.json")).unwrap();
    assert_eq!(findings.len(), 2);

    let critical = findings
        .iter()
        .find(|f| f.severity == Severity::Critical)
        .unwrap();
    assert_eq!(critical.tool, Tool::Trivy);
    assert_eq!(critical.location.file, "package-lock.json");
    assert!(critical.rule_id.contains("CVE-2020-8203"));
    assert_eq!(critical.cwe, vec![1321]);
    // Debe sugerir la versión corregida en la remediación.
    assert!(critical.remediation.as_deref().unwrap().contains("4.17.20"));

    let high = findings
        .iter()
        .find(|f| f.severity == Severity::High)
        .unwrap();
    assert_eq!(high.cwe, vec![77, 94]);
}

#[test]
fn fingerprint_es_estable_e_idempotente() {
    let a = normalize::from_semgrep(&fixture("semgrep_sample.json")).unwrap();
    let b = normalize::from_semgrep(&fixture("semgrep_sample.json")).unwrap();
    assert_eq!(a[0].fingerprint(), b[0].fingerprint());
    assert_ne!(a[0].fingerprint(), a[1].fingerprint());
}
