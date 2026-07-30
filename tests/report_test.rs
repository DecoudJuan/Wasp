//! Fase 4 (TDD): reporters JSON compacto, SARIF 2.1.0 y Markdown.

use serde_json::Value;
use wasp::model::{Confidence, Finding, Location, Severity, Tool};
use wasp::report;

fn findings_de_muestra() -> Vec<Finding> {
    vec![
        Finding {
            tool: Tool::Semgrep,
            rule_id: "python.injection".to_string(),
            title: "OS Command Injection".to_string(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            owasp: Some("A03:2021 - Injection".to_string()),
            cwe: vec![78],
            location: Location {
                file: "app/main.py".to_string(),
                start_line: 12,
                end_line: 12,
                snippet: Some("subprocess.call(cmd, shell=True)".to_string()),
            },
            message: "Command injection".to_string(),
            remediation: Some("Evitar shell=True".to_string()),
        },
        Finding {
            tool: Tool::Gitleaks,
            rule_id: "aws-access-token".to_string(),
            title: "AWS Access Key".to_string(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
            cwe: vec![798],
            location: Location {
                file: "config/prod.env".to_string(),
                start_line: 3,
                end_line: 3,
                snippet: None,
            },
            message: "Secreto hardcodeado".to_string(),
            remediation: Some("Rotar credencial".to_string()),
        },
    ]
}

#[test]
fn json_compacto_incluye_campos_clave() {
    let json = report::json::compact(&findings_de_muestra()).unwrap();
    let v: Value = serde_json::from_str(&json).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 2);

    let first = &arr[0];
    assert!(first.get("id").is_some());
    assert_eq!(first["severity"], "high");
    assert_eq!(first["file"], "app/main.py");
    assert_eq!(first["line"], 12);
    assert_eq!(first["owasp"], "A03:2021 - Injection");
    assert_eq!(first["cwe"][0], 78);
    assert!(first.get("snippet").is_some());
}

#[test]
fn sarif_es_valido_2_1_0() {
    let sarif = report::sarif::to_sarif(&findings_de_muestra()).unwrap();
    let v: Value = serde_json::from_str(&sarif).unwrap();

    assert_eq!(v["version"], "2.1.0");
    assert!(v["$schema"].as_str().unwrap().contains("sarif"));
    assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "Wasp");

    let results = v["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    // Critical -> "error"; el segundo finding es Critical.
    assert_eq!(results[1]["level"], "error");
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        12
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "app/main.py"
    );
}

#[test]
fn markdown_resume_y_lista_hallazgos() {
    let md = report::markdown::render(&findings_de_muestra());
    assert!(md.contains("# "));
    // Conteo por severidad y detalle de hallazgos.
    assert!(md.contains("Critical") || md.contains("critical"));
    assert!(md.contains("app/main.py:12"));
    assert!(md.contains("A03:2021 - Injection"));
    assert!(md.contains("CWE-78"));
    assert!(md.contains("Evitar shell=True"));
}

#[test]
fn markdown_sin_hallazgos_es_amigable() {
    let md = report::markdown::render(&[]);
    assert!(md.to_lowercase().contains("sin hallazgos") || md.contains("0"));
}
