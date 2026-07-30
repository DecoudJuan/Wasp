//! Reporter SARIF 2.1.0 para integración con GitHub Code Scanning / CI.

use crate::model::{Finding, Severity};
use anyhow::Result;
use serde_json::{json, Value};

/// Nivel SARIF a partir de la severidad normalizada.
fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Serializa los hallazgos a un documento SARIF 2.1.0.
pub fn to_sarif(findings: &[Finding]) -> Result<String> {
    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let tags: Vec<String> = f.cwe.iter().map(|c| format!("CWE-{c}")).collect();
            json!({
                "ruleId": f.rule_id,
                "level": sarif_level(f.severity),
                "message": { "text": f.message },
                "partialFingerprints": { "wasp/v1": f.fingerprint() },
                "properties": {
                    "tool": f.tool.as_str(),
                    "owasp": f.owasp,
                    "cwe": tags,
                    "remediation": f.remediation,
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.location.file },
                        "region": {
                            "startLine": f.location.start_line.max(1),
                            "endLine": f.location.end_line.max(f.location.start_line).max(1)
                        }
                    }
                }]
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": crate::PRODUCT,
                    "informationUri": "https://github.com/DecoudJuan/Wasp",
                    "version": crate::version()
                }
            },
            "results": results
        }]
    });

    Ok(serde_json::to_string_pretty(&doc)?)
}
