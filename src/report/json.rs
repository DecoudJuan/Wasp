//! Reporter JSON compacto: la vista mínima que consume el LLM para hacer triage.
//!
//! Solo incluye los campos de alto valor para no gastar tokens en metadata.

use crate::model::Finding;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize)]
struct CompactFinding<'a> {
    id: String,
    tool: &'a str,
    severity: &'a str,
    rule_id: &'a str,
    file: &'a str,
    line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    owasp: Option<&'a str>,
    cwe: &'a [u32],
    #[serde(skip_serializing_if = "Option::is_none")]
    snippet: Option<&'a str>,
    message: &'a str,
}

/// Serializa los hallazgos a JSON compacto (una línea por documento no; array).
pub fn compact(findings: &[Finding]) -> Result<String> {
    let compact: Vec<CompactFinding> = findings
        .iter()
        .map(|f| CompactFinding {
            id: f.fingerprint(),
            tool: f.tool.as_str(),
            severity: f.severity.as_str(),
            rule_id: &f.rule_id,
            file: &f.location.file,
            line: f.location.start_line,
            owasp: f.owasp.as_deref(),
            cwe: &f.cwe,
            snippet: f.location.snippet.as_deref(),
            message: &f.message,
        })
        .collect();
    Ok(serde_json::to_string_pretty(&compact)?)
}
