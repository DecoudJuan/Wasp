//! Normalizadores: convierten la salida JSON cruda de cada escáner en `Vec<Finding>`.

use crate::model::{parse_cwe, Confidence, Finding, Location, Severity, Tool};
use anyhow::{Context, Result};
use serde::Deserialize;

// ----------------------------- Semgrep -----------------------------

#[derive(Deserialize)]
struct SemgrepOutput {
    results: Vec<SemgrepResult>,
}

#[derive(Deserialize)]
struct SemgrepResult {
    check_id: String,
    path: String,
    start: SemgrepPos,
    end: SemgrepPos,
    extra: SemgrepExtra,
}

#[derive(Deserialize)]
struct SemgrepPos {
    line: u32,
}

#[derive(Deserialize)]
struct SemgrepExtra {
    message: String,
    severity: String,
    #[serde(default)]
    lines: String,
    #[serde(default)]
    metadata: SemgrepMeta,
}

#[derive(Deserialize, Default)]
struct SemgrepMeta {
    #[serde(default, deserialize_with = "string_or_seq")]
    cwe: Vec<String>,
    #[serde(default, deserialize_with = "string_or_seq")]
    owasp: Vec<String>,
}

/// Deserializa un campo que puede venir como string, lista de strings o null.
/// Semgrep usa las tres formas indistintamente para `cwe` y `owasp`.
fn string_or_seq<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrSeq {
        Seq(Vec<String>),
        One(String),
    }
    Ok(match Option::<StringOrSeq>::deserialize(deserializer)? {
        Some(StringOrSeq::Seq(v)) => v,
        Some(StringOrSeq::One(s)) => vec![s],
        None => Vec::new(),
    })
}

/// Semgrep: ERROR→High, WARNING→Medium, INFO→Info.
fn semgrep_severity(raw: &str) -> Severity {
    match raw.to_ascii_uppercase().as_str() {
        "ERROR" => Severity::High,
        "WARNING" => Severity::Medium,
        _ => Severity::Info,
    }
}

pub fn from_semgrep(json: &str) -> Result<Vec<Finding>> {
    let out: SemgrepOutput =
        serde_json::from_str(json).context("parseando salida JSON de semgrep")?;
    let findings = out
        .results
        .into_iter()
        .map(|r| {
            let cwe = r
                .extra
                .metadata
                .cwe
                .iter()
                .filter_map(|s| parse_cwe(s))
                .collect();
            let title = r
                .check_id
                .rsplit('.')
                .next()
                .unwrap_or(&r.check_id)
                .replace('-', " ");
            Finding {
                tool: Tool::Semgrep,
                rule_id: r.check_id,
                title,
                severity: semgrep_severity(&r.extra.severity),
                confidence: Confidence::Medium,
                owasp: r.extra.metadata.owasp.into_iter().next(),
                cwe,
                location: Location {
                    file: r.path,
                    start_line: r.start.line,
                    end_line: r.end.line,
                    snippet: if r.extra.lines.is_empty() {
                        None
                    } else {
                        Some(r.extra.lines)
                    },
                },
                message: r.extra.message,
                remediation: None,
            }
        })
        .collect();
    Ok(findings)
}

// ----------------------------- Gitleaks -----------------------------

#[derive(Deserialize)]
struct GitleaksFinding {
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "StartLine")]
    start_line: u32,
    #[serde(rename = "EndLine")]
    end_line: u32,
    #[serde(rename = "File")]
    file: String,
    #[serde(rename = "RuleID")]
    rule_id: String,
}

pub fn from_gitleaks(json: &str) -> Result<Vec<Finding>> {
    let raw: Vec<GitleaksFinding> =
        serde_json::from_str(json).context("parseando salida JSON de gitleaks")?;
    let findings = raw
        .into_iter()
        .map(|g| Finding {
            tool: Tool::Gitleaks,
            rule_id: g.rule_id,
            title: g.description.clone(),
            severity: Severity::High,
            confidence: Confidence::High,
            // Secretos hardcodeados: A07 (fallas de autenticación) + CWE-798.
            owasp: Some("A07:2021 - Identification and Authentication Failures".to_string()),
            cwe: vec![798],
            location: Location {
                file: g.file,
                start_line: g.start_line,
                end_line: g.end_line,
                // Nunca exponemos el secreto en claro: solo describimos el tipo.
                snippet: None,
            },
            message: format!(
                "Posible secreto hardcodeado ({}). El valor fue omitido por seguridad.",
                g.description
            ),
            remediation: Some(
                "Rotar la credencial expuesta y moverla a un gestor de secretos o variable de entorno."
                    .to_string(),
            ),
        })
        .collect();
    Ok(findings)
}

// ----------------------------- Trivy -----------------------------

#[derive(Deserialize)]
struct TrivyOutput {
    #[serde(rename = "Results", default)]
    results: Vec<TrivyResult>,
}

#[derive(Deserialize)]
struct TrivyResult {
    #[serde(rename = "Target")]
    target: String,
    #[serde(rename = "Vulnerabilities", default)]
    vulnerabilities: Vec<TrivyVuln>,
}

#[derive(Deserialize)]
struct TrivyVuln {
    #[serde(rename = "VulnerabilityID")]
    id: String,
    #[serde(rename = "PkgName")]
    pkg_name: String,
    #[serde(rename = "InstalledVersion")]
    installed_version: String,
    #[serde(rename = "FixedVersion", default)]
    fixed_version: String,
    #[serde(rename = "Severity")]
    severity: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Description", default)]
    description: String,
    #[serde(rename = "CweIDs", default)]
    cwe_ids: Vec<String>,
}

/// Trivy: CRITICAL→Critical, HIGH→High, MEDIUM→Medium, LOW→Low, resto→Info.
fn trivy_severity(raw: &str) -> Severity {
    match raw.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

pub fn from_trivy(json: &str) -> Result<Vec<Finding>> {
    let out: TrivyOutput = serde_json::from_str(json).context("parseando salida JSON de trivy")?;
    let mut findings = Vec::new();
    for result in out.results {
        for v in result.vulnerabilities {
            let cwe = v.cwe_ids.iter().filter_map(|s| parse_cwe(s)).collect();
            let remediation = if v.fixed_version.is_empty() {
                Some(format!(
                    "No hay versión corregida publicada para {}. Evaluar mitigaciones o reemplazo.",
                    v.pkg_name
                ))
            } else {
                Some(format!(
                    "Actualizar {} de {} a {} o superior.",
                    v.pkg_name, v.installed_version, v.fixed_version
                ))
            };
            let title = if v.title.is_empty() {
                format!("{} en {}", v.id, v.pkg_name)
            } else {
                v.title
            };
            findings.push(Finding {
                tool: Tool::Trivy,
                rule_id: format!("{}:{}", v.pkg_name, v.id),
                title,
                severity: trivy_severity(&v.severity),
                confidence: Confidence::High,
                // Componentes con vulnerabilidades conocidas.
                owasp: Some("A06:2021 - Vulnerable and Outdated Components".to_string()),
                cwe,
                location: Location {
                    file: result.target.clone(),
                    start_line: 0,
                    end_line: 0,
                    snippet: None,
                },
                message: if v.description.is_empty() {
                    format!("{} afecta a {} {}", v.id, v.pkg_name, v.installed_version)
                } else {
                    v.description
                },
                remediation,
            });
        }
    }
    Ok(findings)
}
