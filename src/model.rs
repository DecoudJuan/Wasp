//! Modelo unificado de hallazgos. Toda salida de escáner se normaliza a `Finding`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Escáner que originó el hallazgo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tool {
    Semgrep,
    Gitleaks,
    Trivy,
}

impl Tool {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tool::Semgrep => "semgrep",
            Tool::Gitleaks => "gitleaks",
            Tool::Trivy => "trivy",
        }
    }
}

/// Severidad normalizada entre todas las herramientas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    // El orden importa: `Ord` permite ordenar por gravedad descendente.
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// Confianza en que el hallazgo es un verdadero positivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Ubicación del hallazgo en el código.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    /// Fragmento de código relevante. Nunca debe contener secretos en claro.
    pub snippet: Option<String>,
}

/// Un hallazgo de seguridad normalizado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub tool: Tool,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Categoría OWASP Top 10, p.ej. "A03:2021 - Injection".
    pub owasp: Option<String>,
    /// Identificadores CWE numéricos, p.ej. `[78]`.
    pub cwe: Vec<u32>,
    pub location: Location,
    pub message: String,
    pub remediation: Option<String>,
}

impl Finding {
    /// Huella estable e idempotente (herramienta + archivo + línea + regla).
    /// Se usa para deduplicar hallazgos entre corridas.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.tool.as_str().as_bytes());
        hasher.update(b"|");
        hasher.update(self.location.file.as_bytes());
        hasher.update(b"|");
        hasher.update(self.location.start_line.to_string().as_bytes());
        hasher.update(b"|");
        hasher.update(self.rule_id.as_bytes());
        let digest = hasher.finalize();
        // 16 hex chars son suficientes para evitar colisiones prácticas.
        digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
    }
}

/// Extrae el número de un identificador CWE del estilo "CWE-78: ..." o "CWE-78".
pub(crate) fn parse_cwe(raw: &str) -> Option<u32> {
    let after = raw
        .trim()
        .strip_prefix("CWE-")
        .or_else(|| raw.strip_prefix("cwe-"))?;
    let num: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cwe_extrae_numero() {
        assert_eq!(parse_cwe("CWE-78: OS Command Injection"), Some(78));
        assert_eq!(parse_cwe("CWE-1321"), Some(1321));
        assert_eq!(parse_cwe("no-cwe"), None);
    }

    #[test]
    fn severidad_ordena_por_gravedad() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Info);
    }
}
