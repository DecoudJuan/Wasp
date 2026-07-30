//! Reporter Markdown legible para humanos.

use crate::model::{Finding, Severity};

/// Renderiza un reporte Markdown a partir de los hallazgos.
pub fn render(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# 🐝 {} — Reporte de auditoría de seguridad\n\n",
        crate::PRODUCT
    ));

    if findings.is_empty() {
        out.push_str("✅ Sin hallazgos de seguridad detectados.\n");
        return out;
    }

    // Resumen por severidad.
    let cuenta = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    out.push_str(&format!("**{} hallazgos** — ", findings.len()));
    out.push_str(&format!(
        "Critical: {} · High: {} · Medium: {} · Low: {} · Info: {}\n\n",
        cuenta(Severity::Critical),
        cuenta(Severity::High),
        cuenta(Severity::Medium),
        cuenta(Severity::Low),
        cuenta(Severity::Info),
    ));

    // Hallazgos ordenados por severidad descendente.
    let mut ordenados: Vec<&Finding> = findings.iter().collect();
    ordenados.sort_by_key(|f| std::cmp::Reverse(f.severity));

    out.push_str("## Hallazgos\n\n");
    for f in ordenados {
        out.push_str(&format!(
            "### [{}] {} (`{}:{}`)\n\n",
            capitalizar(f.severity.as_str()),
            f.title,
            f.location.file,
            f.location.start_line
        ));
        out.push_str(&format!("- **Herramienta:** {}\n", f.tool.as_str()));
        if let Some(owasp) = &f.owasp {
            out.push_str(&format!("- **OWASP:** {owasp}\n"));
        }
        if !f.cwe.is_empty() {
            let cwes: Vec<String> = f.cwe.iter().map(|c| format!("CWE-{c}")).collect();
            out.push_str(&format!("- **CWE:** {}\n", cwes.join(", ")));
        }
        out.push_str(&format!("- **Detalle:** {}\n", f.message));
        if let Some(rem) = &f.remediation {
            out.push_str(&format!("- **Remediación:** {rem}\n"));
        }
        out.push('\n');
    }

    out
}

fn capitalizar(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}
