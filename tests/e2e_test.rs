//! Fase 7 (TDD): verificación end-to-end sobre el repo vulnerable de fixture.
//!
//! Se adapta al entorno: si un escáner está instalado, exige que encuentre lo
//! esperado; si no, exige que quede correctamente marcado como omitido. Así el
//! test es determinista con o sin escáneres instalados.

use std::path::PathBuf;
use wasp::detect;
use wasp::model::Tool;
use wasp::orchestrator;

fn vuln_repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vuln_repo")
}

#[test]
fn escaneo_e2e_del_repo_vulnerable() {
    let outcome = orchestrator::scan(&vuln_repo());

    // Invariante: las 3 herramientas contabilizadas, sin pánico.
    let total = outcome.ran.len() + outcome.skipped.len() + outcome.errors.len();
    assert_eq!(total, 3);

    // Si gitleaks corrió, debe detectar el secreto en config/prod.env.
    if outcome.ran.contains(&Tool::Gitleaks) {
        assert!(
            outcome
                .findings
                .iter()
                .any(|f| f.tool == Tool::Gitleaks && f.location.file.contains("prod.env")),
            "gitleaks debería detectar el secreto en config/prod.env"
        );
    } else {
        assert!(outcome.skipped.contains(&Tool::Gitleaks) || !outcome.errors.is_empty());
    }

    // Ningún hallazgo debe filtrar el secreto en claro.
    for f in &outcome.findings {
        assert!(!f.message.contains("wJalrXUtnFEMI"));
    }
}

#[test]
fn detecta_stacks_del_repo_vulnerable() {
    let stacks = detect::detect_stacks(&vuln_repo()).unwrap();
    assert!(stacks.contains(&detect::Stack::Npm)); // package.json
}
