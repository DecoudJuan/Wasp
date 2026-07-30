//! Fase 3 (TDD): orquestación de escáneres con degradación con gracia.

use std::path::Path;
use wasp::orchestrator::{self, gitleaks, semgrep, trivy};

#[test]
fn escaneo_contabiliza_las_tres_herramientas_sin_fallar() {
    // Independiente del entorno: cada herramienta cae en exactamente una categoría
    // (ejecutada / omitida / con error) y el escaneo nunca entra en pánico.
    let outcome = orchestrator::scan(Path::new("."));
    let total = outcome.ran.len() + outcome.skipped.len() + outcome.errors.len();
    assert_eq!(total, 3, "las 3 herramientas deben quedar contabilizadas");
}

#[test]
fn comando_semgrep_pide_salida_json() {
    let cmd = semgrep::build_command(Path::new("/repo"));
    let prog = cmd.get_program().to_string_lossy().to_string();
    let args: Vec<String> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect();
    assert!(prog.contains("semgrep"));
    assert!(args.iter().any(|a| a == "--json"));
}

#[test]
fn comando_gitleaks_usa_formato_json() {
    let cmd = gitleaks::build_command(Path::new("/repo"), Path::new("/tmp/out.json"));
    let args: Vec<String> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect();
    assert!(args.iter().any(|a| a == "json"));
    assert!(args.iter().any(|a| a.contains("out.json")));
}

#[test]
fn comando_trivy_pide_formato_json() {
    let cmd = trivy::build_command(Path::new("/repo"));
    let args: Vec<String> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().to_string())
        .collect();
    assert!(args.iter().any(|a| a == "json"));
    assert!(args.iter().any(|a| a == "fs"));
}
