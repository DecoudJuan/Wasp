//! Fase 2 (TDD): la CLI expone `doctor` y reporta el estado de los escáneres.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn doctor_lista_los_escaneres() {
    Command::cargo_bin("wasp")
        .unwrap()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("semgrep"))
        .stdout(predicate::str::contains("gitleaks"))
        .stdout(predicate::str::contains("trivy"));
}

#[test]
fn scan_sin_herramientas_produce_reporte_y_avisa() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("wasp")
        .unwrap()
        .arg("scan")
        .arg(dir.path())
        .assert()
        .success()
        // El reporte Markdown se emite por stdout.
        .stdout(predicate::str::contains("Wasp"));
}

#[test]
fn scan_formato_json_emite_array() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("wasp")
        .unwrap()
        .args(["scan", "--format", "json"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("[").and(predicate::str::contains("]")));
}

#[test]
fn scan_fail_on_sin_hallazgos_devuelve_exito() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("wasp")
        .unwrap()
        .args(["scan", "--fail-on", "high", "--format", "json"])
        .arg(dir.path())
        .assert()
        .success()
        .stderr(predicate::str::contains("OK CI"));
}

#[test]
fn sin_argumentos_muestra_ayuda_y_falla() {
    Command::cargo_bin("wasp")
        .unwrap()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage").or(predicate::str::contains("Uso")));
}
