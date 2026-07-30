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
fn sin_argumentos_muestra_ayuda_y_falla() {
    Command::cargo_bin("wasp")
        .unwrap()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage").or(predicate::str::contains("Uso")));
}
