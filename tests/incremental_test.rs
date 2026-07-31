//! TDD: escaneo con rutas relativas y re-escaneo de subconjunto (staging).

use std::collections::HashSet;
use std::fs;
use wasp::orchestrator;

#[test]
fn scan_devuelve_rutas_relativas_a_la_raiz() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("sub/x.py"), "print(1)\n").unwrap();

    let outcome = orchestrator::scan(dir.path());
    // No afirmamos hallazgos (depende de escáneres); sí que ninguna ruta sea absoluta
    // ni contenga el prefijo del tempdir.
    let base = dir.path().to_string_lossy().replace('\\', "/");
    for f in &outcome.findings {
        let file = f.location.file.replace('\\', "/");
        assert!(!file.starts_with(&*base), "ruta debe ser relativa: {file}");
    }
}

#[test]
fn scan_changed_sin_archivos_no_falla_y_no_escanea() {
    let dir = tempfile::tempdir().unwrap();
    let outcome = orchestrator::scan_changed(dir.path(), &HashSet::new());
    assert!(outcome.findings.is_empty());
    assert!(outcome.ran.is_empty());
}
