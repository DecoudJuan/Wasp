//! TDD: cache incremental — lógica pura de rutas, diff y merge.

use std::collections::{BTreeMap, HashSet};
use wasp::cache;
use wasp::model::{Confidence, Finding, Location, Severity, Tool};

fn finding(file: &str) -> Finding {
    Finding {
        tool: Tool::Semgrep,
        rule_id: "r".to_string(),
        title: "t".to_string(),
        severity: Severity::High,
        confidence: Confidence::Medium,
        owasp: None,
        cwe: vec![],
        location: Location {
            file: file.to_string(),
            start_line: 1,
            end_line: 1,
            snippet: None,
        },
        message: String::new(),
        remediation: None,
    }
}

#[test]
fn relativize_normaliza_y_quita_el_prefijo_base() {
    assert_eq!(cache::relativize("root/a/b.rs", "root"), "a/b.rs");
    assert_eq!(cache::relativize("root\\a\\b.rs", "root"), "a/b.rs");
    assert_eq!(cache::relativize("root/a.rs", "root/"), "a.rs");
    // Sin coincidencia de prefijo: solo normaliza separadores.
    assert_eq!(cache::relativize("otro/a.rs", "root"), "otro/a.rs");
}

#[test]
fn diff_files_detecta_cambiados_y_removidos() {
    let mut old = BTreeMap::new();
    old.insert("a".to_string(), "h1".to_string());
    old.insert("b".to_string(), "h2".to_string());
    old.insert("c".to_string(), "h3".to_string());

    let mut new = BTreeMap::new();
    new.insert("a".to_string(), "h1".to_string()); // igual
    new.insert("b".to_string(), "h2-mod".to_string()); // modificado
    new.insert("d".to_string(), "h4".to_string()); // nuevo
                                                   // "c" removido

    let d = cache::diff_files(&old, &new);
    assert_eq!(d.changed, HashSet::from(["b".to_string(), "d".to_string()]));
    assert_eq!(d.removed, HashSet::from(["c".to_string()]));
}

#[test]
fn merge_incremental_conserva_no_cambiados_y_agrega_frescos() {
    let cached = vec![finding("a"), finding("b"), finding("c")];
    let changed = HashSet::from(["b".to_string()]);
    let removed = HashSet::from(["c".to_string()]);
    // Re-escaneo de "b" produce un hallazgo fresco.
    let fresh = vec![finding("b")];

    let merged = cache::merge_incremental(cached, &changed, &removed, fresh);
    let files: HashSet<String> = merged.iter().map(|f| f.location.file.clone()).collect();
    // "a" se conserva (no cambió), "c" se descarta (removido), "b" viene del fresco.
    assert_eq!(files, HashSet::from(["a".to_string(), "b".to_string()]));
    assert_eq!(merged.len(), 2);
}

#[test]
fn cache_se_guarda_y_se_carga() {
    let dir = tempfile::tempdir().unwrap();
    let mut files = BTreeMap::new();
    files.insert("a.rs".to_string(), "hash".to_string());
    let original = cache::ScanCache {
        commit: Some("abc123".to_string()),
        files,
        findings: vec![finding("a.rs")],
    };
    cache::save(dir.path(), &original).unwrap();
    let loaded = cache::load(dir.path()).unwrap();
    assert_eq!(loaded.commit.as_deref(), Some("abc123"));
    assert_eq!(loaded.findings.len(), 1);
    assert_eq!(loaded.files.get("a.rs").map(String::as_str), Some("hash"));
}

#[test]
fn load_sin_cache_devuelve_none() {
    let dir = tempfile::tempdir().unwrap();
    assert!(cache::load(dir.path()).is_none());
}
