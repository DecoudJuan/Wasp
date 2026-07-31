//! Fase 2 (TDD): recorrido del repo respetando `.gitignore` y detección de stack/herramientas.

use std::fs;
use wasp::detect::{self, Stack};
use wasp::walker;

/// Crea un árbol de archivos temporal y devuelve el `TempDir` (se borra al soltar).
fn repo_de_prueba() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("build")).unwrap();
    fs::write(root.join("src/main.py"), "print('hola')\n").unwrap();
    fs::write(root.join("build/out.o"), "binario").unwrap();
    fs::write(root.join("secret.env"), "TOKEN=abc\n").unwrap();
    fs::write(root.join(".gitignore"), "build/\n*.env\n").unwrap();
    dir
}

#[test]
fn walker_respeta_gitignore() {
    let repo = repo_de_prueba();
    let archivos = walker::walk(repo.path()).unwrap();

    let rutas: Vec<String> = archivos
        .iter()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect();

    assert!(rutas.iter().any(|r| r.ends_with("src/main.py")));
    // Ignorados por .gitignore:
    assert!(!rutas.iter().any(|r| r.ends_with("build/out.o")));
    assert!(!rutas.iter().any(|r| r.ends_with("secret.env")));
    // El propio .gitignore no se reporta como archivo fuente.
    assert!(!rutas.iter().any(|r| r.ends_with(".gitignore")));
}

#[test]
fn walk_all_incluye_ocultos_pero_no_git() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join(".github/workflows")).unwrap();
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::write(root.join(".github/workflows/ci.yml"), "on: push\n").unwrap();
    fs::write(root.join(".git/config"), "[core]\n").unwrap();
    fs::write(root.join("main.rs"), "fn main(){}\n").unwrap();

    let rutas: Vec<String> = walker::walk_all(root)
        .unwrap()
        .iter()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect();

    assert!(rutas
        .iter()
        .any(|r| r.ends_with(".github/workflows/ci.yml")));
    assert!(rutas.iter().any(|r| r.ends_with("main.rs")));
    // Nunca hashear el contenido interno de .git
    assert!(!rutas.iter().any(|r| r.contains("/.git/")));
}

#[test]
fn detecta_stacks_por_manifiestos() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(root.join("package.json"), "{}").unwrap();
    fs::write(root.join("requirements.txt"), "flask\n").unwrap();
    fs::write(root.join("go.mod"), "module x\n").unwrap();

    let stacks = detect::detect_stacks(root).unwrap();
    assert!(stacks.contains(&Stack::Npm));
    assert!(stacks.contains(&Stack::Python));
    assert!(stacks.contains(&Stack::Go));
    assert!(!stacks.contains(&Stack::Php));
}

#[test]
fn tool_available_es_falso_para_binario_inexistente() {
    assert!(!detect::tool_available("wasp-no-existe-xyz-123"));
}

#[test]
fn tool_available_encuentra_binario_en_path_simulado() {
    let dir = tempfile::tempdir().unwrap();
    // Nombre de binario dependiente de plataforma.
    let bin_name = if cfg!(windows) {
        "faketool.exe"
    } else {
        "faketool"
    };
    let bin_path = dir.path().join(bin_name);
    fs::write(&bin_path, "").unwrap();

    let path_os = dir.path().as_os_str().to_os_string();
    assert!(detect::find_in_paths("faketool", Some(&path_os)).is_some());
    assert!(detect::find_in_paths("otro", Some(&path_os)).is_none());
}

#[test]
fn doctor_reporta_las_tres_herramientas() {
    let estado = detect::doctor();
    assert_eq!(estado.len(), 3);
    // No afirmamos disponibilidad (depende del entorno), solo que las cubre todas.
    use wasp::model::Tool;
    let tools: Vec<Tool> = estado.iter().map(|s| s.tool).collect();
    assert!(tools.contains(&Tool::Semgrep));
    assert!(tools.contains(&Tool::Gitleaks));
    assert!(tools.contains(&Tool::Trivy));
}
