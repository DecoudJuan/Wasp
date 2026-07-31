//! Cache incremental: guarda hallazgos + huellas de archivos para re-escanear solo diffs.

use crate::model::Finding;
use crate::walker;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

/// Nombre del archivo de cache en la raíz escaneada.
pub const CACHE_FILE: &str = ".wasp-cache.json";

/// Contenido persistido del cache de un escaneo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCache {
    /// Commit de git en el momento del escaneo (informativo).
    pub commit: Option<String>,
    /// Mapa ruta-relativa → huella de contenido.
    pub files: BTreeMap<String, String>,
    /// Hallazgos del escaneo previo (con rutas relativas a la raíz).
    pub findings: Vec<Finding>,
}

/// Conjunto de rutas cambiadas (nuevas o modificadas) y removidas entre dos árboles.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FileDiff {
    pub changed: HashSet<String>,
    pub removed: HashSet<String>,
}

/// Normaliza `path` a separadores `/` y le quita el prefijo `base` si lo tiene.
pub fn relativize(path: &str, base: &str) -> String {
    let norm = |s: &str| s.replace('\\', "/");
    let path = norm(path);
    let base = norm(base);
    let base = base.trim_end_matches('/');
    if let Some(rest) = path.strip_prefix(base) {
        return rest.trim_start_matches('/').to_string();
    }
    path
}

/// Calcula el diff entre el árbol de huellas viejo y el nuevo.
pub fn diff_files(old: &BTreeMap<String, String>, new: &BTreeMap<String, String>) -> FileDiff {
    let mut changed = HashSet::new();
    for (file, hash) in new {
        if old.get(file) != Some(hash) {
            changed.insert(file.clone());
        }
    }
    let removed = old
        .keys()
        .filter(|f| !new.contains_key(*f))
        .cloned()
        .collect();
    FileDiff { changed, removed }
}

/// Combina hallazgos cacheados (de archivos no cambiados) con los recién escaneados.
pub fn merge_incremental(
    cached: Vec<Finding>,
    changed: &HashSet<String>,
    removed: &HashSet<String>,
    fresh: Vec<Finding>,
) -> Vec<Finding> {
    let conservados = cached.into_iter().filter(|f| {
        let file = &f.location.file;
        !changed.contains(file) && !removed.contains(file)
    });
    let combinados: Vec<Finding> = conservados.chain(fresh).collect();
    crate::dedupe::dedupe(combinados)
}

/// Recorre `root` y devuelve un mapa ruta-relativa → huella de contenido.
pub fn hash_tree(root: &Path) -> Result<BTreeMap<String, String>> {
    let base = root.to_string_lossy();
    let mut tree = BTreeMap::new();
    for path in walker::walk_all(root)? {
        let rel = relativize(&path.to_string_lossy(), &base);
        // El propio archivo de cache no se hashea.
        if rel == CACHE_FILE {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let hash: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
        tree.insert(rel, hash);
    }
    Ok(tree)
}

/// Carga el cache desde `<root>/.wasp-cache.json`, o `None` si no existe/está corrupto.
pub fn load(root: &Path) -> Option<ScanCache> {
    let path = root.join(CACHE_FILE);
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Guarda el cache en `<root>/.wasp-cache.json`.
pub fn save(root: &Path, cache: &ScanCache) -> Result<()> {
    let path = root.join(CACHE_FILE);
    let content = serde_json::to_string(cache).context("serializando cache")?;
    std::fs::write(&path, content).with_context(|| format!("escribiendo {}", path.display()))?;
    Ok(())
}

/// Devuelve el commit HEAD de git en `root`, o `None` si no es un repo git.
pub fn head_commit(root: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if sha.is_empty() {
        None
    } else {
        Some(sha)
    }
}
