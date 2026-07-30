# 🐝 Wasp

**Auditor de seguridad OWASP para cualquier repositorio.**

Wasp escanea una carpeta o repositorio de punta a punta buscando vulnerabilidades
OWASP Top 10, secretos hardcodeados y dependencias vulnerables. Combina dos piezas:

1. **`wasp` (CLI en Rust)** — el *harness* barato y determinista: recorre el repo
   (respetando `.gitignore`), orquesta escáneres OSS probados (**Semgrep**, **Gitleaks**,
   **Trivy/osv**), normaliza y **comprime** los hallazgos en un JSON compacto.
2. **Skill de Claude Code (`wasp`)** — convierte a Claude en un **auditor de
   ciberseguridad senior** que hace *triage* de los hallazgos leyendo solo los
   fragmentos marcados (ahorro de tokens), descarta falsos positivos, mapea a
   OWASP/CWE, asigna severidad y propone remediación.

> **Estado:** en construcción. Ver [ROADMAP.md](ROADMAP.md).

## ¿Por qué?

Pasarle un repo entero a un LLM es caro y ruidoso. Wasp invierte el flujo: las
herramientas deterministas encuentran candidatos, y el LLM solo gasta tokens
**confirmando y explicando** lo de alto valor.

## Instalación

Requiere [Rust](https://rustup.rs/) estable.

```bash
git clone https://github.com/JuanDecoud/Wasp
cd Wasp
cargo build --release
# binario en target/release/wasp
```

### Escáneres externos (opcionales pero recomendados)

Wasp **degrada con gracia**: corre lo que esté instalado y avisa lo que falta
(`wasp doctor`).

| Herramienta | Para qué | Windows nativo |
|-------------|----------|----------------|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | secretos | ✅ binario Go |
| [Trivy](https://github.com/aquasecurity/trivy) | dependencias | ✅ binario Go |
| [Semgrep](https://semgrep.dev/) | código (OWASP) | ⚠️ usar WSL / pipx / Docker |

## Uso (previsto)

```bash
wasp doctor              # reporta qué escáneres hay disponibles
wasp scan <ruta>         # escanea y emite Markdown + SARIF
wasp scan <ruta> --format json   # JSON compacto para el LLM
```

Desde Claude Code, invocá la skill:

```
/wasp <ruta-del-repo-a-auditar>
```

## Desarrollo

Seguimos **TDD estricto (red → green → refactor)**. Los tests no requieren tener
los escáneres instalados: se parsean salidas de ejemplo (`tests/fixtures/`).

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

## Licencia

MIT © 2026 Juan Decoud
