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

Instalación rápida:

```bash
# Windows (winget)
winget install Gitleaks.Gitleaks
winget install AquaSecurity.Trivy

# macOS (brew)
brew install gitleaks trivy semgrep

# Linux / WSL
pipx install semgrep            # o: pip install semgrep
# gitleaks y trivy: binarios desde sus releases de GitHub
```

## Uso (previsto)

```bash
wasp doctor              # reporta qué escáneres hay disponibles
wasp scan <ruta>         # escanea y emite Markdown + SARIF
wasp scan <ruta> --format json   # JSON compacto para el LLM

# Modo CI: falla el build (exit 2) si hay hallazgos en o sobre una severidad
wasp scan <ruta> --fail-on high --format sarif -o wasp.sarif

# Cache incremental: re-escanea solo los archivos cambiados desde la última corrida
wasp scan <ruta> --incremental
```

### Cache incremental

`--incremental` guarda un `.wasp-cache.json` en la raíz escaneada con los hallazgos y
una huella de cada archivo. En la siguiente corrida solo re-escanea los archivos
cambiados (staging temporal) y reusa el resto — en un monorepo grande esto baja de
minutos a segundos (medido: ~142s → ~6s tras cambiar un archivo). Agregá
`.wasp-cache.json` a tu `.gitignore`.

### Modo CI

`--fail-on <critical|high|medium|low|info>` hace que Wasp devuelva **exit code 2**
cuando hay al menos un hallazgo en o por encima de esa severidad (0 si está limpio).
Ideal para bloquear un pipeline. Ejemplo en GitHub Actions:

```yaml
- run: wasp scan . --fail-on high --format sarif -o wasp.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: wasp.sarif }
```

### Probarlo ya

```bash
cargo run -- doctor
cargo run -- scan tests/fixtures/vuln_repo        # mini-repo con vulns intencionales
cargo run -- scan tests/fixtures/vuln_repo --format sarif -o wasp-report.sarif
```

## Uso como skill de Claude Code

La skill vive en `.claude/skills/wasp/`. Dentro de este repo está disponible sin
más. Para usarla en **cualquier otro repo**, copiá la carpeta a tu config global:

```bash
cp -r .claude/skills/wasp ~/.claude/skills/wasp
```

Luego, desde Claude Code:

```
/wasp <ruta-del-repo-a-auditar>
```

Claude compilará/ubicará el binario `wasp`, correrá el escaneo, hará triage de los
hallazgos (confirmado / probable / falso positivo) leyendo solo los fragmentos
marcados, y devolverá un informe con impacto, evidencia y remediación.

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
