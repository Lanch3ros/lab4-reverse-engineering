# Seguridad del proyecto — evidencia del laboratorio

Lab. No. 05 — Seguridad en el ciclo de desarrollo (FDSI).

## 1. Alcance autorizado
- Repositorio: https://github.com/Lanch3ros/lab4-reverse-engineering (público, cuenta personal)
- Rama evaluada y commit (línea base): `main` / `fbabbc23d0b33888a4d43c7292a0b23ec184fcdd`
- Rama del laboratorio: `security/lab-fsi`
- URL de staging propio (si aplica): no aplica por ahora (el proyecto no es una aplicación web).
- Responsable / autorización: Jose Luis Lancheros Ayora, Juan David Gómez Cuellar y Jeyder Nicolay León Lancheros (dueños del repositorio).
- Fuera de alcance: producción, sistemas de terceros, datos reales y pruebas destructivas.

### 1.1 Línea base del proyecto
| Campo | Valor |
|---|---|
| Tecnología | Binarios ELF x86-64 compilados en C (crackmes del docente), script en Python 3, scripts Bash y comandos GDB, documentación en Markdown |
| Archivo de dependencias | No existe (`requirements.txt`, `package.json`, etc.). Las únicas dependencias de terceros son las GitHub Actions del pipeline y la herramienta Semgrep |
| Flujos de autenticación | No hay. Los binarios validan una clave local por argumento (`argv[1]`); no existe login, sesión ni base de datos |
| APIs | No hay APIs propias. El único servicio externo es GitHub (repositorio y Actions) |

### 1.2 Activos
| Activo | Por qué importa |
|---|---|
| Código y documentación del repositorio | Es el entregable del Lab 04; su integridad (que nadie lo altere) es lo más importante |
| Binarios en `bin/` | Material del docente; sus SHA-256 están verificados en `docs/evidence/reverse/baseline.txt` |
| Claves y FLAGs del CTF en la documentación | Se publicaron a propósito como resultado académico; no protegen ningún sistema real |
| Pipeline de GitHub Actions y su `GITHUB_TOKEN` | Ejecuta código de terceros (actions y Semgrep) con permisos sobre el repositorio |

### 1.3 Riesgo principal
El proyecto no expone servicios, por lo que el riesgo principal está en la **cadena de suministro del pipeline (CI)**: las actions de terceros se referencian por etiqueta (`@v4`, `@v3`) y Semgrep se instala sin versión fija. Si una de esas dependencias se viera comprometida, podría alterar el repositorio (**integridad**). Como riesgo secundario, los escáneres de secretos pueden marcar como "secretos" las claves del CTF que están documentadas a propósito (**falsos positivos**).

## 2. Línea base y herramientas
| Herramienta | Tipo | Fecha | Resultado | Enlace a evidencia |
|---|---|---|---|---|
| Semgrep 1.182.0 (`p/owasp-top-ten`, `p/secrets`) | SAST | 2026-10-21 | 11 hallazgos de severidad WARNING, todos de la misma regla (*mutable action tag*); 0 errores; 42 archivos analizados | [Run de Actions](https://github.com/Lanch3ros/lab4-reverse-engineering/actions/runs/39684219094) · [`semgrep.json`](evidence/appsec/semgrep.json) |
| Gitleaks (Action, PR) | Secretos | 2026-10-21 | 0 secretos (2 commits del PR analizados) | [`gitleaks-pr.sarif`](evidence/appsec/gitleaks-pr.sarif) |
| Gitleaks (CLI, historial completo) | Secretos | 2026-10-21 | 0 secretos (13 commits analizados) | [`gitleaks-historial-completo.txt`](evidence/appsec/gitleaks-historial-completo.txt) |
| GitHub secret scanning + push protection | Secretos | 2026-10-21 | Habilitado en el repositorio | Settings → Advanced Security |
| Dependabot | SCA | 2026-10-21 | El repositorio no tiene archivo de dependencias; se revisaron manualmente las dependencias del pipeline (ver 2.3) | Sección 2.3 |
| OWASP ZAP Baseline | DAST pasivo | | Fuera del alcance de esta etapa | |

### 2.1 SAST con Semgrep: análisis de dos resultados

El workflow corre Semgrep en cada Pull Request y publica el artefacto `resultado-semgrep`. Todos los hallazgos son de la regla `yaml.github-actions.security.github-actions-mutable-action-tag`: un paso del workflow usa una action de terceros por **etiqueta** (por ejemplo `@v4`) y no por el **hash del commit** (SHA). Una etiqueta la puede mover el dueño de la action a otro código sin avisar, y ese código correría en nuestro pipeline con acceso al `GITHUB_TOKEN`.

| # | Ubicación | ¿Es real? | Explicación |
|---|---|---|---|
| R1 | `.github/workflows/seguridad-estatica.yml:14` → `actions/checkout@v4` (y las líneas 15, 24, 33 y 37: `setup-python@v5`, `upload-artifact@v4`, `checkout@v4`, `gitleaks-action@v3`) | ✅ **Verdadero positivo** | Este archivo sí se ejecuta en cada PR y push a `main`. Si una etiqueta se moviera a código malicioso, este podría modificar el repositorio o robar el token (**integridad**). Riesgo **bajo-medio**: las actions de `actions/*` son oficiales de GitHub y el workflow solo tiene `permissions: contents: read`, lo que limita el daño. Gitleaks es de un tercero y recibe el `GITHUB_TOKEN`. |
| R2 | `Kit_Integracion_AppSec_GitHub_FSI/.github/workflows/dast-staging.yml:33` (y los 5 hallazgos de `Kit_Integracion_AppSec_GitHub_FSI/.github/workflows/seguridad-estatica.yml`) | ❌ **Falsa alarma para este proyecto** | Son la **copia del kit** que entregó el docente. GitHub solo ejecuta los workflows que están en `.github/workflows/` en la **raíz** del repositorio, así que estos archivos nunca corren. El patrón detectado es correcto, pero no hay riesgo real aquí. Se resuelve excluyendo la carpeta del kit del análisis o sacándola del repositorio. |

**Lo que Semgrep NO encontró, y por qué:**
- Las claves del CTF (por ejemplo `REDTEAM-101` y `FDSI-REVERSE-2026`) aparecen en la documentación, pero ni `p/secrets` ni Gitleaks las marcan. Estas herramientas buscan **formatos de credenciales conocidos** (tokens de GitHub o AWS, llaves privadas, texto con mucha aleatoriedad). Aquí no es un problema, porque esas claves no protegen nada real y se publicaron a propósito, pero muestra un **límite** de las herramientas: un secreto "hecho a mano" puede pasar sin ser detectado.
- Semgrep no analiza los binarios ELF en `bin/`: los ignora porque no son código fuente. El análisis de los binarios se hizo de forma manual en el Lab 04.
- El paso de Semgrep termina con `|| true`, así que el pipeline queda **verde aunque haya hallazgos**. Verde no significa "seguro".

### 2.2 Detección de secretos
- **Gitleaks en el PR:** analizó los 2 commits del Pull Request (por defecto, en un `pull_request` solo revisa los commits nuevos) y no encontró secretos.
- **Gitleaks sobre todo el historial:** para completar la evidencia se ejecutó la CLI oficial (`ghcr.io/gitleaks/gitleaks`) sobre los 13 commits del repositorio, sin secretos encontrados.
- **Licencia:** el repositorio es de una **cuenta personal**, no de una organización, así que Gitleaks no pidió `GITLEAKS_LICENSE`.
- **GitHub secret scanning y push protection** ya están habilitados (los activa GitHub por defecto en repositorios públicos).

### 2.3 SCA: dependencias del proyecto

**Archivo de dependencias:** el proyecto no tiene `requirements.txt`, `package.json` ni similares. El script `scripts/solve_level2.py` solo usa Python estándar. Por eso Dependabot no tiene un manifiesto que revisar. Los únicos componentes de terceros son los del **pipeline**:

| Componente | Versión usada | Última versión (2026-10-21) | Alcance |
|---|---|---|---|
| `actions/checkout` | `v4` | `v7.0.1` | CI (no se distribuye con el proyecto) |
| `actions/setup-python` | `v5` | `v7.0.0` | CI |
| `actions/upload-artifact` | `v4` | `v7.0.2` | CI |
| `gitleaks/gitleaks-action` | `v3` | `v3.0.0` | CI (al día) |
| `semgrep` (pip) | sin versión fija (`--upgrade`); en la ejecución resultó `1.182.0` | — | CI |

**Dependencia seleccionada: `actions/checkout@v4`.**
- **¿Está desactualizada?** Sí: va 3 versiones mayores atrás (`v4` frente a `v7.0.1`). El propio run de Actions muestra la advertencia: *"Node.js 20 is deprecated… actions/checkout@v4… being forced to run on Node.js 24"*.
- **¿Aplica realmente a nuestro código?** Solo al **pipeline**: corre en los servidores de GitHub y no se entrega con el proyecto. Hoy funciona, porque GitHub la fuerza a usar Node 24, pero cuando GitHub retire Node 20 el workflow podría dejar de funcionar (riesgo de **disponibilidad** del control de seguridad). Además está referenciada por etiqueta (hallazgo R1).
- **Medida correctiva propuesta (no aplicada todavía):** actualizar a `v7` **fijada por SHA** (`actions/checkout@<sha> # v7.0.1`), revisando antes las notas de versión, porque los cambios de versión mayor pueden cambiar entradas o comportamiento, y probarla en un PR. Lo mismo con `setup-python` y `upload-artifact`. Para Semgrep, fijar una versión (`semgrep==1.182.0`) y actualizarla de forma controlada. **No se actualiza a ciegas.**
- **Pendiente:** activar **Dependabot alerts** (Settings → Advanced Security). Hoy están desactivadas. Al activarlas, documentar si aparece alguna alerta (lo esperado es que no aparezca ninguna, por falta de manifiestos).

## 3. Hallazgos y gestión
| ID | Categoría | Descripción sin secretos | Riesgo | Archivo/ruta | Cambio propuesto | Estado |
|---|---|---|---|---|---|---|
| F-01 | CWE-829 (componente de origen no confiable) / OWASP A08:2021 | Actions de terceros referenciadas por etiqueta mutable (Semgrep R1) | Bajo-medio (integridad del repositorio) | `.github/workflows/seguridad-estatica.yml` (líneas 14, 15, 24, 33, 37) | Fijar cada action por SHA de commit | Abierto |
| F-02 | OWASP A06:2021 (componentes desactualizados) | `actions/checkout`, `setup-python` y `upload-artifact` 3 versiones mayores atrás; usan Node 20, que está obsoleto | Bajo (disponibilidad del pipeline) | `.github/workflows/seguridad-estatica.yml` | Actualizar a `v7` fijada por SHA, probando en un PR | Abierto |
| — | Falsa alarma | Mismos hallazgos de Semgrep en la copia del kit (Semgrep R2) | No aplica (no se ejecuta) | `Kit_Integracion_AppSec_GitHub_FSI/.github/workflows/` | Excluir del análisis o sacar del repositorio | Descartado |

## 4. Validación antes y después
- Evidencia inicial (captura o artefacto):
- Pull request con corrección:
- Evidencia de reescaneo:
- Riesgo residual y decisión:

## 5. Pentest autorizado
- Hipótesis:
- Entorno de pruebas aislado:
- Solicitudes inocuas y respuestas observadas (sin datos personales):
- Resultado: validado / no reproducible / requiere revisión
- Recomendación y prueba de regresión:
