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
| CodeQL o Semgrep | SAST | | Pendiente | |
| Gitleaks / GitHub secret scanning | Secretos | | Pendiente | |
| Dependabot | SCA | | Pendiente | |
| OWASP ZAP Baseline | DAST pasivo | | Fuera del alcance de esta etapa | |

## 3. Hallazgos y gestión
| ID | Categoría | Descripción sin secretos | Riesgo | Archivo/ruta | Cambio propuesto | Estado |
|---|---|---|---|---|---|---|
| F-01 | | | | | | Abierto |

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
