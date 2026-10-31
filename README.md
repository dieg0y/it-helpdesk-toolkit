# 🧰 IT Helpdesk Toolkit

Un maletín de soporte técnico para Windows que se arma solo con **un script de PowerShell**.
Remoto, VPN, antivirus, reparación de Windows, diagnóstico de red, inventario y hasta un desinstalador para dejar todo como nuevo. Todo desde un solo menú.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?logo=windows&logoColor=white)
![Licencia](https://img.shields.io/badge/licencia-MIT-green)

> Este repo solo trae el script. Las herramientas se descargan al desplegar, directo de sus fuentes oficiales. No se sube ningún binario.

## 🚀 Cómo usarlo

```powershell
git clone https://github.com/dieg0y/it-helpdesk-toolkit.git
cd it-helpdesk-toolkit
powershell -ExecutionPolicy Bypass -File .\Deploy-IT-Toolkit.ps1
```

Eso crea la carpeta `IT-Helpdesk-Toolkit_v4` con todo adentro. Después abre **`Launcher.bat`** (clic derecho → *Ejecutar como administrador* si vas a reparar cosas).

Necesitas Windows 10/11, PowerShell 5.1+ (ya viene) e internet para el despliegue.

## 🧩 Qué trae

| # | Módulo | Qué es |
|---|---|---|
| 00 | Soporte remoto | RustDesk portable |
| 01 | VPN | WireGuard |
| 02 | Windows Update | WAU Manager |
| 03 | Antivirus | KVRT de Kaspersky (con opción de bajar la versión nueva) |
| 04 | Actualizador de apps | UniGetUI |
| 05 | Solución de problemas | `Fix-Windows` + Sysinternals ordenado |
| 06 | Diagnóstico de red | Prueba IP → gateway → Internet → DNS → HTTPS |
| 07 | Inventario | Informe de hardware/SO + ShowKeyPlus |
| 08 | Desinstalar y reset | Quita todo y deja el PC y el toolkit como nuevos |

## 📖 Manuales integrados

Cada módulo tiene su propio manual, tipo `man`. En el menú escribe **`M` + número**:

- `M03` → manual del antivirus
- `M05` → manual de reparación
- `M` solo → manual general

## 🛠️ Detalles que valen la pena

- **Sysinternals sin desorden:** solo 13 herramientas importantes (64 bits) en la carpeta principal, el resto va a `_Otras`. Incluye consola con alias y una guía con ejemplos.
- **Fix-Windows:** limpieza, DISM + SFC, red, reset de Windows Update. Guarda logs y avisa qué opciones son arriesgadas.
- **Módulo 08:** siempre te muestra lo que va a tocar y pide confirmación antes de borrar.
- **Descargas verificadas:** TLS validado, chequeo de archivo, SHA256 de GitHub cuando existe y firma digital en el resumen.
- **Se puede repetir:** si algo falla, vuelve a correr el script y solo baja lo que falta.

## ⚙️ Parámetros

| Parámetro | Para qué |
|---|---|
| `-OutputPath <ruta>` | Elegir dónde crear el toolkit (ej. un USB) |
| `-SkipDownloads` | Solo generar scripts y manuales, sin descargar |
| `-Force` | Volver a descargar todo (para actualizar) |
| `-Retries <1-10>` | Intentos por descarga (por defecto 3) |

## 🆘 Si algo falla

- **"La ejecución de scripts está deshabilitada"** → usa el comando con `-ExecutionPolicy Bypass` de arriba.
- **Error 403 / rate limit de GitHub** → espera un rato o define `$env:GITHUB_TOKEN = '<tu-token>'`.
- **Una descarga falla** → vuelve a ejecutar el script.
- **El antivirus marca PsExec o RustDesk** → es normal, son herramientas legítimas que los atacantes también usan.
- **KVRT no detecta nada nuevo** → usa `03 → B` para bajar la versión actualizada.

## ⚠️ Ojo

Úsalo solo en equipos tuyos o con permiso de su dueño. Las herramientas de terceros tienen sus propias licencias. Revisa el código y haz copia de seguridad antes de usar las opciones de reparación o desinstalación.

## 📄 Licencia

MIT (solo cubre el código de este repo, no las herramientas que descarga). Ver [`LICENSE`](LICENSE).

## 🤖 Aviso sobre el uso de IA

Este proyecto se desarrolló con ayuda de inteligencia artificial (Claude, de Anthropic), que colaboró en la revisión, mejora y documentación del código. El autor es quien lo dirige, lo prueba y se hace responsable del repositorio. Como con cualquier script, revisa el código antes de ejecutarlo y pruébalo primero en un entorno seguro.

---

Hecho por [@dieg0y](https://github.com/dieg0y). Si te sirvió, deja una ⭐ al repo.
