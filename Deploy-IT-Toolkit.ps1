#Requires -Version 5.1
<#
.SYNOPSIS
    Deploy-IT-Toolkit.ps1 v5 - Despliegue del IT Helpdesk Toolkit.

.DESCRIPTION
    Crea la estructura de carpetas, genera los scripts de soporte y los manuales,
    descarga las herramientas portables, ordena Sysinternals (solo lo importante en
    la carpeta principal) y registra hashes SHA256.

.PARAMETER OutputPath
    Carpeta destino. Por defecto: <carpeta del script>\IT-Helpdesk-Toolkit_v4

.PARAMETER SkipDownloads
    Solo genera estructura, scripts y manuales, sin descargar nada.

.PARAMETER Force
    Vuelve a descargar aunque el archivo ya exista.

.PARAMETER Retries
    Intentos por descarga (1-10). Por defecto 3.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Deploy-IT-Toolkit.ps1

.NOTES
    Si la API de GitHub devuelve "rate limit", define antes: $env:GITHUB_TOKEN = '<token>'
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$SkipDownloads,
    [switch]$Force,
    [ValidateRange(1, 10)][int]$Retries = 3
)

Set-StrictMode -Version 1.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # acelera mucho Invoke-WebRequest en Windows PowerShell 5.1

# ----------------------------------------------------------------------
# CONFIGURACION
# ----------------------------------------------------------------------
$WireGuardVersion = '0.5.3'
$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'

# Herramientas Sysinternals que quedan en la carpeta principal (el resto va a _Otras).
# Base = nombre sin sufijo; se elige la version 64 bits si existe.
$SysTools = @(
    @{ Base = 'procexp';   Kind = 'GUI' }
    @{ Base = 'Procmon';   Kind = 'GUI' }
    @{ Base = 'Autoruns';  Kind = 'GUI' }
    @{ Base = 'Tcpview';   Kind = 'GUI' }
    @{ Base = 'RAMMap';    Kind = 'GUI' }
    @{ Base = 'PsExec';    Kind = 'CLI' }
    @{ Base = 'PsKill';    Kind = 'CLI' }
    @{ Base = 'PsList';    Kind = 'CLI' }
    @{ Base = 'sigcheck';  Kind = 'CLI' }
    @{ Base = 'handle';    Kind = 'CLI' }
    @{ Base = 'procdump';  Kind = 'CLI' }
    @{ Base = 'psping';    Kind = 'CLI' }
    @{ Base = 'accesschk'; Kind = 'CLI' }
)

# TLS 1.2 siempre; TLS 1.3 solo si el runtime lo soporta. NO se desactiva la validacion de certificados.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor ([Net.SecurityProtocolType]12288) } catch { }

if (-not $OutputPath) {
    $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputPath = Join-Path $baseDir 'IT-Helpdesk-Toolkit_v4'
}
$ToolkitRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath).TrimEnd('\', '/')

$script:Results = New-Object System.Collections.Generic.List[object]

# ----------------------------------------------------------------------
# FUNCIONES AUXILIARES
# ----------------------------------------------------------------------
function Write-Status {
    param([string]$Message, [string]$Level = 'Info')
    $color = switch ($Level) {
        'Ok'    { 'Green' }
        'Warn'  { 'Yellow' }
        'Error' { 'Red' }
        'Step'  { 'Cyan' }
        default { 'Gray' }
    }
    Write-Host $Message -ForegroundColor $color
}

function Write-TextFile {
    # CRLF siempre (los .bat con LF puro fallan en labels/goto). Ascii para .bat, Utf8Bom para .ps1 y manuales.
    param([string]$Path, [string]$Content, [ValidateSet('Ascii', 'Utf8Bom')][string]$Encoding = 'Ascii')
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $normalized = $Content -replace "`r?`n", "`r`n"
    $enc = if ($Encoding -eq 'Ascii') { New-Object System.Text.ASCIIEncoding } else { New-Object System.Text.UTF8Encoding($true) }
    [IO.File]::WriteAllText($Path, $normalized, $enc)
}

function Test-FileSignature {
    param([string]$Path, [string]$Extension)
    $stream = [IO.File]::OpenRead($Path)
    try {
        $b = New-Object byte[] 4
        [void]$stream.Read($b, 0, 4)
    } finally { $stream.Dispose() }
    switch ($Extension.ToLowerInvariant()) {
        '.exe' { return ($b[0] -eq 0x4D -and $b[1] -eq 0x5A) }
        '.zip' { return ($b[0] -eq 0x50 -and $b[1] -eq 0x4B) }
        '.msi' { return ($b[0] -eq 0xD0 -and $b[1] -eq 0xCF -and $b[2] -eq 0x11 -and $b[3] -eq 0xE0) }
        default { return $true }
    }
}

function Get-SignatureSummary {
    param([string]$Path)
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $Path
        $who = ''
        if ($s.SignerCertificate) { $who = $s.SignerCertificate.GetNameInfo('SimpleName', $false) }
        if ($who) { return "$($s.Status): $who" }
        return [string]$s.Status
    } catch { return 'N/D' }
}

function Invoke-Download {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$OutFile,
        [string]$ExpectedSha256,
        [int]$MinBytes = 20480,
        [int]$MaxAttempts = 3
    )
    $dir = Split-Path -Parent $OutFile
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $tmp = "$OutFile.part"
    $ext = [IO.Path]::GetExtension($OutFile)

    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
            Invoke-WebRequest -Uri $Uri -OutFile $tmp -UserAgent $UserAgent -UseBasicParsing -TimeoutSec 900
            $len = (Get-Item -LiteralPath $tmp).Length
            if ($len -lt $MinBytes) { throw "Archivo demasiado pequeno ($len bytes): probablemente una pagina de error." }
            if (-not (Test-FileSignature -Path $tmp -Extension $ext)) { throw "El contenido no es un archivo $ext valido (el servidor devolvio otra cosa)." }
            if ($ExpectedSha256) {
                $actual = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash
                if ($actual -ne $ExpectedSha256) { throw "SHA256 no coincide. Esperado $ExpectedSha256, obtenido $actual." }
            }
            Move-Item -LiteralPath $tmp -Destination $OutFile -Force
            return
        } catch {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
            if ($i -ge $MaxAttempts) { throw }
            Write-Status "    Intento $i/$MaxAttempts fallido: $($_.Exception.Message) Reintentando..." 'Warn'
            Start-Sleep -Seconds (2 * $i)
        }
    }
}

function Get-GitHubAsset {
    param([Parameter(Mandatory)][string]$Repo, [Parameter(Mandatory)][string]$Pattern)
    $headers = @{ 'User-Agent' = 'IT-Toolkit-Deploy'; 'Accept' = 'application/vnd.github+json' }
    if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $($env:GITHUB_TOKEN)" }
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers -TimeoutSec 60
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match '403|rate limit') { $msg += ' (limite de la API de GitHub: define $env:GITHUB_TOKEN o espera un rato)' }
        throw "No se pudo consultar ${Repo}: $msg"
    }
    $asset = @($release.assets | Where-Object { $_.name -like $Pattern }) | Select-Object -First 1
    if (-not $asset) { throw "La release $($release.tag_name) de $Repo no tiene archivos que coincidan con '$Pattern'." }
    $sha = $null
    if ($asset.digest -and ([string]$asset.digest).StartsWith('sha256:')) { $sha = ([string]$asset.digest).Substring(7) }
    [pscustomobject]@{ Url = $asset.browser_download_url; Tag = $release.tag_name; Name = $asset.name; Sha256 = $sha }
}

function Add-Result {
    param([string]$Name, [string]$Status, [string]$Signature = '', [string]$Detail = '')
    $script:Results.Add([pscustomobject]@{ Name = $Name; Status = $Status; Signature = $Signature; Detail = $Detail })
}

function Optimize-Sysinternals {
    # Deja en la carpeta principal SOLO las herramientas importantes (version 64 bits) y mueve el resto a _Otras.
    # Genera la consola con alias y la guia. Es idempotente: se puede ejecutar varias veces.
    param([Parameter(Mandatory)][string]$Dir)
    if (-not (Test-Path -LiteralPath $Dir)) { return 'Carpeta Sysinternals no existe (omitido).' }
    $files = @(Get-ChildItem -LiteralPath $Dir -File -Force | Where-Object { $_.Name -notlike '.*' })
    if (@($files | Where-Object { $_.Extension -eq '.exe' }).Count -eq 0) { return 'Sysinternals no esta descargado (omitido).' }

    $keep = New-Object System.Collections.Generic.List[string]
    $cliMap = New-Object System.Collections.Generic.List[object]
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($t in $SysTools) {
        $rx = '^' + [regex]::Escape($t.Base) + '(64)?\.exe$'
        $cands = @($files | Where-Object { $_.Name -match $rx })
        $pick = $cands | Where-Object { $_.Name -match '64\.exe$' } | Select-Object -First 1
        if (-not $pick) { $pick = $cands | Select-Object -First 1 }
        if ($pick) {
            $keep.Add($pick.Name)
            if ($t.Kind -eq 'CLI') { $cliMap.Add([pscustomobject]@{ Base = $t.Base; File = $pick.Name }) }
        } else { $missing.Add($t.Base) }
    }

    $generated = @('Sysinternals-Consola.bat', 'GUIA_SYSINTERNALS.txt')
    $other = Join-Path $Dir '_Otras'
    if (-not (Test-Path -LiteralPath $other)) { [void](New-Item -ItemType Directory -Path $other -Force) }
    $moved = 0
    foreach ($f in $files) {
        if ($keep -contains $f.Name) { continue }
        if ($generated -contains $f.Name) { continue }
        Move-Item -LiteralPath $f.FullName -Destination (Join-Path $other $f.Name) -Force
        $moved++
    }

    # Consola con alias (psexec -> PsExec64.exe, etc.). Se genera segun lo que realmente quedo.
    $c = New-Object System.Collections.Generic.List[string]
    foreach ($l in @('@echo off', 'title Sysinternals - Consola de herramientas', 'color 0A', 'set "PATH=%~dp0;%PATH%"', 'cd /d "%~dp0"')) { $c.Add($l) }
    foreach ($m in $cliMap) {
        if ($m.File -ne ($m.Base + '.exe')) { $c.Add('doskey ' + $m.Base.ToLowerInvariant() + '=' + $m.File + ' $*') }
    }
    foreach ($l in @(
        'echo.',
        'echo  CONSOLA SYSINTERNALS - esta carpeta ya esta en el PATH.',
        'echo  La primera vez de cada herramienta agrega -accepteula (ej: psexec -accepteula).',
        'echo.',
        'echo   psexec     ejecuta comandos como SYSTEM o en otro equipo',
        'echo   pskill     termina un proceso por nombre o PID',
        'echo   pslist     lista procesos con CPU y memoria',
        'echo   sigcheck   verifica firma digital y hash de archivos',
        'echo   handle     muestra que proceso tiene abierto un archivo',
        'echo   procdump   vuelca la memoria de un proceso',
        'echo   psping     prueba conectividad TCP a un puerto',
        'echo   accesschk  muestra permisos de archivos y carpetas',
        'echo.',
        'echo  Guia con ejemplos: GUIA_SYSINTERNALS.txt',
        'echo.')) { $c.Add($l) }
    Write-TextFile -Path (Join-Path $Dir 'Sysinternals-Consola.bat') -Content ($c -join "`n") -Encoding Ascii
    Write-TextFile -Path (Join-Path $Dir 'GUIA_SYSINTERNALS.txt') -Content $SysGuideContent -Encoding Utf8Bom

    $msg = "$($keep.Count)/$($SysTools.Count) herramientas principales en la carpeta; $moved archivo(s) movidos a _Otras"
    if ($missing.Count -gt 0) { $msg += ". NO encontradas: $($missing -join ', ')" }
    return $msg
}

# ----------------------------------------------------------------------
Write-Status '=======================================================================' 'Step'
Write-Status '   DESPLEGANDO IT HELPDESK TOOLKIT v5                                  ' 'Step'
Write-Status '=======================================================================' 'Step'
Write-Status " Destino: $ToolkitRoot"

# ----------------------------------------------------------------------
# 1. ESTRUCTURA DE CARPETAS
# ----------------------------------------------------------------------
Write-Status "`n[1/4] Creando arbol de carpetas..." 'Warn'
$Folders = @(
    '00_Remote',
    '01_VPN',
    '02_Updates',
    '03_Antivirus',
    '04_App_Updater',
    '05_PC_Troubleshooting/Sysinternals',
    '06_Network_Repair',
    '07_Audit_Inventory/ShowKeyPlus',
    '08_Uninstall_Reset'
)
foreach ($folder in $Folders) {
    $path = Join-Path $ToolkitRoot $folder
    if (-not (Test-Path -LiteralPath $path)) { [void](New-Item -ItemType Directory -Path $path -Force) }
}
# Limpieza de la carpeta de CrystalDiskInfo de versiones anteriores (solo si esta vacia)
$oldCdi = Join-Path $ToolkitRoot '05_PC_Troubleshooting/CrystalDiskInfo'
if ((Test-Path -LiteralPath $oldCdi) -and (@(Get-ChildItem -LiteralPath $oldCdi -Force).Count -eq 0)) { Remove-Item -LiteralPath $oldCdi -Force }
Write-Status ' -> Estructura lista.' 'Ok'

# ----------------------------------------------------------------------
# 2. SCRIPTS DE SOPORTE
# ----------------------------------------------------------------------
Write-Status "`n[2/4] Generando scripts de soporte..." 'Warn'

# ---------- Fix-Windows.bat ----------
$FixWindowsContent = @'
@echo off
setlocal EnableExtensions
title IT Helpdesk Toolkit - Windows Repair and Maintenance
color 0A

rem --- Verificar privilegios de Administrador (fltmc no depende del servicio Server) ---
fltmc >nul 2>&1
if errorlevel 1 goto NOADMIN

rem --- Marca de tiempo independiente del idioma regional ---
for /f %%i in ('PowerShell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set "STAMP=%%i"

rem --- Carpeta de logs (con alternativa si el medio es de solo lectura) ---
set "LOGDIR=%~dp0Logs"
mkdir "%LOGDIR%" >nul 2>&1
if exist "%LOGDIR%\" goto LOGOK
set "LOGDIR=%ProgramData%\IT-Helpdesk-Toolkit\Logs"
mkdir "%LOGDIR%" >nul 2>&1
:LOGOK
set "LOG=%LOGDIR%\Fix-Windows_%STAMP%.log"
call :LOG "Inicio de sesion en %COMPUTERNAME% (usuario %USERNAME%)"
goto MENU

:NOADMIN
echo.
echo [ERROR] Este script requiere privilegios de Administrador.
echo Haz clic derecho y selecciona "Ejecutar como administrador".
echo.
pause
exit /b 1

:MENU
cls
echo =======================================================================
echo         IT HELPDESK TOOLKIT - REPARACION Y DIAGNOSTICO MODULAR
echo =======================================================================
echo.
echo  [1] Mantenimiento y limpieza del SO (seguro en remoto)
echo  [2] Reparacion de archivos de sistema (DISM + SFC)
echo  [3] Reparacion de red basica (seguro en remoto: DNS / ARP)
echo  [4] Reseteo profundo de red TCP/IP (USO LOCAL: corta la red y pide reinicio)
echo  [5] Restablecer componentes de Windows Update (borra historial de updates)
echo  [6] MANTENIMIENTO COMPLETO (1 + 2 + 3 + 5)
echo.
echo  [M] Ver manual de este menu
echo  [9] Salir
echo.
echo  Log: %LOG%
echo =======================================================================
choice /c 123456M9 /n /m "Selecciona una opcion: "
if errorlevel 8 exit /b 0
if errorlevel 7 goto OPTM
if errorlevel 6 goto OPT6
if errorlevel 5 goto OPT5
if errorlevel 4 goto OPT4
if errorlevel 3 goto OPT3
if errorlevel 2 goto OPT2
goto OPT1

:OPTM
start "" notepad.exe "%~dp0MANUAL.txt"
goto MENU

:OPT1
call :MANTENIMIENTO_SO
pause
goto MENU

:OPT2
call :REPARACION_SISTEMA
pause
goto MENU

:OPT3
call :RED_BASICA
pause
goto MENU

:OPT4
echo.
echo ADVERTENCIA: la red se desconectara y el equipo debera reiniciarse.
choice /c SN /n /m "Continuar? (S/N): "
if errorlevel 2 goto MENU
call :RED_PROFUNDA
pause
goto MENU

:OPT5
echo.
echo ADVERTENCIA: no lo ejecutes mientras Windows esta instalando actualizaciones.
choice /c SN /n /m "Continuar? (S/N): "
if errorlevel 2 goto MENU
call :REPARACION_WU
pause
goto MENU

:OPT6
echo.
echo El mantenimiento completo incluye restablecer Windows Update y puede tardar bastante.
choice /c SN /n /m "Continuar? (S/N): "
if errorlevel 2 goto MENU
call :MANTENIMIENTO_SO
call :REPARACION_SISTEMA
call :RED_BASICA
call :REPARACION_WU
echo.
echo =======================================================================
echo  MANTENIMIENTO COMPLETO FINALIZADO. Revisa el log si hubo errores.
echo =======================================================================
pause
goto MENU

rem =======================================================================
rem  RUTINAS
rem =======================================================================

:LOG
>>"%LOG%" echo [%date% %time%] %~1
exit /b 0

:MANTENIMIENTO_SO
echo.
echo === LIMPIEZA Y MANTENIMIENTO DEL SISTEMA ===
call :LOG "Limpieza de temporales"
echo Limpiando temporales del usuario...
del /q /f /s "%TEMP%\*" >nul 2>&1
for /d %%D in ("%TEMP%\*") do rd /s /q "%%D" >nul 2>&1
echo Limpiando temporales del sistema...
del /q /f /s "%SystemRoot%\Temp\*" >nul 2>&1
for /d %%D in ("%SystemRoot%\Temp\*") do rd /s /q "%%D" >nul 2>&1
echo Vaciando la Papelera de reciclaje...
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"
call :LOG "Limpieza finalizada"
echo [OK] Mantenimiento del SO finalizado.
exit /b 0

:REPARACION_SISTEMA
echo.
echo === REPARACION DE ARCHIVOS DE SISTEMA (DISM + SFC) ===
echo [1/3] DISM /RestoreHealth (puede tardar; necesita Windows Update o una fuente de reparacion)...
call :LOG "DISM RestoreHealth"
dism /online /cleanup-image /restorehealth
call :LOG "DISM RestoreHealth exit=%errorlevel%"
echo.
echo [2/3] SFC /scannow...
sfc /scannow
call :LOG "SFC exit=%errorlevel%"
echo.
echo [3/3] Limpieza del almacen de componentes...
dism /online /cleanup-image /startcomponentcleanup
call :LOG "StartComponentCleanup exit=%errorlevel%"
echo [OK] Finalizado. Si SFC reporto problemas, revisa %windir%\Logs\CBS\CBS.log
exit /b 0

:RED_BASICA
echo.
echo === REPARACION DE RED BASICA (SEGURO EN REMOTO) ===
call :LOG "Red basica"
echo Limpiando cache DNS...
ipconfig /flushdns
echo Limpiando tabla ARP y cache NetBIOS...
arp -d * >nul 2>&1
nbtstat -R >nul 2>&1
echo Registrando DNS de nuevo...
ipconfig /registerdns >nul 2>&1
echo [OK] Cache y registros de red restablecidos.
exit /b 0

:RED_PROFUNDA
echo.
echo === RESETEO PROFUNDO DE RED Y STACK TCP/IP (USO LOCAL) ===
call :LOG "Reseteo profundo de red"
echo Reseteando catalogo Winsock...
netsh winsock reset
echo Reseteando pila TCP/IP...
netsh int ip reset "%LOGDIR%\netsh-ip-reset.log"
echo Liberando y renovando concesiones DHCP...
ipconfig /release >nul 2>&1
ipconfig /renew >nul 2>&1
echo.
echo [OK] Pila de red reseteada.
echo [!] REINICIA el equipo para completar el reseteo.
exit /b 0

:REPARACION_WU
echo.
echo === RESTABLECER COMPONENTES DE WINDOWS UPDATE ===
call :LOG "Reset de Windows Update"
echo Deteniendo servicios (wuauserv, bits, cryptsvc)...
net stop wuauserv >nul 2>&1
net stop bits >nul 2>&1
net stop cryptsvc >nul 2>&1
echo Eliminando respaldos anteriores...
for /d %%D in ("%SystemRoot%\SoftwareDistribution.bak_*") do rd /s /q "%%D" >nul 2>&1
for /d %%D in ("%SystemRoot%\System32\catroot2.bak_*") do rd /s /q "%%D" >nul 2>&1
echo Renombrando SoftwareDistribution y catroot2 (Windows los recrea solo)...
if exist "%SystemRoot%\SoftwareDistribution" ren "%SystemRoot%\SoftwareDistribution" "SoftwareDistribution.bak_%STAMP%"
if exist "%SystemRoot%\System32\catroot2" ren "%SystemRoot%\System32\catroot2" "catroot2.bak_%STAMP%"
echo Iniciando servicios...
net start cryptsvc >nul 2>&1
net start bits >nul 2>&1
net start wuauserv >nul 2>&1
call :LOG "Reset de Windows Update finalizado"
echo [OK] Componentes de Windows Update restablecidos. Busca actualizaciones de nuevo.
exit /b 0
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '05_PC_Troubleshooting/Fix-Windows.bat') -Content $FixWindowsContent -Encoding Ascii


# ---------- Get-Inventory.ps1 ----------
$GetInventoryContent = @'
#Requires -Version 5.1
<#
.SYNOPSIS
    Inventario y diagnostico rapido de hardware y sistema operativo.
#>
[CmdletBinding()]
param([string]$OutputDir)

$ErrorActionPreference = 'SilentlyContinue'

if (-not $OutputDir) { $OutputDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path } }
$OutputFile = Join-Path $OutputDir ('Inventory_{0}_{1}.txt' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmm'))

function Format-Block {
    param($Data)
    if ($null -eq $Data -or @($Data).Count -eq 0) { return '(sin datos)' }
    return ($Data | Format-Table -AutoSize | Out-String -Width 200).Trim()
}

# Cada clase CIM se consulta UNA sola vez
$os   = Get-CimInstance Win32_OperatingSystem
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$cpu  = @(Get-CimInstance Win32_Processor)
$ram  = @(Get-CimInstance Win32_PhysicalMemory)
$gpu  = @(Get-CimInstance Win32_VideoController)

$isAdmin  = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$ramTotal = [math]::Round((($ram | Measure-Object -Property Capacity -Sum).Sum) / 1GB, 2)
$uptime   = if ($os.LastBootUpTime) { (Get-Date) - $os.LastBootUpTime } else { $null }
$uptimeTx = if ($uptime) { '{0}d {1}h {2}m' -f $uptime.Days, $uptime.Hours, $uptime.Minutes } else { 'N/D' }
$secureBoot = Confirm-SecureBootUEFI
$secureBootTx = if ($null -eq $secureBoot) { 'No disponible (BIOS heredada o sin permisos)' } else { [string]$secureBoot }
$tpm = Get-Tpm
$tpmTx = if ($tpm) { 'Presente={0} Listo={1}' -f $tpm.TpmPresent, $tpm.TpmReady } else { 'No disponible (requiere Administrador)' }

$network = Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' } | ForEach-Object {
    [pscustomobject]@{
        Adaptador = $_.InterfaceAlias
        IPv4      = ($_.IPv4Address.IPAddress -join ', ')
        Gateway   = ($_.IPv4DefaultGateway.NextHop -join ', ')
        DNS       = ($_.DnsServer.ServerAddresses -join ', ')
        MAC       = $_.NetAdapter.MacAddress
    }
}

$physDisks = Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, @{ N = 'Size(GB)'; E = { [math]::Round($_.Size / 1GB, 1) } }
$volumes = Get-Volume | Where-Object { $_.DriveLetter } | Select-Object DriveLetter, FileSystemLabel, FileSystem,
    @{ N = 'Size(GB)'; E = { [math]::Round($_.Size / 1GB, 1) } },
    @{ N = 'Free(GB)'; E = { [math]::Round($_.SizeRemaining / 1GB, 1) } },
    @{ N = 'Free(%)';  E = { if ($_.Size) { [math]::Round(100 * $_.SizeRemaining / $_.Size, 1) } } }
$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID, Description, InstalledOn

$report = @"
========================================================
   INVENTARIO Y DIAGNOSTICO RAPIDO DE HARDWARE Y SO
   Generado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')   (Administrador: $isAdmin)
========================================================

[SISTEMA]
Nombre de equipo:  $env:COMPUTERNAME
Usuario actual:    $env:USERNAME
Dominio/Workgroup: $($cs.Domain)  (unido a dominio: $($cs.PartOfDomain))
Edicion de OS:     $($os.Caption)
Version / Build:   $($os.Version) (Build $($os.BuildNumber))
Tiempo encendido:  $uptimeTx
Secure Boot:       $secureBootTx
TPM:               $tpmTx

[HARDWARE Y BIOS]
Fabricante:        $($cs.Manufacturer)
Modelo:            $($cs.Model)
Numero de serie:   $($bios.SerialNumber)
Version de BIOS:   $($bios.SMBIOSBIOSVersion)
Procesador:        $((($cpu | ForEach-Object { '{0} ({1} nucleos / {2} hilos)' -f $_.Name.Trim(), $_.NumberOfCores, $_.NumberOfLogicalProcessors }) -join '; '))
RAM total:         $ramTotal GB en $($ram.Count) modulo(s)
Video:             $((($gpu | ForEach-Object { $_.Name }) -join '; '))

[ADAPTADORES DE RED ACTIVOS]
$(Format-Block $network)

[DISCOS FISICOS]
$(Format-Block $physDisks)

[VOLUMENES]
$(Format-Block $volumes)

[ULTIMAS 5 ACTUALIZACIONES INSTALADAS]
$(Format-Block $hotfixes)
========================================================
"@

try {
    $report | Out-File -FilePath $OutputFile -Encoding utf8 -ErrorAction Stop
} catch {
    # Medio de solo lectura: guardar en TEMP
    $OutputFile = Join-Path $env:TEMP (Split-Path -Leaf $OutputFile)
    $report | Out-File -FilePath $OutputFile -Encoding utf8
}

Write-Host $report
Write-Host "[+] Reporte guardado en: $OutputFile" -ForegroundColor Green
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '07_Audit_Inventory/Get-Inventory.ps1') -Content $GetInventoryContent -Encoding Utf8Bom

# ---------- Network-Diagnostics.ps1 ----------
$NetDiagContent = @'
#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnostico de conectividad por capas: IP -> gateway -> Internet -> DNS -> HTTPS.
    Solo lee y prueba; no modifica nada. Para reparar usa Fix-Windows.bat (opciones 3 y 4).
#>
[CmdletBinding()]
param(
    [string]$InternetTarget = '1.1.1.1',
    [string]$DnsTestName = 'www.microsoft.com'
)

$ErrorActionPreference = 'SilentlyContinue'

function Show-Result {
    param([string]$Label, [bool]$Ok, [string]$Detail = '')
    $tag = if ($Ok) { '[  OK  ]' } else { '[FALLA ]' }
    $color = if ($Ok) { 'Green' } else { 'Red' }
    Write-Host ('{0} {1} {2}' -f $tag, $Label, $Detail) -ForegroundColor $color
}

Write-Host "`n== Configuracion IP activa ==" -ForegroundColor Cyan
$configs = @(Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address })
foreach ($c in $configs) {
    Write-Host (' {0}: IP {1} | GW {2} | DNS {3}' -f $c.InterfaceAlias,
        ($c.IPv4Address.IPAddress -join ', '),
        ($c.IPv4DefaultGateway.NextHop -join ', '),
        ($c.DnsServer.ServerAddresses -join ', '))
}
$hasIp = $configs.Count -gt 0
$apipa = $false
foreach ($c in $configs) { if ($c.IPv4Address.IPAddress -like '169.254.*') { $apipa = $true } }
Show-Result 'Adaptador activo con IPv4' $hasIp
if ($apipa) { Show-Result 'Direccion valida (no APIPA 169.254.x.x)' $false '- el DHCP no responde' }

Write-Host "`n== Pruebas por capas ==" -ForegroundColor Cyan
$gateways = @($configs | ForEach-Object { $_.IPv4DefaultGateway.NextHop } | Where-Object { $_ })
$gwOk = $false
foreach ($gw in $gateways) {
    $ok = Test-Connection -ComputerName $gw -Count 2 -Quiet
    Show-Result "Ping al gateway $gw" ([bool]$ok)
    if ($ok) { $gwOk = $true }
}
if ($gateways.Count -eq 0) { Show-Result 'Gateway predeterminado configurado' $false }

$netOk = [bool](Test-Connection -ComputerName $InternetTarget -Count 2 -Quiet)
Show-Result "Ping a Internet por IP ($InternetTarget)" $netOk

$dnsOk = [bool](Resolve-DnsName -Name $DnsTestName -Type A -DnsOnly -QuickTimeout)
Show-Result "Resolucion DNS ($DnsTestName)" $dnsOk

$httpsOk = [bool](Test-NetConnection -ComputerName $DnsTestName -Port 443 -InformationLevel Quiet)
Show-Result "Conexion HTTPS a ${DnsTestName}:443" $httpsOk

Write-Host "`n== Diagnostico ==" -ForegroundColor Cyan
if (-not $hasIp)       { $dx = 'Sin adaptador activo con IPv4: revisa cable, Wi-Fi o que el adaptador este habilitado.' }
elseif ($apipa)        { $dx = 'Direccion APIPA: el equipo no obtiene IP por DHCP. Revisa router/switch o prueba Fix-Windows opcion 4 (uso local).' }
elseif (-not $gwOk)    { $dx = 'El gateway no responde: problema local (cable, Wi-Fi, switch o router).' }
elseif (-not $netOk)   { $dx = 'Gateway OK pero sin salida a Internet por IP: problema del ISP, ruta o firewall.' }
elseif (-not $dnsOk)   { $dx = 'Hay Internet por IP pero el DNS falla: prueba Fix-Windows opcion 3 o cambia el servidor DNS.' }
elseif (-not $httpsOk) { $dx = 'DNS OK pero HTTPS falla: revisa proxy, firewall o inspeccion TLS.' }
else                   { $dx = 'Conectividad correcta en todas las capas.' }
Write-Host " $dx" -ForegroundColor Yellow
Write-Host ''
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '06_Network_Repair/Network-Diagnostics.ps1') -Content $NetDiagContent -Encoding Utf8Bom

# ---------- Verify-Integrity.ps1 ----------
$VerifyContent = @'
#Requires -Version 5.1
<#
.SYNOPSIS
    Verifica los archivos del toolkit contra INTEGRITY.txt (SHA256).
#>
$root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$listFile = Join-Path $root 'INTEGRITY.txt'
if (-not (Test-Path -LiteralPath $listFile)) { Write-Host '[ERROR] No existe INTEGRITY.txt' -ForegroundColor Red; exit 2 }

$ok = 0; $bad = 0; $missing = 0
foreach ($line in (Get-Content -LiteralPath $listFile -Encoding UTF8)) {
    if ($line -match '^\s*#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line -notmatch '^([0-9A-Fa-f]{64})  (.+)$') { continue }
    $expected = $Matches[1]
    $rel = $Matches[2]
    $full = Join-Path $root $rel
    if (-not (Test-Path -LiteralPath $full)) { Write-Host "[FALTA]      $rel" -ForegroundColor Yellow; $missing++; continue }
    $actual = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
    if ($actual -eq $expected) { $ok++ } else { Write-Host "[MODIFICADO] $rel" -ForegroundColor Red; $bad++ }
}
Write-Host ("`nCorrectos: {0} | Modificados: {1} | Faltantes: {2}" -f $ok, $bad, $missing)
if ($bad -gt 0 -or $missing -gt 0) { exit 1 } else { Write-Host 'Integridad OK' -ForegroundColor Green; exit 0 }
'@
Write-TextFile -Path (Join-Path $ToolkitRoot 'Verify-Integrity.ps1') -Content $VerifyContent -Encoding Utf8Bom

# ---------- Uninstall-Toolkit.ps1 (modulo 08) ----------
$UninstallContent = @'
#Requires -Version 5.1
<#
.SYNOPSIS
    Modulo 08 - Desinstalar y dejar como nuevo.
    Cada paso MUESTRA lo que encontro y pide confirmacion antes de borrar nada.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version 1.0

if (-not $PSScriptRoot) { Write-Host '[ERROR] Ejecuta este archivo como script, no pegado en la consola.' -ForegroundColor Red; exit 1 }
$ToolkitRoot = Split-Path -Parent $PSScriptRoot

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '[ERROR] Este modulo requiere Administrador. Abre Launcher.bat con clic derecho > Ejecutar como administrador.' -ForegroundColor Red
    [void](Read-Host 'Enter para salir')
    exit 1
}

# ---------------- utilidades ----------------
function Write-Line { param([string]$Text = '', [string]$Color = 'Gray') Write-Host $Text -ForegroundColor $Color }

function Confirm-Action {
    param([string]$Question)
    $r = Read-Host "$Question (S/N)"
    return ($r -match '^(s|si|y|yes)$')
}

function Format-Size {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} KB' -f ($Bytes / 1KB))
}

function Get-PathSize {
    param([string]$Path)
    try {
        $m = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum
        if ($m.Sum) { return [long]$m.Sum } else { return [long]0 }
    } catch { return [long]0 }
}

function Get-InstalledPrograms {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, QuietUninstallString, PSChildName
}

function Invoke-Uninstall {
    param($App)
    $us = [string]$App.UninstallString
    if ($us -match '(?i)msiexec' -and $App.PSChildName -match '^\{[0-9A-Fa-f\-]{36}\}$') {
        Start-Process -FilePath 'msiexec.exe' -ArgumentList "/x $($App.PSChildName) /passive /norestart" -Wait
    } elseif ($App.QuietUninstallString) {
        Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('"' + $App.QuietUninstallString + '"') -Wait
    } elseif ($us) {
        Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('"' + $us + '"') -Wait
    } else {
        throw 'No hay comando de desinstalacion registrado.'
    }
}

# ---------------- paso 1: programas instalados ----------------
function Step-UninstallPrograms {
    Write-Line "`n[1] PROGRAMAS INSTALADOS POR EL TOOLKIT" Cyan
    Write-Line ' (RustDesk portable, KVRT, UniGetUI portable y Sysinternals no se instalan: no aparecen aqui)'
    $apps = @(Get-InstalledPrograms | Where-Object { $_.DisplayName -match '^(WireGuard|RustDesk|UniGetUI|WingetUI)' })
    if ($apps.Count -eq 0) { Write-Line ' No hay programas del toolkit instalados.' Green; return }
    foreach ($a in $apps) {
        Write-Line (' Encontrado: {0} {1}' -f $a.DisplayName, $a.DisplayVersion) Yellow
        if (-not (Confirm-Action "  Desinstalar $($a.DisplayName)?")) { Write-Line '  Omitido.'; continue }
        try { Invoke-Uninstall $a } catch { Write-Line "  [ERROR] $($_.Exception.Message)" Red; continue }
        $still = @(Get-InstalledPrograms | Where-Object { $_.DisplayName -eq $a.DisplayName })
        if ($still.Count -eq 0) { Write-Line "  [OK] $($a.DisplayName) desinstalado." Green }
        else { Write-Line '  [!] Sigue apareciendo: la desinstalacion pudo cancelarse o requiere reiniciar.' Yellow }
    }
}

# ---------------- paso 2: restos en el PC ----------------
function Get-LeftoverItems {
    $items = New-Object System.Collections.Generic.List[object]
    $specs = @(
        @{ L = 'KVRT: reportes y cuarentena (no podras restaurar lo puesto en cuarentena)'; P = "$env:SystemDrive\KVRT*_Data" }
        @{ L = 'Respaldos de Windows Update creados por Fix-Windows';  P = "$env:SystemRoot\SoftwareDistribution.bak_*" }
        @{ L = 'Respaldos de catroot2 creados por Fix-Windows';        P = "$env:SystemRoot\System32\catroot2.bak_*" }
        @{ L = 'Logs de respaldo de Fix-Windows';                      P = "$env:ProgramData\IT-Helpdesk-Toolkit" }
        @{ L = 'Configuracion de RustDesk (usuario)';                  P = "$env:APPDATA\RustDesk" }
        @{ L = 'Configuracion de RustDesk (equipo)';                   P = "$env:ProgramData\RustDesk" }
        @{ L = 'Configuracion de RustDesk (servicio)';                 P = "$env:SystemRoot\ServiceProfiles\LocalService\AppData\Roaming\RustDesk" }
        @{ L = 'Carpeta de WireGuard (incluye tuneles guardados)';     P = "$env:ProgramFiles\WireGuard" }
        @{ L = 'Datos de UniGetUI';                                    P = "$env:LOCALAPPDATA\UniGetUI" }
        @{ L = 'Datos de UniGetUI (version antigua)';                  P = "$env:USERPROFILE\.wingetui" }
    )
    foreach ($s in $specs) {
        foreach ($m in @(Get-Item -Path $s.P -Force -ErrorAction SilentlyContinue)) {
            $items.Add([pscustomobject]@{ Label = $s.L; Path = $m.FullName; Kind = 'Folder'; Size = (Get-PathSize $m.FullName) })
        }
    }
    if (Test-Path 'HKCU:\Software\Sysinternals') {
        $items.Add([pscustomobject]@{ Label = 'Sysinternals: EULA aceptados y ajustes (usuario actual)'; Path = 'HKCU:\Software\Sysinternals'; Kind = 'Registry'; Size = 0 })
    }
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe'
    $dbg = (Get-ItemProperty -Path $ifeo -Name Debugger -ErrorAction SilentlyContinue).Debugger
    if ($dbg -and $dbg -match 'procexp') {
        $items.Add([pscustomobject]@{ Label = 'Process Explorer esta reemplazando al Administrador de tareas'; Path = $ifeo; Kind = 'IFEO'; Size = 0 })
    }
    return $items
}

function Remove-LeftoverItem {
    param($Item)
    try {
        switch ($Item.Kind) {
            'IFEO' { Remove-ItemProperty -Path $Item.Path -Name Debugger -ErrorAction Stop }
            default { Remove-Item -LiteralPath $Item.Path -Recurse -Force -ErrorAction Stop }
        }
        Write-Line "  [OK] $($Item.Label)" Green
    } catch {
        Write-Line "  [ERROR] $($Item.Label): $($_.Exception.Message)" Red
    }
}

function Step-CleanLeftovers {
    Write-Line "`n[2] RESTOS EN EL PC (configuraciones, caches, respaldos)" Cyan
    $items = @(Get-LeftoverItems)
    if ($items.Count -eq 0) { Write-Line ' No se encontraron restos.' Green; return }
    $i = 0
    foreach ($it in $items) {
        $i++
        $size = if ($it.Kind -eq 'Folder') { Format-Size $it.Size } else { '-' }
        Write-Line (' {0,2}. {1}' -f $i, $it.Label) Yellow
        Write-Line ('     {0}   [{1}]' -f $it.Path, $size)
    }
    $ans = (Read-Host "`n Eliminar [T]odo, [U]no por uno, [N]ada").ToUpper()
    if ($ans -eq 'T') { foreach ($it in $items) { Remove-LeftoverItem $it } }
    elseif ($ans -eq 'U') { foreach ($it in $items) { if (Confirm-Action "  Eliminar: $($it.Label)?") { Remove-LeftoverItem $it } } }
    else { Write-Line ' Omitido.' }
}

# ---------------- paso 3: ajustes de Windows Update (WAU Manager) ----------------
function Step-RevertWindowsUpdate {
    Write-Line "`n[3] AJUSTES DE WINDOWS UPDATE (revertir lo que haya hecho WAU Manager)" Cyan
    $found = $false

    $svc = Get-CimInstance Win32_Service -Filter "Name='wuauserv'" -ErrorAction SilentlyContinue
    if ($svc -and $svc.StartMode -eq 'Disabled') {
        $found = $true
        Write-Line ' El servicio de Windows Update esta DESACTIVADO.' Yellow
        if (Confirm-Action '  Volver a ponerlo en Manual (valor por defecto) e iniciarlo?') {
            try { Set-Service -Name wuauserv -StartupType Manual -ErrorAction Stop; Start-Service -Name wuauserv -ErrorAction Stop; Write-Line '  [OK] Servicio restablecido.' Green }
            catch { Write-Line "  [ERROR] $($_.Exception.Message)" Red }
        }
    }

    $au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $noAuto = (Get-ItemProperty -Path $au -Name NoAutoUpdate -ErrorAction SilentlyContinue).NoAutoUpdate
    if ($null -ne $noAuto) {
        $found = $true
        Write-Line " Hay una directiva local 'NoAutoUpdate' = $noAuto (actualizaciones automaticas configuradas por politica)." Yellow
        Write-Line '  Aviso: en equipos de una empresa/dominio la puede haber puesto tu administrador.'
        if (Confirm-Action '  Quitar la directiva NoAutoUpdate?') {
            try { Remove-ItemProperty -Path $au -Name NoAutoUpdate -ErrorAction Stop; Write-Line '  [OK] Directiva eliminada (se aplica tras gpupdate o reinicio).' Green }
            catch { Write-Line "  [ERROR] $($_.Exception.Message)" Red }
        }
    }

    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        (($_.Actions | ForEach-Object { '{0} {1}' -f $_.Execute, $_.Arguments }) -join ' ') -match 'WAU[ _]?Manager'
    })
    foreach ($t in $tasks) {
        $found = $true
        Write-Line (" Tarea programada de WAU Manager: {0}{1}" -f $t.TaskPath, $t.TaskName) Yellow
        if (Confirm-Action '  Eliminar esta tarea?') {
            try { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop; Write-Line '  [OK] Tarea eliminada.' Green }
            catch { Write-Line "  [ERROR] $($_.Exception.Message)" Red }
        }
    }
    if (-not $found) { Write-Line ' Windows Update esta con su configuracion normal. Nada que revertir.' Green }
}

# ---------------- paso 4: resetear el toolkit ----------------
function Get-ResetItems {
    $r = New-Object System.Collections.Generic.List[object]
    $dirs = @('00_Remote', '01_VPN', '02_Updates', '03_Antivirus', '04_App_Updater',
              '05_PC_Troubleshooting\Sysinternals', '05_PC_Troubleshooting\Logs', '07_Audit_Inventory\ShowKeyPlus')
    foreach ($d in $dirs) {
        $p = Join-Path $ToolkitRoot $d
        if (Test-Path -LiteralPath $p) {
            foreach ($i in @(Get-ChildItem -LiteralPath $p -Force | Where-Object { $_.Name -ne 'MANUAL.txt' })) { $r.Add($i) }
        }
    }
    $inv = Join-Path $ToolkitRoot '07_Audit_Inventory'
    if (Test-Path -LiteralPath $inv) {
        foreach ($i in @(Get-ChildItem -LiteralPath $inv -Filter 'Inventory_*.txt' -Force)) { $r.Add($i) }
    }
    $integ = Join-Path $ToolkitRoot 'INTEGRITY.txt'
    if (Test-Path -LiteralPath $integ) { $r.Add((Get-Item -LiteralPath $integ -Force)) }
    return $r
}

function Step-ResetToolkit {
    Write-Line "`n[4] RESETEAR EL TOOLKIT (borra las herramientas descargadas, informes y logs)" Cyan
    Write-Line ' Se conservan: Launcher, scripts, manuales y la estructura de carpetas.'
    $items = @(Get-ResetItems)
    if ($items.Count -eq 0) { Write-Line ' El toolkit ya esta limpio.' Green; return }
    $total = [long]0
    foreach ($i in $items) {
        $sz = if ($i.PSIsContainer) { Get-PathSize $i.FullName } else { [long]$i.Length }
        $total += $sz
        Write-Line ('   {0}   [{1}]' -f $i.FullName.Substring($ToolkitRoot.Length).TrimStart('\'), (Format-Size $sz))
    }
    Write-Line (" Total a borrar: {0} en {1} elemento(s)." -f (Format-Size $total), $items.Count) Yellow
    if (-not (Confirm-Action ' Borrar todo lo listado?')) { Write-Line ' Omitido.'; return }
    foreach ($i in $items) {
        try { Remove-Item -LiteralPath $i.FullName -Recurse -Force -ErrorAction Stop }
        catch { Write-Line "  [ERROR] $($i.FullName): $($_.Exception.Message)" Red }
    }
    Write-Line ' [OK] Toolkit reseteado. Para volver a descargar todo ejecuta Deploy-IT-Toolkit.ps1.' Green
}

# ---------------- paso 5: eliminar el toolkit completo ----------------
function Step-DeleteToolkit {
    Write-Line "`n[5] ELIMINAR EL TOOLKIT COMPLETO" Red
    Write-Line " Se borrara la carpeta entera: $ToolkitRoot"
    if (-not ((Test-Path -LiteralPath (Join-Path $ToolkitRoot 'Launcher.bat')) -and (Test-Path -LiteralPath (Join-Path $ToolkitRoot '08_Uninstall_Reset')))) {
        Write-Line ' [ERROR] La carpeta no parece un toolkit valido. Cancelado por seguridad.' Red
        return
    }
    $ans = Read-Host ' Escribe ELIMINAR en mayusculas para confirmar'
    if ($ans -cne 'ELIMINAR') { Write-Line ' Cancelado.'; return }
    Set-Location -Path $env:SystemRoot
    $cmd = 'ping 127.0.0.1 -n 6 >nul & rd /s /q "{0}" & ping 127.0.0.1 -n 3 >nul & rd /s /q "{0}"' -f $ToolkitRoot
    Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $cmd -WindowStyle Hidden
    Write-Line ' El toolkit se borrara en unos segundos. Cerrando...' Yellow
    Start-Sleep -Seconds 2
    exit 10
}

# ---------------- menu ----------------
while ($true) {
    Clear-Host
    Write-Line '=======================================================================' Cyan
    Write-Line '   08 - DESINSTALAR Y DEJAR COMO NUEVO' Cyan
    Write-Line '=======================================================================' Cyan
    Write-Line ''
    Write-Line ' [1] Desinstalar programas instalados por el toolkit (WireGuard, RustDesk...)'
    Write-Line ' [2] Limpiar restos en el PC (configuraciones, KVRT, respaldos, EULA Sysinternals)'
    Write-Line ' [3] Revertir ajustes de Windows Update (por si usaste WAU Manager)'
    Write-Line ' [4] Resetear el toolkit (borra herramientas descargadas, informes y logs)'
    Write-Line ' [5] Eliminar el toolkit COMPLETO (la carpeta entera)'
    Write-Line ' [6] TODO: pasos 1 + 2 + 3 + 4 (dejar el PC y el toolkit como nuevos)'
    Write-Line ''
    Write-Line ' [M] Ver manual     [X] Salir'
    Write-Line ' Cada paso muestra lo que encontro y pide confirmacion antes de borrar.'
    Write-Line ''
    $opt = (Read-Host ' Opcion').Trim().ToUpper()
    $skipPause = $false
    switch ($opt) {
        '1' { Step-UninstallPrograms }
        '2' { Step-CleanLeftovers }
        '3' { Step-RevertWindowsUpdate }
        '4' { Step-ResetToolkit }
        '5' { Step-DeleteToolkit }
        '6' { Step-UninstallPrograms; Step-CleanLeftovers; Step-RevertWindowsUpdate; Step-ResetToolkit }
        'M' { Start-Process -FilePath 'notepad.exe' -ArgumentList ('"' + (Join-Path $PSScriptRoot 'MANUAL.txt') + '"'); $skipPause = $true }
        'X' { exit 0 }
        default { $skipPause = $true }
    }
    if ($skipPause) { continue }
    Write-Line ''
    [void](Read-Host ' Enter para volver al menu')
}
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '08_Uninstall_Reset/Uninstall-Toolkit.ps1') -Content $UninstallContent -Encoding Utf8Bom

# ---------- Launcher.bat ----------
$LauncherContent = @'
@echo off
setlocal EnableExtensions
title IT HELPDESK TOOLKIT v5 - MASTER LAUNCHER
color 0B
set "ROOT=%~dp0"

fltmc >nul 2>&1
if errorlevel 1 (set "ADMIN=NO") else (set "ADMIN=SI")

:MAIN
cls
echo =======================================================================
echo                 IT HELPDESK TOOLKIT v5 - PRO EDITION
echo                 Administrador: %ADMIN%
echo =======================================================================
echo.
echo  [00] Soporte remoto (RustDesk)
echo  [01] VPN (instalador de WireGuard)
echo  [02] Windows Update (WAU Manager)
echo  [03] Antivirus bajo demanda (KVRT)
echo  [04] Actualizador de aplicaciones (UniGetUI)
echo  [05] Solucion de problemas del PC (Fix-Windows y Sysinternals)
echo  [06] Diagnostico de red
echo  [07] Auditoria e inventario
echo  [08] Desinstalar y dejar como nuevo
echo.
echo  [99] SALIR
echo =======================================================================
echo  MANUAL: escribe M + numero del modulo (ej: M03, M05). Solo M = manual general.
echo =======================================================================
set "choice="
set /p "choice=Selecciona un modulo: "
if not defined choice goto MAIN
if /i "%choice:~0,1%"=="M" goto MANUAL
if "%choice:~1,1%"=="" set "choice=0%choice%"
if "%choice%"=="00" goto M00
if "%choice%"=="01" goto M01
if "%choice%"=="02" goto M02
if "%choice%"=="03" goto M03
if "%choice%"=="04" goto M04
if "%choice%"=="05" goto M05
if "%choice%"=="06" goto M06
if "%choice%"=="07" goto M07
if "%choice%"=="08" goto M08
if "%choice%"=="99" exit /b 0
goto MAIN

:MANUAL
set "mn=%choice:~1%"
if not defined mn goto MAN_GENERAL
if "%mn:~1,1%"=="" set "mn=0%mn%"
set "MD="
if "%mn%"=="00" set "MD=00_Remote"
if "%mn%"=="01" set "MD=01_VPN"
if "%mn%"=="02" set "MD=02_Updates"
if "%mn%"=="03" set "MD=03_Antivirus"
if "%mn%"=="04" set "MD=04_App_Updater"
if "%mn%"=="05" set "MD=05_PC_Troubleshooting"
if "%mn%"=="06" set "MD=06_Network_Repair"
if "%mn%"=="07" set "MD=07_Audit_Inventory"
if "%mn%"=="08" set "MD=08_Uninstall_Reset"
if not defined MD goto MAIN
call :RUN_MAN "%ROOT%%MD%\MANUAL.txt"
goto MAIN

:MAN_GENERAL
call :RUN_MAN "%ROOT%MANUAL.txt"
goto MAIN

:M00
call :RUN "%ROOT%00_Remote\RustDesk_Portable.exe"
goto MAIN

:M01
call :RUN "%ROOT%01_VPN\WireGuard_Setup.msi"
goto MAIN

:M02
call :RUN "%ROOT%02_Updates\WAU_Manager.exe"
goto MAIN

:M03
cls
echo  KVRT - Kaspersky Virus Removal Tool
echo.
echo  [A] Ejecutar el KVRT incluido
echo  [B] Descargar un KVRT actualizado y ejecutarlo (recomendado: las firmas caducan)
echo  [X] Volver
choice /c ABX /n /m "Opcion: "
if errorlevel 3 goto MAIN
if errorlevel 2 goto M03_UPDATE
call :RUN "%ROOT%03_Antivirus\KVRT.exe"
goto MAIN

:M03_UPDATE
echo Descargando KVRT actualizado...
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -Uri 'https://devbuilds.s.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe' -OutFile '%ROOT%03_Antivirus\KVRT.exe.new' -ErrorAction Stop; Move-Item -Force '%ROOT%03_Antivirus\KVRT.exe.new' '%ROOT%03_Antivirus\KVRT.exe'; exit 0 } catch { Write-Host $_; exit 1 }"
if errorlevel 1 goto M03_FAIL
call :RUN "%ROOT%03_Antivirus\KVRT.exe"
goto MAIN

:M03_FAIL
echo.
echo [ERROR] No se pudo descargar. Se usara la version incluida.
pause
call :RUN "%ROOT%03_Antivirus\KVRT.exe"
goto MAIN

:M04
call :RUN_FIND "%ROOT%04_App_Updater" "UniGetUI.exe"
goto MAIN

:M05
cls
echo  05 - SOLUCION DE PROBLEMAS DEL PC
echo.
echo  [A] Fix-Windows - reparacion y mantenimiento de Windows (pide Administrador)
echo  [B] Sysinternals - herramientas de diagnostico avanzado
echo  [X] Volver
choice /c ABX /n /m "Opcion: "
if errorlevel 3 goto MAIN
if errorlevel 2 goto M05B
if "%ADMIN%"=="SI" goto M05A_RUN
PowerShell -NoProfile -Command "Start-Process -FilePath '%ROOT%05_PC_Troubleshooting\Fix-Windows.bat' -Verb RunAs"
goto MAIN

:M05A_RUN
call "%ROOT%05_PC_Troubleshooting\Fix-Windows.bat"
color 0B
goto MAIN

:M05B
cls
echo =======================================================================
echo   SYSINTERNALS - HERRAMIENTAS PRINCIPALES   (guia completa: opcion G)
echo =======================================================================
echo.
echo  GRAFICAS (abren su propia ventana)
echo   [1] Process Explorer - administrador de tareas avanzado: quien gasta CPU, RAM o usa un archivo
echo   [2] Process Monitor  - graba en vivo la actividad de archivos, registro y procesos
echo   [3] Autoruns         - todo lo que arranca con Windows: programas, servicios, tareas
echo   [4] TCPView          - conexiones de red abiertas y que programa las usa
echo   [5] RAMMap           - como usa el sistema la memoria RAM
echo.
echo  LINEA DE COMANDOS
echo   [C] Consola Sysinternals - psexec, pskill, pslist, sigcheck, handle, procdump, psping, accesschk
echo.
echo   [F] Abrir carpeta     [G] Guia completa     [X] Volver
echo.
choice /c 12345CFGX /n /m "Opcion: "
if errorlevel 9 goto M05
if errorlevel 8 goto SYS_G
if errorlevel 7 goto SYS_F
if errorlevel 6 goto SYS_C
if errorlevel 5 goto SYS_5
if errorlevel 4 goto SYS_4
if errorlevel 3 goto SYS_3
if errorlevel 2 goto SYS_2
call :RUN_SYS procexp
goto M05B

:SYS_2
call :RUN_SYS Procmon
goto M05B

:SYS_3
call :RUN_SYS Autoruns
goto M05B

:SYS_4
call :RUN_SYS Tcpview
goto M05B

:SYS_5
call :RUN_SYS RAMMap
goto M05B

:SYS_C
if not exist "%ROOT%05_PC_Troubleshooting\Sysinternals\Sysinternals-Consola.bat" goto SYS_MISSING
start "Sysinternals - Consola" cmd /k call "%ROOT%05_PC_Troubleshooting\Sysinternals\Sysinternals-Consola.bat"
goto M05B

:SYS_F
start "" "%ROOT%05_PC_Troubleshooting\Sysinternals"
goto M05B

:SYS_G
call :RUN_MAN "%ROOT%05_PC_Troubleshooting\Sysinternals\GUIA_SYSINTERNALS.txt"
goto M05B

:SYS_MISSING
echo.
echo [!] Falta la consola de Sysinternals. Ejecuta Deploy-IT-Toolkit.ps1 de nuevo.
pause
goto M05B

:M06
PowerShell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%06_Network_Repair\Network-Diagnostics.ps1"
pause
goto MAIN

:M07
cls
echo  07 - AUDITORIA E INVENTARIO
echo.
echo  [A] Generar inventario de hardware y SO
echo  [B] ShowKeyPlus (claves de Windows)
echo  [C] Abrir carpeta
echo  [X] Volver
choice /c ABCX /n /m "Opcion: "
if errorlevel 4 goto MAIN
if errorlevel 3 goto M07C
if errorlevel 2 goto M07B
PowerShell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%07_Audit_Inventory\Get-Inventory.ps1"
pause
goto MAIN

:M07B
call :RUN_FIND "%ROOT%07_Audit_Inventory\ShowKeyPlus" "ShowKeyPlus.exe"
goto MAIN

:M07C
start "" "%ROOT%07_Audit_Inventory"
goto MAIN

:M08
if "%ADMIN%"=="SI" goto M08_RUN
echo.
echo [!] El modulo 08 modifica el sistema y requiere Administrador.
echo     Cierra esta ventana y abre Launcher.bat con clic derecho - Ejecutar como administrador.
pause
goto MAIN

:M08_RUN
PowerShell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%08_Uninstall_Reset\Uninstall-Toolkit.ps1"
if errorlevel 10 exit
goto MAIN

rem =======================================================================
rem  RUTINAS
rem =======================================================================

:RUN
if not exist "%~1" goto RUN_MISSING
start "" "%~1"
exit /b 0
:RUN_MISSING
echo.
echo [!] No encontrado: %~1
echo     Ejecuta Deploy-IT-Toolkit.ps1 de nuevo para descargarlo.
pause
exit /b 1

:RUN_MAN
if not exist "%~1" goto RUN_MAN_MISSING
start "" notepad.exe "%~1"
exit /b 0
:RUN_MAN_MISSING
echo.
echo [!] Manual no encontrado: %~1
echo     Ejecuta Deploy-IT-Toolkit.ps1 de nuevo para generarlo.
pause
exit /b 1

:RUN_SYS
set "SYSDIR=%ROOT%05_PC_Troubleshooting\Sysinternals"
set "T=%~1"
if exist "%SYSDIR%\%T%64.exe" goto RUN_SYS_64
if exist "%SYSDIR%\%T%.exe" goto RUN_SYS_32
echo.
echo [!] No se encontro %T% en la carpeta de Sysinternals.
echo     Ejecuta Deploy-IT-Toolkit.ps1 de nuevo.
pause
exit /b 1
:RUN_SYS_64
start "" "%SYSDIR%\%T%64.exe"
exit /b 0
:RUN_SYS_32
start "" "%SYSDIR%\%T%.exe"
exit /b 0

:RUN_FIND
set "FOUND="
for /f "delims=" %%F in ('dir /s /b "%~1\%~2" 2^>nul') do if not defined FOUND set "FOUND=%%F"
if not defined FOUND goto RUN_FIND_MISSING
start "" "%FOUND%"
exit /b 0
:RUN_FIND_MISSING
echo.
echo [!] No se encontro %~2 dentro de %~1
echo     Ejecuta Deploy-IT-Toolkit.ps1 de nuevo para descargarlo.
pause
exit /b 1
'@
Write-TextFile -Path (Join-Path $ToolkitRoot 'Launcher.bat') -Content $LauncherContent -Encoding Ascii

Write-Status ' -> Launcher, Fix-Windows, inventario, diagnostico de red, verificador y modulo 08 listos.' 'Ok'

# ----------------------------------------------------------------------
# MANUALES (uno por modulo + manual general + guia de Sysinternals)
# En el Launcher: M + numero (ej: M03). Solo M = manual general.
# ----------------------------------------------------------------------
Write-Status ' -> Generando manuales...' 'Warn'

$ManualGeneral = @'
================================================================
 IT HELPDESK TOOLKIT v5 - MANUAL GENERAL
================================================================

QUÉ ES
Un maletín portátil de herramientas para soporte técnico (helpdesk).
Reúne en una sola carpeta: acceso remoto, VPN, antivirus bajo demanda,
reparación de Windows, diagnóstico de red, inventario y desinstalación.
Todo se maneja desde Launcher.bat.

CÓMO EMPEZAR
 1. Abre Launcher.bat. Para reparar Windows o usar el módulo 08,
    hazlo con clic derecho > "Ejecutar como administrador".
 2. Escribe el número del módulo y pulsa Enter.
 3. MANUAL (como el comando "man"): escribe M + número del módulo.
      M03  -> manual del antivirus        M05  -> manual de reparación
      M    -> este manual general
    Además, cada carpeta tiene su propio MANUAL.txt.

MÓDULOS
 00 Soporte remoto ......... RustDesk: ver/controlar un equipo a distancia
 01 VPN .................... WireGuard: túnel seguro hacia otra red
 02 Windows Update ......... WAU Manager: control de actualizaciones
 03 Antivirus .............. KVRT: escáner de Kaspersky bajo demanda
 04 Actualizador de apps ... UniGetUI: actualiza programas desde un solo sitio
 05 Solución de problemas .. Fix-Windows (reparación) y Sysinternals (diagnóstico)
 06 Diagnóstico de red ..... prueba la conexión capa por capa
 07 Auditoría e inventario . informe de hardware/SO y claves de Windows
 08 Desinstalar y reset .... deja el PC y el toolkit "como nuevos"

CONCEPTOS BÁSICOS
 Portable ........ se ejecuta sin instalarse (RustDesk, KVRT, Sysinternals...).
 Instalador ...... instala en el equipo (WireGuard). Se quita con el módulo 08.
 Administrador .. permisos elevados; necesarios para reparar el sistema.

ARCHIVOS DE LA CARPETA PRINCIPAL
 Launcher.bat ............ menú principal
 Verify-Integrity.ps1 .... comprueba que ningún archivo cambió desde el despliegue
 INTEGRITY.txt ........... huellas SHA256 de los ejecutables y scripts

ACTUALIZAR O REPARAR EL TOOLKIT
 Ejecuta de nuevo Deploy-IT-Toolkit.ps1 (el script que lo creó, fuera de esta
 carpeta). Solo descarga lo que falta. Con -Force vuelve a descargar todo.

AVISOS DE WINDOWS Y ANTIVIRUS
 - SmartScreen puede avisar al abrir un .exe nuevo: "Más información" >
   "Ejecutar de todas formas", solo si confías en el origen.
 - Algunos antivirus marcan herramientas legítimas (PsExec, RustDesk) como
   "riesgo", porque los atacantes también las usan. Es normal.

USO RESPONSABLE
 Usa estas herramientas solo en equipos propios o con autorización expresa.
'@
Write-TextFile -Path (Join-Path $ToolkitRoot 'MANUAL.txt') -Content $ManualGeneral -Encoding Utf8Bom

$Manual00 = @'
================================================================
 MANUAL - 00 SOPORTE REMOTO (RustDesk)
================================================================

QUÉ ES
RustDesk es un programa de escritorio remoto de código abierto, parecido a
TeamViewer o AnyDesk. Aquí viene en versión portable (RustDesk_Portable.exe).

PARA QUÉ SIRVE
Ver y controlar el equipo de otra persona (o dejar que te ayuden con el tuyo)
sin estar físicamente delante: ayudar a un usuario, administrar un servidor.

CÓMO SE USA
 1. Ejecuta RustDesk_Portable.exe en AMBOS equipos.
 2. El equipo que será controlado te da su ID y su contraseña (se ven en la
    ventana principal).
 3. En tu equipo escribe ese ID en "Control remoto" y pulsa Conectar.
 4. La otra persona acepta la conexión (si no usa contraseña permanente).
 5. Al terminar, cierra la sesión y el programa.

CUÁNDO USARLO
 Soporte a usuarios, tareas de administración, ayuda a familiares.

PRECAUCIONES
 - Nunca compartas tu ID y contraseña con desconocidos: es la estafa más
   común de "falso soporte técnico".
 - Por defecto usa los servidores públicos de RustDesk. Una empresa puede
   configurar su propio servidor en Ajustes > Red.
 - Si pulsas "Instalar" dentro de RustDesk, se instala en el equipo.
   Para quitarlo usa el módulo 08.
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '00_Remote/MANUAL.txt') -Content $Manual00 -Encoding Utf8Bom

$Manual01 = @'
================================================================
 MANUAL - 01 VPN (WireGuard)
================================================================

QUÉ ES
WireGuard es un cliente VPN moderno, rápido y ligero. Una VPN crea un túnel
cifrado entre tu equipo y otra red (la de la empresa o la de tu casa).

PARA QUÉ SIRVE
 - Trabajar desde fuera con acceso seguro a recursos internos.
 - Proteger el tráfico en redes Wi-Fi públicas (si tienes un servidor VPN).

CÓMO SE USA
 1. Opción 01 del Launcher: abre WireGuard_Setup.msi (instalador; pide
    permisos de administrador).
 2. Abre WireGuard desde el menú Inicio.
 3. "Importar túnel(es) desde archivo" y elige el archivo .conf que te dio
    el administrador del servidor VPN.
 4. Pulsa "Activar". El estado cambia a "Activo".

IMPORTANTE
 - WireGuard NO es portable: se instala en el equipo.
 - Sin un archivo .conf de un servidor WireGuard no hay nada a lo que conectar.
 - El archivo .conf contiene claves privadas: no lo compartas ni lo subas
   a servicios públicos.

DESINSTALAR
 Módulo 08 > opción 1, o Configuración de Windows > Aplicaciones.
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '01_VPN/MANUAL.txt') -Content $Manual01 -Encoding Utf8Bom

$Manual02 = @'
================================================================
 MANUAL - 02 WINDOWS UPDATE (WAU Manager)
================================================================

QUÉ ES
WAU Manager es una herramienta de terceros que reemplaza la pantalla de
Windows Update y da más control sobre cuándo y qué se instala.

PARA QUÉ SIRVE
 - Buscar, instalar y ocultar actualizaciones concretas.
 - Ver el historial y desinstalar actualizaciones problemáticas.
 - Elegir el modo de actualización (automático, solo avisar, manual).

CÓMO SE USA
 Opción 02 del Launcher. Usa las pestañas del programa para ver las
 actualizaciones pendientes o el historial.

PRECAUCIONES
 - WAU Manager puede DESACTIVAR el servicio de Windows Update. Un equipo
   sin parches de seguridad es un riesgo. No lo uses en equipos que no
   administras ni dejes el servicio desactivado indefinidamente.
 - Si lo desactivaste, puedes volver al estado normal con el módulo 08,
   opción 3 (revierte servicio, directiva y tareas programadas de WAU Manager).
 - Si creó un acceso directo en el escritorio, bórralo a mano.

ALTERNATIVAS INCLUIDAS
 Fix-Windows opción 5 (módulo 05) restablece los componentes de Windows
 Update cuando las actualizaciones fallan o se quedan atascadas.
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '02_Updates/MANUAL.txt') -Content $Manual02 -Encoding Utf8Bom

$Manual03 = @'
================================================================
 MANUAL - 03 ANTIVIRUS BAJO DEMANDA (KVRT)
================================================================

QUÉ ES
Kaspersky Virus Removal Tool es un escáner antivirus gratuito que se ejecuta
solo cuando tú lo abres. No protege en tiempo real.

PARA QUÉ SIRVE
 - Segunda opinión cuando sospechas de un virus y tu antivirus no ve nada.
 - Limpiar equipos infectados (adware, troyanos, rootkits).

CÓMO SE USA
 1. Opción 03 del Launcher.
 2. Elige [B] "Descargar KVRT actualizado": las firmas de virus vienen
    incrustadas en el ejecutable y caducan en pocos días. [A] usa el que
    ya está en la carpeta, que puede estar desactualizado.
 3. Acepta los términos, pulsa "Change parameters" si quieres elegir qué
    escanear (memoria, arranque, sistema) y luego "Start scan".
 4. Revisa los resultados ANTES de elegir una acción para cada elemento.

PRECAUCIONES
 - NO reemplaza a un antivirus instalado. Es un complemento.
 - Puede dar falsos positivos: ante un archivo importante, elige
   "Omitir" y verifícalo antes de eliminar.
 - Deja informes y cuarentena en C:\KVRT_Data. El módulo 08 > opción 2
   puede limpiarlos (perderás lo puesto en cuarentena).
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '03_Antivirus/MANUAL.txt') -Content $Manual03 -Encoding Utf8Bom

$Manual04 = @'
================================================================
 MANUAL - 04 ACTUALIZADOR DE APLICACIONES (UniGetUI)
================================================================

QUÉ ES
UniGetUI es una interfaz gráfica para los gestores de paquetes de Windows
(WinGet, Scoop, Chocolatey...). Muestra todos tus programas y sus
actualizaciones en una sola pantalla.

PARA QUÉ SIRVE
 - Ver qué programas están desactualizados y actualizarlos con un clic.
 - Instalar programas nuevos desde catálogos conocidos.
 - Desinstalar programas desde un único lugar.

CÓMO SE USA
 1. Opción 04 del Launcher (busca y abre UniGetUI.exe).
 2. Pestaña "Actualizaciones de software": marca las que quieras y
    pulsa actualizar (o "Actualizar todo").
 3. "Descubrir paquetes" sirve para buscar e instalar programas.

PRECAUCIONES
 - Para que funcione bien necesita WinGet (App Installer) en Windows.
 - Actualizar todo de golpe puede romper programas delicados: en equipos
   de producción actualiza por partes.
 - Es la versión portable (zip extraído): no se instala.
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '04_App_Updater/MANUAL.txt') -Content $Manual04 -Encoding Utf8Bom

$Manual05 = @'
================================================================
 MANUAL - 05 SOLUCIÓN DE PROBLEMAS DEL PC
================================================================
Contiene dos partes:  A) Fix-Windows.bat   B) Sysinternals

----------------------------------------------------------------
 A) FIX-WINDOWS.BAT  -  menú de reparación de Windows
----------------------------------------------------------------
Requiere Administrador. Cada sesión guarda un log en la carpeta Logs.
Pulsa M dentro del menú para abrir este manual.

[1] Mantenimiento y limpieza del SO
    Qué hace: borra temporales del usuario y del sistema y vacía la papelera.
    Cuándo: PC lento o con poco espacio. Seguro, también en remoto.
    No toca tus documentos.

[2] Reparación de archivos de sistema (DISM + SFC)
    Qué hace: DISM /RestoreHealth repara la imagen de Windows (descarga
    archivos de Windows Update), SFC /scannow comprueba y repara archivos
    protegidos y se limpia el almacén de componentes.
    Cuándo: pantallazos azules, errores raros, programas del sistema que fallan.
    Tarda de 15 a 60 minutos. Si SFC avisa de problemas: C:\Windows\Logs\CBS\CBS.log

[3] Reparación de red básica
    Qué hace: vacía caché DNS, tabla ARP y caché NetBIOS y re-registra el DNS.
    Cuándo: una web no carga aunque hay Internet, o cambió la IP de un servidor.
    Seguro en remoto.

[4] Reseteo profundo de red TCP/IP   (SOLO EN LOCAL)
    Qué hace: reinicia Winsock y la pila TCP/IP y renueva el DHCP.
    Efecto: CORTA la red y exige REINICIAR. Puede perder configuraciones de
    IP fija. No se puede deshacer.
    Cuándo: la red no funciona tras malware, una VPN rota o drivers raros.

[5] Restablecer Windows Update
    Qué hace: detiene los servicios, renombra SoftwareDistribution y catroot2
    (Windows los recrea) y reinicia los servicios.
    Efecto: se pierde el historial de actualizaciones. No lo uses mientras
    Windows está instalando actualizaciones.
    Cuándo: las actualizaciones fallan o se quedan atascadas.

[6] Mantenimiento completo = 1 + 2 + 3 + 5   (no incluye la 4)

Qué NO se puede deshacer: lo hecho por las opciones 4 y 5 (limpieza de red
y de Windows Update). Las demás no dejan cambios que revertir.

----------------------------------------------------------------
 B) SYSINTERNALS  -  diagnóstico avanzado de Microsoft
----------------------------------------------------------------
Colección de herramientas de Microsoft (Mark Russinovich) para ver qué
hace realmente Windows. En la carpeta Sysinternals solo están las
IMPORTANTES (versión 64 bits); el resto está en la subcarpeta _Otras.
Desde el Launcher (05 > B) cada herramienta aparece con su descripción.
Guía completa con ejemplos: Sysinternals\GUIA_SYSINTERNALS.txt
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '05_PC_Troubleshooting/MANUAL.txt') -Content $Manual05 -Encoding Utf8Bom

$Manual06 = @'
================================================================
 MANUAL - 06 DIAGNÓSTICO DE RED
================================================================

QUÉ ES
Network-Diagnostics.ps1 prueba tu conexión capa por capa y te dice dónde
está el problema. Solo LEE y prueba: no cambia nada en el equipo.

PARA QUÉ SIRVE
Responder rápido a "no tengo Internet": ¿falla el cable/Wi-Fi, el router,
la salida a Internet o el DNS?

QUÉ COMPRUEBA (en este orden)
 1. Adaptador activo con IPv4 ... ¿hay una conexión con IP?
    Una IP 169.254.x.x (APIPA) significa que el DHCP no respondió.
 2. Ping al gateway ............. ¿llega al router? Si falla, el problema es
                                  local (cable, Wi-Fi, switch o router).
 3. Ping a 1.1.1.1 .............. ¿sale a Internet por IP? Si falla, el
                                  problema está en el ISP, la ruta o un firewall.
 4. Resolución DNS .............. ¿traduce nombres? Si falla pero el paso 3
                                  funciona, el problema es el DNS.
 5. HTTPS (puerto 443) .......... ¿abre conexiones web? Si falla, puede ser
                                  un proxy, un firewall o inspección TLS.
Al final muestra un diagnóstico en una frase.

CÓMO SE USA
 Opción 06 del Launcher. No necesita Administrador.

SI HAY PROBLEMAS, QUÉ HACER
 - DNS o web fallando: Fix-Windows opción 3 (módulo 05).
 - Red totalmente rota en local: Fix-Windows opción 4 (corta la red y
   reinicia; léela antes en el manual 05).
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '06_Network_Repair/MANUAL.txt') -Content $Manual06 -Encoding Utf8Bom

$Manual07 = @'
================================================================
 MANUAL - 07 AUDITORÍA E INVENTARIO
================================================================

A) GET-INVENTORY.PS1  -  informe del equipo
 Qué es: genera un informe de texto (Inventory_<EQUIPO>_<fecha>.txt) con:
   Sistema ...... nombre, usuario, dominio, versión de Windows, tiempo
                  encendido, Secure Boot y TPM
   Hardware ..... fabricante, modelo, número de serie, BIOS, procesador, RAM, video
   Red .......... adaptadores activos con IP, gateway, DNS y MAC
   Discos ....... modelo y estado de salud de los discos físicos, y espacio
                  libre de cada volumen
   Parches ...... las 5 últimas actualizaciones instaladas
 Para qué sirve: inventariar equipos, documentar un caso de soporte, ver
 rápido si falta espacio o si un disco reporta un estado de salud malo.
 Cómo se usa: opción 07 > A. Con Administrador muestra también el TPM.
 Aviso: el informe contiene número de serie y datos de red. No lo publiques.

B) SHOWKEYPLUS  -  claves de Windows
 Qué es: muestra la clave de producto instalada y la clave OEM guardada en
 el firmware (BIOS/UEFI) del equipo, y el tipo de licencia.
 Para qué sirve: comprobar con qué clave está activado Windows o recuperar la
 clave del equipo antes de formatear.
 Cómo se usa: opción 07 > B.
 Aviso: úsalo solo en equipos propios o autorizados. Una clave de producto
 es información sensible.
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '07_Audit_Inventory/MANUAL.txt') -Content $Manual07 -Encoding Utf8Bom

$Manual08 = @'
================================================================
 MANUAL - 08 DESINSTALAR Y DEJAR COMO NUEVO
================================================================

QUÉ ES
Un asistente que quita lo que el toolkit dejó en el equipo y puede devolver
el propio toolkit a su estado inicial. CADA PASO MUESTRA lo que encontró y
PIDE CONFIRMACIÓN antes de borrar nada.

CÓMO SE USA
 Abre Launcher.bat como Administrador y elige 08.

OPCIONES
 [1] Desinstalar programas ... quita WireGuard, RustDesk (si lo instalaste
     desde su ventana) y UniGetUI (si estaba instalado).
     RustDesk portable, KVRT, Sysinternals y UniGetUI portable no se
     instalan, así que no aparecen aquí.
 [2] Limpiar restos ........... elimina, solo si existen:
       - configuración de RustDesk y datos de UniGetUI
       - carpeta de WireGuard (incluye los túneles guardados)
       - C:\KVRT_Data (informes y cuarentena de KVRT)
       - respaldos SoftwareDistribution.bak_* y catroot2.bak_* de Fix-Windows
       - EULA y ajustes de Sysinternals del usuario actual
       - el reemplazo del Administrador de tareas por Process Explorer
 [3] Revertir Windows Update .. si WAU Manager desactivó el servicio, puso
     una directiva o creó tareas programadas, lo detecta y lo restablece.
     (En equipos de una empresa, la directiva puede ser de tu administrador.)
 [4] Resetear el toolkit ...... borra las herramientas descargadas, los
     informes de inventario y los logs. Conserva Launcher, scripts y
     manuales. Para volver a descargar todo: Deploy-IT-Toolkit.ps1.
 [5] Eliminar el toolkit COMPLETO  borra la carpeta entera. Exige escribir
     ELIMINAR para confirmar.
 [6] TODO = 1 + 2 + 3 + 4 ..... deja el equipo y el toolkit como nuevos.

LO QUE NO SE PUEDE REVERTIR
 Los cambios de Fix-Windows en la red (opción 4) y el historial de Windows
 Update no se pueden restaurar: el módulo 08 no los toca.

CONSEJO
 Si no estás seguro, empieza por [2] y [3]: solo listan y preguntan.
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '08_Uninstall_Reset/MANUAL.txt') -Content $Manual08 -Encoding Utf8Bom

$SysGuideContent = @'
================================================================
 GUÍA DE SYSINTERNALS - HERRAMIENTAS PRINCIPALES
================================================================
Sysinternals es una colección de utilidades de Microsoft para ver y
diagnosticar lo que hace Windows por dentro.

ORGANIZACIÓN DE ESTA CARPETA
 Aquí solo están las herramientas importantes, en su versión de 64 bits.
 Las demás (versiones de 32 bits, ARM64, ayudas y herramientas avanzadas)
 están en la subcarpeta _Otras. Documentación oficial:
 https://learn.microsoft.com/sysinternals

PRIMERA VEZ
 Cada herramienta muestra un aviso de licencia (EULA) la primera vez.
 En consola, añade -accepteula (ejemplo: psexec -accepteula).
 Para ver el efecto completo ejecútalas como Administrador.

----------------------------------------------------------------
 HERRAMIENTAS GRÁFICAS (doble clic o desde el Launcher: 05 > B)
----------------------------------------------------------------
PROCESS EXPLORER  (procexp64.exe)
  Qué es: un Administrador de tareas mucho más potente.
  Sirve para: ver qué proceso consume CPU o RAM, qué archivos/DLL usa, de qué
  proceso depende cada uno (vista de árbol) y a qué programa pertenece una ventana.
  Consejos: Ctrl+F busca qué proceso tiene abierto un archivo (útil cuando
  Windows dice "archivo en uso"). Options > Verify Image Signatures marca los
  procesos sin firma. No actives "Replace Task Manager" salvo que quieras
  sustituirlo (se revierte desde el módulo 08).

PROCESS MONITOR  (Procmon64.exe)
  Qué es: graba en tiempo real la actividad de archivos, registro, red y procesos.
  Sirve para: averiguar por qué un programa falla al abrir, qué archivo o clave
  de registro no encuentra, o quién modifica algo.
  Consejos: requiere Administrador. Ctrl+E inicia/detiene la captura, Ctrl+X
  limpia, Ctrl+L abre los filtros (filtra por nombre de proceso o por resultado,
  por ejemplo "ACCESS DENIED"). Sin filtros genera miles de eventos por segundo.

AUTORUNS  (Autoruns64.exe)
  Qué es: lista TODO lo que arranca con Windows: programas, servicios, tareas
  programadas, controladores, extensiones.
  Sirve para: encontrar por qué un equipo arranca lento o detectar software
  sospechoso que se ejecuta solo.
  Consejos: Options > Hide Microsoft Entries deja solo lo de terceros.
  Rosa = sin firma ni editor; amarillo = el archivo ya no existe.
  Desmarcar una entrada la desactiva (reversible); "Delete" la elimina.

TCPVIEW  (Tcpview64.exe o Tcpview.exe)
  Qué es: muestra las conexiones de red abiertas y qué programa las usa.
  Sirve para: ver con quién habla un programa, detectar conexiones
  sospechosas o ver qué proceso ocupa un puerto.
  Estados comunes: ESTABLISHED (conectado), LISTENING (esperando conexiones),
  TIME_WAIT (cerrándose). Clic derecho permite cerrar una conexión.

RAMMAP  (RAMMap64.exe)
  Qué es: muestra con detalle cómo usa Windows la memoria RAM.
  Sirve para: entender por qué "la RAM está llena" (a menudo es caché normal).
  Consejo: menú Empty > Empty Standby List libera la caché en espera.

----------------------------------------------------------------
 HERRAMIENTAS DE LÍNEA DE COMANDOS
----------------------------------------------------------------
Se usan desde la "Consola Sysinternals" (Launcher: 05 > B > C). La carpeta ya
está en el PATH y puedes escribir los nombres cortos (psexec, handle...).

PSEXEC   Ejecuta comandos como otro usuario, como SYSTEM o en otro equipo.
         psexec -accepteula -s -i cmd      (consola como SYSTEM en este equipo)
         psexec \\EQUIPO -s cmd            (consola en un equipo remoto, con permisos)
         Aviso: muchos antivirus lo marcan porque los atacantes también lo usan.
         Úsalo solo en equipos autorizados.

PSKILL   Termina un proceso por nombre o PID.   pskill nombre.exe   /   pskill 1234

PSLIST   Lista procesos con CPU y memoria.   pslist   /   pslist -t  (en árbol)

SIGCHECK Verifica la firma digital y el hash de archivos.
         sigcheck -a archivo.exe                     (información extendida)
         sigcheck -u -e -s C:\Windows\System32       (ejecutables sin firma)

HANDLE   Muestra qué proceso tiene abierto un archivo o carpeta.
         handle documento.docx      (útil cuando no puedes borrar o mover algo)

PROCDUMP Crea un volcado de memoria de un proceso, para analizar cuelgues.
         procdump -ma nombre_o_PID

PSPING   Prueba la conectividad TCP a un puerto y mide la latencia.
         psping servidor.com:443

ACCESSCHK Muestra qué permisos tiene un usuario sobre un archivo o carpeta.
         accesschk usuario C:\Carpeta

----------------------------------------------------------------
 ¿Y LAS DEMÁS? (carpeta _Otras)
----------------------------------------------------------------
Contiene el resto de la suite (decenas de utilidades) y las variantes de
32 bits y ARM64. Si necesitas alguna, la encuentras ahí; consulta la
documentación oficial de Microsoft para cada una.
'@
Write-TextFile -Path (Join-Path $ToolkitRoot '05_PC_Troubleshooting/Sysinternals/GUIA_SYSINTERNALS.txt') -Content $SysGuideContent -Encoding Utf8Bom

Write-Status ' -> Manuales listos (general + 00 a 08 + guia de Sysinternals).' 'Ok'
# ----------------------------------------------------------------------
# 3. DESCARGAS
# ----------------------------------------------------------------------
if ($SkipDownloads) {
    Write-Status "`n[3/4] Descargas omitidas (-SkipDownloads)." 'Warn'
} else {
    Write-Status "`n[3/4] Descargando herramientas (fuentes oficiales)..." 'Warn'

    # Source 'github' = ultima release (valida SHA256 si GitHub lo publica) | 'url' = enlace directo
    # Extract = $true  ->  Dest es una carpeta donde se descomprime el .zip
    $Downloads = @(
        @{ Name = 'RustDesk';        Source = 'github'; Repo = 'rustdesk/rustdesk';      Pattern = 'rustdesk-*-x86_64.exe'; Dest = '00_Remote/RustDesk_Portable.exe' }
        @{ Name = 'WireGuard';       Source = 'url';    Url = "https://download.wireguard.com/windows-client/wireguard-amd64-$WireGuardVersion.msi"; Dest = '01_VPN/WireGuard_Setup.msi' }
        @{ Name = 'WAU-Manager';     Source = 'url';    Url = 'https://www.carifred.com/wau_manager/WAU%20Manager.exe'; Dest = '02_Updates/WAU_Manager.exe' }
        @{ Name = 'KVRT';            Source = 'url';    Url = 'https://devbuilds.s.kaspersky-labs.com/devbuilds/KVRT/latest/full/KVRT.exe'; Dest = '03_Antivirus/KVRT.exe' }
        @{ Name = 'UniGetUI';        Source = 'github'; Repo = 'Devolutions/UniGetUI';   Pattern = 'UniGetUI.x64.zip';      Dest = '04_App_Updater/UniGetUI'; Extract = $true }
        @{ Name = 'Sysinternals';    Source = 'url';    Url = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'; Dest = '05_PC_Troubleshooting/Sysinternals'; Extract = $true }
        @{ Name = 'ShowKeyPlus';     Source = 'github'; Repo = 'Superfly-Inc/ShowKeyPlus'; Pattern = 'ShowKeyPlus*.zip';    Dest = '07_Audit_Inventory/ShowKeyPlus'; Extract = $true; Nested = '*_x64.zip' }
    )

    foreach ($item in $Downloads) {
        $name = $item.Name
        $isZip = [bool]$item.Extract
        $destPath = Join-Path $ToolkitRoot $item.Dest
        $marker = if ($isZip) { Join-Path $destPath ".$name.ok" } else { $null }

        try {
            # Idempotencia: no repetir lo ya descargado
            if (-not $Force) {
                if ($isZip -and (Test-Path -LiteralPath $marker)) {
                    Add-Result $name 'Omitido' '' 'Ya instalado (usa -Force para repetir)'
                    Write-Status " -> $name : ya instalado, omitido." 'Info'
                    continue
                }
                if ((-not $isZip) -and (Test-Path -LiteralPath $destPath) -and ((Get-Item -LiteralPath $destPath).Length -gt 0)) {
                    Add-Result $name 'Omitido' '' 'Ya existe (usa -Force para repetir)'
                    Write-Status " -> $name : ya existe, omitido." 'Info'
                    continue
                }
            }

            $uri = $item.Url
            $sha = $null
            $detail = ''
            if ($item.Source -eq 'github') {
                $asset = Get-GitHubAsset -Repo $item.Repo -Pattern $item.Pattern
                $uri = $asset.Url
                $sha = $asset.Sha256
                $detail = "$($asset.Tag) / $($asset.Name)"
            }

            Write-Status " -> Descargando $name ..." 'Warn'
            $target = if ($isZip) { Join-Path ([IO.Path]::GetTempPath()) ("$name-" + [guid]::NewGuid().ToString('N') + '.zip') } else { $destPath }
            Invoke-Download -Uri $uri -OutFile $target -ExpectedSha256 $sha -MaxAttempts $Retries

            $sigText = ''
            if ($isZip) {
                if (-not (Test-Path -LiteralPath $destPath)) { [void](New-Item -ItemType Directory -Path $destPath -Force) }
                Expand-Archive -LiteralPath $target -DestinationPath $destPath -Force
                Remove-Item -LiteralPath $target -Force
                if ($item.Nested) {
                    # Algunos paquetes (ShowKeyPlus) traen zips x64/x86 dentro del zip: se extrae solo el pedido
                    $inner = @(Get-ChildItem -LiteralPath $destPath -Recurse -File -Filter '*.zip')
                    $pick = $inner | Where-Object { $_.Name -like $item.Nested } | Select-Object -First 1
                    if (-not $pick) { throw "El paquete no contiene un zip interno que coincida con '$($item.Nested)'." }
                    Expand-Archive -LiteralPath $pick.FullName -DestinationPath $destPath -Force
                    $inner | Remove-Item -Force
                }
                Set-Content -LiteralPath $marker -Value (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -Encoding ASCII
            } else {
                $sigText = Get-SignatureSummary -Path $destPath
            }
            if ($sha) { $detail = "$detail (SHA256 verificado)".Trim() }
            Add-Result $name 'OK' $sigText $detail
            Write-Status "    [OK] $name $sigText" 'Ok'
        } catch {
            Add-Result $name 'ERROR' '' $_.Exception.Message
            Write-Status "    [ERROR] ${name}: $($_.Exception.Message)" 'Error'
        }
    }
}

# ----------------------------------------------------------------------
# 3b. ORDENAR SYSINTERNALS (solo lo importante en la carpeta principal)
# ----------------------------------------------------------------------
Write-Status "`nOrganizando Sysinternals..." 'Warn'
try {
    $sysMsg = Optimize-Sysinternals -Dir (Join-Path $ToolkitRoot '05_PC_Troubleshooting/Sysinternals')
    Write-Status " -> $sysMsg" 'Ok'
} catch {
    Write-Status " -> [ERROR] No se pudo ordenar Sysinternals: $($_.Exception.Message)" 'Error'
}

# ----------------------------------------------------------------------
# 4. README, INTEGRIDAD Y RESUMEN
# ----------------------------------------------------------------------
Write-Status "`n[4/4] Generando registro de integridad SHA256..." 'Warn'


$integrity = New-Object System.Collections.Generic.List[string]
$integrity.Add('# IT Helpdesk Toolkit v4 - Registro de integridad (SHA256)')
$integrity.Add("# Generado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') en $($env:COMPUTERNAME)")
$integrity.Add('# Formato: HASH<2 espacios>ruta relativa. Verificar con Verify-Integrity.ps1')
$hashExt = @('.exe', '.msi', '.bat', '.ps1')
Get-ChildItem -Path $ToolkitRoot -Recurse -File |
    Where-Object { $hashExt -contains $_.Extension.ToLowerInvariant() } |
    Sort-Object FullName |
    ForEach-Object {
        try {
            $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
            $rel = $_.FullName.Substring($ToolkitRoot.Length).TrimStart('\', '/')
            $integrity.Add("$h  $rel")
        } catch {
            Write-Status "    [!] No se pudo calcular hash de $($_.FullName)" 'Warn'
        }
    }
Write-TextFile -Path (Join-Path $ToolkitRoot 'INTEGRITY.txt') -Content ($integrity -join "`n") -Encoding Utf8Bom
Write-Status " -> $($integrity.Count - 3) archivos registrados en INTEGRITY.txt" 'Ok'

if ($script:Results.Count -gt 0) {
    Write-Status "`nRESUMEN DE DESCARGAS" 'Step'
    $script:Results | Format-Table Name, Status, Signature, Detail -AutoSize -Wrap | Out-String -Width 200 | Write-Host
    $failed = @($script:Results | Where-Object { $_.Status -eq 'ERROR' })
    if ($failed.Count -gt 0) {
        Write-Status "$($failed.Count) descarga(s) fallaron. Corrige la causa y vuelve a ejecutar: solo se repetira lo que falta." 'Warn'
    }
}

Write-Status "`n=======================================================================" 'Step'
Write-Status '    TOOLKIT v5 DESPLEGADO' 'Step'
Write-Status "    Ubicacion: $ToolkitRoot" 'Step'
Write-Status '=======================================================================' 'Step'
