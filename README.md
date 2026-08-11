<#==========================================================================#>
# Test-VolumeIdentity.ps1
# ---------------------------------------------------------------------------
#  1) Desmonta (si está montado) el VHDX que respalda la unidad T:
#  2) Lo copia a “…_copy.vhdx”.
#  3) Monta ambas imágenes simultáneamente como T: (original) y U: (copia).
#  4) Obtiene el GUID del volumen (UniqueId) de cada letra con Get‑Volume.
#  5) Opcional: usa volume‑verifier.exe para registrar/validar cada una.
#  6) Informa si los GUID coinciden → el UniqueId se copia; si divergen → se genera uno nuevo.
#==========================================================================#>

param(
    [Parameter(Mandatory=$true,
               HelpMessage="Ruta completa del VHDX que está montado como T:")]
    [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})]
    [string] $OriginalVhdxPath
)

# -------------------------------------------------------------------------
# Funciones auxiliares
# -------------------------------------------------------------------------
function Get-VolumeGuid {
    param([char]$DriveLetter)
    # Get‑Volume devuelve la propiedad UniqueId (GUID del volumen)
    $vol = Get-Volume -DriveLetter $DriveLetter -ErrorAction SilentlyContinue
    if (-not $vol) { return $null }
    return $vol.UniqueId
}

function Show-Info {
    param([char]$Letter, [string]$Guid)
    Write-Host "Drive $Letter: GUID = $Guid"
}

# -------------------------------------------------------------------------
# 1️⃣  Preparación – desmontar el VHDX original (si ya está montado)
# -------------------------------------------------------------------------
$mountInfo = Get-VHD -Path $OriginalVhdxPath -ErrorAction SilentlyContinue
if ($mountInfo -and $mountInfo.Attached) {
    Write-Host "Desmontando VHDX original..."
    Dismount-VHD -Path $OriginalVhdxPath -Confirm:$false
}

# -------------------------------------------------------------------------
# 2️⃣  Copiar el VHDX
# -------------------------------------------------------------------------
$copyPath = [IO.Path]::Combine(
                [IO.Path]::GetDirectoryName($OriginalVhdxPath),
                [IO.Path]::GetFileNameWithoutExtension($OriginalVhdxPath) + "_copy.vhdx")
Write-Host "Copiando VHDX a $copyPath ..."
Copy-Item -LiteralPath $OriginalVhdxPath -Destination $copyPath -Force

# -------------------------------------------------------------------------
# 3️⃣  Montar ambas imágenes (original → T:, copia → U:)
# -------------------------------------------------------------------------
Write-Host "`nMontando VHDX original como T: ..."
$origDisk = Mount-VHD -Path $OriginalVhdxPath -PassThru
$origVol  = $origDisk | Get-Disk | Get-Partition | Where-Object {$_.DriveLetter -eq $null}
if (-not $origVol) { $origVol = $origDisk | Get-Disk | Initialize-Disk -PartitionStyle GPT -PassThru | `
                               Get-Partition | Where-Object {$_.DriveLetter -eq $null} }
Add-PartitionAccessPath -DiskNumber $origDisk.DiskNumber -PartitionNumber $origVol.PartitionNumber -AccessPath 'T:\'

Write-Host "Montando copia del VHDX como U: ..."
$copyDisk = Mount-VHD -Path $copyPath -PassThru
$copyVol  = $copyDisk | Get-Disk | Get-Partition | Where-Object {$_.DriveLetter -eq $null}
if (-not $copyVol) { $copyVol = $copyDisk | Get-Disk | Initialize-Disk -PartitionStyle GPT -PassThru | `
                               Get-Partition | Where-Object {$_.DriveLetter -eq $null} }
Add-PartitionAccessPath -DiskNumber $copyDisk.DiskNumber -PartitionNumber $copyVol.PartitionNumber -AccessPath 'U:\'

# Pequeña pausa para que Windows asigne los GUID
Start-Sleep -Seconds 2

# -------------------------------------------------------------------------
# 4️⃣  Obtener los GUID (UniqueId) de T: y U:
# -------------------------------------------------------------------------
$guidT = Get-VolumeGuid -DriveLetter 'T'
$guidU = Get-VolumeGuid -DriveLetter 'U'

Show-Info -Letter 'T' -Guid $guidT
Show-Info -Letter 'U' -Guid $guidU

# -------------------------------------------------------------------------
# 5️⃣  (Opcional) Registrar / Verificar con la herramienta compilada
# -------------------------------------------------------------------------
$verifier = "volume-verifier.exe"   # asume que está en el mismo directorio
if (-not (Test-Path -LiteralPath $verifier)) {
    Write-Warning "No se encontró $verifier – se omite la fase de registro/validación."
} else {
    # Registrar la unidad T: (si no está ya en el store)
    Write-Host "`nRegistrando el GUID de T: ..."
    & $verifier --volume T: --register

    # Verificar la copia U:
    Write-Host "Verificando la copia U: ..."
    & $verifier --volume U:
}

# -------------------------------------------------------------------------
# 6️⃣  Resultado de la prueba
# -------------------------------------------------------------------------
if ($guidT -eq $null -or $guidU -eq $null) {
    Write-Error "No se pudieron obtener los GUID de alguna de las unidades. Revisa que ambas estén correctamente montadas."
} elseif ($guidT -eq $guidU) {
    Write-Host "`n=== RESULTADO ==="
    Write-Host "Los GUID son idénticos → **UniqueId se copia** con el VHDX."
    Write-Host "Esto significa que el GUID solo prueba continuidad lógica del contenedor, no propiedad física."
} else {
    Write-Host "`n=== RESULTADO ==="
    Write-Host "Los GUID difieren → Windows genera un nuevo UniqueId al montar la copia."
    Write-Host "En ese caso el GUID sí puede usarse como evidencia de que la unidad es la misma instancia."
}

# -------------------------------------------------------------------------
# 7️⃣  Limpieza (desmontar ambas imágenes)
# -------------------------------------------------------------------------
Write-Host "`nDesmontando ambas VHDX..."
Dismount-VHD -Path $OriginalVhdxPath -Confirm:$false
Dismount-VHD -Path $copyPath -Confirm:$false

Write-Host "`n¡Prueba completada!"