# Testing / Reproduction Guide

This document describes how to independently verify the claims made about
**Volume Verifier**. The goal is that a third party can reproduce the
experiment without trusting this description.

**No confíes en la descripción. Reproduce el experimento.**

## 1. Build from source

```powershell
pip install -r requirements.txt
./build.ps1
```

`build.ps1` produces `dist/volume-verifier.exe` and prints its SHA-256.
Compare that hash against `SHA256SUMS.txt` and, more importantly, verify the
behavior matches the source.

## 2. Unit tests (no hardware needed)

```powershell
python -m unittest discover tests -v
```

129 tests, including the T1–T12 hardening scenarios plus the crypto.raw
suite (raw sector parsers, bounds checking, Shamir 2-of-3, error mapping)
and the v1.4 raw-corroboration verdicts:

| # | Scenario | Expectation |
|---|---|---|
| T1 | Normal BitLocker metadata | register STANDARD, verify PASS |
| T2 | BitLocker metadata unavailable | STANDARD verify → `DENY BITLOCKER_METADATA_UNAVAILABLE` (no silent fallback) |
| T3 | `manage-bde` failure | registration blocked (`BITLOCKER_QUERY_FAILED`) |
| T4 | Insufficient privileges | `INSUFFICIENT_PRIVILEGES`, including HRESULT `0x80070005` classification |
| T5 | Malformed external output | `VOLUME_QUERY_FAILED` / metadata unavailable — explicit |
| T6 | Store missing | `DENY STORE_MISSING` |
| T7 | Store corrupted | `ERROR STORE_CORRUPTED` |
| T8 | Store modified (tampered) | DPAPI decrypt failure → `STORE_CORRUPTED` |
| T9 | Registered original volume | PASS (mocked, mirrors experiment) |
| T10 | Copied VHDX (different UniqueId) | `DENY FINGERPRINT_MISMATCH` (mocked) |
| T11 | Detach/attach (same UniqueId) | PASS (mocked) |
| T12 | Unsupported platform | `UNSUPPORTED_PLATFORM` |
| R1 | `--raw` corroborated match | `PASS` with `STRENGTH: RAW` |
| R2 | `--raw` FVE GUID / LUKS UUID mismatch | `DENY EVIDENCE_CONFLICT` |
| R3 | API says BitLocker/LUKS, no header on disk | `DENY EVIDENCE_CONFLICT` |
| R4 | Registered raw NTFS serial changed | `DENY EVIDENCE_CONFLICT` (continuity) |
| R5 | Raw read needs privileges | `ERROR RAW_INSUFFICIENT_PRIVILEGES` |
| R6 | `--raw` off | raw channel never touched |

All tests use mocked evidence acquisition and temporary stores. No real
volume is modified, destroyed, unlocked, or formatted.

## 3. The identity-copy experiment

### Question

Does an exact copy of a VHDX keep the same volume `UniqueId` as the
original?

### Procedure

1. Create a VHDX, mount it as **T:**.
2. Record its `UniqueId`:

   ```powershell
   (Get-Volume -DriveLetter T).UniqueId
   ```

3. Register it (needs an elevated shell for the `manage-bde` query):

   ```powershell
   volume-verifier.exe --volume T: --register
   volume-verifier.exe --volume T:    # expect VERDICT: PASS
   ```

4. Dismount the VHDX and create an exact copy:

   ```powershell
   Dismount-VHD -Path $Original -Confirm:$false
   Copy-Item $Original "$([IO.Path]::GetFileNameWithoutExtension($Original))_copy.vhdx"
   ```

5. Mount the copy as **U:** and verify it:

   ```powershell
   volume-verifier.exe --volume U:    # expect VERDICT: DENY
   (Get-Volume -DriveLetter U).UniqueId
   ```

### Expected results

- Original after detach/attach: **same** `UniqueId` → `PASS`.
- Copy: **different** `UniqueId` → `DENY / FINGERPRINT_MISMATCH`.

The automated version of this procedure is `Test-VolumeIdentity.ps1` (below).

## 4. Automated experiment script

```powershell
# requires: the VHDX mounted as T: (or offline), volume-verifier.exe in the
#           same directory, and an elevated shell for registration
.\Test-VolumeIdentity.ps1 -OriginalVhdxPath "C:\path\to\test-volume.vhdx"
```

```powershell
<#==========================================================================#>
# Test-VolumeIdentity.ps1
# ---------------------------------------------------------------------------
#  1) Desmonta (si está montado) el VHDX que respalda la unidad T:
#  2) Lo copia a "..._copy.vhdx".
#  3) Monta ambas imágenes simultáneamente como T: (original) y U: (copia).
#  4) Obtiene el GUID del volumen (UniqueId) de cada letra con Get-Volume.
#  5) Opcional: usa volume-verifier.exe para registrar/validar cada una.
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
    # Get-Volume devuelve la propiedad UniqueId (GUID del volumen)
    $vol = Get-Volume -DriveLetter $DriveLetter -ErrorAction SilentlyContinue
    if (-not $vol) { return $null }
    return $vol.UniqueId
}

function Show-Info {
    param([char]$Letter, [string]$Guid)
    Write-Host "Drive $Letter: GUID = $Guid"
}

# -------------------------------------------------------------------------
# 1  Preparación - desmontar el VHDX original (si ya está montado)
# -------------------------------------------------------------------------
$mountInfo = Get-VHD -Path $OriginalVhdxPath -ErrorAction SilentlyContinue
if ($mountInfo -and $mountInfo.Attached) {
    Write-Host "Desmontando VHDX original..."
    Dismount-VHD -Path $OriginalVhdxPath -Confirm:$false
}

# -------------------------------------------------------------------------
# 2  Copiar el VHDX
# -------------------------------------------------------------------------
$copyPath = [IO.Path]::Combine(
                [IO.Path]::GetDirectoryName($OriginalVhdxPath),
                [IO.Path]::GetFileNameWithoutExtension($OriginalVhdxPath) + "_copy.vhdx")
Write-Host "Copiando VHDX a $copyPath ..."
Copy-Item -LiteralPath $OriginalVhdxPath -Destination $copyPath -Force

# -------------------------------------------------------------------------
# 3  Montar ambas imágenes (original → T:, copia → U:)
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
# 4  Obtener los GUID (UniqueId) de T: y U:
# -------------------------------------------------------------------------
$guidT = Get-VolumeGuid -DriveLetter 'T'
$guidU = Get-VolumeGuid -DriveLetter 'U'

Show-Info -Letter 'T' -Guid $guidT
Show-Info -Letter 'U' -Guid $guidU

# -------------------------------------------------------------------------
# 5  (Opcional) Registrar / Verificar con la herramienta compilada
# -------------------------------------------------------------------------
$verifier = "volume-verifier.exe"   # asume que está en el mismo directorio
if (-not (Test-Path -LiteralPath $verifier)) {
    Write-Warning "No se encontró $verifier - se omite la fase de registro/validación."
} else {
    # Registrar la unidad T: (si no está ya en el store)
    Write-Host "`nRegistrando el GUID de T: ..."
    & $verifier --volume T: --register

    # Verificar la copia U:
    Write-Host "Verificando la copia U: ..."
    & $verifier --volume U:
}

# -------------------------------------------------------------------------
# 6  Resultado de la prueba
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
# 7  Limpieza (desmontar ambas imágenes)
# -------------------------------------------------------------------------
Write-Host "`nDesmontando ambas VHDX..."
Dismount-VHD -Path $OriginalVhdxPath -Confirm:$false
Dismount-VHD -Path $copyPath -Confirm:$false

Write-Host "`n¡Prueba completada!"
```

Note: since v1.1, `volume-verifier.exe --register` requires a successful
`manage-bde` query (elevated shell). Without elevation the registration
fails explicitly with `BITLOCKER_QUERY_FAILED` or
`INSUFFICIENT_PRIVILEGES` — this is by design, not a bug.

## 5. Store behavior changes in v1.1+

- Stores are now DPAPI-protected and schema-versioned (`format_version: 2`).
- A legacy v1 plaintext store is rejected on verify
  (`STORE_SCHEMA_MISMATCH`) and migrated automatically the next time
  `--register` is run.
- Store tampering is detected (`STORE_CORRUPTED`): the payload is encrypted,
  so an invalid modification cannot be parsed as valid identity.

## 5b. HMAC_PASSPHRASE portable store (v1.2)

Optional portable protection via passphrase (integrity/authenticity only —
no encryption, no keys derived beyond the passphrase, no BitLocker keys):

```powershell
# Register with a passphrase -> the store becomes HMAC_PASSPHRASE
volume-verifier.exe --volume C: --register --passphrase "mi-frase"

# Verify with the passphrase
volume-verifier.exe --volume C: --passphrase "mi-frase"
# or via environment
$env:VOLUME_VERIFIER_PASSPHRASE = "mi-frase"
volume-verifier.exe --volume C:
```

Expected behaviors:

- HMAC store without passphrase → `ERROR / STORE_PASSPHRASE_REQUIRED`.
- Wrong passphrase → `ERROR / STORE_MAC_MISMATCH` (same reason as tampering;
  the two are cryptographically indistinguishable).
- Payload is visible in the file (integrity-only by design).
- A passphrase on an existing DPAPI store deterministically re-protects it
  to HMAC_PASSPHRASE (entries preserved).
- Default remains DPAPI when no passphrase is given.

## 6. Linux platform (v1.3, evidence-backed)

The Linux source is functional and has been verified against a real WSL2
Ubuntu 26.04 environment (kernel 6.18.33.1-microsoft-standard-WSL2).
All observations come from standard, non-root commands:

```bash
# Register a plain ext4 volume (WEAK — no LUKS)
volume-verifier.py --volume /mnt/data --register --passphrase "k1"

# Register a LUKS-encrypted volume (STANDARD — has LUKS UUID)
volume-verifier.py --volume /mnt/crypt --register --passphrase "k1"

# Verify
volume-verifier.py --volume /mnt/data --passphrase "k1"
# VERDICT: PASS / WEAK
volume-verifier.py --volume /mnt/crypt --passphrase "k1"
# VERDICT: PASS / STANDARD
```

Strength semantics (mirrors Windows):

| Strength | Condition |
|----------|-----------|
| WEAK | Filesystem UUID only (no LUKS encryption metadata) |
| STANDARD | Filesystem UUID + LUKS UUID (encryption metadata present) |

Expected behaviors (same HMAC store model as Windows):

- Store without passphrase → `ERROR / STORE_PASSPHRASE_REQUIRED`.
- Wrong passphrase → `ERROR / STORE_MAC_MISMATCH`.
- Registered STANDARD entry but LUKS UUID now unreadable →
  `DENY / LUKS_METADATA_UNAVAILABLE`.
- No `blkid`, no root; commands used: `findmnt`, `lsblk`, `cryptsetup`.

Full raw evidence and experiment logs in `evidence/linux-identity/raw/`.

## 7. Test matrix (v1.4)

| Platform | Store | Passphrase | Expected outcome |
|----------|-------|------------|------------------|
| win32 | DPAPI (default) | none | register/verify work |
| win32 | HMAC | correct | PASS |
| win32 | HMAC | wrong | ERROR STORE_MAC_MISMATCH |
| win32 | HMAC | missing | ERROR STORE_PASSPHRASE_REQUIRED |
| win32 | tampered | correct | ERROR STORE_MAC_MISMATCH |
| linux (WSL2) | HMAC | correct | PASS (WEAK or STANDARD) |
| linux (WSL2) | HMAC | wrong | ERROR STORE_MAC_MISMATCH |
| darwin | any | any | ERROR UNSUPPORTED_PLATFORM |

## 6. Interpreting the result

- If the GUIDs **differ**: Windows assigns a new `UniqueId` to the copy.
  The verifier's `DENY` is evidence that the copy is a different logical
  volume instance.
- If the GUIDs were **identical**: the identity check would pass on a copy —
  which is exactly why the tool's claim is limited to "same logical
  instance", never "original physical hardware".
- A `DENY` with `REASON: BITLOCKER_METADATA_UNAVAILABLE` means the registered
  identity was STANDARD but the BitLocker Volume ID could not be obtained
  now — not that the volume is a copy.

Either outcome is informative. Run the experiment and record your own
numbers before drawing conclusions.
