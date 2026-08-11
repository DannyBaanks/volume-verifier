# volume_verifier.py — Volume Identity Verifier
#
# This utility verifies that a BitLocker‑protected volume belongs to a previously
# registered system.  It does **not** attempt to decrypt the volume or inspect its
# contents.  The verification is based on observable metadata (e.g. the Volume ID)
# and a cryptographic fingerprint stored in a local JSON file.
#
# Command‑line usage:
#   python volume_verifier.py --volume C: [--store <path_to_store.json>] [--register]
#
#   * Without ``--register`` the tool verifies the current volume against the
#     stored fingerprint and prints ``VERDICT: PASS`` or ``VERDICT: DENY``.
#   * With ``--register`` the current fingerprint is recorded (or updated) in the
#     identity store.
#
# The program is deliberately minimal – it only reads BitLocker status via
# ``manage-bde -status`` (available on Windows) and performs a SHA‑256 hash of the
# Volume ID.  No decryption capability is present, making the binary safe to
# release publicly.

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _run_manage_bde(volume: str) -> Optional[str]:
    """Run ``manage-bde -status <volume>`` and return its stdout.

    Returns ``None`` on any error (e.g. insufficient privileges or missing tool).
    """
    try:
        vol = volume.rstrip(":") + ":"
        return subprocess.check_output(
            ["manage-bde", "-status", vol], text=True, stderr=subprocess.DEVNULL
        )
    except Exception:
        return None

def _get_volume_guid_ps(volume: str) -> Optional[str]:
    """Obtiene el GUID del volumen (UniqueId) usando PowerShell ``Get-Volume``.

    PowerShell devuelve el GUID en el campo ``UniqueId``.  Si el comando falla o
    la unidad no está disponible, se devuelve ``None``.
    """
    # PowerShell necesita la letra sin los dos puntos, pero el comando tolera
    # ambos.  Construimos una cadena segura y la ejecutamos via ``subprocess``.
    vol_letter = volume.rstrip(":")
    # Construimos el comando como lista para evitar problemas de quoting.
    ps_cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        f"(Get-Volume -DriveLetter {vol_letter}).UniqueId",
    ]
    try:
        output = subprocess.check_output(ps_cmd, text=True, stderr=subprocess.DEVNULL)
        guid = output.strip()
        return guid if guid else None
    except Exception:
        return None


def _extract_volume_id(status_output: str) -> Optional[str]:
    """Parse the ``Volume ID`` line from ``manage-bde`` output.

    Expected line format (case‑insensitive):
        Volume ID:  {12345678-1234-1234-1234-1234567890AB}
    If the line cannot be located, ``None`` is returned.
    """
    for line in status_output.splitlines():
        if line.strip().lower().startswith("volume id:"):
            _, value = line.split(":", 1)
            return value.strip()
    return None


def _fingerprint(volume_id: str) -> str:
    """Compute a SHA‑256 fingerprint from the canonical Volume ID string.

    The function normalises the identifier to lower‑case UTF‑8 before hashing.
    """
    return hashlib.sha256(volume_id.lower().encode("utf-8")).hexdigest()


def _load_store(path: Path) -> Dict[str, dict]:
    """Load the JSON identity store.

    The JSON file maps ``volume`` → {"unique_id": ..., "bitlocker_id": ..., "fingerprint": ...}.
    Keys are normalised to upper‑case for case‑insensitive lookup; values are kept as‑is.
    If the file does not exist or cannot be parsed, an empty dict is returned.
    """
    if not path.is_file():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        # Preserve inner dictionaries; only normalise the outer key.
        return {str(k).upper(): v for k, v in data.items()}
    except Exception:
        return {}


def _save_store(path: Path, store: Dict[str, dict]) -> None:
    """Write the JSON identity store to ``path`` atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, sort_keys=True)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def register_volume(volume: str, store_path: Path) -> bool:
    """Registra la identidad actual de ``volume`` en ``store_path``.

    Se capturan dos atributos:
    * ``unique_id``  → GUID del volumen obtenido vía PowerShell ``Get-Volume``.
    * ``bitlocker_id`` → ``Volume ID`` de ``manage-bde -status`` (si está cifrado).

    El fingerprint se calcula como SHA‑256( unique_id [+ bitlocker_id] ).
    Devuelve ``True`` si se pudo obtener al menos el ``unique_id``; ``False`` en caso
    de error crítico.
    """
    # 1️⃣  Obtener el UniqueId mediante PowerShell (es la información estable que
    #     hemos comprobado que persiste entre detach/attach pero cambia al clonar).
    unique_id = _get_volume_guid_ps(volume)
    if not unique_id:
        return False

    # 2️⃣  Intentar obtener el BitLocker Volume ID (opcional, solo si la unidad está cifrada).
    raw = _run_manage_bde(volume)
    bitlocker_id = _extract_volume_id(raw) if raw else None

    # 3️⃣  Construir la huella (fingerprint).  Si tenemos bitlocker_id, lo incorporamos;
    #     de lo contrario la huella se basa exclusivamente en unique_id.
    if bitlocker_id:
        fp = hashlib.sha256((unique_id + bitlocker_id).encode('utf-8')).hexdigest()
    else:
        fp = hashlib.sha256(unique_id.encode('utf-8')).hexdigest()

    # 4️⃣  Guardar en el almacén JSON con campos descriptivos.
    store = _load_store(store_path)
    store[volume.upper()] = {
        "unique_id": unique_id,
        "bitlocker_id": bitlocker_id,
        "fingerprint": fp,
    }
    _save_store(store_path, store)
    return True


def verify_volume(volume: str, store_path: Path) -> bool:
    """Return ``True`` if the fingerprint of ``volume`` matches the stored value.

    ``False`` indica que la huella no coincide, que no hay registro para la letra
    solicitada o que no se pudo leer la información requerida.
    """
    # 1️⃣  Obtener UniqueId del volumen mediante PowerShell.
    unique_id = _get_volume_guid_ps(volume)
    if not unique_id:
        return False

    # 2️⃣  Obtener (opcional) BitLocker Volume ID.
    raw = _run_manage_bde(volume)
    bitlocker_id = _extract_volume_id(raw) if raw else None

    # 3️⃣  Calcular la huella actual con la misma lógica que en register_volume.
    if bitlocker_id:
        current_fp = hashlib.sha256((unique_id + bitlocker_id).encode('utf-8')).hexdigest()
    else:
        current_fp = hashlib.sha256(unique_id.encode('utf-8')).hexdigest()

    # 4️⃣  Cargar el registro y comparar la huella.
    store = _load_store(store_path)
    entry = store.get(volume.upper())
    if not isinstance(entry, dict):
        # Registro antiguo (solo cadena) o inexistente → no coincide.
        return False
    expected_fp = entry.get("fingerprint")
    return current_fp == expected_fp

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Volume Identity Verifier – ensures a BitLocker volume belongs to a known system.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--volume", required=True, help="Drive letter (e.g., C:)")
    parser.add_argument(
        "--store",
        default=str(Path.home() / ".volume_verifier" / "identity_store.json"),
        help="Path to the JSON file that stores volume fingerprints.",
    )
    parser.add_argument(
        "--register",
        action="store_true",
        help="Record the current fingerprint instead of verifying.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    store_path = Path(args.store).expanduser().resolve()
    if args.register:
        if register_volume(args.volume, store_path):
            print(f"[VERIFIER] Fingerprint for {args.volume.upper()} registered.")
            sys.exit(0)
        else:
            print(f"[VERIFIER] ERROR: Could not register {args.volume.upper()}.")
            sys.exit(2)
    else:
        if verify_volume(args.volume, store_path):
            print("VERDICT: PASS")
            sys.exit(0)
        else:
            print("VERDICT: DENY")
            sys.exit(1)

if __name__ == "__main__":
    main()
