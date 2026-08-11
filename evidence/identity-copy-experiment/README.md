# Identity Copy Experiment

## Steps performed

1. Mounted original VHDX as drive **T:**.
2. Recorded its `UniqueId` using PowerShell `Get-Volume` (e.g., `e61f72b3-...`).
3. Registered the volume with `volume-verifier.exe --volume T: --register`. Result: `PASS`.
4. Dismounted the VHDX and created an exact copy `test-volume-copy.vhdx`.
5. Mounted the copy as drive **U:**.
6. Queried `UniqueId` for **U:** – a different GUID (e.g., `3c470898-...`).
7. Verified the copy with `volume-verifier.exe --volume U:`. Result: `DENY`.

## Conclusions

- The `UniqueId` is stable for a given VHDX while it remains the same instance.
- Cloning the VHDX produces a new `UniqueId`, allowing the verifier to distinguish the original from a copy.
- The verifier does **not** attempt decryption; it only checks the observable identity.
