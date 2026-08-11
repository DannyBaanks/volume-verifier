# TPM Identity — Experiment

Status: SEPARATE EXPERIMENT. No implementation. Treated strictly as
**platform evidence**, never as volume identity.

## Machine evidence (2026-08-11)

`Get-Tpm` on this machine returned no TPM properties (TpmPresent empty).
This host (likely a VM) exposes no usable TPM. All TPM work is therefore
deferred to hardware with TPM 2.0.

## Semantics (what TPM identity IS and is NOT)

| Claim | Verdict |
|---|---|
| TPM proves "this platform has the same TPM as before" | yes (cryptographic, via sealed keys / attestation) |
| TPM proves "this volume is the same volume" | **no** — a volume has no relation to the TPM |
| TPM helps recovery of documents after disk loss | **no** — a dead disk cannot be attested |
| TPM protects data from a lost OS? | partially: a sealed key can outlive an OS reinstall on the same machine+TPM |

Critical, documented consequence: a TPM-sealed secret is **not a recovery
mechanism**. TPM state changes (BIOS updates, secure boot changes, TPM
clear) can render sealed data unreadable. BitLocker's own recovery key
exists precisely because TPM alone cannot guarantee recoverability.

## Proposed protocol (for a TPM 2.0 machine)

1. `tpm2_createprimary` + `tpm2_create` + `tpm2_load` + `tpm2_unseal`
   round-trip (Linux `tpm2-tools`) or Windows `Get-Tpm` + TPM cmdlets.
2. Measure:
   a. sealed blob round-trips within the same machine/session;
   b. sealed blob **fails** to unseal on a different machine (evidence of
      platform binding);
   c. sealed blob survives an OS reinstall on the same machine+TPM
      (if testable).
3. Record all outputs in `evidence/tpm-identity/results/`.

## Integration rule (if it ever happens)

A TPM-derived observation could join the identity model as additional
**platform evidence**, with its own strength semantics and honest
limitations. It must never be labeled "volume identity" and must never
become a decryption or bypass mechanism. Volume Verifier's claim stays:
continuity of observable volume metadata.
