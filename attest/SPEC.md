# metatron-cert/1 — open certificate format for token launch scans

A **certificate** is a signed, tamper-evident record of what a scanner found about a token
*at a specific moment*. It converts "trust our report" into "verify our proof".

## Why

- Findings that can't be edited after the fact: the signature covers the exact claims + the hash of the raw scan data.
- Anyone can verify with the issuer's public key — no account, no API key, ~50 lines of dependency-light Python.
- The format is open: any scanner can issue certificates with its own ed25519 key. Verifiers pin the issuer pubkey they trust.

## File structure

```json
{
  "certificate": {
    "format": "metatron-cert/1",
    "issuer": "Metatron Research",
    "issuer_contact": "metatron.backup2026@tutamail.com",
    "issuer_pubkey": "<64 hex chars>",
    "subject": {"chain": "solana", "address": "<mint>", "symbol": "XYZ"},
    "issued_at": "2026-10-04T20:15:00+00:00",
    "tool": "token-launch-scan",
    "claims": { "mint_authority": "renounced", "...": "..." },
    "verdict": ["GREEN: ...", "INFO: ..."],
    "evidence": {"raw_scan_sha256": "<64 hex>", "raw_scan_bytes": 1234},
    "disclaimer": "Automated snapshot at issued_at, not an audit. ..."
  },
  "signature": {"alg": "ed25519", "value": "<128 hex chars>", "pubkey": "<64 hex chars>"}
}
```

## Canonicalization (the exact rule)

The signed bytes are:

```
json.dumps(certificate, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

No whitespace, sorted keys, UTF-8. Ed25519 signature lives in `signature.value`.

The evidence hash is the same canonicalization applied to the raw scanner JSON output —
so anyone who re-runs the scan can compare the canonical bytes' sha256 against
`evidence.raw_scan_sha256` (note: live scans will differ if on-chain state changed —
the hash proves *what the issuer scanned*, not that the chain hasn't moved since).

## Verify

```bash
python verify_certificate.py certificate.json                     # basic
python verify_certificate.py certificate.json --pubkey <issuer-hex>  # pinned issuer
```

## Issue

```bash
python certify.py keygen --out certifier-key.json     # once — keep the key secret
python certify.py certify --chain solana --address <MINT> --symbol XYZ --key certifier-key.json
```

## Trust model (read this)

- The signature proves: **these claims + this evidence hash were issued by the holder of `issuer_pubkey`, and nothing was modified afterwards.**
- It does **not** prove the absence of risk, nor that the token is safe — it is a snapshot, timestamped in `issued_at`.
- Verifiers should pin the issuer pubkey out-of-band (from the issuer's site) rather than trusting the key inside the certificate for adversarial use-cases.

## Metatron Research issuer key

- Algorithm: ed25519
- Pubkey: see `issuer-keys/metatron-research.pub` in this directory (and the store's certificates page).
