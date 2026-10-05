#!/usr/bin/env python3
"""verify_certificate.py — verify a metatron-cert/1 certificate. Standalone; only needs `cryptography`.

Usage:
  python verify_certificate.py certificate.json [--pubkey <hex-to-pin>]

Exit codes: 0 = PASS, 1 = FAIL.
"""
import argparse, hashlib, json, sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("certificate")
    ap.add_argument("--pubkey", default=None, help="pin the issuer public key (hex) and fail if it differs")
    a = ap.parse_args()

    with open(a.certificate, encoding="utf-8") as f:
        doc = json.load(f)
    payload = doc.get("certificate") or {}
    sig = doc.get("signature") or {}
    if sig.get("alg") != "ed25519" or not sig.get("value") or not sig.get("pubkey"):
        print("FAIL: missing ed25519 signature block"); return 1
    if payload.get("issuer_pubkey") != sig.get("pubkey"):
        print("FAIL: issuer_pubkey mismatch between payload and signature block"); return 1
    if a.pubkey and a.pubkey.lower() != sig["pubkey"].lower():
        print("FAIL: certificate issued by a different key than the pinned one"); return 1

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["pubkey"]))
        pub.verify(bytes.fromhex(sig["value"]), canonical(payload))
    except InvalidSignature:
        print("FAIL: signature does not match payload (tampered or corrupt)"); return 1
    except Exception as e:
        print("FAIL:", str(e)[:200]); return 1

    s = payload.get("subject") or {}
    claims = payload.get("claims") or {}
    print("PASS — signature valid")
    print("  format:   ", payload.get("format"))
    print("  issuer:   ", payload.get("issuer"), "<%s>" % payload.get("issuer_contact"))
    print("  pubkey:   ", sig["pubkey"])
    print("  subject:  ", "%s on %s" % (s.get("symbol") or "(unnamed)", s.get("chain")), s.get("address"))
    print("  issued_at:", payload.get("issued_at"))
    print("  claims:   ", json.dumps(claims)[:300])
    print("  evidence: ", (payload.get("evidence") or {}).get("raw_scan_sha256"))
    print("  note:     ", payload.get("disclaimer"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
