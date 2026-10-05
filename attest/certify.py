#!/usr/bin/env python3
"""certify.py — issue a signed, tamper-evident certificate for a token launch scan.

Format: metatron-cert/1 (see SPEC-certificates.md). Open format — anyone can issue
with their own ed25519 key; anyone can verify with the issuer's public key.

Usage:
  python certify.py keygen --out certifier-key.json
  python certify.py certify --chain solana --address <MINT> [--symbol XYZ] [--key certifier-key.json] [--out ./certificates]
"""
import argparse, datetime, hashlib, json, os, subprocess, sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")

SELF_DIR = os.path.dirname(os.path.abspath(__file__))
ZERO_ADDRS = ("", "0x0000000000000000000000000000000000000000", "11111111111111111111111111111111")
ISSUER = "Metatron Research"
ISSUER_CONTACT = "metatron.backup2026@tutamail.com"
FORMAT = "metatron-cert/1"


def find_scanner():
    cands = [
        os.path.join(SELF_DIR, "launch_scan.py"),
        os.path.join(os.path.dirname(SELF_DIR), "launch_scan.py"),
        os.path.join(os.path.dirname(SELF_DIR), "tools", "launch_scan.py"),
        os.path.join(SELF_DIR, "tools", "launch_scan.py"),
    ]
    for c in cands:
        if os.path.exists(c):
            return c
    sys.exit("launch_scan.py not found next to certify.py (checked: %s)" % cands)


def canonical(obj):
    """Deterministic bytes for hashing/signing: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def run_scan(chain, addr):
    r = subprocess.run([sys.executable, find_scanner(), "--chain", chain, "--address", addr, "--json"],
                       capture_output=True, text=True, timeout=240)
    out = (r.stdout or "").strip()
    i = out.find("{")
    if i < 0:
        sys.exit("scan failed: " + ((r.stderr or out)[:300]))
    return json.loads(out[i:])


def extract_claims(scan):
    c = {}
    rpc = scan.get("rpc") or {}
    rc = scan.get("rugcheck") or {}
    g = scan.get("goplus") or {}
    h = scan.get("honeypot") or {}
    if "mintAuthority" in rpc:
        ma = rpc.get("mintAuthority")
        c["mint_authority"] = "renounced" if ma in ZERO_ADDRS + (None,) or not ma else str(ma)
    if "freezeAuthority" in rpc:
        fa = rpc.get("freezeAuthority")
        c["freeze_authority"] = "none" if fa in ZERO_ADDRS + (None,) or not fa else str(fa)
    if rpc.get("supply") is not None:
        c["supply_raw"] = str(rpc.get("supply"))
    if rc:
        if rc.get("score_normalised") is not None:
            c["rugcheck_score"] = rc.get("score_normalised")
        risks = rc.get("risks") or []
        if risks:
            c["rugcheck_risks"] = [str(r.get("name") or r.get("title") or r)[:100] for r in risks][:10]
        if rc.get("totalHolders") is not None:
            c["holder_count"] = rc.get("totalHolders")
        th = rc.get("topHolders") or []
        pcts = [float(x.get("pct")) for x in th if isinstance(x, dict) and x.get("pct") is not None]
        if pcts:
            c["largest_holder_pct"] = round(pcts[0], 2)
            c["top5_holder_pct"] = round(sum(pcts[:5]), 2)
    if g:
        if g.get("is_mintable") is not None:
            c["mintable"] = "yes" if str(g.get("is_mintable")) == "1" else "no"
        if g.get("is_open_source") is not None:
            c["source_verified"] = "yes" if str(g.get("is_open_source")) == "1" else "no"
        if g.get("is_honeypot") is not None:
            c["honeypot_flag"] = str(g.get("is_honeypot"))
        if g.get("holder_count") is not None and "holder_count" not in c:
            c["holder_count"] = g.get("holder_count")
        owner = (g.get("owner") or "").lower()
        if owner or "owner" in g:
            c["owner_renounced"] = "yes" if owner in ZERO_ADDRS else "no"
        bt, st = g.get("buy_tax"), g.get("sell_tax")
        if bt is not None or st is not None:
            c["buy_sell_tax"] = "%s%% / %s%%" % (bt if bt is not None else "?", st if st is not None else "?")
        lps = g.get("lp_holders") or []
        if lps:
            if any(str(x.get("is_locked")) == "1" for x in lps if isinstance(x, dict)):
                c["lp_status"] = "locked"
            elif any((x.get("addr") or "").startswith("0x0000000") for x in lps if isinstance(x, dict)):
                c["lp_status"] = "burned"
            else:
                c["lp_status"] = "not locked/burned"
    if h and h.get("honeypot_result") is not None:
        c["honeypot_simulation"] = str(h.get("honeypot_result"))
    verdict = scan.get("verdict") or []
    counts = {"green": 0, "info": 0, "warn": 0, "red": 0, "other": 0}
    for v in verdict:
        p = str(v).split(":", 1)[0].strip().lower()
        counts[p if p in counts else "other"] += 1
    c["verdict_counts"] = counts
    return c


def cmd_keygen(args):
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    doc = {"alg": "ed25519", "seed_hex": seed.hex(), "pubkey_hex": pub.hex(),
           "created": datetime.datetime.now(datetime.timezone.utc).isoformat(), "purpose": "metatron-cert/1 issuer key"}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    try:
        os.chmod(args.out, 0o600)
    except Exception:
        pass
    print("key written:", args.out)
    print("pubkey:", pub.hex())


def cmd_certify(args):
    with open(args.key, encoding="utf-8") as f:
        k = json.load(f)
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(k["seed_hex"]))
    pub_hex = k["pubkey_hex"]

    print("scanning %s on %s ..." % (args.address, args.chain))
    scan = run_scan(args.chain, args.address)
    raw_sha = sha256_hex(canonical(scan))

    payload = {
        "format": FORMAT,
        "issuer": ISSUER,
        "issuer_contact": ISSUER_CONTACT,
        "issuer_pubkey": pub_hex,
        "subject": {"chain": args.chain, "address": args.address, "symbol": args.symbol or None},
        "issued_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tool": "token-launch-scan",
        "claims": extract_claims(scan),
        "verdict": (scan.get("verdict") or [])[:20],
        "evidence": {"raw_scan_sha256": raw_sha, "raw_scan_bytes": len(canonical(scan))},
        "disclaimer": "Automated snapshot at issued_at, not an audit. Signature proves issuance and integrity, not the absence of risk.",
    }
    sig = priv.sign(canonical(payload)).hex()
    cert = {"certificate": payload, "signature": {"alg": "ed25519", "value": sig, "pubkey": pub_hex}}

    out_dir = args.out or os.path.join(os.getcwd(), "certificates", "%s-%s" % (args.chain, args.address[:8]))
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "certificate.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2, ensure_ascii=False)
    print("certificate:", path)
    print("issuer pubkey:", pub_hex)
    print("evidence sha256:", raw_sha)
    print("verify with: python verify_certificate.py %s" % path)


def main():
    ap = argparse.ArgumentParser(description="Issue metatron-cert/1 certificates")
    sub = ap.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen"); kg.add_argument("--out", default="certifier-key.json"); kg.set_defaults(fn=cmd_keygen)
    ce = sub.add_parser("certify")
    ce.add_argument("--chain", required=True); ce.add_argument("--address", required=True)
    ce.add_argument("--symbol"); ce.add_argument("--key", default="certifier-key.json"); ce.add_argument("--out")
    ce.set_defaults(fn=cmd_certify)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
