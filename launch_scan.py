#!/usr/bin/env python3
"""launch_scan.py - free launch-safety snapshot for a token (EVM + Solana).
Usage:
  python launch_scan.py --chain base --address 0x...        [--out report.md] [--json]
Sources: gopluslabs.io, honeypot.is (EVM); rugcheck.xyz (Solana). No API keys.
"""
import argparse, json, sys, urllib.request

UA = {"User-Agent": "Mozilla/5.0 (research; launch-scan)"}

def get(url, timeout=25):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))

GOPLUS = {"ethereum": "1", "bsc": "56", "base": "8453", "arbitrum": "42161", "polygon": "137"}
HONEY = {"ethereum": "1", "bsc": "56", "base": "8453", "arbitrum": "42161"}

def evm_scan(chain, addr):
    out = {"chain": chain, "address": addr}
    try:
        d = get("https://api.gopluslabs.io/api/v1/token_security/%s?contract_addresses=%s" % (GOPLUS[chain], addr))
        info = (d.get("result") or {}).get(addr.lower()) or {}
        if info:
            out["goplus"] = {
                "is_mintable": info.get("is_mintable"),
                "owner": info.get("owner_address"),
                "can_take_back_ownership": info.get("can_take_back_ownership"),
                "is_proxy": info.get("is_proxy"),
                "is_honeypot": info.get("is_honeypot"),
                "buy_tax": info.get("buy_tax"),
                "sell_tax": info.get("sell_tax"),
                "transfer_pausable": info.get("transfer_pausable"),
                "cannot_sell_all": info.get("cannot_sell_all"),
                "is_blacklisted": info.get("is_blacklisted"),
                "holder_count": info.get("holder_count"),
                "creator_percent": info.get("creator_percent"),
                "lp_holder_count": info.get("lp_holder_count"),
                "lp_total_supply": info.get("lp_total_supply"),
                "holders": [{"pct": h.get("percent"), "addr": (h.get("address") or "")[:10], "tag": h.get("tag")} for h in (info.get("holders") or [])[:8]],
                "dex": [x.get("name") for x in (info.get("dex") or [])][:4],
            }
    except Exception as e:
        out["goplus_err"] = str(e)[:140]
    try:
        h = get("https://api.honeypot.is/v2/IsHoneypot?address=%s&chainID=%s" % (addr, HONEY[chain]))
        out["honeypot"] = {
            "is_honeypot": (h.get("honeypotResult") or {}).get("isHoneypot"),
            "risk_level": (h.get("summary") or {}).get("riskLevel"),
            "buy_tax": (h.get("simulationResult") or {}).get("buyTax"),
            "sell_tax": (h.get("simulationResult") or {}).get("sellTax"),
            "flags": [f.get("flag") for f in ((h.get("summary") or {}).get("flags") or [])][:8],
        }
    except Exception as e:
        out["honeypot_err"] = str(e)[:140]
    return out

def sol_scan(addr):
    out = {"chain": "solana", "address": addr}
    try:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
                           "params": [addr, {"encoding": "jsonParsed"}]}).encode()
        req = urllib.request.Request("https://api.mainnet-beta.solana.com", data=body,
                                     headers={"Content-Type": "application/json", **UA})
        with urllib.request.urlopen(req, timeout=25) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
        val = (d.get("result") or {}).get("value") or {}
        info = ((val.get("data") or {}).get("parsed") or {}).get("info") or {}
        out["rpc"] = {"mintAuthority": info.get("mintAuthority"), "freezeAuthority": info.get("freezeAuthority"),
                      "supply": info.get("supply"), "decimals": info.get("decimals")}
        if not val:
            out["rpc_note"] = "account not found on-chain"
    except Exception as e:
        out["rpc_err"] = str(e)[:140]
    try:
        r = get("https://api.rugcheck.xyz/v1/tokens/%s/report" % addr)
        out["rugcheck"] = {
            "score_normalised": r.get("score_normalised"),
            "risks": [{"name": x.get("name"), "level": x.get("level")} for x in (r.get("risks") or [])][:12],
            "totalHolders": r.get("totalHolders"),
            "topHolders": [{"pct": h.get("pct"), "insider": h.get("insider")} for h in (r.get("topHolders") or [])][:8],
        }
    except Exception as e:
        out["rugcheck_note"] = str(e)[:90]
    return out

def verdict_lines(scan):
    lines = []
    g = scan.get("goplus") or {}
    h = scan.get("honeypot") or {}
    rc = scan.get("rugcheck")
    rpc = scan.get("rpc")
    if rpc:
        if rpc.get("mintAuthority"): lines.append("RED: Solana mint authority still set (%s...)" % str(rpc.get("mintAuthority"))[:6])
        else: lines.append("GREEN: Solana mint authority renounced")
        if rpc.get("freezeAuthority"): lines.append("AMBER: freeze authority set")
        else: lines.append("GREEN: no freeze authority")
    if g:
        if g.get("is_mintable") == "1": lines.append("RED: mint function active (supply can be inflated)")
        if g.get("can_take_back_ownership") == "1": lines.append("RED: ownership can be reclaimed after renounce")
        if g.get("transfer_pausable") == "1": lines.append("RED: transfers can be paused")
        if g.get("cannot_sell_all") == "1": lines.append("RED: cannot-sell-all flag (sell limiter)")
        if g.get("is_blacklisted") == "1": lines.append("RED: blacklist function present")
        if g.get("is_honeypot") == "1": lines.append("RED: GoPlus flags honeypot")
        bt, st = g.get("buy_tax"), g.get("sell_tax")
        try:
            if bt is not None and float(bt) > 0.10: lines.append("AMBER: buy tax %s" % bt)
            if st is not None and float(st) > 0.10: lines.append("AMBER: sell tax %s" % st)
        except Exception: pass
        if g.get("owner") in (None, "", "0x0000000000000000000000000000000000000000", "0x000000000000000000000000000000000000dead"):
            lines.append("GREEN: owner renounced/none")
        if g.get("lp_holder_count") not in (None, ""):
            lines.append("INFO: LP holders: %s" % g.get("lp_holder_count"))
    if h:
        if h.get("is_honeypot") is True: lines.append("RED: honeypot simulation says honeypot")
        if h.get("risk_level"): lines.append("INFO: honeypot.is risk level: %s" % h.get("risk_level"))
    if rc:
        if rc.get("mintAuthority"): lines.append("RED: Solana mint authority still set")
        if rc.get("freezeAuthority"): lines.append("AMBER: freeze authority set")
        for r in (rc.get("risks") or []):
            lv = (r.get("level") or "").lower()
            if lv in ("danger", "warn"):
                lines.append(("%s: %s" % ("RED" if lv == "danger" else "AMBER", r.get("name"))))
        if rc.get("score_normalised") is not None:
            lines.append("INFO: rugcheck score (higher=riskier): %s" % rc.get("score_normalised"))
    return lines

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", required=True, choices=["ethereum", "base", "bsc", "arbitrum", "polygon", "solana"])
    ap.add_argument("--address", required=True)
    ap.add_argument("--out")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    scan = sol_scan(a.address) if a.chain == "solana" else evm_scan(a.chain, a.address)
    scan["verdict"] = verdict_lines(scan)
    txt = json.dumps(scan, indent=2) if a.json else ("# Launch scan: %s (%s)\n\n" % (a.address, a.chain) + "\n".join("- " + v for v in scan["verdict"]) + "\n\n```json\n" + json.dumps({k: v for k, v in scan.items() if k != "verdict"}, indent=2)[:4000] + "\n```")
    print(txt)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(txt)

if __name__ == "__main__":
    main()
