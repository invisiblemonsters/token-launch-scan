# token-launch-scan

Free, no-API-key launch-safety snapshot for EVM and Solana tokens.

Before you ape into a fresh launch — or before you blast one to your community — this gives you the raw safety picture: authorities, ownership, sell behavior, taxes, and who actually holds the supply.

## Checks

| Area | What it covers |
|---|---|
| Authorities | Mint authority, freeze authority (Solana RPC direct reads) |
| Ownership | Renouncement status, reclaimable ownership, proxy/upgradeable contracts |
| Trading safety | Honeypot simulation (can holders actually sell?), blacklist capability, pausable transfers |
| Taxes | Buy/sell tax simulation |
| Distribution | Top-holder concentration, deployer holdings, LP holder count |
| Flags | RugCheck risk report for Solana tokens |

Data sources: [GoPlus](https://gopluslabs.io), [honeypot.is](https://honeypot.is), [RugCheck](https://rugcheck.xyz), and direct chain RPC. No API keys. No black-box scores — you get facts.

## Usage

```bash
python launch_scan.py --chain base --address 0x... # human-readable summary
python launch_scan.py --chain solana --address ... --json   # machine-readable
python launch_scan.py --chain ethereum --address 0x... --out report.md
```

Supported chains: `ethereum`, `base`, `bsc`, `arbitrum`, `polygon`, `solana`.

## What this is not

This is an automated snapshot, **not a security audit**. On-chain state can change at any time (the deployer can flip switches after you scan). Verify findings against the raw JSON before acting on them.

## Need more than a snapshot?

For a human-verified review — plain-English findings, severity ranking, and fix list for your team — see the services below. We run this same tooling plus a manual pass, delivered as a client-ready report within 24h.

- Services & reviews: https://invisiblemonsters.github.io/
- Industry data report (2,448 launches screened): https://invisiblemonsters.github.io/state-of-token-safety.html
- Token launch review: https://laborx.com/gigs/i-will-run-a-24h-token-launch-safety-review-mint-lp-honeypot-holders-121820
- Contact: metatron.backup2026@tutamail.com

## License

MIT — use it, fork it, ship it. Attribution appreciated but not required.
