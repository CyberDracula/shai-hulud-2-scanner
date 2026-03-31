# Fallback IOC Files

This directory contains offline fallback versions of the threat intelligence feeds.

## Purpose

If the scanner cannot reach the remote IOC sources (network issues, rate limits, etc.), it will automatically fall back to these files to ensure scanning can still proceed.

## Files

- `wiz-iocs.csv` - Offline copy of Wiz Research IOCs (Shai-Hulud 2.0 campaign)
- `malicious-packages.json` - Offline copy of Hemachandsai malicious package list
- `canisterworm-packages.csv` - CanisterWorm / TeamPCP IOC list (66 packages, 141+ malicious versions)
- `custom-iocs.txt` - Optional local IOC list you maintain manually (supports `package`, `package@version`, and CSV-style `package,version`)

## Maintenance

These files should be updated periodically to ensure the fallback data remains current. Run:

```
node update-fallbacks.js
```

This updates the Wiz and Hemachandsai feeds automatically. The CanisterWorm CSV must be updated manually (see below).

For Wiz and Hemachandsai, you can also download directly from:

- Wiz Research: https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv
- Hemachandsai: https://raw.githubusercontent.com/hemachandsai/shai-hulud-malicious-packages/main/malicious_npm_packages.json

## CanisterWorm IOC Notes

The `canisterworm-packages.csv` file is the **authoritative offline source** for CanisterWorm. It was compiled from:
- Socket Research Team (March 20, 2026): https://socket.dev/blog/canisterworm-npm-publisher-compromise-deploys-backdoor-across-29-packages
- Endor Labs (March 21, 2026): https://www.endorlabs.com/learn/canisterworm

### Keeping it current

The CanisterWorm live feed is hosted at [socket.dev/supply-chain-attacks/canisterworm](https://socket.dev/supply-chain-attacks/canisterworm) but is protected by Cloudflare and cannot be downloaded programmatically with a plain HTTPS request. To update it, choose one of:

1. **Automated (recommended)** — use the Playwright-based fetcher in this folder:

   ```bash
   # One-time setup (installs only into fallback/node_modules — not the main project)
   cd fallback
   npm install
   npx playwright install chromium

   # Fetch latest IOCs (run from repo root)
   node fallback/tools/fetch-canisterworm.js

   # Debug mode (opens a visible browser window)
   node fallback/tools/fetch-canisterworm.js --headed
   ```

   See [fetch-canisterworm.js](./fetch-canisterworm.js) for full options (`--out`, `--timeout`).

2. **Pull this repo** — the bundled CSV is kept up to date with each release.
3. **Download manually** — go to https://socket.dev/supply-chain-attacks/canisterworm, click **Download CSV**, and replace this file with the downloaded copy.

The scanner will automatically cache downloaded data for 30 minutes to reduce network requests.
