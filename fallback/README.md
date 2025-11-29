# Fallback IOC Files

This directory contains offline fallback versions of the threat intelligence feeds.

## Purpose

If the scanner cannot reach the remote IOC sources (network issues, rate limits, etc.), it will automatically fall back to these files to ensure scanning can still proceed.

## Files

- `wiz-iocs.csv` - Offline copy of Wiz Research IOCs
- `malicious-packages.json` - Offline copy of Hemachandsai malicious packages

## Maintenance

These files should be updated periodically to ensure the fallback data remains current. You can manually download the latest versions from:

- Wiz Research: https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv
- Hemachandsai: https://raw.githubusercontent.com/hemachandsai/shai-hulud-malicious-packages/main/malicious_npm_packages.json

The scanner will automatically cache downloaded data for 30 minutes to reduce network requests.
