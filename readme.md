# Shai-Hulud 2.0 Malware Scanner

A forensic auditing tool designed to detect the Shai-Hulud 2.0 (and related) npm supply chain attacks. It scans local caches, global installations, and project directories against the IOCs (Indicators of Compromise) provided by Wiz Research.

READ THIS FOR MORE INFO: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack

## 🚀 Features

* **Zero Dependencies:** Runs on standard Node.js (v14+). No 'npm install' required. Audit the code in 1 minute.
* **Dual Threat Intelligence:** Automatically syncs with two IOC sources:
  * [Wiz Research](https://github.com/wiz-sec-public/wiz-research-iocs) - Official Shai-Hulud 2.0 packages (CSV)
  * [Hemachandsai Malicious Packages](https://github.com/hemachandsai/shai-hulud-malicious-packages) - Extended denylist (JSON)
* **Deep NVM Support:** Automatically detects NVM installations (Windows/macOS/Linux) and scans inside every installed Node version.
* **Forensic Scan:** Checks for physical malware files (setup_bun.js, bun_environment.js) regardless of version numbers.
* **Metadata Scan:** Validates installed packages against live threat intelligence feeds.
* **Ghost Detection:** Alerts on empty/broken directories that match target package names (potential failed malware installs).
* **Enterprise Reporting:** Generates a CSV report with optional centralized upload capability for organizations.
  
## 📋 Prerequisites

* Node.js: Installed and available in your PATH.
* Internet Connection: Required to fetch the latest IOC lists from:
  * Wiz Research IOC repository
  * Hemachandsai malicious packages database

## 🛠️ Installation

1.  Download `scan.js` to a centralized folder.
2.  Run it immediately — no installation needed!

## 🏃Usage

You can run the script directly with Node, or use the provided helper scripts.

### Full System Scan (Default)

Scans all system caches (npm, Yarn, pnpm, NVM) and the current directory. **Generates a local CSV report only.**

    node scan.js

### Project-Only Scan

Pass a path to scan **only that specific project directory** (skips system caches for faster scanning):

    node scan.js C:\Projects\MyApp

### Full System Scan with Custom Path

To scan both system caches AND a specific directory, use the `--full-scan` flag:

    node scan.js C:\Projects\MyApp --full-scan

### Optional: Organization Reporting

**For companies/organizations only:** If you want to centrally aggregate scan results across multiple machines, you can configure automatic report uploads:

1. Edit the configuration at the top of `scan.js`:

    ```javascript
    const UPLOAD_API_URL = 'https://your-company-api.example.com/upload';
    const API_KEY = 'your-secure-api-key';
    ```

2. Run the scan normally — reports will be uploaded automatically.

3. To disable uploads and only generate local CSV:

    ```bash
    node scan.js --no-upload
    ```

> **Note:** By default, reports are saved locally as `shai-hulud-report.csv`. No data is uploaded unless you explicitly configure an API endpoint.

----------------------------------------------------------------

## Interpreting the Report (shai-hulud-report.csv)

The tool categorizes findings into five types:

| Finding Type | Severity | Description | Action Required |
|-------------|----------|-------------|-----------------|
| **FORENSIC_MATCH** | 🔴 **CRITICAL** | Actual malware files (setup_bun.js) were found on disk | ⚠️ **DELETE IMMEDIATELY.** Rotate secrets. |
| **WILDCARD_MATCH** | 🔴 **CRITICAL** | Package matches a strict denylist where all versions are malicious. | ⚠️ **DELETE IMMEDIATELY.** |
| **VERSION_MATCH** | 🟠 **HIGH** | Package name and version match the known infected list | Uninstall package. Check package-lock.json. |
| **LOCKFILE_HIT** | 🟠 **HIGH** | The compromised version is defined in your lockfile, meaning it will be installed next time you run npm install | Delete package-lock.json and run 'npm install' to regenerate it with safe versions. |
| **WILDCARD_LOCK_HIT** | 🟠 **HIGH** | Lockfile contains a dependency that is known malware (any version). | Delete `package-lock.json` & remove dependency. |
| **GHOST_PACKAGE** | 🟡 **WARNING** | Folder exists with a targeted name, but is empty/broken | Investigate manually. Likely a failed install or artifact. |
| **SAFE_MATCH** | 🔵 **INFO** | Package name matches a target, but the version is safe | No action needed. Logged for audit purposes. |

## Disclaimer

This tool is provided "as is" to assist in detection. It relies on public IOCs from Wiz Research. False negatives are possible if the malware authors change file names or package versions. Always perform manual verification on critical systems.

## Contributing
Contributions are welcome! Please submit issues or pull requests on the GitHub repository.