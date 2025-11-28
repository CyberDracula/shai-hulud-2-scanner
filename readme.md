# Shai-Hulud 2.0 Malware Scanner

A forensic auditing tool designed to detect the Shai-Hulud 2.0 (and related) npm supply chain attacks. It scans local caches, global installations, and project directories against the IOCs (Indicators of Compromise) provided by Wiz Research.

READ THIS FOR MORE INFO: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack

## 🚀 Features

* No npm install required. Zero dependencies. Audit the code in 1 minute.
* Zero Dependencies: Runs on standard Node.js (v14+). No 'npm install' required.
* Deep NVM Support: Automatically detects NVM installations (Windows/macOS/Linux) and scans inside every installed Node version.
* Forensic Scan: Checks for physical malware files (setup_bun.js, bun_environment.js) regardless of version numbers.
* Metadata Scan: Compares installed packages against the live Wiz.io IOC CSV list.
* Ghost Detection: Alerts on empty/broken directories that match target package names (potential failed malware installs).
* **Reporting:** Generates a CSV report and **automatically uploads** it to the security API.
  
## 📋 Prerequisites

* Node.js: Installed and available in your PATH.
* Internet Connection: Required to fetch the latest IOC list from GitHub.

## 🛠️ Installation

1.  Download `scan.js` to a centralized folder.
2.  (Optional) Edit the configuration at the top of the file to add your API endpoint:
    ```javascript
    const UPLOAD_API_URL = 'https://your-lambda-url...';
    const API_KEY = 'your-secure-key';
    ```

## 🏃Usage

You can run the script directly with Node, or use the provided helper scripts.

### Basic Scan
Scans system caches (npm, Yarn, pnpm, NVM) and the current directory.

    node scan.js

### Scan Specific Directory
Pass a path to scan a specific project or drive location.

    node scan.js C:\Projects\MyApp

### Scan & Upload Report
If you want to generate the CSV locally without sending it to the API, use the flag:

    node scan.js --no-upload

----------------------------------------------------------------

## Interpreting the Report (shai-hulud-report.csv)

The tool categorizes findings into five types:

| Finding Type | Severity | Description | Action Required |
|-------------|----------|-------------|-----------------|
| **FORENSIC_MATCH** | 🔴 **CRITICAL** | Actual malware files (setup_bun.js) were found on disk | ⚠️ **DELETE IMMEDIATELY.** Rotate secrets. |
| **VERSION_MATCH** | 🟠 **HIGH** | Package name and version match the known infected list | Uninstall package. Check package-lock.json. |
| **LOCKFILE_HIT** | 🟠 **HIGH** | The compromised version is defined in your lockfile, meaning it will be installed next time you run npm install | Delete package-lock.json and run 'npm install' to regenerate it with safe versions. |
| **GHOST_PACKAGE** | 🟡 **WARNING** | Folder exists with a targeted name, but is empty/broken | Investigate manually. Likely a failed install or artifact. |
| **SAFE_MATCH** | 🔵 **INFO** | Package name matches a target, but the version is safe | No action needed. Logged for audit purposes. |

## Disclaimer

This tool is provided "as is" to assist in detection. It relies on public IOCs from Wiz Research. False negatives are possible if the malware authors change file names or package versions. Always perform manual verification on critical systems.

