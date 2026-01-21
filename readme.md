# Shai-Hulud 1.0/2.0 Malware Scanner

[![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)](https://github.com/CyberDracula/shai-hulud-2-scanner/releases)
[![Node.js](https://img.shields.io/badge/node-%3E%3D12.0.0-brightgreen.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/CyberDracula/shai-hulud-2-scanner?style=social)](https://github.com/CyberDracula/shai-hulud-2-scanner)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](package.json)
[![Security Hardened](https://img.shields.io/badge/security-hardened-green.svg)](CHANGELOG.md#200---2025-12-01)
[![No Vulnerabilities](https://img.shields.io/badge/vulnerabilities-0-brightgreen.svg)](package.json)
[![Auditable](https://img.shields.io/badge/code-auditable-blue.svg)](scan.js)
[![Last Commit](https://img.shields.io/github/last-commit/CyberDracula/shai-hulud-2-scanner)](https://github.com/CyberDracula/shai-hulud-2-scanner/commits/main)

A forensic auditing tool designed to detect the Shai-Hulud 1.0/2.0 (and related) npm supply chain attacks. It scans local caches, global installations, and project directories against the IOCs (Indicators of Compromise) provided by Wiz Research.

## 🛡️ Security Hardening (v2.0.0)

Shai-Hulud Scanner now includes advanced security protections:

- **Symlink & Path Traversal Protection:** Prevents malicious symlinks and directory escapes during scan.
- **Resource Limits:** Enforces max memory, file count, and scan duration to avoid resource exhaustion.
- **CSV Injection Prevention:** All CSV reports are sanitized to prevent formula/code injection.
- **Sensitive Data Redaction:** API keys, user info, and secrets are never included in reports.
- **Graceful Shutdown:** If interrupted, generates a partial report with all findings up to that point.

READ THIS FOR MORE INFO: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack

## 🚀 Features

* **Zero Dependencies:** Runs on standard Node.js (v14+). No 'npm install' required. Audit the code in 1 minute.
* **Dual Threat Intelligence:** Automatically syncs with two IOC sources:
  * [Wiz Research](https://github.com/wiz-sec-public/wiz-research-iocs) - Official Shai-Hulud 2.0 packages (CSV)
  * [Hemachandsai Malicious Packages](https://github.com/hemachandsai/shai-hulud-malicious-packages) - Extended denylist (JSON)
* **Smart Caching:** IOC data is cached for 30 minutes to reduce network requests. Automatic fallback to offline data if network is unavailable.
* **Deep NVM Support:** Automatically detects NVM installations (Windows/macOS/Linux) and scans inside every installed Node version.
* **Forensic Scan:** Checks for physical malware files (setup_bun.js, bun_environment.js) regardless of version numbers.
* **Metadata Scan:** Validates installed packages against live threat intelligence feeds.
* **Ghost Detection:** Alerts on empty/broken directories that match target package names (potential failed malware installs).
* **Enterprise Reporting:** Generates a sanitized CSV report with optional centralized upload capability for organizations.
* **Case-Insensitive Detection:** Flags malware regardless of filename casing.
* **Scan Statistics:** Reports total files scanned, scan duration, and summary stats.
* **Built-in Help System:** Run with `--help` for usage instructions.
* **Environment Variable Configuration:** API keys and upload URLs can be set via environment variables for secure automation.
  
## 📋 Prerequisites

* Node.js: Installed and available in your PATH.
* Internet Connection: Required to fetch the latest IOC lists from:
  * Wiz Research IOC repository
  * Hemachandsai malicious packages database

## 🛠️ Installation

1.  Download `scan.js` to a centralized folder.
2.  Run it immediately — no installation needed!

## 🧪 Testing

To verify the scanner correctly handles scoped packages and prevents false positives:

```bash
npm test
```

This runs the test suite (`test-scoped-packages.js`) which validates:
- ✅ Scoped packages (e.g., `@babel/plugin-syntax-class-properties`) are NOT flagged when searching for unscoped malicious packages (e.g., `syntax-class-properties`)
- ✅ Actual malicious packages are correctly detected
- ✅ Package name matching is exact (no substring matching)

## 🏃Usage

You can run the script directly with Node, or use the provided helper scripts.

### Full System Scan (Default)

Scans all system caches (npm, Yarn, pnpm, NVM) and the current directory. **Generates a local CSV report only.**

    node scan.js

### Project-Only Scan

Pass a path to scan **only that specific project directory** (skips system caches for faster scanning):

    node scan.js C:\Projects\MyApp
    or
    node scan.js /home/user/projects/myapp

### Full System Scan with Custom Path

To scan both system caches AND a specific directory, use the `--full-scan` flag:

    node scan.js C:\Projects\MyApp --full-scan
    or
    node scan.js /home/user/projects/myapp --full-scan

### Advanced Options

**Bypass Cache (Force Fresh Download)**

IOC data is cached for 30 minutes. To force a fresh download:

    node scan.js --no-cache

**Set API Keys/Upload URLs via Environment Variables**

For secure automation, you can set the following environment variables:

    export SHAI_HULUD_API_KEY="your-secure-api-key"
    export SHAI_HULUD_UPLOAD_URL="https://your-company-api.example.com/upload"

These override the defaults in `scan.js` and are recommended for CI/CD.

#### Limit Directory Traversal Depth

Control how deep the scanner traverses directories (default: 5). Useful to speed up scans or focus locally:

    node scan.js --depth=3
    node scan.js C:\Projects\MyApp --full-scan --depth 7

Notes:

* Accepts `--depth=<n>` or `--depth <n>` formats
* Applies to both project-only and full-system scan modes

#### CI/CD Integration (Exit Codes)

Control when the scanner fails builds based on finding severity. By default, the scanner always exits with code 0. Use `--fail-on` to enable CI/CD mode:

    node scan.js /path/to/project --fail-on=critical

    node scan.js /path/to/project --fail-on=warning

    node scan.js /path/to/project --fail-on=off

**Modes:**

* `--fail-on=critical`: Exit code 1 only on **CRITICAL** findings (FORENSIC_MATCH, CRITICAL_SCRIPT, VERSION_MATCH, WILDCARD_MATCH, LOCKFILE_HIT, WILDCARD_LOCK_HIT)
* `--fail-on=warning`: Exit code 1 on **CRITICAL or WARNING** findings (includes SCRIPT_WARNING, GHOST_PACKAGE, CORRUPT_PACKAGE)
* `--fail-on=off`: Always exit code 0 (report only, never fail builds)

**Jenkins Example:**

```groovy
stage('Security Scan') {
    steps {
        sh 'npx @cyberdracula/shai-hulud-2-scanner /path/to/project --fail-on=critical'
    }
}
```

**GitHub Actions Example:**

```yaml
- name: Scan for Supply Chain Attacks
  run: npx @cyberdracula/shai-hulud-2-scanner /path/to/project --fail-on=critical
```

**GitLab CI Example:**

```yaml
security_scan:
  script:
    - npx @cyberdracula/shai-hulud-2-scanner /path/to/project --fail-on=critical
```

> **Note:** Without the `--fail-on` flag, the scanner maintains backwards-compatible behavior (always exits 0). This ensures existing workflows are not disrupted.

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

✅ Known False Positives (Safe to Ignore)
React Native projects: contents.json files in the ios/ folder are standard iOS asset catalog files (Xcode resources), NOT malware indicators. These are safe to ignore.
----------------------------------------------------------------

## Interpreting the Report (shai-hulud-report.csv)

The tool categorizes findings into different severity levels. Understanding what each means is critical for proper response.

| Finding Type | Severity | Description | Action Required |
|-------------|----------|-------------|-----------------|
| **FORENSIC_MATCH** | 🔴 **CRITICAL** | High-confidence malware files (setup_bun.js, bun_environment.js, truffleSecrets.json, actionsSecrets.json, .github/workflows/discussion.yml) found with no content verification needed | ⚠️ **SYSTEM COMPROMISED.** See emergency response steps below. |
| **FORENSIC_ARTIFACT** | 🟠 **HIGH** | Suspicious file detected (bundle.js, contents.json, cloud.json, environment.json) that matches malicious content signatures after deep inspection | Investigate file origin. If legitimate (e.g., React Native contents.json), mark as safe. Otherwise, remove immediately. |
| **WILDCARD_MATCH** | 🔴 **CRITICAL** | Package matches a strict denylist where ALL versions are malicious. | ⚠️ **DELETE IMMEDIATELY.** Follow remediation steps below. |
| **CRITICAL_SCRIPT** | 🔴 **CRITICAL** | Install/preinstall/postinstall script contains high-confidence malicious behavior (e.g., piping remote code to shell, base64→sh chains, privileged Docker flags, workflow backdoor files) | ⚠️ **ACTION NEEDED** Treat as incident: isolate host, remove package, rotate credentials, investigate lateral movement. |
| **VERSION_MATCH** | 🟠 **HIGH** | Package name and version match the known infected list | Uninstall package. Check lockfiles. Clear caches. |
| **LOCKFILE_HIT** | 🟠 **HIGH** | Malicious version is locked in package-lock.json/yarn.lock - will auto-install on every `npm install` | ⚠️ **CRITICAL FOR CI/CD.** Delete lockfile, remove package, regenerate. |
| **WILDCARD_LOCK_HIT** | 🟠 **HIGH** | Lockfile contains a dependency that is known malware (any version). | Delete lockfile, remove dependency, regenerate with safe versions. |
| **GHOST_PACKAGE** | 🟡 **WARNING** | Folder exists with a targeted name, but is empty/broken | Investigate manually. Likely a failed install or cleanup artifact. |
| **SCRIPT_WARNING** | 🟡 **WARNING** | Install/preinstall/postinstall script has suspicious indicators (e.g., obfuscation via Buffer/Base64, dynamic Function(), GitHub API/artifact usage, `nc`/`socat`) | Review and validate script intent. If not business-critical, remove or pin safe version; open a security ticket. |
| **SAFE_MATCH** | 🔵 **INFO** | Package name matches a target, but the version is safe | No action needed. Logged for audit purposes. |

> **Side Note for FORENSIC_MATCH:**
> This finding can sometimes generate false positives (except setup_bun.js, bun_environment.js). Please verify if the found file is expected to be present (e.g., part of your own code or a legitimate tool). If unsure, investigate the file's origin and contents before taking action.

> **CSV Report Security:**
> All CSV reports are sanitized to prevent formula/code injection. Sensitive data (API keys, user info) is never included in the report.

> **Partial Reports:**
> If the scan is interrupted, a partial report is generated with all findings up to that point.

### Behavioral Heuristics (Install Script Scanner)

The scanner analyzes common lifecycle hooks (`preinstall`, `install`, `postinstall`, `prepublish`, `prepare`) and flags:

* High-confidence malicious patterns: piping remote content to shell, base64→shell chains, Docker `--privileged` and host mounts, workflow backdoor files
* Suspicious indicators: obfuscation via `Buffer.from(..., 'hex'|'base64')`, dynamic `Function(...)`, GitHub API/artifact usage, backdoor primitives (`nc`, `socat`)
* Whitelisted safe scripts: typical tooling like `tsc`, `node-gyp`, `prebuild-install`, `opencollective-postinstall`, `electron-builder install-app-deps`, `lerna bootstrap`, `nx/turbo run`, `esbuild`

#### Indicators (What you may see in `Issue_Type` and `Details`)

The scanner emits normalized indicator tags to help triage:

* `REMOTE_CODE_EXEC`: Downloading or piping remote content into shell; subshell/backtick curl/wget; `bash -c` with network fetch
* `OBFUSCATION`: Base64/hex decoding, `String.fromCharCode`, escape sequences, packed or encoded payloads
* `CODE_INJECTION`: `eval`, `Function(...)`, direct `child_process` execution, sync exec/spawn usage
* `SHAI_HULUD`: References to loader or payload artifacts (`setup_bun`, `bun_environment`, signature tokens)
* `PERSISTENCE`: CI/CD workflow backdoor files (e.g., `.github/workflows/discussion.yml`)
* `PRIV_ESC`: Docker `--privileged` runs or host filesystem mounts (`-v /:/host`)
* `INSECURE_NETWORK`: Plain `http://` network calls in install-time scripts
* `EXFIL_ATTEMPT`: GitHub API interactions or Actions artifact uploads from lifecycle scripts
* `BACKDOOR_PRIMITIVE`: Use of `nc` or `socat` for reverse shells or listeners

### 🚨 Emergency Response Steps (If FORENSIC_MATCH or WILDCARD_MATCH Found)

**Your system has been compromised. The malware may have already stolen credentials.**

#### 1. Immediate Actions

**Windows (PowerShell):**

```powershell
# Stop all package managers and builds
Stop-Process -Name node, npm, yarn, pnpm -Force -ErrorAction SilentlyContinue

# Clear all caches
npm cache clean --force
yarn cache clean --all
pnpm store prune
Remove-Item node_modules -Recurse -Force -ErrorAction SilentlyContinue
```

**macOS/Linux (Bash):**

```bash
# Stop all package managers and builds
killall -9 node npm yarn pnpm 2>/dev/null

# Clear all caches
npm cache clean --force
yarn cache clean --all
pnpm store prune
rm -rf node_modules
```

#### 2. Check for Backdoors

**Windows (PowerShell):**

```powershell
# Look for malicious GitHub workflows
Get-ChildItem -Path .github\workflows -Filter "discussion.yaml" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path .github\workflows -Filter "formatter_*.yml" -Recurse -ErrorAction SilentlyContinue
```

**macOS/Linux (Bash):**

```bash
# Look for malicious GitHub workflows
find .github/workflows -name "discussion.yaml" 2>/dev/null
find .github/workflows -name "formatter_*.yml" 2>/dev/null
```

**Check for self-hosted runners (named "SHA1HULUD"):**

Visit: `https://github.com/<your-org>/<repo>/settings/actions/runners`

#### 3. Rotate ALL Credentials (Assume Breach)

The malware targets these secrets:

- **GitHub:** Personal Access Tokens (PATs), deploy keys, Actions secrets
- **Cloud Providers:** AWS credentials (AKIA keys), GCP service accounts, Azure tokens
- **Package Managers:** npm tokens, registry credentials
- **Environment Variables:** All API keys, database passwords, service tokens
- **SSH Keys:** Regenerate all SSH keys that were on the infected machine

#### 4. Search for Exposed Secrets

Your credentials may have been published to public GitHub repositories:

```powershell
# Search GitHub for your organization's exposed data
# Visit: https://github.com/search?q="Shai-Hulud"+OR+"SHA1-HULUD"+"<your-org-name>"&type=repositories
```

**⚠️ Cross-Victim Exposure:** Your secrets may appear in repositories owned by OTHER victims. You must search broadly.

#### 5. Clean and Rebuild

**Windows (PowerShell):**

```powershell
# Remove lockfiles
Remove-Item package-lock.json, yarn.lock, npm-shrinkwrap.json -ErrorAction SilentlyContinue

# Remove the malicious package from package.json (manually edit)

# Reinstall with safe versions
npm install

# Verify no malware files remain
Get-ChildItem -Recurse -Include setup_bun.js, bun_environment.js, truffleSecrets.json, cloud.json, contents.json, environment.json, actionsSecrets.json
```

**macOS/Linux (Bash):**

```bash
# Remove lockfiles
rm -f package-lock.json yarn.lock npm-shrinkwrap.json

# Remove the malicious package from package.json (manually edit)

# Reinstall with safe versions
npm install

# Verify no malware files remain
find . -type f \( -name "setup_bun.js" -o -name "bun_environment.js" -o -name "truffleSecrets.json" -o -name "cloud.json" -o -name "contents.json" -o -name "environment.json" -o -name "actionsSecrets.json" \)
```

#### 6. CI/CD Pipeline Review

**LOCKFILE_HIT is especially dangerous in CI/CD environments:**

- Malware executes during `preinstall` (before your code runs)
- Runs synchronously in CI (blocks until complete exfiltration)
- May attempt Docker privilege escalation
- Can modify sudoers for persistent root access

**Action:** Review all CI/CD logs from the past 30 days for:
- Unexpected network connections
- Failed privilege escalation attempts
- New GitHub runners registered
- Unusual workflow executions

### Understanding LOCKFILE_HIT Risk

When found in **both project and cache**, this means:

1. **Automatic Reinfection:** Every `npm install` will reinstall the malware
2. **Team-Wide Exposure:** All developers who clone the repo will be infected
3. **CI/CD Compromise:** Every pipeline run will execute the malware
4. **Container Builds:** Every Docker build will be compromised

**The lockfile acts as a time bomb** - the malware will keep coming back until you remove it from the lockfile AND rotate all credentials.

## 🔄 Updating Offline Fallback Files

The scanner includes offline fallback IOC files in the `fallback/` directory. To keep them current:

```bash
node update-fallbacks.js
```

This utility:
- Downloads the latest threat intelligence from both sources
- Shows current file status (age and size)
- Updates the fallback files used when offline
- Run this periodically to maintain up-to-date offline data

## Disclaimer

This tool is provided "as is" to assist in detection. It relies on public IOCs from Wiz Research. False negatives are possible if the malware authors change file names or package versions. Always perform manual verification on critical systems.

## Contributing

Contributions are welcome! Please submit issues or pull requests on the GitHub repository.

## Contributors

Special thanks to everyone who has contributed to the Shai-Hulud 2.0 Scanner project:

- MaSMas0 (https://github.com/MaSMas0) — Security hardening in 2.0
- Hemachandsai (malicious package IOC feed)
- Wiz Research (threat intelligence)
