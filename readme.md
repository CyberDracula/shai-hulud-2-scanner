# Shai-Hulud 1.0/2.0 Malware Scanner

A forensic auditing tool designed to detect the Shai-Hulud 1.0/2.0 (and related) npm supply chain attacks. It scans local caches, global installations, and project directories against the IOCs (Indicators of Compromise) provided by Wiz Research.

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

The tool categorizes findings into different severity levels. Understanding what each means is critical for proper response.

| Finding Type | Severity | Description | Action Required |
|-------------|----------|-------------|-----------------|
| **FORENSIC_MATCH** | 🔴 **CRITICAL** | Actual malware files (setup_bun.js, bun_environment.js) were found on disk | ⚠️ **SYSTEM COMPROMISED.** See emergency response steps below. |
| **WILDCARD_MATCH** | 🔴 **CRITICAL** | Package matches a strict denylist where ALL versions are malicious. | ⚠️ **DELETE IMMEDIATELY.** Follow remediation steps below. |
| **VERSION_MATCH** | 🟠 **HIGH** | Package name and version match the known infected list | Uninstall package. Check lockfiles. Clear caches. |
| **LOCKFILE_HIT** | 🟠 **HIGH** | Malicious version is locked in package-lock.json/yarn.lock - will auto-install on every `npm install` | ⚠️ **CRITICAL FOR CI/CD.** Delete lockfile, remove package, regenerate. |
| **WILDCARD_LOCK_HIT** | 🟠 **HIGH** | Lockfile contains a dependency that is known malware (any version). | Delete lockfile, remove dependency, regenerate with safe versions. |
| **GHOST_PACKAGE** | 🟡 **WARNING** | Folder exists with a targeted name, but is empty/broken | Investigate manually. Likely a failed install or cleanup artifact. |
| **SAFE_MATCH** | 🔵 **INFO** | Package name matches a target, but the version is safe | No action needed. Logged for audit purposes. |

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