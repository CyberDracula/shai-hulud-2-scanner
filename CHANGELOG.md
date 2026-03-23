# Changelog

All notable changes to the Shai-Hulud 1.0/2.0 Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-03-23

### Added

- **CanisterWorm / TeamPCP Campaign Detection** (March 2026 supply chain worm)
  - New **Source 3** IOC feed for CanisterWorm in `fetchThreats()` — loaded from bundled `fallback/canisterworm-packages.csv` (socket.dev live feed cannot be fetched programmatically due to Cloudflare; update by pulling this repo or downloading the CSV manually)
  - Bundled fallback file `fallback/canisterworm-packages.csv` with **66 malicious packages / 141+ versions** compiled from Socket Research Team and Endor Labs reporting
  - New `FORENSIC_RULES` entry for `scripts/deploy.js`: flags the CanisterWorm worm republishing script by detecting the `/-/whoami` npm API call (content-verified, bounded regex)
  - New `CRITICAL_PATTERNS` entries for CanisterWorm behavioral indicators (all bounded, ReDoS-safe):
    - `tdtqy-oyaaa-aaaae-af2dq-cai.*.icp0.io` — ICP blockchain canister C2 identifier
    - `raw.icp0.io` — Internet Computer Protocol C2 channel
    - `systemctl --user enable|start pgmon` — pgmon persistence service install
    - `pgmon.service` — pgmon service file reference
    - `/tmp/pglog` — secondary payload drop path
    - `.local/share/pgmon` — Python implant installation path

- **Campaign Tagging in Reports**
  - All `detectedIssues` objects now carry a `campaign` field (`CANISTERWORM`, `SHAI_HULUD_2`, or empty)
  - CSV report gains a new **`Campaign`** column (inserted after `Issue_Type`) for easy filtering in spreadsheet tools
  - `campaignMap` (module-level Map) populated at IOC-load time; CanisterWorm entries take precedence over any prior Shai-Hulud tag for the same package

- **CanisterWorm Incident Response Advisory**
  - New `printCanisterWormAdvisory()` function automatically called when CanisterWorm findings are detected
  - Outputs 6-step remediation guidance (check `/tmp/pglog`, revoke npm tokens, stop pgmon service, clean deps, check for worm-republished packages) — adapted from security team advisories

- **`update-fallbacks.js` extended**
  - Now updates Wiz and Hemachandsai feeds automatically and prints a manual-update notice for `canisterworm-packages.csv` (download from socket.dev or pull latest release)

### Changed

- Scanner banner updated to `Shai-Hulud 2.0 / CanisterWorm Detector (v2.2.0)`
- `fetchThreats()` step label updated from `Dual Feed` to `Triple Feed`
- Scanner version string updated to `2.2.0`

## [2.1.0] - 2025-12-03

### Fixed

- **Node.js Compatibility**
  - Removed optional chaining operators (`?.`)

### Added

- **Severity-Based Alerting**
  - To address the false/positive issues, forensic detections now differentiate between confirmed malware and suspicious artifacts
  - `CRITICAL` severity (setup_bun.js, truffleSecrets.json, etc.):
    - Red console output with `[!!!]` prefix
    - Report type: `FORENSIC_MATCH`
    - Label: "CRITICAL: MALWARE FILE FOUND"
  - `HIGH` severity (bundle.js, contents.json with malicious patterns):
    - Yellow console output with `[??]` prefix  
    - Report type: `FORENSIC_ARTIFACT`
    - Label: "SUSPICIOUS: Artifact Found"
  - Provides better visibility into detection confidence levels
  - Files matching forensic rules but verified as benign are now logged as `SAFE_MATCH`

## [2.0.0] - 2025-12-01

### Security

- **CRITICAL: Removed Hardcoded Credentials** (CWE-798)
  - API key and URL now read from environment variables (`SHAI_HULUD_API_KEY`, `SHAI_HULUD_API_URL`)
  - Eliminates credential exposure in source code and version control

- **CRITICAL: CSV Injection Prevention** (CWE-1236)
  - Added `escapeCSV()` function to sanitize all user-controlled fields
  - Prefixes dangerous characters (`=`, `+`, `-`, `@`, `\t`, `\r`) with single quote
  - Prevents formula injection attacks when reports are opened in spreadsheet applications

- **CRITICAL: ReDoS Mitigation** (CWE-1333)
  - Replaced all unbounded regex quantifiers (`.*`, `.+`) with bounded versions
  - Example: `curl\s+.*\|` → `curl\s+[^\s|]{1,500}\s*\|`
  - Prevents catastrophic backtracking on malicious input

- **CRITICAL: Symlink Attack Protection** (CWE-59)
  - Added `checkSymlink()` with configurable depth limiting (`MAX_SYMLINK_DEPTH: 3`)
  - Prevents directory traversal via symlink chains
  - Tracks and reports skipped symlinks in scan statistics

- **HIGH: Path Traversal Prevention** (CWE-22)
  - Added `validatePath()` function for all path inputs
  - Rejects null bytes, enforces max path length (4096 chars)
  - Optional base directory confinement validation

- **HIGH: TOCTOU Race Condition Mitigation** (CWE-367)
  - Atomic file writes using temp file + `rename()` pattern
  - Applies to cache files and report generation

- **MEDIUM: Resource Exhaustion Protection** (CWE-400)
  - `MAX_FILE_SIZE_BYTES`: 50 MB limit for package.json reads
  - `MAX_LOCKFILE_SIZE_BYTES`: 100 MB limit for lockfile reads
  - `MAX_DIRECTORIES_SCANNED`: 100,000 directory limit
  - `MAX_PACKAGES_SCANNED`: 50,000 package limit
  - `MAX_SCAN_DEPTH`: 10 (hard ceiling, overrides CLI flag)
  - Network response size capped at 10 MB

- **MEDIUM: IOC Data Integrity Verification** (CWE-354)
  - SHA256 hash stored alongside cached IOC files
  - Cache integrity verified before use; re-fetches on mismatch

- **MEDIUM: Secure Network Requests** (CWE-295)
  - Enforced HTTPS-only for all external URLs
  - URL validation before any network request
  - Disabled automatic redirect following
  - Added `User-Agent` header for request identification

- **LOW: Log Output Sanitization**
  - Added `sanitizeForLog()` to strip control characters from console output
  - Prevents log injection and terminal escape sequence attacks

- **LOW: Sensitive Data Redaction**
  - Removed `gitName`, `gitEmail`, `npmUser` from API upload payload
  - Only non-PII metadata sent to security API

### Added

- **Help System**: New `--help` / `-h` flag with comprehensive usage documentation
- **Scan Statistics**: Detailed metrics displayed after scan completion
  - Directories scanned, packages checked, lockfiles analyzed
  - Scan duration in seconds
  - Symlinks skipped count
  - Errors encountered count
- **Extended CSV Report Fields**:
  - `Report_Type`: COMPLETE or PARTIAL (for interrupted scans)
  - `Node_Version`: Node.js runtime version
  - `Scanner_Version`: Scanner version string
  - `Scan_Duration_MS`: Total scan time in milliseconds
  - `Directories_Scanned`: Count of directories traversed
  - `Packages_Scanned`: Count of packages analyzed
- **Graceful Shutdown Handling**: 
  - SIGINT/SIGTERM handlers generate partial reports before exit
  - Exit code 130 for interrupted scans
- **Case-Insensitive Malware Detection**:
  - Detects case variants of malware files (e.g., `Setup_Bun.js`, `SETUP_BUN.JS`)
  - Pre-computed lowercase set for O(1) lookups
- **npm-shrinkwrap.json Support**: Added to lockfile detection list
- **TTY Color Detection**: Colors automatically disabled in non-TTY environments (CI/CD safety)

### Changed

- **Strict Mode**: Added `'use strict'` directive for better error detection
- **Frozen Configuration**: `Object.freeze()` on all config objects prevents accidental mutation
- **Timeout Enforcement**: All `execSync` calls now have explicit timeouts (5-10 seconds)
- **Safe File Reading**: New `safeReadFile()` wrapper with size limits and error handling
- **JSON Schema Validation**: Basic structure validation for parsed IOC data
- **Improved Error Messages**: Errors no longer expose full file paths; uses `sanitizeForLog()`

### Fixed

- **Unbounded Recursion**: Hard depth limit prevents stack overflow on deeply nested directories
- **Memory Exhaustion**: File size checks prevent OOM on large files
- **Infinite Loops**: Scan limits prevent runaway scans on massive node_modules trees

### Deprecated

- Direct configuration of `API_KEY` and `UPLOAD_API_URL` constants (use environment variables)

---

## [1.3.2] - 2025-12-01

### Fixed

- Fixed a bug where the script would stop if `mallwareFile` was found for that directory and it will not scan for heuristics and metadata

### Changed

- **Malware File List Update:**
  - Added a new file to the list of detected malware payloads for improved coverage. `.github/workflows/discussion.yaml` according to https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack can be created by Shai-Hulud.

### Documentation

- **False Positive Guidance:**
  - Added a side note in the README to warn users that FORENSIC_MATCH can sometimes generate false positives, advising verification of found files.

## [1.3.1] - 2025-11-30

### Fixed

- **CSV Parser Enhancement:** Fixed multi-version IOC parsing from Wiz Research feed
  - Now correctly handles entries with multiple versions separated by `||` delimiter
  - Example: `test-foundry-app,= 1.0.4 || = 1.0.3 || = 1.0.2 || = 1.0.1` now captures all four versions
  - Previously only the first version would be captured, missing subsequent vulnerable versions
  - Ensures complete threat intelligence coverage for packages with multiple compromised versions

## [1.3.0] - 2025-11-30

### Added

- **CI/CD Integration:** Configurable exit codes for build pipeline integration
  - New `--fail-on` flag with three modes: `critical`, `warning`, or `off`
  - `--fail-on=critical`: Fails build (exit 1) only on critical findings (FORENSIC_MATCH, CRITICAL_SCRIPT, VERSION_MATCH, WILDCARD_MATCH, LOCKFILE_HIT)
  - `--fail-on=warning`: Fails build on any critical or warning findings (includes SCRIPT_WARNING, GHOST_PACKAGE, CORRUPT_PACKAGE)
  - `--fail-on=off`: Report-only mode, always exits with code 0
  - **Opt-in behavior**: CI/CD exit logic only activates when `--fail-on` is explicitly provided
  - Backwards compatible: Without the flag, scanner maintains default behavior (exit 0)
  - Perfect for Jenkins, GitHub Actions, GitLab CI, and other automation platforms

## [1.2.1] - 2025-11-29

### Fixed

- **Root Package Scanning:** Project root `package.json` files now receive full security analysis
  - Ensures monorepo roots and standalone projects are properly analyzed
- **Lockfile Coverage in node_modules:** Added scanning for lockfiles within installed packages
  - Some npm packages ship with their own `package-lock.json` or `yarn.lock`

## [1.2.0] - 2025-11-29

### Added

- **Behavioral Heuristics (Script Scanner):** Expanded detection for high-confidence malicious install scripts
  - Detects piping raw GitHub content to shell (`curl|wget … githubusercontent.com | sh`)
  - Flags decode-then-exec sequences (`base64|b64 … | sh`)
  - Detects Docker privilege-escalation indicators (`docker run --privileged`, `-v /:/host`)
  - Detects GitHub workflow backdoor artifacts (`.github/workflows/discussion.yaml`)
- **Suspicious Behavior Warnings:** Broadened coverage for obfuscation and exfil
  - Hex/base64 decodes via `Buffer.from(..., 'hex'|'base64')`, `Function(...)`
  - GitHub API/Actions artifact usage as potential exfil signals
  - Shelling out to `curl|wget|nc|bash|sh`; backdoor primitives (`nc`, `socat`)
- **Depth Control:** Configurable traversal depth for directory scanning
  - New constant `DEFAULT_MAX_SCAN_DEPTH` (default: 5)
  - CLI flag `--depth=<n>` or `--depth <n>` to override per run

### Changed

- **Whitelist Performance:** Converted `SCRIPT_WHITELIST` to a `Set` and now use `has()` for O(1) checks
- **Whitelist Coverage:** Extended `SCRIPT_WHITELIST_REGEX` to include common safe hooks
  - `opencollective-postinstall`, `node scripts/postinstall(.js)`, `electron-builder install-app-deps`
  - `lerna bootstrap`, `nx/turbo run`, `esbuild`, `node-pre-gyp install`

## [1.1.0] - 2025-11-29

### Added

- **Smart Caching System**: IOC data is now cached locally for 30 minutes to reduce network requests and improve scan performance
  - Cache directory: `.cache/` (auto-created, gitignored)
  - Configurable timeout via `CACHE_TIMEOUT_MS` constant
  - Cache age displayed in console output
- **Offline Fallback Support**: Automatic fallback to offline IOC files when network is unavailable
  - Fallback directory: `fallback/` with baseline IOC files
  - Graceful handling of network timeouts and errors
  - Works completely offline if needed
  - New `update-fallbacks.js` utility script to refresh offline IOC files

## [1.0.0] - 2025-11-28

### Added

- Initial release of comprehensive Shai-Hulud 2.0 scanner
- Multi-layer detection: forensic, metadata, behavioral, lockfile
- Cross-platform support (Windows, macOS, Linux)
- NVM deep scanning
- Ghost package detection
- Enterprise reporting with optional API upload
- **Dual Threat Intelligence Sources**: Now fetches from two independent IOC feeds
  - Wiz Research (CSV format)
  - Hemachandsai malicious packages (JSON format)
  - Wildcard version matching support (`*` for all versions)
- **Bun Package Manager Support**: Added scanning for Bun global modules and cache
  - `~/.bun/install/global/node_modules`
  - `~/.bun/install/cache`
- **Enhanced CSV Report**: Added more context to reports
  - Hostname and platform information
  - NPM user login detection
  - Git user information
- **Project-Only Scan Mode**: When a path is specified, only that directory is scanned (faster)
  - Use `--full-scan` flag to scan both system caches and specific path
- **Command-Line Flags**:
  - `--no-cache`: Force fresh download, bypass cache
  - `--no-upload`: Generate report locally without API upload
  - `--full-scan`: Scan system caches + specified path

### Changed

- Improved lockfile detection with wildcard support
  - Better handling of npm lockfile v1/v2/v3 formats
  - Stricter Yarn lock parsing with regex
  - Added `WILDCARD_MATCH` and `WILDCARD_LOCK_HIT` detection types
- Enhanced network error handling with 10-second timeout
- Better logging with color-coded status messages

### Fixed

- Windows NVM detection now properly uses `NVM_HOME` environment variable
- Cache validation properly checks file modification time
- Network failures gracefully fall back to offline data