# Changelog

All notable changes to the Shai-Hulud 1.0/2.0 Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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