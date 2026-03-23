# AGENTS.md — Shai-Hulud 2.0 Supply Chain Attack Scanner

This file provides guidance for AI coding agents (GitHub Copilot, Codex, etc.) working in this repository. Read it entirely before making any changes.

---

## Project Overview

**shai-hulud-2-scanner** is a forensic auditing tool that detects compromised npm packages from the Shai-Hulud 1.0/2.0 supply chain attack. It scans local npm/Yarn/pnpm caches, global installations, NVM environments, and project directories against live threat intelligence (IOC) feeds from Wiz Research and Hemachandsai.

- **Version:** 2.1.0
- **Runtime:** Node.js ≥ 12.0.0 (no npm install required)
- **Zero Dependencies:** The tool ships with zero runtime dependencies — `require()` only Node.js built-ins (`fs`, `path`, `https`, `os`, `crypto`, `child_process`).
- **Entry point:** `scan.js` (also the CLI binary)
- **Security posture:** This is a security product. Code must meet a higher-than-average standard of correctness and safety.

---

## Repository Structure

```
scan.js                     # Main scanner — the entire tool is one self-contained file
update-fallbacks.js         # Standalone utility — refreshes offline IOC fallback data
package.json                # Metadata only (no dependencies)
CHANGELOG.md                # All notable changes with CWE references
readme.md                   # End-user documentation
run-scanner.bat             # Windows convenience launcher
run-scanner.sh              # Unix/macOS convenience launcher
shai-hulud-report.csv       # Sample/output CSV report
fallback/
  wiz-iocs.csv              # Offline copy of Wiz Research IOC list
  malicious-packages.json   # Offline copy of Hemachandsai malicious package list
  README.md                 # Explains fallback data purpose
tests/
  test-csv-parser.js        # Self-contained test for parseWizCSV()
```

---

## Running the Scanner

```bash
# Full system scan (npm/Yarn/pnpm/NVM caches + cwd)
node scan.js

# Scan a specific project only
node scan.js /path/to/project

# Full system scan AND a specific project
node scan.js /path/to/project --full-scan

# Force fresh IOC download (bypass 30-minute cache)
node scan.js --no-cache

# Limit directory traversal depth (default: 5, max: 10)
node scan.js --depth=3

# CI/CD mode — exit 1 on critical findings
node scan.js /path/to/project --fail-on=critical

# CI/CD mode — exit 1 on critical or warning findings
node scan.js /path/to/project --fail-on=warning

# Update offline fallback IOC files
node update-fallbacks.js
```

## Running Tests

```bash
node tests/test-csv-parser.js
```

There is no test framework dependency — tests use a hand-rolled assertion helper and output pass/fail to stdout. Exit code is non-zero on any failure.

---

## Environment Variables

| Variable             | Purpose                                             |
| -------------------- | --------------------------------------------------- |
| `SHAI_HULUD_API_KEY` | API key for optional centralized report upload      |
| `SHAI_HULUD_API_URL` | Endpoint URL for optional centralized report upload |
| `NO_COLOR`           | Set to any value to disable terminal color output   |
| `FORCE_COLOR=0`      | Alternative way to disable color output             |

**Never hardcode credentials.** The tool was specifically patched (v2.0.0, CWE-798) to remove hardcoded secrets — do not reintroduce them.

---

## Architecture & Key Concepts

### Detection Pipeline

The scanner performs five independent detection passes, each producing typed findings:

| Finding Type        | Severity | Trigger                                                   |
| ------------------- | -------- | --------------------------------------------------------- |
| `FORENSIC_MATCH`    | CRITICAL | High-confidence malware file found (e.g., `setup_bun.js`) |
| `FORENSIC_ARTIFACT` | HIGH     | Suspicious file with malicious content signature          |
| `WILDCARD_MATCH`    | CRITICAL | Package name matches an all-versions denylist             |
| `CRITICAL_SCRIPT`   | CRITICAL | install/pre/postinstall script has malicious pattern      |
| `VERSION_MATCH`     | HIGH     | Package name + version in known-bad IOC list              |
| `LOCKFILE_HIT`      | HIGH     | Malicious version pinned in lockfile                      |
| `WILDCARD_LOCK_HIT` | HIGH     | Any-version malicious package in lockfile                 |
| `GHOST_PACKAGE`     | WARNING  | Target-named directory exists but is empty/broken         |
| `SCRIPT_WARNING`    | WARNING  | Install script has suspicious but ambiguous patterns      |
| `SAFE_MATCH`        | INFO     | Target package name found, but version is safe            |

### IOC Loading Strategy

1. Attempt fresh download from Wiz Research (CSV) and Hemachandsai (JSON)
2. On failure: fall back to `.cache/` (if fresh within 30 minutes and SHA256 intact)
3. On cache miss/stale: fall back to `fallback/` (bundled offline copies)

### Security Hardening Already in Place

When modifying `scan.js`, preserve all of the following — they address real CVEs and CWEs:

| Protection                | CWE      | Mechanism                                       |
| ------------------------- | -------- | ----------------------------------------------- |
| No hardcoded credentials  | CWE-798  | Env var reads only                              |
| CSV injection prevention  | CWE-1236 | `escapeCSV()` on all report fields              |
| ReDoS mitigation          | CWE-1333 | Bounded quantifiers on all regex (`{1,N}`)      |
| Symlink attack protection | CWE-59   | `checkSymlink()` with depth limit               |
| Path traversal prevention | CWE-22   | `validatePath()` with null byte & length checks |
| TOCTOU race condition     | CWE-367  | Atomic write via temp file + `rename()`         |
| Resource exhaustion       | CWE-400  | Hard limits on files, dirs, depth, size         |
| IOC integrity             | CWE-354  | SHA256 hash stored and verified alongside cache |
| Log sanitization          | —        | `sanitizeForLog()` strips control characters    |

---

## Coding Conventions

### Language & Style

- **Node.js only** — no transpilers, no build steps, no bundlers.
- `'use strict';` at the top of every file.
- `const` by default; `let` when reassignment is required; never `var`.
- Functions are plain named function declarations or `const fn = () => {}` arrow functions.
- All configuration lives in the frozen `CONFIG` object at the top of `scan.js`. Do not scatter magic numbers in logic.
- Module pattern: single-file, no ES modules (`require()` not `import`).

### Regex Rules (Critical)

**All regex patterns must use bounded quantifiers.** Unbounded `.*` and `.+` are banned in any pattern applied to untrusted input. Use `[^\s]{1,200}`, `[^|]{1,500}`, etc. This prevents ReDoS (CWE-1333).

```js
// ❌ WRONG — unbounded, ReDoS risk
/curl\s+.*\|\s*bash/i

// ✅ CORRECT — bounded
/curl\s+[^\s|]{1,500}\s*\|\s*bash/i
```

### Path Handling

Always call `validatePath()` before using user-supplied or externally derived paths. Never pass raw input to `fs` methods.

### File I/O

Always call `safeReadFile()` with an appropriate size limit. Never use `fs.readFileSync()` directly on files that could be attacker-controlled or unexpectedly large.

### No New Dependencies

The zero-dependency constraint is a core feature explicitly called out in the readme and marketing. Do **not** add any `require()` calls to third-party modules. If a capability is needed, implement it using built-in Node.js modules.

### Error Handling

- Catch-and-continue is preferred for scan operations — a single unreadable file must never abort the whole scan.
- Fatal errors (IOC load failure, invalid CLI args) should print a clear human-readable message and exit with a non-zero code.
- Increment `scanStats.errorsEncountered` for any non-fatal error caught during scanning.

### Output & Logging

- Use `colors.*` wrappers for all console output (respects `NO_COLOR` / `FORCE_COLOR`).
- Severity prefix conventions: `[!!!]` for CRITICAL, `[??]` for HIGH/suspicious, `[!]` for WARNING.
- Never log raw file content, package metadata, or environment values — potential credential exposure.

---

## IOC & Threat Intelligence

### FORENSIC_RULES (in `scan.js`)

The `FORENSIC_RULES` object maps filenames to detection configurations:

- `checkContent: false` — flag immediately on filename alone (high-confidence malware files).
- `checkContent: true` — must inspect content before alerting (reduces false positives on common filenames like `bundle.js` or `contents.json`).
- `safePatterns` — if a safe pattern matches, suppress the alert.
- `requiredKeys` (JSON files) — alert only if the JSON contains these keys.

When adding new forensic rules, assess whether a content check is needed to prevent false positives for legitimate tools.

### Pattern Lists

- `CRITICAL_PATTERNS` — behavioral signatures that produce `CRITICAL_SCRIPT` findings.
- `WARNING_PATTERNS` — lower-confidence patterns that produce `SCRIPT_WARNING` findings.
- `SCRIPT_WHITELIST` / `SCRIPT_WHITELIST_REGEX` — exact strings and patterns for known-safe install scripts (e.g., Husky, tsc, node-gyp). Add safe patterns here when filing false positive reports.

---

## CI/CD Integration

The `--fail-on` flag controls exit behavior:

| Flag                 | Exit 1 when                                                                                                            |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `--fail-on=critical` | Any FORENSIC_MATCH, FORENSIC_ARTIFACT, WILDCARD_MATCH, CRITICAL_SCRIPT, VERSION_MATCH, LOCKFILE_HIT, WILDCARD_LOCK_HIT |
| `--fail-on=warning`  | Any of the above, PLUS SCRIPT_WARNING, GHOST_PACKAGE, CORRUPT_PACKAGE                                                  |
| `--fail-on=off`      | Never (report-only; default behavior)                                                                                  |

**Default behavior (no flag):** always exits 0. This is intentional for backward compatibility.

---

## Pull Request & Commit Guidelines

### Commit Messages

Use Conventional Commits format:

```
<type>(<scope>): <short summary>

[optional body]
[optional footer: Closes #issue, CWE-XXX, etc.]
```

Types: `feat`, `fix`, `security`, `docs`, `test`, `refactor`, `chore`

Examples:
```
security(csv): add escapeCSV() to prevent formula injection (CWE-1236)
fix(regex): bound all quantifiers to mitigate ReDoS (CWE-1333)
feat(cli): add --fail-on flag for CI/CD exit code control
```

### CHANGELOG

Every user-visible change must have a corresponding entry in `CHANGELOG.md` under the correct version. Security fixes must reference their CWE number.

### What Belongs in PRs

- **Do:** Bug fixes, new IOC detection capabilities, improved false-positive handling, documentation updates, test additions.
- **Do not:** Add runtime dependencies, weaken detection thresholds, remove security hardening, change default exit-code behavior (except with explicit intent and docs).

---

## Agent Guidance

### Allowed Actions

- Modify detection patterns in `FORENSIC_RULES`, `CRITICAL_PATTERNS`, `WARNING_PATTERNS`, or `SCRIPT_WHITELIST` when backed by threat intelligence or false-positive evidence.
- Add entries to `SCRIPT_WHITELIST` / `SCRIPT_WHITELIST_REGEX` for confirmed safe install scripts.
- Improve `parseWizCSV()` or `parseJsonIOC()` for format changes in upstream IOC feeds.
- Add or improve tests in `tests/`.
- Update `fallback/` data via `node update-fallbacks.js`.
- Improve CLI help text, readme documentation, or CHANGELOG entries.

### Restricted Actions (Require Human Review)

- **Modifying `escapeCSV()`, `validatePath()`, `checkSymlink()`, or `safeReadFile()`** — these are security-critical functions. Any change must be reviewed for weakening of protections.
- **Changing `CONFIG` security limits** (file sizes, scan depths, directory counts) — lowering these could enable resource exhaustion attacks.
- **Modifying report upload logic** — output paths for sensitive data require careful review.
- **Removing or loosening regex bounds** — must not reintroduce ReDoS vectors.
- **Changing default `--fail-on` behavior** — breaking change for existing CI/CD pipelines.

### Do Not

- Add `require()` calls to third-party npm packages.
- Hardcode API keys, URLs, or credentials anywhere.
- Write unbounded regex quantifiers (`.*`, `.+`) that apply to untrusted input.
- Call `fs.readFileSync()` directly on attacker-reachable files.
- Log raw file contents, environment variables, or user-supplied values.
- Guess at IOC accuracy — always link to an authoritative source when adding or removing package names.

---

## False Positives

Known safe patterns that generate alerts and should be handled via `SCRIPT_WHITELIST`:

- **React Native projects:** `contents.json` in `ios/` is a standard Xcode asset catalog — not malware.
- **Webpack/Babel:** `bundle.js` from build tools — check for `safePatterns` match before alerting.
- **Husky, tsc, node-gyp, rimraf, patch-package, electron-builder**: all in `SCRIPT_WHITELIST`; add variants as needed.

When filing a false positive, add both the exact string to `SCRIPT_WHITELIST` (Set) and a regex to `SCRIPT_WHITELIST_REGEX` (Array) to ensure both lookup paths are covered.

---

## References

- [Wiz Research — Shai-Hulud 2.0 blog post](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Wiz Research IOC Repository](https://github.com/wiz-sec-public/wiz-research-iocs)
- [Hemachandsai Malicious Packages](https://github.com/hemachandsai/shai-hulud-malicious-packages)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
- [Conventional Commits](https://www.conventionalcommits.org/)
