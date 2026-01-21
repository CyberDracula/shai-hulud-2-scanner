#!/usr/bin/env node
/**
 * Shai-Hulud 2.0 Supply Chain Attack Scanner
 * 
 * A forensic auditing tool for detecting compromised npm packages associated with
 * the Shai-Hulud 2.0 supply chain attack. Performs deep analysis of local caches,
 * global installations, and project dependencies against threat intelligence IOCs.
 * 
 * Key Capabilities:
 * - Multi-layer Detection: Forensic file scanning, metadata validation, and behavioral analysis
 * - Cross-Platform Support: Windows, macOS, Linux with native NVM integration
 * - Zero Dependencies: Self-contained scanner requiring only Node.js runtime
 * - Threat Intelligence: Auto-syncs with Wiz Research IOC database and Hemachandsai malicious package list
 * - Enterprise Reporting: Optional centralized report aggregation for organizations
 * 
 * Detection Methods:
 * 1. Forensic Analysis: Scans for known malware payloads (setup_bun.js, etc.)
 * 2. Version Matching: Validates installed packages against IOC registry
 * 3. Lockfile Inspection: Identifies compromised dependencies in lock files
 * 4. Ghost Detection: Alerts on suspicious directory structures
 * 5. Behavioral Signatures: Detects malicious script patterns in package.json
 */

'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const os = require('os');
const crypto = require('crypto');
const { execSync } = require('child_process');

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = Object.freeze({
    // Report Settings
    REPORT_FILE: 'shai-hulud-report.csv',

    // IOC Sources
    IOC_CSV_URL: 'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv',
    IOC_JSON_URL: 'https://raw.githubusercontent.com/hemachandsai/shai-hulud-malicious-packages/main/malicious_npm_packages.json',

    // Cache Configuration
    CACHE_DIR: path.join(__dirname, '.cache'),
    FALLBACK_DIR: path.join(__dirname, 'fallback'),
    CACHE_TIMEOUT_MS: 30 * 60 * 1000, // 30 minutes

    // Security Limits
    MAX_FILE_SIZE_BYTES: 50 * 1024 * 1024, // 50MB max file read
    MAX_LOCKFILE_SIZE_BYTES: 100 * 1024 * 1024, // 100MB for lockfiles
    MAX_SCAN_DEPTH: 10, // Hard limit on recursion
    DEFAULT_SCAN_DEPTH: 5,
    NETWORK_TIMEOUT_MS: 15000, // 15 seconds
    MAX_PATH_LENGTH: 4096,
    MAX_SYMLINK_DEPTH: 3,

    // CI/CD Defaults
    DEFAULT_FAIL_ON: 'critical',

    // Scan Stats Limits (prevent infinite loops)
    MAX_DIRECTORIES_SCANNED: 100000,
    MAX_PACKAGES_SCANNED: 50000,
});

// Derived cache paths
const CACHE_WIZ_FILE = path.join(CONFIG.CACHE_DIR, 'wiz-iocs.csv');
const CACHE_JSON_FILE = path.join(CONFIG.CACHE_DIR, 'malicious-packages.json');
const FALLBACK_WIZ_FILE = path.join(CONFIG.FALLBACK_DIR, 'wiz-iocs.csv');
const FALLBACK_JSON_FILE = path.join(CONFIG.FALLBACK_DIR, 'malicious-packages.json');

// API Configuration - Use environment variables for sensitive data
const UPLOAD_API_URL = process.env.SHAI_HULUD_API_URL || '';
const API_KEY = process.env.SHAI_HULUD_API_KEY || '';

// ============================================================================
// TERMINAL COLORS (with detection)
// ============================================================================

const supportsColor = process.stdout.isTTY &&
    (process.env.FORCE_COLOR !== '0') &&
    (process.env.NO_COLOR === undefined);

const colors = supportsColor ? {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    reset: '\x1b[0m',
    dim: '\x1b[2m',
    bold: '\x1b[1m'
} : {
    red: '', green: '', yellow: '', cyan: '', reset: '', dim: '', bold: ''
};

// ============================================================================
// FORENSIC FILE LIST
// ============================================================================

const FORENSIC_RULES = {
    // === HIGH CONFIDENCE (Alert immediately if found) ===
    'setup_bun.js': { type: 'CRITICAL', checkContent: false },
    'bun_environment.js': { type: 'CRITICAL', checkContent: false },
    'truffleSecrets.json': { type: 'CRITICAL', checkContent: false },
    'actionsSecrets.json': { type: 'CRITICAL', checkContent: false },
    '.github/workflows/discussion.yaml': { type: 'CRITICAL', checkContent: false },
    '.github/workflows/discussion.yml': { type: 'CRITICAL', checkContent: false },

    // === LOW CONFIDENCE (Must verify content to avoid False Positives) ===
    
    // "bundle.js" is common in Webpack/Babel. 
    // Malware version contains the string "setup_bun" or obfuscated shell calls.
    'bundle.js': { 
        type: 'HIGH', 
        checkContent: true, 
        indicators: [/setup_bun/i, /bun_environment/i, /child_process/, /socket\.connect/],
        safePatterns: [/webpack/i, /react/i, /babel/i] // Heuristic for common libs
    },

    // "contents.json" is standard in iOS/Xcode (React Native). 
    // Malware version contains stolen env vars/tokens.
    // Xcode version contains "images": [] and "info": { "version": 1, "author": "xcode" }
    'contents.json': { 
        type: 'HIGH', 
        checkContent: true, 
        isJson: true,
        requiredKeys: ['aws', 'key', 'token', 'secret', 'password', 'env'], // Malware likely has these
        safeKeys: ['images', 'info', 'properties'] // Xcode assets have these
    },

    // "cloud.json" and "environment.json" are generic.
    // Malware version is a dump of env vars.
    'cloud.json': { 
        type: 'HIGH', 
        checkContent: true, 
        isJson: true,
        requiredKeys: ['aws_access_key_id', 'azure_client_id', 'gcp_token'] 
    },
    'environment.json': { 
        type: 'HIGH', 
        checkContent: true, 
        isJson: true,
        requiredKeys: ['PATH', 'USER', 'SHELL', 'HOME', 'npm_config_'] // Env dump signature
    }
};

// Create sets for fast lookup
const FORENSIC_RULES_ENTRIES = Object.entries(FORENSIC_RULES); // Cache entries array
const FORENSIC_RULES_KEYS_LOWER = Object.keys(FORENSIC_RULES).reduce((map, key) => {
    map[key.toLowerCase()] = key;
    return map;
}, {}); // Cache lowercase to original key mapping

// ============================================================================
// HEURISTIC CONFIGURATION (ReDoS-hardened patterns)
// ============================================================================

const SCRIPT_WHITELIST = new Set([
    'husky install', 'husky', 'is-ci || husky install',
    'ngcc', 'ngcc --properties es2015 browser module main', 'ivy-ngcc',
    'tsc', 'tsc -p tsconfig.json', 'tsc --build',
    'rimraf', 'rimraf dist', 'shx',
    'prebuild-install', 'node-gyp rebuild', 'node-pre-gyp install --fallback-to-build',
    'patch-package', 'esbuild',
    'node scripts/postinstall.js', 'node scripts/postinstall',
    'lerna bootstrap', 'nx',
    'electron-builder install-app-deps',
    'exit 0', 'true', 'echo'
]);

const SCRIPT_WHITELIST_REGEX = [
    /^echo\s/,
    /^rimraf\s/,
    /^shx\s/,
    /^tsc(?:\s|$)/,
    /^ngcc(?:\s|$)/,
    /^node-gyp\s/,
    /^prebuild-install/,
    /^husky(?:\s|$)/,
    /^is-ci\s/,
    /^opencollective(?:-postinstall)?/,
    /^patch-package/,
    /^node\s+scripts\/postinstall(?:\.js)?$/,
    /^electron-builder\s+install-app-deps/,
    /^lerna\s+bootstrap/,
    /^(?:nx|turbo)\s+run/,
    /^esbuild(?:\s|$)/,
    /^node-pre-gyp\s+install(?:\s|$)/
];

// ReDoS-hardened critical patterns (using possessive-like constructs and bounded quantifiers)
const CRITICAL_PATTERNS = [
    // Remote code execution patterns - limited repetition
    { pattern: /curl\s+[^\s|]{1,500}\s*\|\s*(?:sh|bash|zsh)/i, desc: 'Curl piped to shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /wget\s+[^\s|]{1,500}\s*\|\s*(?:sh|bash|zsh)/i, desc: 'Wget piped to shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /curl\s+[^\s]{1,500}>\s*[^|&\s]+\s*&&\s*(?:sh|bash|chmod)/i, desc: 'Curl download & exec', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /curl\s+[^\s]{0,200}githubusercontent\.com\/[^\s|]{1,300}\|\s*(?:sh|bash|zsh)/i, desc: 'Pipe raw GitHub content to shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /wget\s+[^\s]{0,200}raw\.githubusercontent\.com\/[^\s|]{1,300}\|\s*(?:sh|bash|zsh)/i, desc: 'Pipe raw GitHub content to shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /\b(?:b64|base64)\b[^|]{0,100}\|\s*(?:sh|bash)/i, desc: 'Decode then execute via shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /base64\s+(?:-d|--decode)/i, desc: 'Base64 decoding', indicator: 'OBFUSCATION' },
    { pattern: /\beval\s*\(/, desc: 'Eval statement', indicator: 'CODE_INJECTION' },
    { pattern: /setup_bun/i, desc: 'Shai-Hulud Loader', indicator: 'SHAI_HULUD' },
    { pattern: /bun_environment/i, desc: 'Shai-Hulud Payload', indicator: 'SHAI_HULUD' },
    { pattern: /SHA1HULUD/i, desc: 'Shai-Hulud Signature', indicator: 'SHAI_HULUD' },
    { pattern: /node\s+-e\s+["']require\s*\(\s*["']child_process["']\s*\)/, desc: 'Hidden child_process', indicator: 'CODE_INJECTION' },
    { pattern: /child_process[^)]{0,50}exec[^)]{0,50}\$\(/, desc: 'Shell command via child_process', indicator: 'CODE_INJECTION' },
    { pattern: /\$\(curl/i, desc: 'Subshell curl', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /`curl/i, desc: 'Backtick curl', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /bash\s+-c\s+["'][^"']{0,200}curl/i, desc: 'bash -c curl', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /curl\s+[^\s]{1,300}-o\s+\S+\s*&&\s*(?:sh|bash|chmod)/i, desc: 'curl save & exec', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /wget\s+[^\s]{1,300}-O\s+\S+\s*&&\s*(?:sh|bash|chmod)/i, desc: 'wget save & exec', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /require\s*\(\s*["']child_process["']\s*\)\.\s*(?:exec|execSync|spawn|spawnSync)/i, desc: 'Direct child_process call', indicator: 'CODE_INJECTION' },
    { pattern: /\b(?:execSync|spawnSync|execFileSync)\s*\(/, desc: 'Sync process execution', indicator: 'CODE_INJECTION' },
    { pattern: /\.github\/workflows\/discussion\.ya?ml/i, desc: 'GitHub workflow backdoor', indicator: 'PERSISTENCE' },
    { pattern: /docker\s+run\s+[^\n]{0,200}--privileged/i, desc: 'Privileged Docker run', indicator: 'PRIV_ESC' },
    { pattern: /-v\s+\/:\/host\b/i, desc: 'Host mount in container', indicator: 'PRIV_ESC' }
];

const WARNING_PATTERNS = [
    { pattern: /http:\/\/[^\s"']{1,200}/, desc: 'Unencrypted HTTP', indicator: 'INSECURE_NETWORK' },
    { pattern: /\\x[0-9a-fA-F]{2}/, desc: 'Hex-encoded string', indicator: 'OBFUSCATION' },
    { pattern: /String\.fromCharCode/, desc: 'Char code obfuscation', indicator: 'OBFUSCATION' },
    { pattern: /atob\s*\(/, desc: 'Base64 atob decode', indicator: 'OBFUSCATION' },
    { pattern: /Buffer\.from\s*\([^)]{1,100},\s*['"]base64['"]\)/, desc: 'Buffer base64 decode', indicator: 'OBFUSCATION' },
    { pattern: /Buffer\.from\s*\([^)]{1,100},\s*['"]hex['"]\)/, desc: 'Buffer hex decode', indicator: 'OBFUSCATION' },
    { pattern: /Function\s*\([^)]{0,200}\)/, desc: 'Dynamic function creation', indicator: 'OBFUSCATION' },
    { pattern: /actions\/upload-artifact/i, desc: 'GitHub Actions artifact usage', indicator: 'EXFIL_ATTEMPT' },
    { pattern: /https?:\/\/api\.github\.com\/(?:repos|gists|uploads)/i, desc: 'GitHub API interaction', indicator: 'EXFIL_ATTEMPT' },
    { pattern: /child_process\.(?:exec|spawn|execSync|spawnSync)\([^)]{0,50}(?:curl|wget|nc|bash|sh)/i, desc: 'Shelling out to network tools', indicator: 'CODE_INJECTION' },
    { pattern: /\bnc\b\s+(?:-[a-zA-Z]+\s+){0,5}\S+/i, desc: 'Netcat usage', indicator: 'BACKDOOR_PRIMITIVE' },
    { pattern: /\bsocat\b\s+/i, desc: 'socat usage', indicator: 'BACKDOOR_PRIMITIVE' }
];

// ============================================================================
// GLOBAL STATE
// ============================================================================

const detectedIssues = [];
const scanStats = {
    directoriesScanned: 0,
    packagesScanned: 0,
    filesChecked: 0,
    lockfilesChecked: 0,
    startTime: null,
    symlinksSkipped: 0,
    errorsEncountered: 0
};

let isShuttingDown = false;

// ============================================================================
// SECURITY UTILITIES
// ============================================================================

/**
 * Escapes a string for safe CSV inclusion (prevents CSV injection)
 * @param {string} str - String to escape
 * @returns {string} - Escaped string safe for CSV
 */
function escapeCSV(str) {
    if (str === null || str === undefined) return '';
    const s = String(str);

    // CSV injection prevention: if starts with dangerous chars, prefix with single quote
    // Dangerous chars: =, +, -, @, tab, carriage return
    const dangerousStart = /^[=+\-@\t\r]/;
    let escaped = s;

    if (dangerousStart.test(escaped)) {
        escaped = "'" + escaped;
    }

    // Standard CSV escaping: double quotes and wrap if needed
    if (escaped.includes('"') || escaped.includes(',') || escaped.includes('\n') || escaped.includes('\r')) {
        escaped = '"' + escaped.replace(/"/g, '""') + '"';
    } else if (escaped.includes(' ') || escaped.startsWith("'")) {
        escaped = '"' + escaped + '"';
    }

    return escaped;
}

/**
 * Escapes special regex characters in a string
 * @param {string} string - String to escape
 * @returns {string} - Regex-safe string
 */
function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Validates and normalizes a path, preventing traversal attacks
 * @param {string} inputPath - Path to validate
 * @param {string} basePath - Base path that inputPath must be within (optional)
 * @returns {string|null} - Normalized path or null if invalid
 */
function validatePath(inputPath, basePath = null) {
    if (!inputPath || typeof inputPath !== 'string') return null;
    if (inputPath.length > CONFIG.MAX_PATH_LENGTH) return null;

    // Normalize the path
    let normalized;
    try {
        normalized = path.resolve(inputPath);
    } catch (e) {
        return null;
    }

    // Check for null bytes (path traversal attack vector)
    if (normalized.includes('\0')) return null;

    // If basePath provided, ensure normalized path is within it
    if (basePath) {
        const normalizedBase = path.resolve(basePath);
        if (!normalized.startsWith(normalizedBase + path.sep) && normalized !== normalizedBase) {
            return null;
        }
    }

    return normalized;
}

/**
 * Safely checks if a path is a symlink and resolves it with depth limiting
 * @param {string} filePath - Path to check
 * @param {number} depth - Current symlink resolution depth
 * @returns {{isSymlink: boolean, realPath: string|null, safe: boolean}}
 */
function checkSymlink(filePath, depth = 0) {
    try {
        const stats = fs.lstatSync(filePath);
        if (!stats.isSymbolicLink()) {
            return { isSymlink: false, realPath: filePath, safe: true };
        }

        if (depth >= CONFIG.MAX_SYMLINK_DEPTH) {
            return { isSymlink: true, realPath: null, safe: false };
        }

        const realPath = fs.realpathSync(filePath);
        return { isSymlink: true, realPath, safe: true };
    } catch (e) {
        return { isSymlink: false, realPath: null, safe: false };
    }
}

/**
 * Safely reads a file with size limits
 * @param {string} filePath - Path to read
 * @param {number} maxSize - Maximum file size in bytes
 * @returns {{content: string|null, error: string|null, size: number}}
 */
function safeReadFile(filePath, maxSize = CONFIG.MAX_FILE_SIZE_BYTES) {
    try {
        const stats = fs.statSync(filePath);

        if (stats.size > maxSize) {
            return { content: null, error: 'FILE_TOO_LARGE', size: stats.size };
        }

        const content = fs.readFileSync(filePath, 'utf8');
        return { content, error: null, size: stats.size };
    } catch (e) {
        return { content: null, error: e.code || 'READ_ERROR', size: 0 };
    }
}

/**
 * Computes SHA256 hash of content for integrity verification
 * @param {string} content - Content to hash
 * @returns {string} - Hex-encoded SHA256 hash
 */
function computeHash(content) {
    return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * Sanitizes a string for safe logging (removes control characters)
 * @param {string} str - String to sanitize
 * @param {number} maxLength - Maximum length
 * @returns {string} - Sanitized string
 */
function sanitizeForLog(str, maxLength = 200) {
    if (!str) return '';
    // Remove control characters except common whitespace
    const sanitized = String(str)
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
        .slice(0, maxLength);
    return sanitized;
}

// ============================================================================
// SIGNAL HANDLING
// ============================================================================

function setupSignalHandlers() {
    const handleShutdown = (signal) => {
        if (isShuttingDown) return;
        isShuttingDown = true;

        console.log(`\n${colors.yellow}[!] Received ${signal}, generating partial report...${colors.reset}`);

        // Try to generate report with what we have
        try {
            const partialReport = generateReport({
                gitName: 'INTERRUPTED',
                gitEmail: 'INTERRUPTED',
                npmUser: 'INTERRUPTED',
                hostname: os.hostname(),
                platform: os.platform()
            }, true);
            console.log(`${colors.yellow}    > Partial report saved.${colors.reset}`);
        } catch (e) {
            console.log(`${colors.red}    > Could not save partial report: ${e.message}${colors.reset}`);
        }

        process.exit(130); // Standard exit code for SIGINT
    };

    process.on('SIGINT', () => handleShutdown('SIGINT'));
    process.on('SIGTERM', () => handleShutdown('SIGTERM'));
}

// ============================================================================
// USER INFO COLLECTION
// ============================================================================

function getUserInfo() {
    console.log(`${colors.cyan}[1/5] Identifying User Environment...${colors.reset}`);
    const info = {
        gitName: 'Unknown',
        gitEmail: 'Unknown',
        npmUser: 'Not Logged In',
        hostname: os.hostname(),
        platform: os.platform(),
        nodeVersion: process.version,
        scannerVersion: '2.1.0-hardened'
    };

    try {
        const result = execSync('git config user.name', { timeout: 5000, encoding: 'utf8' });
        info.gitName = sanitizeForLog(result.trim(), 100);
    } catch (e) { }

    try {
        const result = execSync('git config user.email', { timeout: 5000, encoding: 'utf8' });
        info.gitEmail = sanitizeForLog(result.trim(), 100);
    } catch (e) { }

    try {
        const npmWhoami = execSync('npm whoami', {
            stdio: ['pipe', 'pipe', 'ignore'],
            timeout: 10000,
            encoding: 'utf8'
        }).trim();
        if (npmWhoami) info.npmUser = sanitizeForLog(npmWhoami, 50);
    } catch (e) { }

    console.log(`    > User: ${info.gitName} <${info.gitEmail}>`);
    console.log(`    > NPM User: ${info.npmUser}`);
    console.log(`    > Host: ${info.hostname} (${info.platform})`);
    console.log(`    > Node: ${info.nodeVersion}`);

    return info;
}

// ============================================================================
// CACHE MANAGEMENT
// ============================================================================

function ensureDir(dir) {
    const validated = validatePath(dir);
    if (!validated) {
        throw new Error(`Invalid directory path: ${sanitizeForLog(dir)}`);
    }

    if (!fs.existsSync(validated)) {
        fs.mkdirSync(validated, { recursive: true, mode: 0o755 });
    }
}

function isCacheValid(cacheFile) {
    try {
        const validated = validatePath(cacheFile);
        if (!validated || !fs.existsSync(validated)) return false;

        const stats = fs.statSync(validated);
        const age = Date.now() - stats.mtimeMs;
        return age < CONFIG.CACHE_TIMEOUT_MS;
    } catch (e) {
        return false;
    }
}

function loadFromCache(cacheFile, type) {
    try {
        const validated = validatePath(cacheFile);
        if (!validated) return null;

        const { content, error, size } = safeReadFile(validated);
        if (error) return null;

        const ageMinutes = Math.round((Date.now() - fs.statSync(validated).mtimeMs) / 1000 / 60);
        console.log(`    > ${type}: Loaded from cache (age: ${ageMinutes}m, size: ${(size / 1024).toFixed(1)}KB)`);
        return content;
    } catch (e) {
        return null;
    }
}

function loadFromFallback(fallbackFile, type) {
    try {
        const validated = validatePath(fallbackFile);
        if (!validated || !fs.existsSync(validated)) return null;

        const { content, error } = safeReadFile(validated);
        if (error) return null;

        console.log(`    > ${type}: ${colors.yellow}Using offline fallback${colors.reset}`);
        return content;
    } catch (e) {
        return null;
    }
}

function saveToCache(cacheFile, content) {
    try {
        const validated = validatePath(cacheFile);
        if (!validated) {
            console.log(`    > Warning: Invalid cache path`);
            return;
        }

        ensureDir(path.dirname(validated));

        // Write atomically using temp file
        const tempFile = validated + '.tmp.' + process.pid;
        fs.writeFileSync(tempFile, content, { encoding: 'utf8', mode: 0o644 });
        fs.renameSync(tempFile, validated);

        // Store hash for integrity verification
        const hashFile = validated + '.sha256';
        fs.writeFileSync(hashFile, computeHash(content), { encoding: 'utf8', mode: 0o644 });
    } catch (e) {
        console.log(`    > Warning: Could not write to cache: ${e.message}`);
    }
}

function verifyCacheIntegrity(cacheFile) {
    try {
        const hashFile = cacheFile + '.sha256';
        if (!fs.existsSync(hashFile)) return true; // No hash file, skip verification

        const storedHash = fs.readFileSync(hashFile, 'utf8').trim();
        const { content } = safeReadFile(cacheFile);
        if (!content) return false;

        return computeHash(content) === storedHash;
    } catch (e) {
        return false;
    }
}

// ============================================================================
// THREAT INTELLIGENCE FETCHING
// ============================================================================

async function fetchThreats(forceNoCache = false) {
    console.log(`\n${colors.cyan}[2/5] Downloading Threat Intelligence (Dual Feed)...${colors.reset}`);
    if (forceNoCache) console.log(`    > ${colors.yellow}Cache bypassed (--no-cache flag)${colors.reset}`);

    try {
        // Manual Promise handling for Node.js v12.0-v12.8 compatibility (allSettled added in v12.9.0)
        let wizData = { status: 'rejected', reason: { message: 'Not fetched' }, value: null };
        let jsonData = { status: 'rejected', reason: { message: 'Not fetched' }, value: null };

        try {
            const wizResult = await fetchWithCache(CONFIG.IOC_CSV_URL, CACHE_WIZ_FILE, FALLBACK_WIZ_FILE, 'Wiz.io CSV', forceNoCache);
            wizData = { status: 'fulfilled', value: wizResult };
        } catch (err) {
            wizData = { status: 'rejected', reason: err };
        }

        try {
            const jsonResult = await fetchWithCache(CONFIG.IOC_JSON_URL, CACHE_JSON_FILE, FALLBACK_JSON_FILE, 'Malicious JSON', forceNoCache);
            jsonData = { status: 'fulfilled', value: jsonResult };
        } catch (err) {
            jsonData = { status: 'rejected', reason: err };
        }

        const badPackages = {};
        let count = 0;

        // Process Source 1 (Wiz CSV)
        if (wizData.status === 'fulfilled' && wizData.value) {
            const parsed = parseWizCSV(wizData.value);
            for (const [pkg, vers] of Object.entries(parsed)) {
                if (!badPackages[pkg]) badPackages[pkg] = new Set();
                vers.forEach(v => badPackages[pkg].add(v));
            }
            console.log(`    > [Source 1] Wiz.io: Loaded successfully.`);
        } else {
            const wizError = wizData.reason && wizData.reason.message ? wizData.reason.message : 'No data';
            console.log(`${colors.red}    > [Source 1] Failed: ${wizError}${colors.reset}`);
        }

        // Process Source 2 (Hemachandsai JSON)
        if (jsonData.status === 'fulfilled' && jsonData.value) {
            const parsed = parseMaliciousJSON(jsonData.value);
            for (const [pkg, vers] of Object.entries(parsed)) {
                if (!badPackages[pkg]) badPackages[pkg] = new Set();
                if (vers.length === 0) {
                    badPackages[pkg].add('*');
                } else {
                    vers.forEach(v => badPackages[pkg].add(v));
                }
            }
            console.log(`    > [Source 2] Hemachandsai: Loaded successfully.`);
        } else {
            const jsonError = jsonData.reason && jsonData.reason.message ? jsonData.reason.message : 'No data';
            console.log(`${colors.red}    > [Source 2] Failed: ${jsonError}${colors.reset}`);
        }

        // Count packages
        for (const pkg in badPackages) {
            count++;
        }

        console.log(`    > Total Threat Database: ${count} unique packages targeted.`);
        return badPackages;
    } catch (e) {
        console.error(`${colors.red}Critical Error fetching feeds: ${e.message}${colors.reset}`);
        return {};
    }
}

function fetchWithCache(url, cacheFile, fallbackFile, sourceName, forceNoCache = false) {
    return new Promise((resolve, reject) => {
        // 1. Check cache validity
        if (!forceNoCache && isCacheValid(cacheFile)) {
            if (verifyCacheIntegrity(cacheFile)) {
                const cached = loadFromCache(cacheFile, sourceName);
                if (cached) return resolve(cached);
            } else {
                console.log(`    > ${sourceName}: ${colors.yellow}Cache integrity check failed, re-fetching...${colors.reset}`);
            }
        }

        // 2. Validate URL before fetching
        let parsedUrl;
        try {
            parsedUrl = new URL(url);
            if (parsedUrl.protocol !== 'https:') {
                throw new Error('Only HTTPS URLs are allowed');
            }
        } catch (e) {
            return reject(new Error(`Invalid URL: ${e.message}`));
        }

        // 3. Try to fetch from network with timeout
        const timeout = setTimeout(() => {
            console.log(`    > ${sourceName}: ${colors.yellow}Network timeout, trying fallback...${colors.reset}`);
            const fallback = loadFromFallback(fallbackFile, sourceName);
            if (fallback) resolve(fallback);
            else reject(new Error('Timeout and no fallback available'));
        }, CONFIG.NETWORK_TIMEOUT_MS);

        const req = https.get(url, {
            timeout: CONFIG.NETWORK_TIMEOUT_MS,
            headers: {
                'User-Agent': 'Shai-Hulud-Scanner/2.1.0'
            }
        }, (res) => {
            clearTimeout(timeout);

            // Check for redirects (limit to prevent infinite loops)
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                // Don't follow redirects automatically for security
                console.log(`    > ${sourceName}: ${colors.yellow}Redirect detected, using fallback...${colors.reset}`);
                const fallback = loadFromFallback(fallbackFile, sourceName);
                if (fallback) return resolve(fallback);
                return reject(new Error(`Redirect to ${res.headers.location}`));
            }

            let data = '';
            let receivedBytes = 0;
            const maxBytes = 10 * 1024 * 1024; // 10MB max download

            res.on('data', chunk => {
                receivedBytes += chunk.length;
                if (receivedBytes > maxBytes) {
                    res.destroy();
                    reject(new Error('Response too large'));
                    return;
                }
                data += chunk;
            });

            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    console.log(`    > ${sourceName}: Downloaded from network (${(receivedBytes / 1024).toFixed(1)}KB).`);
                    saveToCache(cacheFile, data);
                    resolve(data);
                } else {
                    console.log(`    > ${sourceName}: HTTP ${res.statusCode}, trying fallback...`);
                    const fallback = loadFromFallback(fallbackFile, sourceName);
                    if (fallback) resolve(fallback);
                    else reject(new Error(`HTTP ${res.statusCode}`));
                }
            });
        });

        req.on('error', (e) => {
            clearTimeout(timeout);
            console.log(`    > ${sourceName}: ${colors.yellow}Network error, trying fallback...${colors.reset}`);
            const fallback = loadFromFallback(fallbackFile, sourceName);
            if (fallback) resolve(fallback);
            else reject(e);
        });

        req.on('timeout', () => {
            req.destroy();
        });
    });
}

function parseWizCSV(data) {
    if (!data || typeof data !== 'string') return {};

    const lines = data.split('\n').filter(l => l.trim() !== '');
    const result = {};
    const startIdx = (lines[0] && lines[0].toLowerCase().includes('package')) ? 1 : 0;

    for (let i = startIdx; i < lines.length && i < 100000; i++) {
        const parts = lines[i].split(',');
        if (parts.length >= 2) {
            const rawName = parts[0].replace(/["']/g, '').trim();

            // Validate package name (basic npm naming rules)
            if (!rawName || rawName.length > 214 || !/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(rawName)) {
                continue;
            }

            const versionField = parts.slice(1).join(',').trim();
            const versions = versionField.split('||').map(v =>
                v.replace(/["'=<>v\s]/g, '').trim()
            ).filter(v => v !== '' && v.length <= 50);

            if (rawName && versions.length > 0) {
                if (!result[rawName]) result[rawName] = [];
                result[rawName].push(...versions);
            }
        }
    }
    return result;
}

function parseMaliciousJSON(data) {
    if (!data || typeof data !== 'string') return {};

    try {
        const json = JSON.parse(data);

        // Validate structure
        if (typeof json !== 'object' || json === null || Array.isArray(json)) {
            console.log(`    > Warning: Unexpected JSON structure`);
            return {};
        }

        const result = {};
        let count = 0;
        const maxPackages = 100000;

        for (const [pkg, details] of Object.entries(json)) {
            if (count++ > maxPackages) break;

            // Validate package name
            if (!pkg || typeof pkg !== 'string' || pkg.length > 214) continue;

            // Validate details structure
            if (details && typeof details === 'object' && Array.isArray(details.versions)) {
                result[pkg] = details.versions.filter(v =>
                    typeof v === 'string' && v.length <= 50
                );
            } else {
                result[pkg] = [];
            }
        }
        return result;
    } catch (e) {
        console.log(`    > Error parsing JSON: ${e.message}`);
        return {};
    }
}

// ============================================================================
// PATH DISCOVERY
// ============================================================================

function getSearchPaths() {
    console.log(`\n${colors.cyan}[3/5] Locating Cache & Global Directories...${colors.reset}`);
    const paths = [];
    const home = os.homedir();
    const platform = os.platform();

    // A. Active Global (NPM)
    try {
        const globalPrefix = execSync('npm root -g', { timeout: 10000, encoding: 'utf8' }).trim();
        const validated = validatePath(globalPrefix);
        if (validated && fs.existsSync(validated)) {
            paths.push(validated);
            console.log(`    > [NPM] Active Global: ${validated}`);
        }
    } catch (e) { }

    // B. BUN Support
    const bunBase = path.join(home, '.bun', 'install');

    const bunGlobal = path.join(bunBase, 'global', 'node_modules');
    if (fs.existsSync(bunGlobal)) {
        paths.push(bunGlobal);
        console.log(`    > [BUN] Global Modules: ${bunGlobal}`);
    }

    const bunCache = path.join(bunBase, 'cache');
    if (fs.existsSync(bunCache)) {
        paths.push(bunCache);
        console.log(`    > [BUN] Global Cache: ${bunCache}`);
    }

    // C. NVM Deep Scan
    let nvmRoot = null;

    if (platform === 'win32') {
        if (process.env.NVM_HOME && fs.existsSync(process.env.NVM_HOME)) {
            nvmRoot = process.env.NVM_HOME;
        } else {
            const possible = path.join(process.env.APPDATA || '', 'nvm');
            if (fs.existsSync(possible)) nvmRoot = possible;
        }
    } else {
        const possible = path.join(home, '.nvm', 'versions', 'node');
        if (fs.existsSync(possible)) nvmRoot = possible;
    }

    if (nvmRoot) {
        console.log(`    > [NVM] Root found at: ${nvmRoot}`);
        try {
            const versions = fs.readdirSync(nvmRoot, { withFileTypes: true })
                .filter(d => d.isDirectory() && d.name.toLowerCase().startsWith('v'))
                .slice(0, 100); // Limit versions scanned

            console.log(`    > [NVM] Found ${versions.length} installed versions.`);

            versions.forEach(v => {
                let vPath;
                if (platform === 'win32') {
                    vPath = path.join(nvmRoot, v.name, 'node_modules');
                } else {
                    vPath = path.join(nvmRoot, v.name, 'lib', 'node_modules');
                }

                if (fs.existsSync(vPath)) {
                    paths.push(vPath);
                    console.log(`      -> Added version: ${v.name}`);
                }
            });
        } catch (e) {
            console.log(`    > [NVM] Error reading versions: ${e.message}`);
        }
    } else {
        console.log(`    > [NVM] Not detected.`);
    }

    // D. Yarn Specifics
    const yarnPaths = platform === 'darwin' ? [
        path.join(home, 'Library/Caches/Yarn'),
        path.join(home, '.yarn/berry/cache'),
        path.join(home, '.config/yarn/global/node_modules')
    ] : [
        path.join(home, '.config/yarn/global/node_modules')
    ];

    yarnPaths.forEach(yPath => {
        if (fs.existsSync(yPath)) {
            paths.push(yPath);
            console.log(`    > [YARN] ${yPath}`);
        }
    });

    // E. Generic Caches
    const yCache = path.join(home, platform === 'win32' ? 'AppData/Local/Yarn/Cache' : '.cache/yarn');
    if (fs.existsSync(yCache)) {
        paths.push(yCache);
        console.log(`    > [YARN] Standard Cache: ${yCache}`);
    }

    const npmCache = path.join(home, platform === 'win32' ? 'AppData/Roaming/npm-cache' : '.npm');
    if (fs.existsSync(npmCache)) {
        paths.push(npmCache);
        console.log(`    > [NPM] Standard Cache: ${npmCache}`);
    }

    const pnpmStore = path.join(home, platform === 'win32' ? 'AppData/Local/pnpm/store' : '.local/share/pnpm/store');
    if (fs.existsSync(pnpmStore)) {
        paths.push(pnpmStore);
        console.log(`    > [PNPM] Store: ${pnpmStore}`);
    }

    return [...new Set(paths)];
}

// ============================================================================
// SCANNING LOGIC (Hardened)
// ============================================================================

function scanDir(currentPath, badPackages, depth = 0, maxDepth = CONFIG.DEFAULT_SCAN_DEPTH) {
    // Check shutdown flag
    if (isShuttingDown) return;

    // Check scan limits
    if (scanStats.directoriesScanned >= CONFIG.MAX_DIRECTORIES_SCANNED) {
        if (scanStats.directoriesScanned === CONFIG.MAX_DIRECTORIES_SCANNED) {
            console.log(`${colors.yellow}    > Warning: Directory scan limit reached (${CONFIG.MAX_DIRECTORIES_SCANNED})${colors.reset}`);
        }
        return;
    }

    // Enforce hard depth limit
    if (depth > Math.min(maxDepth, CONFIG.MAX_SCAN_DEPTH)) return;

    // Validate path
    const validated = validatePath(currentPath);
    if (!validated) return;

    // Check for symlinks
    const symlinkCheck = checkSymlink(validated);
    if (symlinkCheck.isSymlink) {
        if (!symlinkCheck.safe) {
            scanStats.symlinksSkipped++;
            return;
        }
        // Use real path for symlinks
        currentPath = symlinkCheck.realPath;
    }

    scanStats.directoriesScanned++;

    if (path.basename(currentPath) === 'node_modules') {
        scanNodeModules(currentPath, badPackages);
        return;
    }

    let entries;
    try {
        entries = fs.readdirSync(currentPath, { withFileTypes: true });
    } catch (e) {
        scanStats.errorsEncountered++;
        return;
    }

    checkPackageJson(currentPath, path.basename(currentPath), badPackages);

    for (const entry of entries) {
        if (isShuttingDown) break;

        const fullPath = path.join(currentPath, entry.name);

        if (entry.isFile() && (entry.name === 'package-lock.json' || entry.name === 'yarn.lock' || entry.name === 'npm-shrinkwrap.json')) {
            checkLockfile(fullPath, badPackages);
        }
        else if (entry.isDirectory() && entry.name === 'node_modules') {
            scanNodeModules(fullPath, badPackages);
        }
        else if (entry.isDirectory() && !entry.name.startsWith('.') && !entry.name.startsWith('_')) {
            scanDir(fullPath, badPackages, depth + 1, maxDepth);
        }
    }
}

function scanNodeModules(modulesPath, badPackages) {
    if (isShuttingDown) return;

    try {
        const packages = fs.readdirSync(modulesPath);

        for (const pkg of packages) {
            if (isShuttingDown) break;
            if (pkg.startsWith('.')) continue;

            if (scanStats.packagesScanned >= CONFIG.MAX_PACKAGES_SCANNED) {
                if (scanStats.packagesScanned === CONFIG.MAX_PACKAGES_SCANNED) {
                    console.log(`${colors.yellow}    > Warning: Package scan limit reached (${CONFIG.MAX_PACKAGES_SCANNED})${colors.reset}`);
                }
                return;
            }

            if (pkg.startsWith('@')) {
                const scopedPath = path.join(modulesPath, pkg);
                try {
                    const scopedPackages = fs.readdirSync(scopedPath);
                    for (const sp of scopedPackages) {
                        const pkgPath = path.join(scopedPath, sp);
                        checkPackageJson(pkgPath, `${pkg}/${sp}`, badPackages);
                        checkPackageLockfiles(pkgPath, badPackages);
                        scanStats.packagesScanned++;
                    }
                } catch (e) {
                    scanStats.errorsEncountered++;
                }
            } else {
                const pkgPath = path.join(modulesPath, pkg);
                checkPackageJson(pkgPath, pkg, badPackages);
                checkPackageLockfiles(pkgPath, badPackages);
                scanStats.packagesScanned++;
            }
        }
    } catch (e) {
        scanStats.errorsEncountered++;
    }
}

function checkPackageLockfiles(pkgPath, badPackages) {
    const lockFiles = ['package-lock.json', 'yarn.lock', 'npm-shrinkwrap.json'];
    for (const lockFile of lockFiles) {
        const lockPath = path.join(pkgPath, lockFile);
        try {
            // Use lstatSync to check existence and file type in one call
            const stats = fs.lstatSync(lockPath);
            if (stats.isFile()) {
                checkLockfile(lockPath, badPackages);
            }
        } catch (e) {
            // File doesn't exist or can't be accessed - skip silently
        }
    }
}

// ============================================================================
// CORE PACKAGE CHECKING (Forensic + Metadata + Ghost)
// ============================================================================

function checkPackageJson(pkgPath, pkgName, badPackages) {
    if (isShuttingDown) return;

    scanStats.filesChecked++;

    // Validate package path
    const validatedPkgPath = validatePath(pkgPath);
    if (!validatedPkgPath) return;

    // 1. FORENSIC CHECK (Malware files)
    for (const [forensicPath] of FORENSIC_RULES_ENTRIES) {
        const fullPath = path.join(validatedPkgPath, forensicPath);
        
        // Fast path: Check if file exists before expensive operations
        try {
            const stats = fs.lstatSync(fullPath);
            if (!stats.isFile()) continue;
        } catch (e) {
            continue; // File doesn't exist - skip remaining checks
        }
        
        // File exists - validate path for security (only when needed)
        const validatedFullPath = validatePath(fullPath, validatedPkgPath);
        if (!validatedFullPath) continue;
        
        // Verify file content
        const verification = verifySuspiciousFile(validatedFullPath, forensicPath);
        
        // Track verification errors
        if (verification.reason === 'Read error') {
            scanStats.errorsEncountered++;
            continue;
        }
        
        if (verification.confirmed) {
            const severity = verification.severity || 'HIGH';
            const isCritical = severity === 'CRITICAL';
            
            // Use different colors and labels based on severity
            const label = isCritical ? 'CRITICAL: MALWARE FILE FOUND' : 'SUSPICIOUS: Artifact Found';
            const color = isCritical ? colors.red : colors.yellow;
            const issueType = isCritical ? 'FORENSIC_MATCH' : 'FORENSIC_ARTIFACT';
            
            const msg = `[${isCritical ? '!!!' : '??'}] ${label}: ${sanitizeForLog(forensicPath, 100)} in ${sanitizeForLog(pkgName)}`;
            console.log(`${color}${msg}${colors.reset}`);
            if (forensicPath !== 'setup_bun.js') { // detailed log for contextual files
                console.log(`${colors.dim}    Reason: ${sanitizeForLog(verification.reason, 150)}${colors.reset}`);
            }

            detectedIssues.push({
                type: issueType,
                package: pkgName,
                version: 'UNKNOWN',
                location: validatedPkgPath,
                details: `${sanitizeForLog(forensicPath, 100)} (${sanitizeForLog(verification.reason, 150)})`
            });
            
        } else {
            // False positive - record as safe match (silent, like version safe matches)
            detectedIssues.push({
                type: 'SAFE_MATCH',
                package: pkgName,
                version: 'UNKNOWN',
                location: validatedPkgPath,
                details: `Benign ${sanitizeForLog(forensicPath, 50)}: ${sanitizeForLog(verification.reason, 100)}`
            });
        }
    }

    const pJsonPath = path.join(validatedPkgPath, 'package.json');

    // 2. GHOST CHECK & 3. METADATA CHECK & HEURISTIC CHECK
    let packageJson;
    try {
        const { content, error } = safeReadFile(pJsonPath, CONFIG.MAX_FILE_SIZE_BYTES);

        if (error) {
            if (badPackages[pkgName]) {
                if (error === 'ENOENT') {
                    // Ghost package - folder exists but no package.json
                    console.log(`${colors.yellow}    [?] WARNING: Ghost folder "${sanitizeForLog(pkgName)}"${colors.reset}`);
                    detectedIssues.push({
                        type: 'GHOST_PACKAGE',
                        package: pkgName,
                        version: 'UNKNOWN',
                        location: pkgPath,
                        details: 'Targeted package folder exists but package.json is missing'
                    });
                } else {
                    detectedIssues.push({
                        type: 'CORRUPT_PACKAGE',
                        package: pkgName,
                        version: 'UNKNOWN',
                        location: pkgPath,
                        details: `package.json ${error}`
                    });
                }
            }
            return;
        }

        packageJson = JSON.parse(content);

        // A. HEURISTIC SCRIPT CHECK (Run on everything)
        checkScripts(packageJson, pkgName, pkgPath);

        // B. TARGET CHECK
        if (!badPackages[pkgName]) return;

        // C. VERSION CHECK
        const version = packageJson.version;
        if (!version || typeof version !== 'string') {
            detectedIssues.push({
                type: 'CORRUPT_PACKAGE',
                package: pkgName,
                version: 'UNKNOWN',
                location: pkgPath,
                details: 'Missing or invalid version field'
            });
            return;
        }

        const targetVersions = badPackages[pkgName];

        const hasWildcard = targetVersions.has('*');
        if (hasWildcard || targetVersions.has(version)) {
            const matchType = hasWildcard ? 'WILDCARD_MATCH' : 'VERSION_MATCH';
            console.log(`${colors.red}    [!] ALERT: ${sanitizeForLog(pkgName)}@${sanitizeForLog(version)} matches denylist (${matchType})${colors.reset}`);
            detectedIssues.push({
                type: matchType,
                package: pkgName,
                version: version,
                location: pkgPath
            });
        } else {
            detectedIssues.push({
                type: 'SAFE_MATCH',
                package: pkgName,
                version: version,
                location: pkgPath
            });
        }
    } catch (e) {
        if (badPackages[pkgName]) {
            detectedIssues.push({
                type: 'CORRUPT_PACKAGE',
                package: pkgName,
                version: 'UNKNOWN',
                location: pkgPath,
                details: `package.json parse error: ${e.message}`
            });
        }
    }
}


// ============================================================================
// FORNSIC FILE VERIFICATION (Deep Content Scan)
// ============================================================================

function verifySuspiciousFile(filePath, fileName) {
    // Input validation
    if (!filePath || typeof filePath !== 'string' || !fileName || typeof fileName !== 'string') {
        return { confirmed: false, reason: 'Invalid parameters' };
    }
    
    // Validate path
    const validatedPath = validatePath(filePath);
    if (!validatedPath) {
        return { confirmed: false, reason: 'Invalid file path' };
    }
    
    // 1. Get rule
    // Handle case-insensitive match logic
    const exactRule = FORENSIC_RULES[fileName];
    const lowerKey = FORENSIC_RULES_KEYS_LOWER[fileName.toLowerCase()];
    const rule = exactRule || FORENSIC_RULES[lowerKey];

    if (!rule) return { confirmed: false, reason: 'No rule found' };

    // 2. High Confidence files need no verification
    if (!rule.checkContent) {
        return { confirmed: true, reason: 'High confidence IOC', severity: rule.type };
    }

    // 3. Read File Content (Limit to 5MB to prevent freezing on huge bundles)
    const { content, error, size } = safeReadFile(validatedPath, 5 * 1024 * 1024);
    if (error) return { confirmed: false, reason: 'Read error' };
    if (!content || size === 0) return { confirmed: false, reason: 'Empty file' };
    
    // Additional safety: Limit content length for regex operations to prevent ReDoS
    const MAX_CONTENT_LENGTH_FOR_REGEX = 10 * 1024 * 1024; // 10MB
    if (content.length > MAX_CONTENT_LENGTH_FOR_REGEX) {
        return { confirmed: false, reason: 'File too large for content analysis' };
    }

    // 4. JSON Validation (for contents.json, cloud.json)
    if (rule.isJson) {
        try {
            // Prevent JSON bomb attacks - limit JSON depth and size
            if (content.length > 5 * 1024 * 1024) { // 5MB limit for JSON
                return { confirmed: false, reason: 'JSON file too large' };
            }
            
            const json = JSON.parse(content);
            
            // Validate JSON structure
            if (typeof json !== 'object' || json === null) {
                return { confirmed: false, reason: 'Invalid JSON structure' };
            }
            
            const keys = Object.keys(json);
            
            // Bounds check on keys
            if (keys.length > 10000) {
                return { confirmed: false, reason: 'JSON has too many keys' };
            }
            
            // Check Safe Keys (Allowlist) - If it has these, it's likely safe
            if (rule.safeKeys && rule.safeKeys.some(safeKey => keys.includes(safeKey))) {
                return { confirmed: false, reason: 'Contains whitelisted JSON keys' };
            }

            // Check Malicious Keys (Blocklist) - Must have at least one suspicious key
            const hasSuspiciousKey = rule.requiredKeys.some(reqKey => {
                if (!reqKey || typeof reqKey !== 'string') return false;
                
                // Check top level keys
                if (keys.some(k => k && k.toLowerCase().includes(reqKey.toLowerCase()))) {
                    return true;
                }
                
                // Or check generic "env" dumps where values are strings
                // Limit stringified JSON length to prevent DoS
                try {
                    const jsonStr = JSON.stringify(json);
                    if (jsonStr.length > 1024 * 1024) { // 1MB limit
                        return false; // Skip deep scan if too large
                    }
                    return jsonStr.includes(reqKey);
                } catch (e) {
                    return false;
                }
            });

            if (hasSuspiciousKey) {
                return { confirmed: true, reason: 'Contains suspicious JSON keys', severity: rule.type };
            }
            return { confirmed: false, reason: 'JSON structure benign', severity: rule.type };

        } catch (e) {
            // If it's meant to be JSON but fails parsing, it's not our target (or corrupt)
            return { confirmed: false, reason: 'Invalid JSON' };
        }
    }

    // 5. Text/Script Validation (for bundle.js)
    if (rule.indicators) {
        // For large files, limit content checked to prevent performance issues
        const contentToCheck = content.length > 1024 * 1024 
            ? content.slice(0, 1024 * 1024) // Check first 1MB only
            : content;
        
        // Check for indicators with ReDoS protection
        const matchesIndicator = rule.indicators.some(regex => {
            try {
                return regex.test(contentToCheck);
            } catch (e) {
                scanStats.errorsEncountered++;
                return false;
            }
        });
        
        // Optional: Check for safe patterns (like Webpack boilerplate) to reduce noise
        const matchesSafe = rule.safePatterns ? rule.safePatterns.some(regex => {
            try {
                return regex.test(contentToCheck);
            } catch (e) {
                scanStats.errorsEncountered++;
                return false;
            }
        }) : false;

        if (matchesIndicator && !matchesSafe) {
            return { confirmed: true, reason: 'Matched malicious content signatures', severity: rule.type };
        }
        
        // Special logic: If bundle.js is huge and has no suspicious strings, it's likely safe.
        // Malware payloads are often relatively small or specific.
        return { confirmed: false, reason: 'Content did not match malware signatures', severity: rule.type };
    }

    return { confirmed: false, reason: 'Inconclusive' };
}

// ============================================================================
// HEURISTIC SCRIPT SCANNER
// ============================================================================

function checkScripts(content, pkgName, pkgPath) {
    if (!content || !content.scripts || typeof content.scripts !== 'object') return;

    const hooks = ['preinstall', 'install', 'postinstall', 'prepublish', 'prepare', 'preuninstall', 'postuninstall'];
    
    // Quick check: do any lifecycle hooks exist?
    const hasLifecycleHooks = hooks.some(hook => content.scripts[hook]);
    if (!hasLifecycleHooks) return; // Fast path for packages without lifecycle scripts

    for (const hook of hooks) {
        if (!content.scripts[hook]) continue;

        const cmd = content.scripts[hook];
        if (typeof cmd !== 'string') continue;

        // Limit command length to prevent ReDoS
        const truncatedCmd = cmd.slice(0, 2000);

        // 1. Whitelist Check
        if (SCRIPT_WHITELIST.has(truncatedCmd)) continue;

        const isWhitelistedRegex = SCRIPT_WHITELIST_REGEX.some(regex => {
            try {
                return regex.test(truncatedCmd);
            } catch (e) {
                return false;
            }
        });
        if (isWhitelistedRegex) continue;

        // 2. Critical Check
        for (const rule of CRITICAL_PATTERNS) {
            try {
                if (rule.pattern.test(truncatedCmd)) {
                    console.log(`${colors.red}    [!] SCRIPT ALERT: ${sanitizeForLog(pkgName)} [${hook}] -> ${rule.desc}${colors.reset}`);
                    detectedIssues.push({
                        type: 'CRITICAL_SCRIPT',
                        package: pkgName,
                        version: content.version || 'UNKNOWN',
                        location: pkgPath,
                        details: `${rule.indicator}: ${rule.desc}`
                    });
                    return; // Stop checking this script
                }
            } catch (e) {
                scanStats.errorsEncountered++;
            }
        }

        // 3. Warning Check
        for (const rule of WARNING_PATTERNS) {
            try {
                if (rule.pattern.test(truncatedCmd)) {
                    detectedIssues.push({
                        type: 'SCRIPT_WARNING',
                        package: pkgName,
                        version: content.version || 'UNKNOWN',
                        location: pkgPath,
                        details: `${rule.indicator}: ${rule.desc}`
                    });
                }
            } catch (e) {
                scanStats.errorsEncountered++;
            }
        }
    }
}

// ============================================================================
// LOCKFILE CHECKING
// ============================================================================

function checkDependenciesRecursive(deps, badPackages, lockPath, depth = 0) {
    if (depth > 100) return; // Prevent infinite recursion

    for (const [pkg, details] of Object.entries(deps)) {
        if (badPackages[pkg] && details && details.version) {
            checkVersionMatch(pkg, details.version, badPackages[pkg], lockPath, 'NPM_LOCK_V1');
        }
        if (details && details.dependencies && typeof details.dependencies === 'object') {
            checkDependenciesRecursive(details.dependencies, badPackages, lockPath, depth + 1);
        }
    }
}

function checkVersionMatch(pkg, ver, badVersions, lockPath, type) {
    if (!ver || typeof ver !== 'string') return;

    const cleanVer = ver.slice(0, 50); // Limit version string length

    if (badVersions.has(cleanVer)) {
        detectedIssues.push({
            type: 'LOCKFILE_HIT',
            package: pkg,
            version: cleanVer,
            location: lockPath,
            details: `Exact match in ${type}`
        });
    }
    else if (badVersions.has('*')) {
        detectedIssues.push({
            type: 'WILDCARD_LOCK_HIT',
            package: pkg,
            version: cleanVer,
            location: lockPath,
            details: `Wildcard match in ${type}`
        });
    }
}

function checkLockfile(lockPath, badPackages) {
    if (isShuttingDown) return;

    scanStats.lockfilesChecked++;

    const fileName = path.basename(lockPath);

    const { content, error, size } = safeReadFile(lockPath, CONFIG.MAX_LOCKFILE_SIZE_BYTES);
    if (error) {
        if (error === 'FILE_TOO_LARGE') {
            console.log(`${colors.yellow}    > Skipping large lockfile (${(size / 1024 / 1024).toFixed(1)}MB): ${sanitizeForLog(lockPath, 100)}${colors.reset}`);
        }
        return;
    }

    // --- 1. NPM Lockfile ---
    if (fileName === 'package-lock.json' || fileName === 'npm-shrinkwrap.json') {
        try {
            const json = JSON.parse(content);

            // Check v2/v3 "packages" section
            if (json.packages && typeof json.packages === 'object') {
                for (const [key, details] of Object.entries(json.packages)) {
                    const pkgName = key.replace(/^.*node_modules\//, '');

                    if (pkgName && badPackages[pkgName] && details && details.version) {
                        checkVersionMatch(pkgName, details.version, badPackages[pkgName], lockPath, 'NPM_LOCK_V3');
                    }
                }
            }

            // Check v1 "dependencies" section
            if (json.dependencies && typeof json.dependencies === 'object') {
                checkDependenciesRecursive(json.dependencies, badPackages, lockPath);
            }

        } catch (e) {
            // Silently ignore parse errors for lockfiles (common with partial writes)
        }
    }

    // --- 2. Yarn Lockfile ---
    else if (fileName === 'yarn.lock') {
        // Parse yarn.lock once and check against badPackages
        // This is much faster than regex matching for each package×version combination
        const lines = content.split('\n');
        let currentPkg = null;
        let currentVersion = null;
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            
            // Package declaration line (e.g., "pkg@^1.0.0:" or "@scope/pkg@^1.0.0:")
            if (line && !line.startsWith(' ') && line.includes('@') && line.endsWith(':')) {
                const match = line.match(/^"?(@?[^@"]+)@/);
                if (match) {
                    currentPkg = match[1];
                    currentVersion = null;
                }
            }
            // Version line (e.g., "  version "1.0.0"")
            else if (currentPkg && line.trim().startsWith('version ')) {
                const versionMatch = line.match(/version\s+"([^"]+)"/);
                if (versionMatch) {
                    currentVersion = versionMatch[1];
                    
                    // Check if this package/version is in our denylist
                    if (badPackages[currentPkg]) {
                        const badVersions = badPackages[currentPkg];
                        if (badVersions.has('*')) {
                            detectedIssues.push({
                                type: 'WILDCARD_LOCK_HIT',
                                package: currentPkg,
                                version: currentVersion,
                                location: lockPath,
                                details: 'Yarn Lock match (Wildcard)'
                            });
                        } else if (badVersions.has(currentVersion)) {
                            detectedIssues.push({
                                type: 'LOCKFILE_HIT',
                                package: currentPkg,
                                version: currentVersion,
                                location: lockPath,
                                details: 'Yarn Lock match (Strict)'
                            });
                        }
                    }
                    currentPkg = null; // Reset after processing
                }
            }
        }
    }
}

// ============================================================================
// REPORTING
// ============================================================================

function generateReport(userInfo, isPartial = false) {
    console.log(`\n${colors.cyan}[5/5] Generating Report...${colors.reset}`);

    const headers = [
        'Timestamp',
        'Report_Type',
        'Hostname',
        'Git_User',
        'Git_Email',
        'NPM_User',
        'Platform',
        'Node_Version',
        'Scanner_Version',
        'Issue_Type',
        'Package',
        'Version',
        'Location',
        'Details',
        'Scan_Duration_MS',
        'Directories_Scanned',
        'Packages_Scanned'
    ];

    let csvContent = headers.join(',') + '\n';
    const now = new Date().toISOString();
    const duration = scanStats.startTime ? Date.now() - scanStats.startTime : 0;
    const reportType = isPartial ? 'PARTIAL' : 'COMPLETE';

    detectedIssues.forEach(issue => {
        const row = [
            escapeCSV(now),
            escapeCSV(reportType),
            escapeCSV(userInfo.hostname),
            escapeCSV(userInfo.gitName),
            escapeCSV(userInfo.gitEmail),
            escapeCSV(userInfo.npmUser),
            escapeCSV(userInfo.platform),
            escapeCSV(userInfo.nodeVersion || process.version),
            escapeCSV(userInfo.scannerVersion || '2.1.0-hardened'),
            escapeCSV(issue.type),
            escapeCSV(issue.package),
            escapeCSV(issue.version),
            escapeCSV(issue.location),
            escapeCSV(issue.details || ''),
            escapeCSV(String(duration)),
            escapeCSV(String(scanStats.directoriesScanned)),
            escapeCSV(String(scanStats.packagesScanned))
        ];
        csvContent += row.join(',') + '\n';
    });

    // Write atomically
    const tempFile = CONFIG.REPORT_FILE + '.tmp.' + process.pid;
    try {
        fs.writeFileSync(tempFile, csvContent, { encoding: 'utf8', mode: 0o644 });
        fs.renameSync(tempFile, CONFIG.REPORT_FILE);
        console.log(`    > CSV saved to: ${CONFIG.REPORT_FILE}`);
    } catch (e) {
        // Fallback: direct write
        fs.writeFileSync(CONFIG.REPORT_FILE, csvContent, { encoding: 'utf8', mode: 0o644 });
        console.log(`    > CSV saved to: ${CONFIG.REPORT_FILE}`);
    }

    return csvContent;
}

async function uploadReport(csvContent, userInfo) {
    if (!UPLOAD_API_URL) {
        console.log(`${colors.dim}    > Skipping upload (API URL not configured via SHAI_HULUD_API_URL env var)${colors.reset}`);
        return;
    }

    if (!API_KEY) {
        console.log(`${colors.yellow}    > Warning: API key not set (SHAI_HULUD_API_KEY env var)${colors.reset}`);
    }

    console.log(`${colors.yellow}    > Uploading Report to Security API...${colors.reset}`);

    // Validate URL
    let parsedUrl;
    try {
        parsedUrl = new URL(UPLOAD_API_URL);
        if (parsedUrl.protocol !== 'https:') {
            console.log(`${colors.red}    > Upload Failed: Only HTTPS URLs are allowed${colors.reset}`);
            return;
        }
    } catch (e) {
        console.log(`${colors.red}    > Upload Failed: Invalid API URL${colors.reset}`);
        return;
    }

    const payload = JSON.stringify({
        userInfo: {
            hostname: userInfo.hostname,
            platform: userInfo.platform,
            nodeVersion: userInfo.nodeVersion,
            scannerVersion: userInfo.scannerVersion
            // Note: Removed potentially sensitive gitName, gitEmail, npmUser from upload
        },
        reportHash: computeHash(csvContent),
        issueCount: detectedIssues.length,
        criticalCount: detectedIssues.filter(i =>
            ['FORENSIC_MATCH', 'CRITICAL_SCRIPT', 'VERSION_MATCH', 'WILDCARD_MATCH', 'LOCKFILE_HIT', 'WILDCARD_LOCK_HIT'].includes(i.type)
        ).length,
        report: csvContent
    });

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            'User-Agent': 'Shai-Hulud-Scanner/2.1.0',
            ...(API_KEY && { 'x-api-key': API_KEY })
        },
        timeout: 30000
    };

    return new Promise((resolve) => {
        const req = https.request(UPLOAD_API_URL, options, (res) => {
            let responseBody = '';

            res.on('data', (chunk) => {
                if (responseBody.length < 10000) { // Limit response size
                    responseBody += chunk;
                }
            });

            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    console.log(`${colors.green}    > Upload Success!${colors.reset}`);
                } else {
                    console.log(`${colors.red}    > Upload Failed (Status: ${res.statusCode})${colors.reset}`);
                }
                resolve();
            });
        });

        req.on('error', (e) => {
            console.log(`    > Upload Error: ${e.message}`);
            resolve();
        });

        req.on('timeout', () => {
            req.destroy();
            console.log(`    > Upload Timeout`);
            resolve();
        });

        req.write(payload);
        req.end();
    });
}

// ============================================================================
// HELP TEXT
// ============================================================================

function printHelp() {
    console.log(`
${colors.bold}Shai-Hulud 2.0 Supply Chain Attack Scanner (Enhanced)${colors.reset}

${colors.cyan}USAGE:${colors.reset}
    node shai-hulud-scanner-enhanced.js [path] [options]

${colors.cyan}OPTIONS:${colors.reset}
    --full-scan       Scan system paths in addition to project path
    --no-cache        Bypass IOC cache and fetch fresh data
    --no-upload       Skip uploading report to security API
    --depth=<n>       Set maximum directory traversal depth (default: ${CONFIG.DEFAULT_SCAN_DEPTH}, max: ${CONFIG.MAX_SCAN_DEPTH})
    --fail-on=<level> Set CI/CD exit code threshold:
                        critical - Exit 1 on critical findings only (default)
                        warning  - Exit 1 on critical or warning findings
                        off      - Always exit 0 (report only)
    --help, -h        Show this help message

${colors.cyan}EXAMPLES:${colors.reset}
    # Scan current directory only
    node shai-hulud-scanner-enhanced.js

    # Scan specific project
    node shai-hulud-scanner-enhanced.js /path/to/project

    # Full system scan with fresh IOC data
    node shai-hulud-scanner-enhanced.js --full-scan --no-cache

    # CI/CD usage - fail build on any findings
    node shai-hulud-scanner-enhanced.js --fail-on=warning

${colors.cyan}ENVIRONMENT VARIABLES:${colors.reset}
    SHAI_HULUD_API_URL   URL for report upload API
    SHAI_HULUD_API_KEY   API key for authentication

${colors.cyan}EXIT CODES:${colors.reset}
    0   - Scan complete, no critical issues (or --fail-on=off)
    1   - Critical or warning issues found (depending on --fail-on)
    130 - Interrupted by user (SIGINT)
`);
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

(async () => {
    const args = process.argv.slice(2);

    // Help check
    if (args.includes('--help') || args.includes('-h')) {
        printHelp();
        process.exit(0);
    }

    setupSignalHandlers();
    scanStats.startTime = Date.now();

    console.log(`\n${colors.yellow}=== Shai-Hulud 2.0 Detector (Enhanced & Hardened) ===${colors.reset}`);

    // Parse arguments
    const pathArg = args.find(arg => !arg.startsWith('--'));
    const inputPath = pathArg || process.cwd();
    const isFullScan = args.includes('--full-scan');
    const shouldUpload = !args.includes('--no-upload');
    const noCache = args.includes('--no-cache');

    // Validate and normalize scan path
    const scanPath = validatePath(inputPath);
    if (!scanPath) {
        console.error(`${colors.red}Error: Invalid scan path provided${colors.reset}`);
        process.exit(1);
    }

    if (!fs.existsSync(scanPath)) {
        console.error(`${colors.red}Error: Path does not exist: ${sanitizeForLog(scanPath)}${colors.reset}`);
        process.exit(1);
    }

    // Parse depth
    let maxDepth = CONFIG.DEFAULT_SCAN_DEPTH;
    const depthEqArg = args.find(a => a.startsWith('--depth='));
    const depthIdx = args.findIndex(a => a === '--depth');
    if (depthEqArg) {
        const val = Number(depthEqArg.split('=')[1]);
        if (!Number.isNaN(val) && val >= 0 && val <= CONFIG.MAX_SCAN_DEPTH) {
            maxDepth = val;
        }
    } else if (depthIdx !== -1 && args[depthIdx + 1]) {
        const val = Number(args[depthIdx + 1]);
        if (!Number.isNaN(val) && val >= 0 && val <= CONFIG.MAX_SCAN_DEPTH) {
            maxDepth = val;
        }
    }

    // Parse fail-on
    let failOn = CONFIG.DEFAULT_FAIL_ON;
    const failOnEqArg = args.find(a => a.startsWith('--fail-on='));
    const failOnIdx = args.findIndex(a => a === '--fail-on');
    if (failOnEqArg) {
        const val = failOnEqArg.split('=')[1].toLowerCase();
        if (['critical', 'warning', 'off'].includes(val)) failOn = val;
    } else if (failOnIdx !== -1 && args[failOnIdx + 1]) {
        const val = args[failOnIdx + 1].toLowerCase();
        if (['critical', 'warning', 'off'].includes(val)) failOn = val;
    }

    const isProjectOnlyMode = pathArg && !isFullScan;

    const userInfo = getUserInfo();
    const badPackages = await fetchThreats(noCache);

    if (Object.keys(badPackages).length === 0) {
        console.log(`${colors.yellow}    > Warning: No threat intelligence loaded. Continuing with forensic checks only.${colors.reset}`);
    }

    console.log(`\n${colors.cyan}[4/5] Starting Deep Scan...${colors.reset}`);
    console.log(`    > Max Depth: ${maxDepth}`);

    if (isProjectOnlyMode) {
        console.log(`${colors.yellow}    > Mode: Project-Only Scan${colors.reset}`);
        console.log(`    > Scanning Project Dir: ${scanPath}`);
        scanDir(scanPath, badPackages, 0, maxDepth);
    } else {
        console.log(`${colors.yellow}    > Mode: Full System Scan${colors.reset}`);
        const systemPaths = getSearchPaths();

        systemPaths.forEach(p => {
            if (isShuttingDown) return;
            console.log(`    > Scanning System Path: ${p}`);
            scanDir(p, badPackages, 0, maxDepth);
        });

        if (!isShuttingDown) {
            console.log(`    > Scanning Project Dir: ${scanPath}`);
            scanDir(scanPath, badPackages, 0, maxDepth);
        }
    }

    // 3. Summary
    const threats = detectedIssues.filter(i => i.type !== 'SAFE_MATCH');
    const duration = Date.now() - scanStats.startTime;

    console.log(`\n${colors.dim}    Scan Stats: ${scanStats.directoriesScanned} dirs, ${scanStats.packagesScanned} packages, ${scanStats.lockfilesChecked} lockfiles in ${(duration / 1000).toFixed(1)}s${colors.reset}`);

    if (scanStats.symlinksSkipped > 0) {
        console.log(`${colors.dim}    Symlinks skipped: ${scanStats.symlinksSkipped}${colors.reset}`);
    }

    if (threats.length > 0) {
        console.log(`\n${colors.red}!!! THREATS DETECTED: ${threats.length} !!!${colors.reset}`);
    } else if (detectedIssues.length > 0) {
        console.log(`\n${colors.green}✓ System clean. (Found ${detectedIssues.length} safe versions for audit).${colors.reset}`);
    } else {
        console.log(`\n${colors.green}✓ System clean. No target packages found.${colors.reset}`);
    }

    const reportCSV = generateReport(userInfo);
    // --- UPLOAD LOGIC ---
    if (detectedIssues.length === 0) {
        console.log(`${colors.dim}    > Report is empty. Skipping upload.${colors.reset}`);
    } else if (shouldUpload) {
        await uploadReport(reportCSV, userInfo);
    } else {
        console.log(`${colors.dim}    > Upload skipped (disabled by user).${colors.reset}`);
    }

    // --- CI/CD EXIT CODE LOGIC ---
    // Only apply exit code logic if --fail-on flag was explicitly provided
    if (failOnEqArg || failOnIdx !== -1) {
        const criticalTypes = ['FORENSIC_MATCH', 'CRITICAL_SCRIPT', 'VERSION_MATCH', 'WILDCARD_MATCH', 'LOCKFILE_HIT', 'WILDCARD_LOCK_HIT'];
        const warningTypes = ['SCRIPT_WARNING', 'GHOST_PACKAGE', 'CORRUPT_PACKAGE'];

        const criticalCount = detectedIssues.filter(i => criticalTypes.includes(i.type)).length;
        const warningCount = detectedIssues.filter(i => warningTypes.includes(i.type)).length;

        if (failOn === 'off') {
            console.log(`${colors.dim}\n[CI/CD] Exit mode: OFF - Always exiting with code 0${colors.reset}`);
            process.exit(0);
        } else if (failOn === 'critical') {
            if (criticalCount > 0) {
                console.log(`${colors.red}\n[CI/CD] FAIL: ${criticalCount} critical finding(s) detected (--fail-on=critical)${colors.reset}`);
                process.exit(1);
            } else {
                console.log(`${colors.green}\n[CI/CD] PASS: No critical findings (${warningCount} warning(s) ignored)${colors.reset}`);
                process.exit(0);
            }
        } else if (failOn === 'warning') {
            if (criticalCount > 0 || warningCount > 0) {
                console.log(`${colors.red}\n[CI/CD] FAIL: ${criticalCount} critical, ${warningCount} warning(s) detected (--fail-on=warning)${colors.reset}`);
                process.exit(1);
            } else {
                console.log(`${colors.green}\n[CI/CD] PASS: No critical or warning findings${colors.reset}`);
                process.exit(0);
            }
        }
    }
    // If --fail-on not provided, exit normally (code 0)
})();