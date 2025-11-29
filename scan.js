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

const fs = require('fs');
const path = require('path');
const https = require('https');
const os = require('os');
const { execSync } = require('child_process');

// --- CONFIGURATION ---
const REPORT_FILE = 'shai-hulud-report.csv';
// Source 1: Wiz Research - CSV
const IOC_CSV_URL = 'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv';
// Source 2: Hemachandsai Malicious Packages
const IOC_JSON_URL = 'https://raw.githubusercontent.com/hemachandsai/shai-hulud-malicious-packages/main/malicious_npm_packages.json';

// Cache Configuration
const CACHE_DIR = path.join(__dirname, '.cache');
const FALLBACK_DIR = path.join(__dirname, 'fallback');
const CACHE_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes (configurable)
const CACHE_WIZ_FILE = path.join(CACHE_DIR, 'wiz-iocs.csv');
const CACHE_JSON_FILE = path.join(CACHE_DIR, 'malicious-packages.json');
const FALLBACK_WIZ_FILE = path.join(FALLBACK_DIR, 'wiz-iocs.csv');
const FALLBACK_JSON_FILE = path.join(FALLBACK_DIR, 'malicious-packages.json');

// API Configuration
const UPLOAD_API_URL = 'https://YOUR-LAMBDA-URL.lambda-url.us-east-1.on.aws/';
const API_KEY = 'secure-me-1234';
// ---------------------

// --- SCAN SETTINGS ---
// Default maximum directory traversal depth when scanning.
// Can be overridden via CLI flag: --depth=<number>
const DEFAULT_MAX_SCAN_DEPTH = 5;
// ---------------------

const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    reset: '\x1b[0m',
    dim: '\x1b[2m'
};


 // --- FORENSIC file list ---

const malwareFiles = [
    // Active Payloads (Shai-Hulud 2.0)
    'setup_bun.js', 
    'bun_environment.js',
    
    // Active Payloads (Shai-Hulud 1.0)
    'bundle.js', 

    // Exfiltration Evidence (If found, data was likely stolen)
    'truffleSecrets.json',
    'cloud.json',
    'contents.json',
    'environment.json',
    'actionsSecrets.json'
];

// --- HEURISTIC CONFIGURATION ---

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
    /^echo\s/, /^rimraf\s/, /^shx\s/, /^tsc(\s|$)/, /^ngcc(\s|$)/,
    /^node-gyp\s/, /^prebuild-install/, /^husky(\s|$)/, /^is-ci\s/,
    /^opencollective(-postinstall)?/, /^patch-package/,
    /^node\s+scripts\/postinstall(\.js)?$/, /^electron-builder\s+install-app-deps/,
    /^lerna\s+bootstrap/, /^(nx|turbo)\s+run/, /^esbuild(\s|$)/,
    /^node-pre-gyp\s+install(\s|$)/
];

const CRITICAL_PATTERNS = [
    { pattern: /curl\s+.*\|\s*(sh|bash|zsh)/i, desc: 'Curl piped to shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /wget\s+.*\|\s*(sh|bash|zsh)/i, desc: 'Wget piped to shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /curl\s+.*>\s*[^|]+\s*&&\s*(sh|bash|chmod)/i, desc: 'Curl download & exec', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /curl\s+.*githubusercontent\.com\/.*\|\s*(sh|bash|zsh)/i, desc: 'Pipe raw GitHub content to shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /wget\s+.*raw\.githubusercontent\.com\/.*\|\s*(sh|bash|zsh)/i, desc: 'Pipe raw GitHub content to shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /\b(b64|base64)\b[\s\S]*\|\s*(sh|bash)/i, desc: 'Decode then execute via shell', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /base64\s+(-d|--decode)/i, desc: 'Base64 decoding', indicator: 'OBFUSCATION' },
    { pattern: /\beval\s*\(/, desc: 'Eval statement', indicator: 'CODE_INJECTION' },
    { pattern: /setup_bun/i, desc: 'Shai-Hulud Loader', indicator: 'SHAI_HULUD' },
    { pattern: /bun_environment/i, desc: 'Shai-Hulud Payload', indicator: 'SHAI_HULUD' },
    { pattern: /SHA1HULUD/i, desc: 'Shai-Hulud Signature', indicator: 'SHAI_HULUD' },
    { pattern: /node\s+-e\s+["']require\s*\(\s*["']child_process["']\s*\)/, desc: 'Hidden child_process', indicator: 'CODE_INJECTION' },
    { pattern: /child_process.*exec.*\$\(/, desc: 'Shell command via child_process', indicator: 'CODE_INJECTION' },
    { pattern: /\$\(curl/i, desc: 'Subshell curl', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /`curl/i, desc: 'Backtick curl', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /bash\s+-c\s+["'].*curl/i, desc: 'bash -c curl', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /curl\s+.*-o\s+\S+\s*&&\s*(sh|bash|chmod)/i, desc: 'curl save & exec', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /wget\s+.*-O\s+\S+\s*&&\s*(sh|bash|chmod)/i, desc: 'wget save & exec', indicator: 'REMOTE_CODE_EXEC' },
    { pattern: /require\s*\(\s*["']child_process["']\s*\)\.\s*(exec|execSync|spawn|spawnSync)/i, desc: 'Direct child_process call', indicator: 'CODE_INJECTION' },
    { pattern: /\b(execSync|spawnSync|execFileSync)\s*\(/, desc: 'Sync process execution', indicator: 'CODE_INJECTION' },
    { pattern: /\.github\/workflows\/discussion\.ya?ml/i, desc: 'GitHub workflow backdoor', indicator: 'PERSISTENCE' },
    { pattern: /docker\s+run\s+[^\n]*--privileged/i, desc: 'Privileged Docker run', indicator: 'PRIV_ESC' },
    { pattern: /-v\s+\/:\/host\b/i, desc: 'Host mount in container', indicator: 'PRIV_ESC' }
];

const WARNING_PATTERNS = [
    { pattern: /http:\/\//, desc: 'Unencrypted HTTP', indicator: 'INSECURE_NETWORK' },
    { pattern: /\\x[0-9a-fA-F]{2}/, desc: 'Hex-encoded string', indicator: 'OBFUSCATION' },
    { pattern: /String\.fromCharCode/, desc: 'Char code obfuscation', indicator: 'OBFUSCATION' },
    { pattern: /atob\s*\(/, desc: 'Base64 atob decode', indicator: 'OBFUSCATION' },
    { pattern: /Buffer\.from\s*\([^)]+,\s*['"]base64['"]\)/, desc: 'Buffer base64 decode', indicator: 'OBFUSCATION' },
    { pattern: /Buffer\.from\s*\([^)]+,\s*['"]hex['"]\)/, desc: 'Buffer hex decode', indicator: 'OBFUSCATION' },
    { pattern: /Function\s*\([^)]*\)/, desc: 'Dynamic function creation', indicator: 'OBFUSCATION' },
    { pattern: /actions\/upload-artifact/i, desc: 'GitHub Actions artifact usage', indicator: 'EXFIL_ATTEMPT' },
    { pattern: /https?:\/\/api\.github\.com\/(repos|gists|uploads)/i, desc: 'GitHub API interaction', indicator: 'EXFIL_ATTEMPT' },
    { pattern: /child_process\.(exec|spawn|execSync|spawnSync)\([^)]*(curl|wget|nc|bash|sh)/i, desc: 'Shelling out to network tools', indicator: 'CODE_INJECTION' },
    { pattern: /\bnc\b\s+(-[a-zA-Z]+\s+)*\S+/i, desc: 'Netcat usage', indicator: 'BACKDOOR_PRIMITIVE' },
    { pattern: /\bsocat\b\s+/i, desc: 'socat usage', indicator: 'BACKDOOR_PRIMITIVE' }
];

const detectedIssues = [];

// --- 1. User Info ---
function getUserInfo() {
    console.log(`${colors.cyan}[1/5] Identifying User Environment...${colors.reset}`);
    const info = {
        gitName: 'Unknown',
        gitEmail: 'Unknown',
        npmUser: 'Not Logged In',
        hostname: os.hostname(),
        platform: os.platform()
    };

    try { info.gitName = execSync('git config user.name').toString().trim(); } catch (e) {}
    try { info.gitEmail = execSync('git config user.email').toString().trim(); } catch (e) {}
    try { 
        const npmWhoami = execSync('npm whoami', { stdio: ['pipe', 'pipe', 'ignore'] }).toString().trim();
        if (npmWhoami) info.npmUser = npmWhoami;
    } catch (e) {}
    
    console.log(`    > User: ${info.gitName} <${info.gitEmail}>`);
    console.log(`    > NPM User: ${info.npmUser}`);
    console.log(`    > Host: ${info.hostname} (${info.platform})`);
    return info;
}

// --- 2. Cache Helpers ---
function ensureDir(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}

function isCacheValid(cacheFile) {
    if (!fs.existsSync(cacheFile)) return false;
    const stats = fs.statSync(cacheFile);
    const age = Date.now() - stats.mtimeMs;
    return age < CACHE_TIMEOUT_MS;
}

function loadFromCache(cacheFile, type) {
    try {
        const content = fs.readFileSync(cacheFile, 'utf8');
        console.log(`    > ${type}: Loaded from cache (age: ${Math.round((Date.now() - fs.statSync(cacheFile).mtimeMs) / 1000 / 60)}m)`);
        return content;
    } catch (e) {
        return null;
    }
}

function loadFromFallback(fallbackFile, type) {
    try {
        if (!fs.existsSync(fallbackFile)) return null;
        const content = fs.readFileSync(fallbackFile, 'utf8');
        console.log(`    > ${type}: ${colors.yellow}Using offline fallback${colors.reset}`);
        return content;
    } catch (e) {
        return null;
    }
}

function saveToCache(cacheFile, content) {
    try {
        ensureDir(path.dirname(cacheFile));
        fs.writeFileSync(cacheFile, content, 'utf8');
    } catch (e) {
        console.log(`    > Warning: Could not write to cache: ${e.message}`);
    }
}

// --- 3. Threat Intelligence (Dual Feed with Caching) ---
async function fetchThreats(forceNoCache = false) {
    console.log(`\n${colors.cyan}[2/5] Downloading Threat Intelligence (Dual Feed)...${colors.reset}`);
    if (forceNoCache) console.log(`    > ${colors.yellow}Cache bypassed (--no-cache flag)${colors.reset}`);
    
    try {
        const [wizData, jsonData] = await Promise.allSettled([
            fetchWithCache(IOC_CSV_URL, CACHE_WIZ_FILE, FALLBACK_WIZ_FILE, 'Wiz.io CSV', forceNoCache),
            fetchWithCache(IOC_JSON_URL, CACHE_JSON_FILE, FALLBACK_JSON_FILE, 'Malicious JSON', forceNoCache)
        ]);

        const badPackages = {};
        let count = 0;

        // Process Source 1 (Wiz CSV)
        if (wizData.status === 'fulfilled' && wizData.value) {
            const parsed = parseWizCSV(wizData.value);
            for (const [pkg, vers] of Object.entries(parsed)) {
                if (!badPackages[pkg]) badPackages[pkg] = [];
                badPackages[pkg].push(...vers);
            }
            console.log(`    > [Source 1] Wiz.io: Loaded successfully.`);
        } else {
            console.log(`${colors.red}    > [Source 1] Failed: ${wizData.reason || 'No data'}${colors.reset}`);
        }

        // Process Source 2 (Hemachandsai JSON)
        if (jsonData.status === 'fulfilled' && jsonData.value) {
            const parsed = parseMaliciousJSON(jsonData.value);
            for (const [pkg, vers] of Object.entries(parsed)) {
                if (!badPackages[pkg]) badPackages[pkg] = [];
                // If versions is empty [], it means ALL versions are bad -> Add Wildcard '*'
                if (vers.length === 0) {
                    if (!badPackages[pkg].includes('*')) badPackages[pkg].push('*');
                } else {
                    badPackages[pkg].push(...vers);
                }
            }
            console.log(`    > [Source 2] Hemachandsai: Loaded successfully.`);
        } else {
            console.log(`${colors.red}    > [Source 2] Failed: ${jsonData.reason || 'No data'}${colors.reset}`);
        }

        // Clean duplicates
        for (const pkg in badPackages) {
            badPackages[pkg] = [...new Set(badPackages[pkg])];
            count++;
        }

        console.log(`    > Total Threat Database: ${count} unique packages targetted.`);
        return badPackages;
    } catch (e) {
        console.error("Critical Error fetching feeds:", e);
        return {};
    }
}

// Helper: Unified fetch with cache and fallback
function fetchWithCache(url, cacheFile, fallbackFile, sourceName, forceNoCache = false) {
    return new Promise((resolve, reject) => {
        // 1. Check if cache is valid (skip if --no-cache flag is used)
        if (!forceNoCache && isCacheValid(cacheFile)) {
            const cached = loadFromCache(cacheFile, sourceName);
            if (cached) return resolve(cached);
        }

        // 2. Try to fetch from network
        const timeout = setTimeout(() => {
            console.log(`    > ${sourceName}: ${colors.yellow}Network timeout, trying fallback...${colors.reset}`);
            const fallback = loadFromFallback(fallbackFile, sourceName);
            if (fallback) resolve(fallback);
            else reject(new Error('Timeout and no fallback available'));
        }, 10000); // 10 second network timeout

        https.get(url, (res) => {
            clearTimeout(timeout);
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    console.log(`    > ${sourceName}: Downloaded from network.`);
                    saveToCache(cacheFile, data);
                    resolve(data);
                } else {
                    console.log(`    > ${sourceName}: HTTP ${res.statusCode}, trying fallback...`);
                    const fallback = loadFromFallback(fallbackFile, sourceName);
                    if (fallback) resolve(fallback);
                    else reject(new Error(`HTTP ${res.statusCode}`));
                }
            });
        }).on('error', (e) => {
            clearTimeout(timeout);
            console.log(`    > ${sourceName}: ${colors.yellow}Network error, trying fallback...${colors.reset}`);
            const fallback = loadFromFallback(fallbackFile, sourceName);
            if (fallback) resolve(fallback);
            else reject(e);
        });
    });
}

// Helper: Parse Wiz CSV
function parseWizCSV(data) {
    const lines = data.split('\n').filter(l => l.trim() !== '');
    const result = {};
    const startIdx = lines[0].toLowerCase().includes('package') ? 1 : 0;
    for (let i = startIdx; i < lines.length; i++) {
        const parts = lines[i].split(',');
        if (parts.length >= 2) {
            const rawName = parts[0].replace(/["']/g, '').trim();
            const rawVer = parts[1].replace(/["'=<>v\s]/g, '');
            if (rawName && rawVer) {
                if (!result[rawName]) result[rawName] = [];
                result[rawName].push(rawVer);
            }
        }
    }
    return result;
}

// Helper: Parse Malicious JSON
function parseMaliciousJSON(data) {
    try {
        const json = JSON.parse(data);
        const result = {};
        // Format: { "pkgName": { "versions": [] } }
        for (const [pkg, details] of Object.entries(json)) {
            result[pkg] = details.versions || [];
        }
        return result;
    } catch (e) {
        console.log(`    > Error parsing JSON: ${e.message}`);
        return {};
    }
}

// --- 3. Path Discovery (Fixed for Windows NVM) ---
function getSearchPaths() {
    console.log(`\n${colors.cyan}[3/5] Locating Cache & Global Directories...${colors.reset}`);
    const paths = [];
    const home = os.homedir();
    const platform = os.platform();

    // A. Active Global (NPM)
    try {
        const globalPrefix = execSync('npm root -g').toString().trim();
        paths.push(globalPrefix);
        console.log(`    > [NPM] Active Global: ${globalPrefix}`);
    } catch(e) {}

    // B. BUN Support (NEW)
    // Bun standard location is ~/.bun/install/
    const bunBase = path.join(home, '.bun', 'install');
    
    // 1. Bun Global Modules (Actual installed packages)
    const bunGlobal = path.join(bunBase, 'global', 'node_modules');
    if (fs.existsSync(bunGlobal)) {
        paths.push(bunGlobal);
        console.log(`    > [BUN] Global Modules: ${bunGlobal}`);
    }

    // 2. Bun Cache (Downloaded artifacts)
    const bunCache = path.join(bunBase, 'cache');
    if (fs.existsSync(bunCache)) {
        paths.push(bunCache);
        console.log(`    > [BUN] Global Cache: ${bunCache}`);
    }

    // C. NVM Deep Scan (Windows Fix Applied)
    let nvmRoot = null;
    
    if (platform === 'win32') {
        // FIX: Check NVM_HOME env var first (Standard for nvm-windows)
        if (process.env.NVM_HOME && fs.existsSync(process.env.NVM_HOME)) {
            nvmRoot = process.env.NVM_HOME;
        } 
        // Fallback: Check AppData/nvm just in case
        else {
             const possible = path.join(process.env.APPDATA || '', 'nvm');
             if (fs.existsSync(possible)) nvmRoot = possible;
        }
    } else {
        // macOS/Linux Standard
        const possible = path.join(home, '.nvm', 'versions', 'node');
        if (fs.existsSync(possible)) nvmRoot = possible;
    }

    if (nvmRoot) {
        console.log(`    > [NVM] Root found at: ${nvmRoot}`);
        try {
            const versions = fs.readdirSync(nvmRoot, { withFileTypes: true })
                .filter(d => d.isDirectory() && d.name.toLowerCase().startsWith('v'));
            
            console.log(`    > [NVM] Found ${versions.length} installed versions.`);

            versions.forEach(v => {
                let vPath;
                if (platform === 'win32') {
                    // Windows Structure: C:\nvm\v14.0.0\node_modules
                    vPath = path.join(nvmRoot, v.name, 'node_modules');
                } else {
                    // Mac/Linux Structure: ~/.nvm/versions/node/v14.0.0/lib/node_modules
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
    if (platform === 'darwin') {
        const yMac = path.join(home, 'Library/Caches/Yarn');
        if (fs.existsSync(yMac)) {
             paths.push(yMac);
             console.log(`    > [YARN] Mac Cache: ${yMac}`);
        }
        const yBerry = path.join(home, '.yarn/berry/cache');
        if (fs.existsSync(yBerry)) {
            paths.push(yBerry);
            console.log(`    > [YARN] Berry Cache: ${yBerry}`);
        }
        const yGlobal = path.join(home, '.config/yarn/global/node_modules');
        if (fs.existsSync(yGlobal)) {
            paths.push(yGlobal);
            console.log(`    > [YARN] Global Modules: ${yGlobal}`);
        }
    } else {
        const yLinux = path.join(home, '.config/yarn/global/node_modules');
        if (fs.existsSync(yLinux)) {
            paths.push(yLinux);
            console.log(`    > [YARN] Global Modules: ${yLinux}`);
        }
    }
    
    // E. Generic Caches
    const yCache = path.join(home, platform === 'win32' ? 'AppData/Local/Yarn/Cache' : '.cache/yarn');
    if (fs.existsSync(yCache)) {
        paths.push(yCache);
        console.log(`    > [YARN] Standard Cache: ${yCache}`);
    }

    const npmCache = path.join(home, platform === 'win32' ? 'AppData/Roaming/npm-cache' : '.npm');
    if(fs.existsSync(npmCache)) {
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

// --- 4. Scanning Logic ---
function scanDir(currentPath, badPackages, depth = 0, maxDepth = DEFAULT_MAX_SCAN_DEPTH) {
    if (depth > maxDepth) return; 

    if (path.basename(currentPath) === 'node_modules') {
        scanNodeModules(currentPath, badPackages);
        return;
    }
    
    let entries;
    try { entries = fs.readdirSync(currentPath, { withFileTypes: true }); } catch (e) { return; }

    for (const entry of entries) {
        const fullPath = path.join(currentPath, entry.name);

        if (entry.isFile() && (entry.name === 'package-lock.json' || entry.name === 'yarn.lock')) {
            checkLockfile(fullPath, badPackages, entry.name);
        }
        else if (entry.isDirectory() && entry.name === 'node_modules') {
            scanNodeModules(fullPath, badPackages);
        }
        else if (entry.isDirectory() && !entry.name.startsWith('.')) {
            scanDir(fullPath, badPackages, depth + 1, maxDepth);
        }
    }
}

function scanNodeModules(modulesPath, badPackages) {
    try {
        const packages = fs.readdirSync(modulesPath);
        for (const pkg of packages) {
            if (pkg.startsWith('.')) continue;

            if (pkg.startsWith('@')) {
                const scopedPath = path.join(modulesPath, pkg);
                if (fs.existsSync(scopedPath)) {
                    const scopedPackages = fs.readdirSync(scopedPath);
                    for (const sp of scopedPackages) {
                        checkPackageJson(path.join(scopedPath, sp), `${pkg}/${sp}`, badPackages);
                    }
                }
            } else {
                checkPackageJson(path.join(modulesPath, pkg), pkg, badPackages);
            }
        }
    } catch (e) {}
}

// --- 5. The Core Check (Forensic + Metadata + Ghost) ---
function checkPackageJson(pkgPath, pkgName, badPackages) {
    const pJsonPath = path.join(pkgPath, 'package.json');
    
    // 1. FORENSIC CHECK (Files exist?)
    for (const file of malwareFiles) {
        if (fs.existsSync(path.join(pkgPath, file))) {
            const msg = `[!!!] CRITICAL: MALWARE FILE FOUND: ${file} in ${pkgName}`;
            console.log(`${colors.red}${msg}${colors.reset}`);
            detectedIssues.push({
                type: 'FORENSIC_MATCH',
                package: pkgName,
                version: 'UNKNOWN',
                location: pkgPath,
                details: file
            });
            return; 
        }
    }

    // 2. GHOST CHECK (Folder exists, matching bad name, but no package.json)
    if (!fs.existsSync(pJsonPath)) {
        // Only report "Ghost" if it WAS a targeted package
        if (badPackages[pkgName]) {
            console.log(`${colors.yellow}    [?] WARNING: Ghost folder "${pkgName}"${colors.reset}`);
            detectedIssues.push({
                type: 'GHOST_PACKAGE',
                package: pkgName,
                version: 'UNKNOWN',
                location: pkgPath,
                details: 'Targeted package folder exists but package.json is missing'
            });
        }
        return; // Stop because there is no JSON to read
    }

    // 3. METADATA CHECK & HEURISTIC CHECK
    try {
        const content = JSON.parse(fs.readFileSync(pJsonPath, 'utf8'));
        // A. HEURISTIC SCRIPT CHECK (Run on everything)
        checkScripts(content, pkgName, pkgPath);
        
        // B. TARGET CHECK (Stop here if package is not on the hit-list)
        if (!badPackages[pkgName]) return;

        // C. VERSION CHECK
        const version = content.version;
        const targetVersions = badPackages[pkgName];
        
        // Now valid because we stripped the '=' in fetchIOCs
        if (targetVersions.includes('*') || targetVersions.includes(version)) {
            const matchType = targetVersions.includes('*') ? 'WILDCARD_MATCH' : 'VERSION_MATCH';
            console.log(`${colors.red}    [!] ALERT: ${pkgName}@${version} matches denylist (${matchType})${colors.reset}`);
            detectedIssues.push({
                type: matchType,
                package: pkgName,
                version: version,
                location: pkgPath
            });
        } else {
            // Safe Version
            detectedIssues.push({
                type: 'SAFE_MATCH',
                package: pkgName,
                version: version,
                location: pkgPath
            });
        }
    } catch (e) {
         detectedIssues.push({
            type: 'CORRUPT_PACKAGE',
            package: pkgName,
            version: 'UNKNOWN',
            location: pkgPath,
            details: 'package.json unreadable'
        });
    }

} 

// --- Helper Function: Heuristic Script Scanner // BEHAVIORAL CHECK (Look for the "Scar") ---
function checkScripts(content, pkgName, pkgPath) {
    if (!content.scripts) return;
    const hooks = ['preinstall', 'install', 'postinstall', 'prepublish', 'prepare'];

    for (const hook of hooks) {
        if (!content.scripts[hook]) continue;
        const cmd = content.scripts[hook];

        // 1. Whitelist Check (Pass immediately if safe)
        if (SCRIPT_WHITELIST.has(cmd)) continue;
        const isWhitelistedRegex = SCRIPT_WHITELIST_REGEX.some(regex => regex.test(cmd));
        if (isWhitelistedRegex) continue;

        // 2. Critical Check
        for (const rule of CRITICAL_PATTERNS) {
            if (rule.pattern.test(cmd)) {
                console.log(`${colors.red}    [!] SCRIPT ALERT: ${pkgName} [${hook}] -> ${rule.desc}${colors.reset}`);
                detectedIssues.push({
                    type: 'CRITICAL_SCRIPT',
                    package: pkgName,
                    version: content.version || 'UNKNOWN',
                    location: pkgPath,
                    details: `${rule.indicator}: ${rule.desc}`
                });
                return; // Stop checking this script (Priority 1)
            }
        }

        // 3. Warning Check
        for (const rule of WARNING_PATTERNS) {
            if (rule.pattern.test(cmd)) {
                detectedIssues.push({
                    type: 'SCRIPT_WARNING',
                    package: pkgName,
                    version: content.version || 'UNKNOWN',
                    location: pkgPath,
                    details: `${rule.indicator}: ${rule.desc}`
                });
            }
        }
    }
}


function checkDependenciesRecursive(deps, badPackages, lockPath) {
    for (const [pkg, details] of Object.entries(deps)) {
        if (badPackages[pkg]) {
            checkVersionMatch(pkg, details.version, badPackages[pkg], lockPath, 'NPM_LOCK_V1');
        }
        if (details.dependencies) {
            checkDependenciesRecursive(details.dependencies, badPackages, lockPath);
        }
    }
}

function checkVersionMatch(pkg, ver, badVersions, lockPath, type) {
    if (!ver) return;
    
    if (badVersions.includes(ver)) {
        detectedIssues.push({
            type: 'LOCKFILE_HIT',
            package: pkg,
            version: ver,
            location: lockPath,
            details: `Exact match in ${type}`
        });
    }
    else if (badVersions.includes('*')) {
        detectedIssues.push({
            type: 'WILDCARD_LOCK_HIT',
            package: pkg,
            version: ver,
            location: lockPath,
            details: `Wildcard match in ${type}`
        });
    }
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function checkLockfile(lockPath, badPackages) {
    const fileName = path.basename(lockPath);
    
    // Read file (safely)
    let content;
    try { content = fs.readFileSync(lockPath, 'utf8'); } catch(e) { return; }

    // --- 1. NPM Lockfile (Accurate JSON Parsing) ---
    if (fileName === 'package-lock.json' || fileName === 'npm-shrinkwrap.json') {
        try {
            const json = JSON.parse(content);
            
            // Check v2/v3 "packages" section (Most accurate)
            if (json.packages) {
                for (const [key, details] of Object.entries(json.packages)) {
                    // key is "node_modules/pkgName" -> grab just pkgName
                    const pkgName = key.replace(/^.*node_modules\//, '');
                    
                    if (badPackages[pkgName]) {
                        checkVersionMatch(pkgName, details.version, badPackages[pkgName], lockPath, 'NPM_LOCK_V3');
                    }
                }
            }
            
            // Check v1 "dependencies" section (Recursive)
            if (json.dependencies) {
                checkDependenciesRecursive(json.dependencies, badPackages, lockPath);
            }

        } catch (e) {
            console.log(`${colors.yellow}    [!] Warning: Could not parse ${lockPath} as JSON.${colors.reset}`);
        }
    }
    
    // --- 2. Yarn Lockfile (Stricter Regex Check) ---
    else if (fileName === 'yarn.lock') {
        for (const [pkg, badVersions] of Object.entries(badPackages)) {
            // Yarn Entry Format:
            // "package-name@^1.0.0":
            //   version "1.2.3"
            
            // We loop through every BAD version to see if it exists in the block for this package
            badVersions.forEach(badVer => {
                // Regex Explanation:
                // 1. Literal package name (escaped)
                // 2. @ character
                // 3. Any characters (the range) until the colon :
                // 4. Newline + Whitespace
                // 5. Literal 'version' + space + quote + BAD VERSION + quote
                const strictRegex = new RegExp(
                    `"?${escapeRegExp(pkg)}@.+?:\\s+version "${escapeRegExp(badVer)}"`, 
                    'm' // Multiline mode is usually default in regex, but good to be implicit via structure
                );
                
                // Wildcard support for Yarn ('*')
                const isWildcard = badVer === '*';
                // For wildcard, we just check if the package block exists at all
                const wildcardRegex = new RegExp(`"?${escapeRegExp(pkg)}@.+?:`, 'g');

                if (isWildcard) {
                    if (wildcardRegex.test(content)) {
                        detectedIssues.push({
                            type: 'WILDCARD_LOCK_HIT',
                            package: pkg,
                            version: 'ALL',
                            location: lockPath,
                            details: 'Yarn Lock match (Wildcard)'
                        });
                    }
                } else {
                    if (strictRegex.test(content)) {
                        detectedIssues.push({
                            type: 'LOCKFILE_HIT',
                            package: pkg,
                            version: badVer,
                            location: lockPath,
                            details: 'Yarn Lock match (Strict)'
                        });
                    }
                }
            });
        }
    }
}

// --- 6. Reporting ---
function generateReport(userInfo) {
    console.log(`\n${colors.cyan}[5/5] Generating Report...${colors.reset}`);
    let csvContent = `Timestamp,Hostname,Git_User,Git_Email,NPM_User,Platform,Issue_Type,Package,Version,Location,Details\n`;
    const now = new Date().toISOString();
    
    detectedIssues.forEach(issue => {
        csvContent += `"${now}","${userInfo.hostname}","${userInfo.gitName}","${userInfo.gitEmail}","${userInfo.npmUser}","${userInfo.platform}","${issue.type}","${issue.package}","${issue.version}","${issue.location}","${issue.details || ''}"\n`;
    });

    fs.writeFileSync(REPORT_FILE, csvContent);
    console.log(`    > CSV saved to: ${REPORT_FILE}`);
    return csvContent;
}

async function uploadReport(csvContent, userInfo) {
    if (UPLOAD_API_URL.includes('YOUR-LAMBDA')) {
        console.log(`${colors.dim}    > Skipping upload (API URL not configured)${colors.reset}`);
        return;
    }
    console.log(`${colors.yellow}    > Uploading Report to Security API...${colors.reset}`);
    
    const payload = JSON.stringify({ userInfo, report: csvContent });
    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            'x-api-key': API_KEY 
        }
    };

    return new Promise((resolve) => {
        const req = https.request(UPLOAD_API_URL, options, (res) => {
            // FIX: Always read the data events, even on error!
            let responseBody = '';
            
            res.on('data', (chunk) => { responseBody += chunk; });
            
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    console.log(`${colors.green}    > Upload Success!${colors.reset}`);
                } else {
                    console.log(`${colors.red}    > Upload Failed (Status: ${res.statusCode})${colors.reset}`);
                    // Optional: Print the error message from Lambda to help debug
                    if (responseBody) console.log(`${colors.dim}      Server said: ${responseBody}${colors.reset}`);
                }
                resolve();
            });
        });

        req.on('error', (e) => { 
            console.log(`    > Upload Error: ${e.message}`); 
            resolve(); 
        });
        
        req.write(payload);
        req.end();
    });
}

// --- MAIN ---
(async () => {
    console.log(`\n${colors.yellow}=== Shai-Hulud 2.0 Detector ===${colors.reset}`);
    const args = process.argv.slice(2);
    
    // Parse arguments
    const pathArg = args.find(arg => !arg.startsWith('--'));
    const scanPath = pathArg || process.cwd();
    const isFullScan = args.includes('--full-scan');
    const shouldUpload = !args.includes('--no-upload');
    const noCache = args.includes('--no-cache');
    // Parse optional depth override: supports "--depth=7" or "--depth 7"
    let maxDepth = DEFAULT_MAX_SCAN_DEPTH;
    const depthEqArg = args.find(a => a.startsWith('--depth='));
    const depthIdx = args.findIndex(a => a === '--depth');
    if (depthEqArg) {
        const val = Number(depthEqArg.split('=')[1]);
        if (!Number.isNaN(val) && val >= 0) maxDepth = val;
    } else if (depthIdx !== -1 && args[depthIdx + 1]) {
        const val = Number(args[depthIdx + 1]);
        if (!Number.isNaN(val) && val >= 0) maxDepth = val;
    }
    
    // Determine scan mode
    const isProjectOnlyMode = pathArg && !isFullScan;

    const userInfo = getUserInfo();
    const badPackages = await fetchThreats(noCache);
    
    console.log(`\n${colors.cyan}[4/5] Starting Deep Scan...${colors.reset}`);
    
    if (isProjectOnlyMode) {
        // Project-only mode: scan only the specified path
        console.log(`${colors.yellow}    > Mode: Project-Only Scan${colors.reset}`);
        console.log(`    > Scanning Project Dir: ${scanPath}`);
        scanDir(scanPath, badPackages, 0, maxDepth);
    } else {
        // Full system scan mode
        console.log(`${colors.yellow}    > Mode: Full System Scan${colors.reset}`);
        const systemPaths = getSearchPaths();
        
        // 1. Scan System Paths (with explicit logs)
        systemPaths.forEach(p => {
            console.log(`    > Scanning System Path: ${p}`);
            scanDir(p, badPackages, 0, maxDepth);
        });

        // 2. Scan Local Dir
        console.log(`    > Scanning Project Dir: ${scanPath}`);
        scanDir(scanPath, badPackages, 0, maxDepth);
    }

    // 3. Summary
    const threats = detectedIssues.filter(i => i.type !== 'SAFE_MATCH');
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
    } 
    else if (shouldUpload) {
        await uploadReport(reportCSV, userInfo);
    } 
    else {
        console.log(`${colors.dim}    > Upload skipped (disabled by user).${colors.reset}`);
    }
})();