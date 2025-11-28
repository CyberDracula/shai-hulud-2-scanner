#!/usr/bin/env node
/**
 * Shai-Hulud 2.0 Scanner Tool (Verbose Edition)
 * * Features:
 * - High Verbosity: Logs every location being scanned.
 * - Deep NVM/Yarn scanning.
 * - Forensic & Metadata analysis.
 * - AWS Report Upload.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const os = require('os');
const { execSync } = require('child_process');

// --- CONFIGURATION ---
const REPORT_FILE = 'shai-hulud-report.csv';
const IOC_URL = 'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv';

// API Configuration
const UPLOAD_API_URL = 'https://YOUR-LAMBDA-URL.lambda-url.us-east-1.on.aws/'; 
const API_KEY = 'secure-me-1234'; 
// ---------------------

const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    reset: '\x1b[0m',
    dim: '\x1b[2m'
};

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
    
    console.log(`    > User: ${info.gitName} <${info.gitEmail}>`);
    console.log(`    > Host: ${info.hostname} (${info.platform})`);
    return info;
}

// --- 2. Fetch IOCs (Robust Parsing) ---
async function fetchIOCs() {
    console.log(`\n${colors.cyan}[2/5] Downloading Threat Intelligence (IOCs)...${colors.reset}`);
    return new Promise((resolve, reject) => {
        https.get(IOC_URL, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                const lines = data.split('\n').filter(l => l.trim() !== '');
                const badPackages = {};
                
                // Determine start index (skip header if present)
                const startIdx = lines[0].toLowerCase().includes('package') ? 1 : 0;
                
                for (let i = startIdx; i < lines.length; i++) {
                    // Split by comma
                    const parts = lines[i].split(',');
                    
                    if (parts.length >= 2) {
                        // CLEANING LOGIC:
                        // 1. Remove quotes (") and (')
                        // 2. Trim whitespace
                        const rawName = parts[0].replace(/["']/g, '').trim();
                        
                        // 3. Clean Version: Remove quotes, =, <, >, v, and spaces
                        //    Converts "= 3.16.26" -> "3.16.26"
                        const rawVer = parts[1].replace(/["'=<>v\s]/g, '');

                        if (rawName && rawVer) {
                            if (!badPackages[rawName]) badPackages[rawName] = [];
                            badPackages[rawName].push(rawVer);
                        }
                    }
                }
                
                const count = Object.keys(badPackages).length;
                console.log(`    > Loaded ${count} target packages from Wiz Research.`);
                
                // // DEBUG: Print one to prove it worked
                // if (badPackages['uniswap-smart-order-router']) {
                //      console.log(`      [Debug] Parsed 'uniswap-smart-order-router' versions: ${JSON.stringify(badPackages['uniswap-smart-order-router'])}`);
                // }

                resolve(badPackages);
            });
        }).on('error', reject);
    });
}

// --- 3. Path Discovery (Fixed for Windows NVM) ---
function getSearchPaths() {
    console.log(`\n${colors.cyan}[3/5] Locating Cache & Global Directories...${colors.reset}`);
    const paths = [];
    const home = os.homedir();
    const platform = os.platform();

    // A. Active Global
    try {
        const globalPrefix = execSync('npm root -g').toString().trim();
        paths.push(globalPrefix);
        console.log(`    > [NPM] Active Global: ${globalPrefix}`);
    } catch(e) {}

    // B. NVM Deep Scan (Windows Fix Applied)
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
        console.log(`    > [NVM] Not detected (Environment variable NVM_HOME missing?)`);
    }

    // C. Yarn Specifics
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
    
    // D. Generic Caches
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
function scanDir(currentPath, badPackages, depth = 0) {
    if (depth > 5) return; 

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
            scanDir(fullPath, badPackages, depth + 1);
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

    // 2. TARGET CHECK
    // If the name is not in our list, we stop here.
    if (!badPackages[pkgName]) return;

    // 3. GHOST CHECK (Folder exists, matching bad name, but no package.json)
    if (!fs.existsSync(pJsonPath)) {
        console.log(`${colors.yellow}    [?] WARNING: Found folder "${pkgName}" (Targeted Name) but missing package.json${colors.reset}`);
        detectedIssues.push({
            type: 'GHOST_PACKAGE',
            package: pkgName,
            version: 'UNKNOWN',
            location: pkgPath,
            details: 'Directory exists but package.json is missing'
        });
        return;
    }

    // 4. METADATA CHECK
    try {
        const content = JSON.parse(fs.readFileSync(pJsonPath, 'utf8'));
        const version = content.version;
        
        // Now valid because we stripped the '=' in fetchIOCs
        if (badPackages[pkgName].includes(version)) {
            console.log(`${colors.red}    [!] ALERT: ${pkgName}@${version} found at ${pkgPath}${colors.reset}`);
            detectedIssues.push({
                type: 'VERSION_MATCH',
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

    // 5. BEHAVIORAL CHECK (Look for the "Scar")
    try {
        const content = JSON.parse(fs.readFileSync(pJsonPath, 'utf8'));
        const scripts = JSON.stringify(content.scripts || {});
        
        // The specific signature of Shai-Hulud 2.0
        if (scripts.includes('setup_bun.js') || scripts.includes('bun_environment.js')) {
            console.log(`${colors.red}    [!] ALERT: Malicious script entry found in package.json (Files might be missing)${colors.reset}`);
            detectedIssues.push({
                type: 'CONFIG_MATCH',
                package: pkgName,
                version: content.version || 'UNKNOWN',
                location: pkgPath,
                details: 'package.json contains "node setup_bun.js"'
            });
        }
    } catch (e) {}

}

function checkLockfile(lockPath, badPackages, type) {
    // Simplified lockfile check
    try {
        const content = fs.readFileSync(lockPath, 'utf8');
        for (const [pkg, versions] of Object.entries(badPackages)) {
            if (content.includes(pkg)) {
                versions.forEach(ver => {
                    if (content.includes(ver)) {
                         detectedIssues.push({
                            type: 'LOCKFILE_HIT',
                            package: pkg,
                            version: ver,
                            location: lockPath
                        });
                    }
                });
            }
        }
    } catch(e) {}
}

// --- 6. Reporting ---
function generateReport(userInfo) {
    console.log(`\n${colors.cyan}[5/5] Generating Report...${colors.reset}`);
    let csvContent = `Timestamp,User,Email,Issue_Type,Package,Version,Location,Details\n`;
    const now = new Date().toISOString();
    
    detectedIssues.forEach(issue => {
        csvContent += `"${now}","${userInfo.gitName}","${userInfo.gitEmail}","${issue.type}","${issue.package}","${issue.version}","${issue.location}","${issue.details || ''}"\n`;
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
            'Content-Length': payload.length,
            'x-api-key': API_KEY 
        }
    };

    return new Promise((resolve) => {
        const req = https.request(UPLOAD_API_URL, options, (res) => {
            if(res.statusCode === 200) console.log(`${colors.green}    > Upload Success!${colors.reset}`);
            else console.log(`${colors.red}    > Upload Failed (Status: ${res.statusCode})${colors.reset}`);
            resolve();
        });
        req.on('error', (e) => { console.log(`    > Upload Error: ${e.message}`); resolve(); });
        req.write(payload);
        req.end();
    });
}

// --- MAIN ---
(async () => {
    console.log(`\n${colors.yellow}=== Shai-Hulud 2.0 Detector ===${colors.reset}`);
    const args = process.argv.slice(2);
    const scanPath = args[0] && !args[0].startsWith('--') ? args[0] : process.cwd();
    const shouldUpload = !args.includes('--no-upload');

    const userInfo = getUserInfo();
    const badPackages = await fetchIOCs();
    const systemPaths = getSearchPaths();
    
    console.log(`\n${colors.cyan}[4/5] Starting Deep Scan...${colors.reset}`);
    
    // 1. Scan System Paths (with explicit logs)
    systemPaths.forEach(p => {
        console.log(`    > Scanning System Path: ${p}`);
        scanDir(p, badPackages);
    });

    // 2. Scan Local Dir
    console.log(`    > Scanning Project Dir: ${scanPath}`);
    scanDir(scanPath, badPackages);

    // 3. Summary
    const threats = detectedIssues.filter(i => i.type !== 'SAFE_MATCH');
    if (threats.length > 0) {
        console.log(`\n${colors.red}!!! THREATS DETECTED: ${threats.length} !!!${colors.reset}`);
    } else {
        console.log(`\n${colors.green}✓ System clean. No active malware found.${colors.reset}`);
    }

    const reportCSV = generateReport(userInfo);
    if (shouldUpload) await uploadReport(reportCSV, userInfo);
})();