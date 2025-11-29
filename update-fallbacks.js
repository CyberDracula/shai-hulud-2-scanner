#!/usr/bin/env node
/**
 * Fallback IOC Updater
 * 
 * This script downloads the latest threat intelligence from remote sources
 * and updates the fallback files used when the scanner runs offline.
 * 
 * Run this periodically to keep your offline fallback data current.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

// Configuration
const IOC_CSV_URL = 'https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv';
const IOC_JSON_URL = 'https://raw.githubusercontent.com/hemachandsai/shai-hulud-malicious-packages/main/malicious_npm_packages.json';
const FALLBACK_DIR = path.join(__dirname, 'fallback');
const FALLBACK_WIZ_FILE = path.join(FALLBACK_DIR, 'wiz-iocs.csv');
const FALLBACK_JSON_FILE = path.join(FALLBACK_DIR, 'malicious-packages.json');

const colors = {
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    red: '\x1b[31m',
    reset: '\x1b[0m',
    bold: '\x1b[1m'
};

// Ensure fallback directory exists
function ensureDir(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}

// Download file from URL
function downloadFile(url, destination, name) {
    return new Promise((resolve, reject) => {
        console.log(`${colors.cyan}Downloading ${name}...${colors.reset}`);
        
        const timeout = setTimeout(() => {
            reject(new Error(`Timeout downloading ${name}`));
        }, 30000); // 30 second timeout

        https.get(url, (res) => {
            clearTimeout(timeout);
            
            if (res.statusCode !== 200) {
                reject(new Error(`HTTP ${res.statusCode} for ${name}`));
                return;
            }

            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    fs.writeFileSync(destination, data, 'utf8');
                    const size = (Buffer.byteLength(data) / 1024).toFixed(2);
                    console.log(`${colors.green}✓ ${name} updated (${size} KB)${colors.reset}`);
                    resolve();
                } catch (e) {
                    reject(e);
                }
            });
        }).on('error', (e) => {
            clearTimeout(timeout);
            reject(e);
        });
    });
}

// Get file info
function getFileInfo(filePath) {
    try {
        const stats = fs.statSync(filePath);
        const age = Math.round((Date.now() - stats.mtimeMs) / 1000 / 60 / 60); // hours
        const size = (stats.size / 1024).toFixed(2);
        return { exists: true, age, size };
    } catch (e) {
        return { exists: false };
    }
}

// Main function
(async () => {
    console.log(`\n${colors.bold}${colors.cyan}=== Fallback IOC Updater ===${colors.reset}\n`);
    
    // Ensure directory exists
    ensureDir(FALLBACK_DIR);
    
    // Show current file status
    console.log(`${colors.yellow}Current fallback status:${colors.reset}`);
    const wizInfo = getFileInfo(FALLBACK_WIZ_FILE);
    const jsonInfo = getFileInfo(FALLBACK_JSON_FILE);
    
    if (wizInfo.exists) {
        console.log(`  • wiz-iocs.csv: ${wizInfo.size} KB (${wizInfo.age}h old)`);
    } else {
        console.log(`  • wiz-iocs.csv: ${colors.red}Not found${colors.reset}`);
    }
    
    if (jsonInfo.exists) {
        console.log(`  • malicious-packages.json: ${jsonInfo.size} KB (${jsonInfo.age}h old)`);
    } else {
        console.log(`  • malicious-packages.json: ${colors.red}Not found${colors.reset}`);
    }
    
    console.log();
    
    // Download updates
    let successCount = 0;
    let failCount = 0;
    
    try {
        await downloadFile(IOC_CSV_URL, FALLBACK_WIZ_FILE, 'Wiz Research IOCs');
        successCount++;
    } catch (e) {
        console.log(`${colors.red}✗ Failed to update Wiz IOCs: ${e.message}${colors.reset}`);
        failCount++;
    }
    
    try {
        await downloadFile(IOC_JSON_URL, FALLBACK_JSON_FILE, 'Hemachandsai Malicious Packages');
        successCount++;
    } catch (e) {
        console.log(`${colors.red}✗ Failed to update Malicious Packages: ${e.message}${colors.reset}`);
        failCount++;
    }
    
    // Clear cache to force fresh data on next scan
    const CACHE_DIR = path.join(__dirname, '.cache');
    if (successCount > 0) {
        console.log();
        console.log(`${colors.cyan}Clearing cache...${colors.reset}`);
        try {
            if (fs.existsSync(CACHE_DIR)) {
                const cacheFiles = fs.readdirSync(CACHE_DIR);
                for (const file of cacheFiles) {
                    fs.unlinkSync(path.join(CACHE_DIR, file));
                }
                console.log(`${colors.green}✓ Cache cleared${colors.reset}`);
            }
        } catch (e) {
            console.log(`${colors.yellow}⚠ Could not clear cache: ${e.message}${colors.reset}`);
        }
    }
    
    // Summary
    console.log();
    if (failCount === 0) {
        console.log(`${colors.green}${colors.bold}✓ All fallback files updated successfully!${colors.reset}`);
    } else {
        console.log(`${colors.yellow}⚠ Updated ${successCount} of ${successCount + failCount} files${colors.reset}`);
    }
    
    console.log(`\n${colors.cyan}Fallback files location: ${FALLBACK_DIR}${colors.reset}\n`);
})();
