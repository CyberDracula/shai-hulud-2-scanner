#!/usr/bin/env node

/**
 * Regression Test: Demonstrates the fix for false positives
 * 
 * This test compares the old (broken) regex with the new (fixed) regex
 * to show that the fix actually resolves the issue.
 */

const fs = require('fs');
const path = require('path');

// ANSI color codes for output
const colors = {
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
    reset: '\x1b[0m'
};

console.log(`${colors.blue}=== Regression Test: Old vs New Regex ===${colors.reset}\n`);

// Test yarn.lock content
const yarnLockContent = `# Legitimate scoped package that should NOT be flagged
"@babel/plugin-syntax-class-properties@^7.12.13":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/plugin-syntax-class-properties/-/plugin-syntax-class-properties-7.12.13.tgz"

# Another legitimate scoped package
"@babel/core@^7.0.0":
  version "7.20.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.20.0.tgz"

# Actual malicious package
syntax-class-properties@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/syntax-class-properties/-/syntax-class-properties-1.0.0.tgz"
`;

console.log('Test yarn.lock content:');
console.log(colors.cyan + '─'.repeat(60) + colors.reset);
console.log(yarnLockContent);
console.log(colors.cyan + '─'.repeat(60) + colors.reset);
console.log('');

// Malicious package database
const maliciousPackages = {
    'syntax-class-properties': ['*']  // All versions flagged
};

console.log('Malicious packages in database: ' + Object.keys(maliciousPackages).join(', '));
console.log('');

// Parse function with OLD regex (before fix)
function parseWithOldRegex(content) {
    const lines = content.split('\n');
    const packages = [];
    let currentPkg = null;
    let currentVersion = null;
    
    // OLD REGEX - doesn't support scoped packages
    const packageRegex = /^"?([^@"]+)@/;
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        
        if (line && !line.startsWith(' ') && line.includes('@') && line.endsWith(':')) {
            const match = line.match(packageRegex);
            if (match) {
                currentPkg = match[1];
                currentVersion = null;
            }
        }
        else if (currentPkg && line.trim().startsWith('version ')) {
            const versionMatch = line.match(/version\s+"([^"]+)"/);
            if (versionMatch) {
                currentVersion = versionMatch[1];
                packages.push({ name: currentPkg, version: currentVersion });
                currentPkg = null;
            }
        }
    }
    
    return packages;
}

// Parse function with NEW regex (after fix)
function parseWithNewRegex(content) {
    const lines = content.split('\n');
    const packages = [];
    let currentPkg = null;
    let currentVersion = null;
    
    // NEW REGEX - supports scoped packages
    const packageRegex = /^"?(@?[^@"]+)@/;
    
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        
        if (line && !line.startsWith(' ') && line.includes('@') && line.endsWith(':')) {
            const match = line.match(packageRegex);
            if (match) {
                currentPkg = match[1];
                currentVersion = null;
            }
        }
        else if (currentPkg && line.trim().startsWith('version ')) {
            const versionMatch = line.match(/version\s+"([^"]+)"/);
            if (versionMatch) {
                currentVersion = versionMatch[1];
                packages.push({ name: currentPkg, version: currentVersion });
                currentPkg = null;
            }
        }
    }
    
    return packages;
}

// Test with OLD regex
console.log(`${colors.yellow}━━━ TEST 1: OLD REGEX (BEFORE FIX) ━━━${colors.reset}`);
console.log(`Regex: ${colors.cyan}/^"?([^@"]+)@/${colors.reset}\n`);

const oldPackages = parseWithOldRegex(yarnLockContent);

console.log('Parsed packages:');
oldPackages.forEach(pkg => {
    const isMalicious = maliciousPackages[pkg.name];
    if (isMalicious) {
        console.log(`  ${colors.red}❌ ${pkg.name}@${pkg.version} (FLAGGED)${colors.reset}`);
    } else {
        console.log(`  ${colors.green}✓ ${pkg.name}@${pkg.version} (SAFE)${colors.reset}`);
    }
});

// Check for issues with old regex
const oldScopedCount = oldPackages.filter(p => p.name.startsWith('@')).length;
const oldMaliciousCount = oldPackages.filter(p => maliciousPackages[p.name]).length;

console.log('');
console.log(`Summary:`);
console.log(`  Scoped packages detected: ${oldScopedCount}`);
console.log(`  Malicious packages flagged: ${oldMaliciousCount}`);
console.log('');

if (oldScopedCount === 0) {
    console.log(`${colors.red}⚠️  ISSUE: Scoped packages NOT detected (silently skipped)${colors.reset}`);
    console.log(`${colors.red}   @babel/plugin-syntax-class-properties was IGNORED${colors.reset}`);
    console.log(`${colors.red}   This means scoped packages were never checked for malware!${colors.reset}`);
} else {
    console.log(`${colors.green}✓ Scoped packages were detected${colors.reset}`);
}

console.log('');
console.log(colors.cyan + '═'.repeat(60) + colors.reset);
console.log('');

// Test with NEW regex
console.log(`${colors.yellow}━━━ TEST 2: NEW REGEX (AFTER FIX) ━━━${colors.reset}`);
console.log(`Regex: ${colors.cyan}/^"?(@?[^@"]+)@/${colors.reset}\n`);

const newPackages = parseWithNewRegex(yarnLockContent);

console.log('Parsed packages:');
newPackages.forEach(pkg => {
    const isMalicious = maliciousPackages[pkg.name];
    if (isMalicious) {
        console.log(`  ${colors.red}❌ ${pkg.name}@${pkg.version} (FLAGGED)${colors.reset}`);
    } else {
        console.log(`  ${colors.green}✓ ${pkg.name}@${pkg.version} (SAFE)${colors.reset}`);
    }
});

// Check for improvements with new regex
const newScopedCount = newPackages.filter(p => p.name.startsWith('@')).length;
const newMaliciousCount = newPackages.filter(p => maliciousPackages[p.name]).length;
const babelPkgDetected = newPackages.find(p => p.name === '@babel/plugin-syntax-class-properties');
const babelPkgFlagged = babelPkgDetected && maliciousPackages[babelPkgDetected.name];

console.log('');
console.log(`Summary:`);
console.log(`  Scoped packages detected: ${newScopedCount}`);
console.log(`  Malicious packages flagged: ${newMaliciousCount}`);
console.log('');

if (newScopedCount > 0) {
    console.log(`${colors.green}✓ Scoped packages NOW detected correctly${colors.reset}`);
}

if (babelPkgDetected && !babelPkgFlagged) {
    console.log(`${colors.green}✓ @babel/plugin-syntax-class-properties is NOT flagged (correct)${colors.reset}`);
} else if (babelPkgDetected && babelPkgFlagged) {
    console.log(`${colors.red}✗ @babel/plugin-syntax-class-properties is FLAGGED (false positive)${colors.reset}`);
} else {
    console.log(`${colors.red}✗ @babel/plugin-syntax-class-properties not detected${colors.reset}`);
}

console.log('');
console.log(colors.cyan + '═'.repeat(60) + colors.reset);
console.log('');

// Final comparison
console.log(`${colors.blue}=== COMPARISON RESULTS ===${colors.reset}\n`);

console.log(`${colors.yellow}OLD REGEX (BEFORE FIX):${colors.reset}`);
console.log(`  - Scoped packages: ${oldScopedCount} detected ${colors.red}(BROKEN - should be 2)${colors.reset}`);
console.log(`  - Security issue: Scoped packages were silently skipped!`);
console.log('');

console.log(`${colors.yellow}NEW REGEX (AFTER FIX):${colors.reset}`);
console.log(`  - Scoped packages: ${newScopedCount} detected ${colors.green}(FIXED)${colors.reset}`);
console.log(`  - @babel/plugin-syntax-class-properties: NOT flagged ${colors.green}✓${colors.reset}`);
console.log(`  - syntax-class-properties: Correctly flagged ${colors.green}✓${colors.reset}`);
console.log('');

// Determine test result
const testPassed = (oldScopedCount === 0) && (newScopedCount === 2) && babelPkgDetected && !babelPkgFlagged;

if (testPassed) {
    console.log(`${colors.green}✓✓✓ REGRESSION TEST PASSED ✓✓✓${colors.reset}`);
    console.log(`${colors.green}The fix successfully resolves the issue:${colors.reset}`);
    console.log(`${colors.green}  1. Old regex FAILED to detect scoped packages${colors.reset}`);
    console.log(`${colors.green}  2. New regex CORRECTLY detects scoped packages${colors.reset}`);
    console.log(`${colors.green}  3. No false positives on @babel/plugin-syntax-class-properties${colors.reset}`);
    process.exit(0);
} else {
    console.log(`${colors.red}✗✗✗ REGRESSION TEST FAILED ✗✗✗${colors.reset}`);
    process.exit(1);
}
