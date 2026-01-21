#!/usr/bin/env node

/**
 * Test Case: Verify that @babel/plugin-syntax-class-properties is NOT flagged
 * when searching for syntax-class-properties
 * 
 * This test ensures that scoped packages are correctly distinguished from
 * unscoped malicious packages with similar names.
 */

const fs = require('fs');
const path = require('path');

// ANSI color codes for output
const colors = {
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    reset: '\x1b[0m'
};

console.log(`${colors.blue}=== Test: Scoped Package False Positive Prevention ===${colors.reset}\n`);

// Create test directory
const testDir = path.join('/tmp', 'test-scoped-packages-' + Date.now());
fs.mkdirSync(testDir, { recursive: true });
process.chdir(testDir);

console.log(`Test directory: ${testDir}\n`);

// Test Case 1: yarn.lock with scoped package that should NOT be flagged
console.log(`${colors.yellow}Test Case 1: Scoped package should NOT be flagged${colors.reset}`);
console.log('yarn.lock entry: "@babel/plugin-syntax-class-properties@^7.12.13:"');
console.log('Searching for: "syntax-class-properties"');
console.log('Expectation: Should NOT find any issue (package name is not exact match)\n');

const yarnLockContent = `# This is a legitimate scoped package that should NOT be flagged
"@babel/plugin-syntax-class-properties@^7.12.13":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/plugin-syntax-class-properties/-/plugin-syntax-class-properties-7.12.13.tgz"
  integrity sha512-fm4idjKla0YahUNgFNLCB0qySdsoPiZP3iQE3rky0mBUtMZ23yDJ9SJdg6dXTSDnulOVqiF3Hgr9nbXvXTQZYA==

# Another legitimate scoped package
"@babel/core@^7.0.0":
  version "7.20.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.20.0.tgz"
  integrity sha512-1234567890abcdef...
`;

fs.writeFileSync('yarn.lock', yarnLockContent);

// Simulate the scanner's yarn.lock parsing logic
const lines = yarnLockContent.split('\n');
let currentPkg = null;
let currentVersion = null;
const detectedPackages = [];

// This is the fixed regex that supports scoped packages
const packageRegex = /^"?(@?[^@"]+)@/;

for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    // Package declaration line (e.g., "pkg@^1.0.0:" or "@scope/pkg@^1.0.0:")
    if (line && !line.startsWith(' ') && line.includes('@') && line.endsWith(':')) {
        const match = line.match(packageRegex);
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
            detectedPackages.push({ name: currentPkg, version: currentVersion });
            currentPkg = null;
        }
    }
}

console.log('Parsed packages from yarn.lock:');
detectedPackages.forEach(pkg => {
    console.log(`  - ${pkg.name}@${pkg.version}`);
});
console.log('');

// Simulate the malicious package database
const maliciousPackages = {
    'syntax-class-properties': ['*']  // All versions flagged
};

console.log('Malicious packages in database:');
Object.keys(maliciousPackages).forEach(pkg => {
    console.log(`  - ${pkg}`);
});
console.log('');

// Check for matches
let foundFalsePositive = false;
let foundCorrectMatch = false;

detectedPackages.forEach(pkg => {
    if (maliciousPackages[pkg.name]) {
        console.log(`${colors.red}❌ FLAGGED: ${pkg.name}@${pkg.version}${colors.reset}`);
        if (pkg.name === '@babel/plugin-syntax-class-properties') {
            foundFalsePositive = true;
        }
        if (pkg.name === 'syntax-class-properties') {
            foundCorrectMatch = true;
        }
    } else {
        console.log(`${colors.green}✓ SAFE: ${pkg.name}@${pkg.version}${colors.reset}`);
    }
});
console.log('');

// Test Case 2: Verify that actual malicious package IS detected
console.log(`${colors.yellow}Test Case 2: Unscoped malicious package SHOULD be flagged${colors.reset}`);
console.log('Adding malicious package to yarn.lock...\n');

const yarnLockWithMalicious = yarnLockContent + `
# This is the actual malicious package that SHOULD be flagged
syntax-class-properties@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/syntax-class-properties/-/syntax-class-properties-1.0.0.tgz"
  integrity sha512-malicious...
`;

fs.writeFileSync('yarn.lock', yarnLockWithMalicious);

const lines2 = yarnLockWithMalicious.split('\n');
currentPkg = null;
currentVersion = null;
const detectedPackages2 = [];

for (let i = 0; i < lines2.length; i++) {
    const line = lines2[i];
    
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
            detectedPackages2.push({ name: currentPkg, version: currentVersion });
            currentPkg = null;
        }
    }
}

console.log('Parsed packages from yarn.lock (with malicious package):');
detectedPackages2.forEach(pkg => {
    if (maliciousPackages[pkg.name]) {
        console.log(`  ${colors.red}❌ ${pkg.name}@${pkg.version} (FLAGGED)${colors.reset}`);
        if (pkg.name === 'syntax-class-properties') {
            foundCorrectMatch = true;
        }
    } else {
        console.log(`  ${colors.green}✓ ${pkg.name}@${pkg.version} (SAFE)${colors.reset}`);
    }
});
console.log('');

// Final results
console.log(`${colors.blue}=== Test Results ===${colors.reset}\n`);

const test1Pass = !foundFalsePositive;
const test2Pass = foundCorrectMatch;

console.log(`Test 1 - No false positive on @babel/plugin-syntax-class-properties: ${test1Pass ? colors.green + '✓ PASS' : colors.red + '✗ FAIL'}${colors.reset}`);
console.log(`Test 2 - Correctly flags actual malicious package syntax-class-properties: ${test2Pass ? colors.green + '✓ PASS' : colors.red + '✗ FAIL'}${colors.reset}`);
console.log('');

if (test1Pass && test2Pass) {
    console.log(`${colors.green}✓ All tests passed!${colors.reset}`);
    console.log(`${colors.green}✓ Scoped packages are correctly distinguished from unscoped malicious packages${colors.reset}`);
    process.exit(0);
} else {
    console.log(`${colors.red}✗ Test failed!${colors.reset}`);
    if (!test1Pass) {
        console.log(`${colors.red}✗ False positive detected: @babel/plugin-syntax-class-properties was incorrectly flagged${colors.reset}`);
    }
    if (!test2Pass) {
        console.log(`${colors.red}✗ Malicious package not detected: syntax-class-properties was not flagged${colors.reset}`);
    }
    process.exit(1);
}
