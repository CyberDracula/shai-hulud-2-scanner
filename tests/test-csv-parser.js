#!/usr/bin/env node
/**
 * Test Suite for parseWizCSV Function
 * Tests multi-version CSV parsing capabilities
 */

// Use the production parseWizCSV implementation from scan.js
const { parseWizCSV } = require("../scan");

// Test helpers
const colors = {
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  reset: "\x1b[0m",
};

let passed = 0;
let failed = 0;

function assertEquals(actual, expected, testName) {
  const actualStr = JSON.stringify(actual);
  const expectedStr = JSON.stringify(expected);

  if (actualStr === expectedStr) {
    console.log(`${colors.green}✓${colors.reset} ${testName}`);
    passed++;
  } else {
    console.log(`${colors.red}✗${colors.reset} ${testName}`);
    console.log(`  Expected: ${expectedStr}`);
    console.log(`  Actual:   ${actualStr}`);
    failed++;
  }
}

// Test cases
console.log(`${colors.cyan}Running CSV Parser Tests...${colors.reset}\n`);

// Test 1: Single version
const test1 = parseWizCSV("my-pkg,= 1.0.0");
assertEquals(test1, { "my-pkg": ["1.0.0"] }, "Single version");

// Test 2: Multiple versions with ||
const test2 = parseWizCSV(
  "test-foundry-app,= 1.0.4 || = 1.0.3 || = 1.0.2 || = 1.0.1",
);
assertEquals(
  test2,
  {
    "test-foundry-app": ["1.0.4", "1.0.3", "1.0.2", "1.0.1"],
  },
  "Multiple versions with ||",
);

// Test 3: Scoped package
const test3 = parseWizCSV("@alexadark/gatsby-theme-wordpress-blog,= 2.0.1");
assertEquals(
  test3,
  {
    "@alexadark/gatsby-theme-wordpress-blog": ["2.0.1"],
  },
  "Scoped package",
);

// Test 4: With header row
const test4 = parseWizCSV("Package,Version\ntest-pkg,= 1.0.0");
assertEquals(test4, { "test-pkg": ["1.0.0"] }, "CSV with header row");

// Test 5: Multiple packages
const test5 = parseWizCSV(`my-pkg-a,= 1.0.0
my-pkg-b,= 2.0.0
my-pkg-c,= 3.0.0`);
assertEquals(
  test5,
  {
    "my-pkg-a": ["1.0.0"],
    "my-pkg-b": ["2.0.0"],
    "my-pkg-c": ["3.0.0"],
  },
  "Multiple packages",
);

// Test 6: Package with quotes
const test6 = parseWizCSV('"quoted-lib","= 1.0.0"');
assertEquals(test6, { "quoted-lib": ["1.0.0"] }, "Quoted package name");

// Test 7: Version with various operators
const test7 = parseWizCSV("test-pkg,>= 1.0.0");
assertEquals(test7, { "test-pkg": ["1.0.0"] }, "Version with >= operator");

// Test 8: Empty lines should be ignored
const test8 = parseWizCSV(`my-pkg-a,= 1.0.0

my-pkg-b,= 2.0.0
`);
assertEquals(
  test8,
  {
    "my-pkg-a": ["1.0.0"],
    "my-pkg-b": ["2.0.0"],
  },
  "Empty lines ignored",
);

// Test 9: Complex multi-version with spaces
const test9 = parseWizCSV("my-pkg, = 1.0.0 || = 1.0.1 || = 1.0.2");
assertEquals(
  test9,
  {
    "my-pkg": ["1.0.0", "1.0.1", "1.0.2"],
  },
  "Multi-version with extra spaces",
);

// Test 10: Scoped package with multiple versions
const test10 = parseWizCSV("@scope/pkg,= 1.0.0 || = 1.0.1");
assertEquals(
  test10,
  {
    "@scope/pkg": ["1.0.0", "1.0.1"],
  },
  "Scoped package with multiple versions",
);

// Test 11: Version with 'v' prefix
const test11 = parseWizCSV("pkg,v1.0.0");
assertEquals(test11, { pkg: ["1.0.0"] }, "Version with v prefix");

// Test 12: Real-world Wiz Research format
const test12 = parseWizCSV(`Package,Version
test-foundry-app,= 1.0.4 || = 1.0.3 || = 1.0.2 || = 1.0.1
@alexadark/gatsby-theme-wordpress-blog,= 2.0.1
another-pkg,= 3.0.0`);
assertEquals(
  test12,
  {
    "test-foundry-app": ["1.0.4", "1.0.3", "1.0.2", "1.0.1"],
    "@alexadark/gatsby-theme-wordpress-blog": ["2.0.1"],
    "another-pkg": ["3.0.0"],
  },
  "Real-world Wiz Research CSV format",
);

// Summary
console.log(`\n${colors.cyan}Test Results:${colors.reset}`);
console.log(`${colors.green}Passed: ${passed}${colors.reset}`);
if (failed > 0) {
  console.log(`${colors.red}Failed: ${failed}${colors.reset}`);
  process.exit(1);
} else {
  console.log(`${colors.green}All tests passed!${colors.reset}`);
  process.exit(0);
}
