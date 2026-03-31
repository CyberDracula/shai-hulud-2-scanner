#!/usr/bin/env node
"use strict";

/**
 * Tests for parseCustomIOCList()
 */

const { parseCustomIOCList } = require("../scan");

const colors = {
  green: "\x1b[32m",
  red: "\x1b[31m",
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

console.log(
  `${colors.cyan}Running Custom IOC Parser Tests...${colors.reset}\n`,
);

assertEquals(parseCustomIOCList(null), {}, "null input returns empty object");
assertEquals(parseCustomIOCList(""), {}, "empty input returns empty object");

const test1 = parseCustomIOCList("left-pad");
assertEquals(
  test1,
  { "left-pad": ["*"] },
  "package-only line becomes wildcard",
);

const test2 = parseCustomIOCList("minimist@1.2.5");
assertEquals(test2, { minimist: ["1.2.5"] }, "package@version format");

const test3 = parseCustomIOCList("@scope/pkg@2.0.0");
assertEquals(
  test3,
  { "@scope/pkg": ["2.0.0"] },
  "scoped package@version format",
);

const test4 = parseCustomIOCList("@scope/pkg,1.9.1");
assertEquals(
  test4,
  { "@scope/pkg": ["1.9.1"] },
  "CSV-style package,version format",
);

const test5 = parseCustomIOCList("@scope/pkg,*");
assertEquals(test5, { "@scope/pkg": ["*"] }, "CSV wildcard format");

const test6 = parseCustomIOCList(
  `# comment line\n; semicolon comment\n\npackage-a@1.0.0`,
);
assertEquals(
  test6,
  { "package-a": ["1.0.0"] },
  "comments and empty lines ignored",
);

const test7 = parseCustomIOCList(
  "package-a@1.0.0\npackage-a@1.0.0\npackage-a@1.0.1",
);
assertEquals(
  test7,
  { "package-a": ["1.0.0", "1.0.1"] },
  "duplicate versions are deduplicated",
);

const test8 = parseCustomIOCList("package-a@1.0.0\npackage-a");
assertEquals(
  test8,
  { "package-a": ["1.0.0", "*"] },
  "wildcard can be combined with prior explicit versions",
);

const test9 = parseCustomIOCList(
  "__proto__@1.0.0\nconstructor@1.0.0\nprototype@1.0.0",
);
assertEquals(test9, {}, "reserved JavaScript keys are ignored");

const test10 = parseCustomIOCList('"quoted-pkg"@"v1.2.3"');
assertEquals(
  test10,
  { "quoted-pkg": ["1.2.3"] },
  "quoted values and v-prefix normalize",
);

const test11 = parseCustomIOCList("pkg@v");
assertEquals(
  test11,
  {},
  "malformed bare version (pkg@v) is ignored and produces no entry",
);

const test12 = parseCustomIOCList("pkg@>=");
assertEquals(
  test12,
  {},
  "malformed comparator-only version (pkg@>=) is ignored",
);

const test13 = parseCustomIOCList('"pkg"@">="');
assertEquals(
  test13,
  {},
  "quoted comparator that normalizes to invalid/empty version is ignored",
);

const test14 = parseCustomIOCList("okpkg@1.2.3\nbadpkg@v");
assertEquals(
  test14,
  { okpkg: ["1.2.3"] },
  "invalid version lines do not create wildcard or empty version entries",
);

console.log(`\n${colors.cyan}Test Results:${colors.reset}`);
console.log(`${colors.green}Passed: ${passed}${colors.reset}`);
if (failed > 0) {
  console.log(`${colors.red}Failed: ${failed}${colors.reset}`);
  process.exit(1);
} else {
  console.log(`${colors.green}All tests passed!${colors.reset}`);
  process.exit(0);
}
