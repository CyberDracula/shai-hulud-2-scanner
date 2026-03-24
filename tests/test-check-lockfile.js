"use strict";

/**
 * Integration-style tests for the real checkLockfile() path.
 *
 * This writes real lockfiles to disk and invokes runCheckLockfileForTest(),
 * which delegates to checkLockfile() with isolated global state.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { runCheckLockfileForTest } = require("../scan");

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
    failed++;
  }
}

function assertEqual(actual, expected, message) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
    console.error(`    expected: ${JSON.stringify(expected)}`);
    console.error(`    actual  : ${JSON.stringify(actual)}`);
    failed++;
  }
}

function test(name, fn) {
  console.log(`\n${name}`);
  fn();
}

function withTempDir(fn) {
  const tempRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "shai-lockfile-test-"),
  );
  try {
    return fn(tempRoot);
  } finally {
    if (typeof fs.rmSync === "function") {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    } else {
      // Node.js 12 compatibility: fs.rmSync is not available
      fs.rmdirSync(tempRoot, { recursive: true });
    }
  }
}

test("real checkLockfile: pnpm exact version hit", () => {
  withTempDir((tempDir) => {
    const lockPath = path.join(tempDir, "pnpm-lock.yaml");
    const content = [
      "lockfileVersion: '9.0'",
      "packages:",
      "  '@vendor/evil-pkg@1.2.3':",
      "    resolution: {integrity: sha512-abc}",
    ].join("\n");

    fs.writeFileSync(lockPath, content, { encoding: "utf8" });

    const badPackages = { "@vendor/evil-pkg": new Set(["1.2.3"]) };
    const hits = runCheckLockfileForTest(lockPath, badPackages);

    assertEqual(hits.length, 1, "one finding emitted");
    assertEqual(hits[0].type, "LOCKFILE_HIT", "exact lockfile hit type");
    assertEqual(hits[0].package, "@vendor/evil-pkg", "package captured");
    assertEqual(hits[0].version, "1.2.3", "version captured");
    assertEqual(
      hits[0].location,
      lockPath,
      "location points to real file path",
    );
  });
});

test("real checkLockfile: pnpm wildcard + campaign mapping", () => {
  withTempDir((tempDir) => {
    const lockPath = path.join(tempDir, "pnpm-lock.yaml");
    const content = [
      "packages:",
      "  bad-any@7.8.9:",
      "    resolution: {integrity: sha512-abc}",
    ].join("\n");

    fs.writeFileSync(lockPath, content, { encoding: "utf8" });

    const badPackages = { "bad-any": new Set(["*"]) };
    const campaigns = new Map([["bad-any", "CANISTERWORM"]]);
    const hits = runCheckLockfileForTest(lockPath, badPackages, campaigns);

    assertEqual(hits.length, 1, "one wildcard finding emitted");
    assertEqual(
      hits[0].type,
      "WILDCARD_LOCK_HIT",
      "wildcard lockfile hit type",
    );
    assertEqual(hits[0].campaign, "CANISTERWORM", "campaign carried through");
  });
});

test("real checkLockfile: pnpm importer dependency version is detected", () => {
  withTempDir((tempDir) => {
    const lockPath = path.join(tempDir, "pnpm-lock.yaml");
    const content = [
      "lockfileVersion: '9.0'",
      "importers:",
      "  .:",
      "    dependencies:",
      "      '@vendor/evil-pkg':",
      "        specifier: 1.2.3",
      "        version: 1.2.3(react@18.3.1)",
    ].join("\n");

    fs.writeFileSync(lockPath, content, { encoding: "utf8" });

    const badPackages = { "@vendor/evil-pkg": new Set(["1.2.3"]) };
    const hits = runCheckLockfileForTest(lockPath, badPackages);

    assertEqual(hits.length, 1, "one importer-based finding emitted");
    assertEqual(hits[0].type, "LOCKFILE_HIT", "importer hit type");
    assertEqual(hits[0].package, "@vendor/evil-pkg", "scoped package parsed");
    assertEqual(hits[0].version, "1.2.3", "peer suffix trimmed from version");
  });
});

test("real checkLockfile: bun.lock exact hit", () => {
  withTempDir((tempDir) => {
    const lockPath = path.join(tempDir, "bun.lock");
    const content = JSON.stringify({
      packages: {
        "evil-pkg@1.2.3": ["evil-pkg@1.2.3"],
      },
    });

    fs.writeFileSync(lockPath, content, { encoding: "utf8" });

    const badPackages = { "evil-pkg": new Set(["1.2.3"]) };
    const hits = runCheckLockfileForTest(lockPath, badPackages);

    assertEqual(hits.length, 1, "one bun finding emitted");
    assertEqual(hits[0].type, "LOCKFILE_HIT", "bun lock hit type");
    assertEqual(hits[0].package, "evil-pkg", "bun package parsed");
  });
});

test("real checkLockfile: bun.lockb is ignored", () => {
  withTempDir((tempDir) => {
    const lockPath = path.join(tempDir, "bun.lockb");
    const content = "binary-ish\u0000bad-any@7.8.9\u0000payload";

    fs.writeFileSync(lockPath, content, { encoding: "utf8" });

    const badPackages = { "bad-any": new Set(["*"]) };
    const hits = runCheckLockfileForTest(lockPath, badPackages);

    assertEqual(hits.length, 0, "bun.lockb is not covered by scanner");
  });
});

test("real checkLockfile: unsupported file name yields no findings", () => {
  withTempDir((tempDir) => {
    const lockPath = path.join(tempDir, "not-a-lockfile.yaml");
    const content = [
      "packages:",
      "  evil-pkg@1.2.3:",
      "    resolution: {integrity: sha512-abc}",
    ].join("\n");

    fs.writeFileSync(lockPath, content, { encoding: "utf8" });

    const badPackages = { "evil-pkg": new Set(["1.2.3"]) };
    const hits = runCheckLockfileForTest(lockPath, badPackages);

    assertEqual(hits.length, 0, "no findings for unsupported filename");
  });
});

console.log(`\n${"─".repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  process.exit(1);
}
