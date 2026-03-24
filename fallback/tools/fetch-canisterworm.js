#!/usr/bin/env node
"use strict";

/**
 * fetch-canisterworm.js — Playwright-based CanisterWorm IOC CSV fetcher
 *
 * The CanisterWorm live feed at socket.dev is protected by Cloudflare and
 * cannot be downloaded with a plain HTTPS request. This script drives a real
 * Chromium browser via Playwright to pass the challenge, then captures the
 * CSV either by intercepting the network response that backs the Download CSV
 * button, or by handling the browser's native file-download event.
 *
 * Usage:
 *   node fallback/tools/fetch-canisterworm.js
 *   node fallback/tools/fetch-canisterworm.js --headed           # visible browser (debug)
 *   node fallback/tools/fetch-canisterworm.js --out=./my.csv     # custom output path
 *   node fallback/tools/fetch-canisterworm.js --timeout=90000    # custom timeout (ms)
 *
 * Prerequisites (one-time setup — isolated to fallback/, not the main project):
 *   cd fallback
 *   npm install
 *   npx playwright install chromium
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

// ── Configuration ──────────────────────────────────────────────────────────────

const TARGET_URL = "https://socket.dev/supply-chain-attacks/canisterworm";
const FALLBACK_DIR = path.resolve(__dirname, ".."); // fallback/ — one level up from tools/
const DEFAULT_OUT = path.join(FALLBACK_DIR, "canisterworm-packages.csv");
const MAX_CSV_BYTES = 5 * 1024 * 1024; // 5 MB sanity cap
const MIN_CSV_BYTES = 50; // must be at least one header row worth

// Selectors tried in order when looking for the download trigger.
// Add new selectors at the top if the page structure changes.
const DOWNLOAD_BUTTON_SELECTORS = [
  'button:has-text("Download CSV")',
  'a:has-text("Download CSV")',
  'button:has-text("Download")',
  '[data-testid*="download"]',
  '[aria-label*="download" i]',
  'a[href*=".csv"]',
];

// Predicate used to intercept network responses that carry CSV payload.
// Matches on URL suffix, Content-Type header, or Content-Disposition header.
// Note: socket.dev serves the download with a UUID filename and
// Content-Disposition: attachment, so we match broadly on attachment too.
function isCsvResponse(resp) {
  try {
    const url = resp.url();
    const headers = resp.headers();
    const ct = (headers["content-type"] || "").toLowerCase();
    const cd = (headers["content-disposition"] || "").toLowerCase();
    return (
      /\.csv([?#]|$)/i.test(url) ||
      ct.includes("text/csv") ||
      ct.includes("application/csv") ||
      cd.includes(".csv") ||
      // Broad fallback: any attachment response on a text-like content type
      (cd.includes("attachment") &&
        (ct.startsWith("text/") || ct.includes("csv")))
    );
  } catch (_) {
    return false;
  }
}

// Race multiple promises — resolves with the first non-null value.
// Unlike Promise.race, null/rejected results are skipped and do NOT win.
// Only resolves null if every promise settles without a truthy value.
// This prevents a hanging Promise.all when one strategy resolves quickly
// (download event) while the other is still waiting for a timeout.
function firstNonNull(...promises) {
  return new Promise((resolve) => {
    let pending = promises.length;
    for (const p of promises) {
      p.then((v) => {
        if (v) {
          resolve(v);
        } else if (--pending === 0) {
          resolve(null);
        }
      }).catch(() => {
        if (--pending === 0) {
          resolve(null);
        }
      });
    }
  });
}

// ── Colour helpers ─────────────────────────────────────────────────────────────

const useColor =
  process.stdout.isTTY &&
  process.env.FORCE_COLOR !== "0" &&
  process.env.NO_COLOR === undefined;

const c = useColor
  ? {
      green: "\x1b[32m",
      yellow: "\x1b[33m",
      cyan: "\x1b[36m",
      red: "\x1b[31m",
      reset: "\x1b[0m",
      bold: "\x1b[1m",
    }
  : { green: "", yellow: "", cyan: "", red: "", reset: "", bold: "" };

// ── CLI argument parsing ───────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { headed: false, outPath: DEFAULT_OUT, timeout: 60000 };
  for (const arg of argv.slice(2)) {
    if (arg === "--headed") {
      args.headed = true;
    } else if (arg.startsWith("--out=")) {
      args.outPath = arg.slice(6);
    } else if (arg.startsWith("--timeout=")) {
      const t = parseInt(arg.slice(10), 10);
      if (!isNaN(t) && t > 0) args.timeout = t;
    } else if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    } else {
      console.error(`${c.yellow}⚠  Unknown argument: ${arg}${c.reset}`);
    }
  }
  return args;
}

function printUsage() {
  console.log(
    `${c.bold}fetch-canisterworm.js${c.reset} — Playwright-based CanisterWorm IOC CSV fetcher\n` +
      `\n` +
      `${c.cyan}Usage:${c.reset}\n` +
      `  node fallback/tools/fetch-canisterworm.js [options]\n` +
      `\n` +
      `${c.cyan}Options:${c.reset}\n` +
      `  --headed           Launch a visible browser window (useful for debugging)\n` +
      `  --out=<path>       Write CSV to a custom path instead of the default\n` +
      `  --timeout=<ms>     Override page/download timeout in ms (default: 60000)\n` +
      `  --help, -h         Show this help message\n` +
      `\n` +
      `${c.cyan}Prerequisites (one-time setup — run from the fallback/ folder):${c.reset}\n` +
      `  cd fallback\n` +
      `  npm install\n` +
      `  npx playwright install chromium\n`,
  );
}

// ── Security helpers ───────────────────────────────────────────────────────────

/**
 * Validate and resolve the output path.
 * Guards against null-byte injection (CWE-158) and path traversal (CWE-22).
 */
function validateOutPath(rawPath) {
  if (typeof rawPath !== "string" || rawPath.trim() === "") {
    throw new Error("Output path must be a non-empty string");
  }
  if (rawPath.includes("\0")) {
    throw new Error(
      "Null byte detected in output path (possible injection attempt)",
    );
  }
  const resolved = path.resolve(rawPath);
  if (resolved.length > 512) {
    throw new Error("Output path exceeds maximum allowed length");
  }
  return resolved;
}

/**
 * Validate that the content looks like a real CSV IOC list.
 * Rejects HTML error pages, empty responses, and oversized payloads.
 */
function validateCsvContent(content) {
  if (typeof content !== "string") {
    throw new Error("CSV content is not a string");
  }
  const bytes = Buffer.byteLength(content, "utf8");
  if (bytes < MIN_CSV_BYTES) {
    throw new Error(
      `Response is too small (${bytes} bytes) — likely an error page, not a CSV`,
    );
  }
  if (bytes > MAX_CSV_BYTES) {
    throw new Error(
      `Response is too large (${(bytes / 1024 / 1024).toFixed(1)} MB) — exceeds 5 MB safety cap`,
    );
  }
  // An HTML error page will not contain CSV-style commas on the first line
  const firstLine = content.split("\n")[0] || "";
  if (!firstLine.includes(",")) {
    throw new Error(
      "First line of response contains no commas — does not look like CSV data",
    );
  }
}

/**
 * Atomically write content to destPath via a temp file + rename.
 * Prevents partial writes being read by concurrent processes (CWE-367).
 */
function atomicWrite(destPath, content) {
  const dir = path.dirname(destPath);
  const tmpPath = path.join(
    dir,
    `.${path.basename(destPath)}.tmp-${process.pid}-${Date.now()}`,
  );
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(tmpPath, content, "utf8");
    fs.renameSync(tmpPath, destPath);
  } catch (err) {
    try {
      if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    } catch (_) {
      /* best-effort cleanup */
    }
    throw err;
  }
}

// ── Browser helpers ────────────────────────────────────────────────────────────

/**
 * Wait until the Cloudflare "Just a moment…" interstitial has cleared.
 * Polls the page title every 500 ms up to the given timeout.
 */
async function waitForCloudflare(page, timeout) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const title = (await page.title()).toLowerCase();
    if (!title.includes("just a moment")) return;
    await page.waitForTimeout(500);
  }
  const title = await page.title();
  throw new Error(
    `Cloudflare challenge did not resolve within ${timeout} ms (page title: "${title}")`,
  );
}

/**
 * Try to locate and click a download-trigger element.
 * Returns the selector that succeeded, or null if none matched.
 */
async function clickDownloadButton(page) {
  for (const selector of DOWNLOAD_BUTTON_SELECTORS) {
    try {
      const el = await page.$(selector);
      if (el) {
        await el.click();
        return selector;
      }
    } catch (_) {
      /* try next */
    }
  }
  return null;
}

// ── Main ───────────────────────────────────────────────────────────────────────

async function main() {
  const args = parseArgs(process.argv);
  const outPath = validateOutPath(args.outPath);

  console.log(
    `\n${c.bold}${c.cyan}=== CanisterWorm IOC CSV Fetcher (Playwright) ===${c.reset}\n`,
  );
  console.log(`${c.cyan}Target:  ${c.reset}${TARGET_URL}`);
  console.log(`${c.cyan}Output:  ${c.reset}${outPath}`);
  console.log(
    `${c.cyan}Mode:    ${c.reset}${args.headed ? "headed (visible browser)" : "headless"}`,
  );
  console.log(`${c.cyan}Timeout: ${c.reset}${args.timeout} ms\n`);

  // ── Load Playwright ──────────────────────────────────────────────────────────
  let playwright;
  try {
    playwright = require("playwright");
  } catch (_) {
    console.error(
      `${c.red}✗ playwright is not installed.${c.reset}\n\n` +
        `  Run the following commands from the fallback/ directory:\n\n` +
        `    cd fallback\n` +
        `    npm install\n` +
        `    npx playwright install chromium\n`,
    );
    process.exit(1);
  }

  // ── Launch browser ───────────────────────────────────────────────────────────
  const browser = await playwright.chromium.launch({ headless: !args.headed });
  let exitCode = 0;

  try {
    const context = await browser.newContext({
      acceptDownloads: true,
      viewport: { width: 1280, height: 800 },
      // Use a realistic UA so Cloudflare does not immediately block us
      userAgent:
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
        "AppleWebKit/537.36 (KHTML, like Gecko) " +
        "Chrome/124.0.0.0 Safari/537.36",
    });

    const page = await context.newPage();

    // ── Navigate ───────────────────────────────────────────────────────────────
    console.log(`${c.cyan}Navigating to page...${c.reset}`);
    await page.goto(TARGET_URL, {
      waitUntil: "domcontentloaded",
      timeout: args.timeout,
    });

    // ── Cloudflare gate ────────────────────────────────────────────────────────
    console.log(
      `${c.cyan}Waiting for Cloudflare challenge to clear...${c.reset}`,
    );
    await waitForCloudflare(page, args.timeout);
    console.log(`${c.green}✓ Page loaded: "${await page.title()}"${c.reset}`);

    // Wait a beat for any JS-rendered content to appear before hunting for the button
    await page.waitForTimeout(1500);

    // ── Set up parallel capture strategies before clicking ────────────────────
    //
    // Strategy A — network interception:
    //   Register a response listener that fires if any CSV-typed response
    //   is observed (catches both XHR/fetch data endpoints and direct CSV files).
    //
    // Strategy B — download event:
    //   If the button triggers a browser download (Content-Disposition: attachment),
    //   Playwright's download event fires and provides a readable temp path.
    //
    // Both promises race; whichever resolves first wins.

    const csvResponsePromise = page
      .waitForResponse(isCsvResponse, { timeout: args.timeout })
      .then((resp) => resp.text())
      .catch(() => null);

    const downloadEventPromise = page
      .waitForEvent("download", { timeout: args.timeout })
      .then(async (dl) => {
        // dl.path() returns null for blob-style or in-progress downloads.
        // Fall back to saveAs() which forces Playwright to materialise the
        // file at a known temp path regardless of the original filename/UUID.
        let filePath = await dl.path();
        if (!filePath) {
          filePath = path.join(
            os.tmpdir(),
            `canisterworm-dl-${process.pid}-${Date.now()}.csv`,
          );
          await dl.saveAs(filePath);
        }
        return filePath ? fs.readFileSync(filePath, "utf8") : null;
      })
      .catch(() => null);

    // ── Click ──────────────────────────────────────────────────────────────────
    console.log(`${c.cyan}Looking for Download CSV button...${c.reset}`);
    const clickedSelector = await clickDownloadButton(page);

    if (clickedSelector) {
      console.log(`${c.green}✓ Clicked: ${clickedSelector}${c.reset}`);
    } else {
      const title = await page.title();
      console.warn(
        `${c.yellow}⚠  No download button found (page: "${title}").\n` +
          `   Waiting to see if a CSV response arrives anyway...\n` +
          `   Tip: re-run with --headed to inspect the page interactively.${c.reset}`,
      );
    }

    // ── Wait for CSV content ───────────────────────────────────────────────────
    // Use firstNonNull rather than Promise.all so the script does not hang
    // for the full timeout when only the download event fires quickly (which
    // happens when socket.dev serves the file with a UUID filename that does
    // not match the isCsvResponse URL predicate).
    console.log(`${c.cyan}Waiting for CSV data...${c.reset}`);
    const csvContent = await firstNonNull(
      csvResponsePromise,
      downloadEventPromise,
    );

    if (!csvContent) {
      throw new Error(
        "CSV content was not captured from either the network response or a browser download.\n" +
          "  • Run with --headed to inspect the page visually.\n" +
          "  • The page structure may have changed; update DOWNLOAD_BUTTON_SELECTORS if needed.",
      );
    }

    // Determine source label for logging (best-effort, non-blocking)
    const source = csvResponsePromise.then
      ? "network response or download"
      : "browser";
    console.log(`${c.green}✓ CSV captured${c.reset}`);

    // ── Validate & write ───────────────────────────────────────────────────────
    validateCsvContent(csvContent);
    atomicWrite(outPath, csvContent);

    const sizeKb = (Buffer.byteLength(csvContent, "utf8") / 1024).toFixed(2);
    const lineCount = csvContent.split("\n").filter(Boolean).length;

    console.log(
      `\n${c.green}${c.bold}✓ canisterworm-packages.csv updated${c.reset}`,
    );
    console.log(`  Size:  ${sizeKb} KB`);
    console.log(`  Rows:  ${lineCount - 1} entries (+ 1 header)`);
    console.log(`  Path:  ${outPath}\n`);
  } catch (err) {
    console.error(`\n${c.red}✗ ${err.message}${c.reset}\n`);
    if (args.headed) {
      // Keep the browser open so the user can inspect the page state
      console.log(
        `${c.yellow}Browser left open for inspection. Press Ctrl+C to exit.${c.reset}`,
      );
      await new Promise(() => {}); // eslint-disable-line no-new -- intentional infinite wait
    }
    exitCode = 1;
  } finally {
    if (exitCode === 0 || !args.headed) {
      await browser.close();
    }
  }

  process.exit(exitCode);
}

main().catch((err) => {
  console.error(`\x1b[31m✗ Fatal: ${err.message}\x1b[0m\n`);
  process.exit(1);
});
