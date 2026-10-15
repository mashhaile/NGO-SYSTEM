#!/usr/bin/env node
/**
 * Loads every backend module once (without starting the server or touching
 * the database) so that any broken require() path shows up as an error.
 *
 * Run from the backend/ folder, on Linux:
 *   node smoke-require.js
 *
 * Exit code 0 = everything loaded, 1 = at least one failure.
 */
const fs = require("fs");
const path = require("path");

const ROOT = process.cwd();
const DIRS = [
  "config",
  "constants",
  "defaults",
  "middleware",
  "models",
  "utils",
  "validators",
  "services",
  "controllers",
  "routes",
  "jobs",
];

// Harmless placeholders so modules that read env vars at load time don't throw.
process.env.JWT_SECRET = process.env.JWT_SECRET || "smoke-test-secret";
process.env.NODE_ENV = process.env.NODE_ENV || "test";

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name.endsWith(".js")) out.push(full);
  }
  return out;
}

const failures = [];
let loaded = 0;

for (const d of DIRS) {
  for (const file of walk(path.join(ROOT, d))) {
    try {
      require(file);
      loaded++;
    } catch (err) {
      failures.push({ file: path.relative(ROOT, file), message: err.message.split("\n")[0] });
    }
  }
}

console.log(`Loaded OK: ${loaded}`);
if (failures.length) {
  console.log(`\nFAILED: ${failures.length}`);
  for (const f of failures) console.log(`  ${f.file}\n     ${f.message}`);
  process.exit(1);
}
console.log("No load errors.");
process.exit(0);
