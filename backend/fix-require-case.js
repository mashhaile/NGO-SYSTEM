#!/usr/bin/env node
/**
 * Finds relative require() paths whose letter-case does not match the real
 * file/folder name on disk, and (with --write) corrects them.
 *
 * Run from the backend/ folder:
 *   node fix-require-case.js           -> dry run, changes nothing
 *   node fix-require-case.js --write   -> rewrites the affected files
 *
 * It changes only the path inside require("..."), never the file names.
 */
const fs = require("fs");
const path = require("path");

const ROOT = process.cwd();
const WRITE = process.argv.includes("--write");
const SKIP_DIRS = new Set(["node_modules", "uploads", ".git"]);
const EXTS = ["", ".js", ".json", ".cjs"];
const REQUIRE_RE = /require\(\s*(['"])(\.{1,2}\/[^'"\r\n]*)\1\s*\)/g;

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(path.join(dir, entry.name), out);
    } else if (entry.name.endsWith(".js")) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

const dirCache = new Map();
function listDir(dir) {
  if (!dirCache.has(dir)) {
    try {
      dirCache.set(dir, fs.readdirSync(dir));
    } catch {
      dirCache.set(dir, []);
    }
  }
  return dirCache.get(dir);
}

// exact match, single case-insensitive match, ambiguous, or missing
function findEntry(dir, name) {
  const entries = listDir(dir);
  if (entries.includes(name)) return { kind: "exact", name };
  const hits = entries.filter((e) => e.toLowerCase() === name.toLowerCase());
  if (hits.length === 1) return { kind: "case", name: hits[0] };
  return { kind: hits.length ? "ambiguous" : "missing" };
}

function resolveSpec(fromDir, spec) {
  const parts = spec.split("/");
  let cur = fromDir;
  const fixed = [];

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    const isLast = i === parts.length - 1;

    if (part === "") {
      fixed.push(part);
      continue;
    }
    if (part === "." || part === "..") {
      cur = path.resolve(cur, part);
      fixed.push(part);
      continue;
    }

    if (!isLast) {
      const hit = findEntry(cur, part);
      if (hit.kind === "missing" || hit.kind === "ambiguous") {
        return { ok: false, reason: hit.kind, at: part };
      }
      cur = path.join(cur, hit.name);
      fixed.push(hit.name);
      continue;
    }

    // Last segment: the extension may be omitted (require("../models/user")).
    let hit = null;
    let ext = "";
    for (const e of EXTS) {
      const h = findEntry(cur, part + e);
      if (h.kind === "exact") {
        hit = h;
        ext = e;
        break;
      }
    }
    if (!hit) {
      for (const e of EXTS) {
        const h = findEntry(cur, part + e);
        if (h.kind === "ambiguous") return { ok: false, reason: "ambiguous", at: part };
        if (h.kind === "case") {
          hit = h;
          ext = e;
          break;
        }
      }
    }
    if (!hit) return { ok: false, reason: "missing", at: part };
    fixed.push(hit.name.slice(0, hit.name.length - ext.length));
  }

  return { ok: true, fixed: fixed.join("/") };
}

const changes = [];
const problems = [];

for (const file of walk(ROOT)) {
  const src = fs.readFileSync(file, "utf8");
  let touched = false;

  const out = src.replace(REQUIRE_RE, (match, quote, spec, offset) => {
    const line = src.slice(0, offset).split("\n").length;
    const res = resolveSpec(path.dirname(file), spec);
    if (!res.ok) {
      problems.push({ file, line, spec, reason: res.reason });
      return match;
    }
    if (res.fixed === spec) return match;
    changes.push({ file, line, from: spec, to: res.fixed });
    touched = true;
    return `require(${quote}${res.fixed}${quote})`;
  });

  if (touched && WRITE) fs.writeFileSync(file, out, "utf8");
}

const rel = (f) => path.relative(ROOT, f).split(path.sep).join("/");
const fileCount = new Set(changes.map((c) => c.file)).size;

console.log(
  `${WRITE ? "FIXED" : "WOULD FIX"}: ${changes.length} require path(s) in ${fileCount} file(s)\n`
);
for (const c of changes) {
  console.log(`  ${rel(c.file)}:${c.line}   ${c.from}  ->  ${c.to}`);
}

if (problems.length) {
  console.log(`\nCANNOT RESOLVE (${problems.length}) - needs a manual look:`);
  for (const p of problems) {
    console.log(`  ${rel(p.file)}:${p.line}   ${p.spec}   [${p.reason}]`);
  }
}

if (!WRITE && changes.length) {
  console.log("\nDry run only. Re-run with --write to apply.");
}
