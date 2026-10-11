#!/usr/bin/env node
/**
 * JS Inline Script Linter for frontend/index.html
 * Extracts all <script> blocks and runs acorn.parse on each.
 * Exit 0 = all pass, Exit 1 = any failure.
 */
const fs = require('fs');
const acorn = require('acorn');

const file = process.argv[2] || 'frontend/index.html';
const src = fs.readFileSync(file, 'utf-8');

const scriptRe = /<script[^>]*>([\s\S]*?)<\/script>/gi;
let m, idx = 0, errors = 0;

while ((m = scriptRe.exec(src)) !== null) {
  idx++;
  const code = m[1].trim();
  if (!code) continue;
  try {
    acorn.parse(code, { ecmaVersion: 'latest' });
    console.log(`[PASS] Script block #${idx}`);
  } catch (e) {
    errors++;
    // Compute line number within the file
    const before = src.slice(0, m.index);
    const line = before.split('\n').length;
    console.error(`[FAIL] Script block #${idx} at line ~${line}: ${e.message}`);
  }
}

if (errors) {
  console.error(`\n${errors} script block(s) failed syntax check.`);
  process.exit(1);
} else {
  console.log(`\nAll ${idx} inline script block(s) passed acorn syntax check.`);
  process.exit(0);
}
