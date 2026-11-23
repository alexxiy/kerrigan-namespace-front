#!/usr/bin/env node
/**
 * Bumps the app version everywhere it is pinned, in one step.
 *
 * The app compares version.json against the version it booted with and prompts the user to
 * reload when they differ. That only helps if the reload actually fetches new assets: every
 * asset in app.html is cache-busted with a hardcoded `?v=<version>`, so if version.json is
 * bumped without those, returning users get the new HTML alongside stale JS/CSS from cache.
 *
 * The app is app.html; index.html is the landing page and carries no ?v= parameters, so
 * pointing this at index.html silently updated nothing while reporting success.
 * security.html pins its own script and stylesheet the same way, so it is updated too.
 *
 * Every file is read and its change worked out before any is written: a pin not found stops
 * the run with nothing changed, where it used to stop it halfway, the files before it bumped
 * and the rest not. Each pin must be found - one missed was skipped without a word before,
 * and the code went out with the old version in it.
 *
 * Usage: npm run set-version 1.0.1
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const version = process.argv[2];

if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
    console.error('Usage: npm run set-version <major.minor.patch>   e.g. npm run set-version 1.0.1');
    process.exit(1);
}

const edits = [];
// path -> new content, written only once every file is worked out.
const writes = new Map();

function refuse(message) {
    console.error(`Refusing to continue, nothing written: ${message}`);
    process.exit(1);
}

// version.json — the file the running app polls to detect a new deployment
const versionPath = join(root, 'version.json');
const versionJson = JSON.parse(readFileSync(versionPath, 'utf8'));
const previous = versionJson.version;
versionJson.version = version;
writes.set(versionPath, JSON.stringify(versionJson, null, 2) + '\n');
edits.push(`version.json: ${previous} -> ${version}`);

// package.json — keep the tooling manifest in step
const pkgPath = join(root, 'package.json');
const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
pkg.version = version;
writes.set(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
edits.push(`package.json: ${version}`);

// package-lock.json — it repeats the version; keep it equal so the lock matches package.json
const lockPath = join(root, 'package-lock.json');
const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
lock.version = version;
if (lock.packages && lock.packages['']) lock.packages[''].version = version;
writes.set(lockPath, JSON.stringify(lock, null, 2) + '\n');
edits.push(`package-lock.json: ${version}`);

// app.html and security.html — every ?v= cache-busting parameter
for (const page of ['app.html', 'security.html']) {
    const htmlPath = join(root, page);
    const html = readFileSync(htmlPath, 'utf8');
    let count = 0;
    const updated = html.replace(/(\?v=)\d+\.\d+\.\d+/g, (_, prefix) => { count++; return prefix + version; });
    if (count === 0) {
        refuse(`no ?v= parameters found in ${page}.`);
    }
    writes.set(htmlPath, updated);
    edits.push(`${page}: ${count} ?v= parameters updated`);
}

// The version built into a script, found exactly once: `pattern` with the version as its second
// group, between the first and the third.
function pinIn(file, pattern, label) {
    const path = join(root, file);
    const source = writes.get(path) ?? readFileSync(path, 'utf8');
    let count = 0;
    const updated = source.replace(pattern, (_, before, _old, after) => { count++; return before + version + after; });
    if (count !== 1) {
        refuse(`${label} found ${count} times in ${file}, where it must be once.`);
    }
    writes.set(path, updated);
    edits.push(`${file}: ${label} updated`);
}

// app.js — the version it runs as: the ?v= of its language files, and what version.json is held
// against to offer the reload.
pinIn('js/app.js', /(const APP_VERSION = ")(\d+\.\d+\.\d+)(";)/g, 'APP_VERSION');

// ... and the ?v= of the libraries it imports from js/vendor/, cached for good like the rest.
const appPath = join(root, 'js', 'app.js');
let vendorCount = 0;
writes.set(appPath, writes.get(appPath).replace(/(from '\.\/vendor\/[\w.-]+\.js\?v=)\d+\.\d+\.\d+(')/g,
    (_, prefix, quote) => { vendorCount++; return prefix + version + quote; }));
if (vendorCount === 0) {
    refuse('no ?v= parameters found on the js/vendor/ imports of js/app.js.');
}
edits.push(`js/app.js: ${vendorCount} js/vendor/ imports' ?v= updated`);

// landing.js — the ?v= of the catalogues of the landing page and security.html.
pinIn('js/landing.js', /(var VERSION = ')(\d+\.\d+\.\d+)(';)/g, 'VERSION');

for (const [path, content] of writes) {
    writeFileSync(path, content);
}

console.log(edits.map(e => '  ' + e).join('\n'));
console.log(`\nNow rebuild styles if any classes changed:  npm run build:css`);
