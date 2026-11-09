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

// version.json — the file the running app polls to detect a new deployment
const versionPath = join(root, 'version.json');
const versionJson = JSON.parse(readFileSync(versionPath, 'utf8'));
const previous = versionJson.version;
versionJson.version = version;
writeFileSync(versionPath, JSON.stringify(versionJson, null, 2) + '\n');
edits.push(`version.json: ${previous} -> ${version}`);

// package.json — keep the tooling manifest in step
const pkgPath = join(root, 'package.json');
const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
pkg.version = version;
writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
edits.push(`package.json: ${version}`);

// package-lock.json — it repeats the version; keep it equal so the lock matches package.json
const lockPath = join(root, 'package-lock.json');
const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
lock.version = version;
if (lock.packages && lock.packages['']) lock.packages[''].version = version;
writeFileSync(lockPath, JSON.stringify(lock, null, 2) + '\n');
edits.push(`package-lock.json: ${version}`);

// app.html and security.html — every ?v= cache-busting parameter
for (const page of ['app.html', 'security.html']) {
    const htmlPath = join(root, page);
    const html = readFileSync(htmlPath, 'utf8');
    let count = 0;
    const updated = html.replace(/(\?v=)\d+\.\d+\.\d+/g, (_, prefix) => { count++; return prefix + version; });
    writeFileSync(htmlPath, updated);
    if (count === 0) {
        console.error(`Refusing to continue: no ?v= parameters found in ${page}.`);
        process.exit(1);
    }
    edits.push(`${page}: ${count} ?v= parameters updated`);
}

// app.js — the fallback used only if version.json cannot be fetched at startup
const appPath = join(root, 'js', 'app.js');
const app = readFileSync(appPath, 'utf8');
const appUpdated = app.replace(/(let APP_VERSION = ")\d+\.\d+\.\d+(")/, `$1${version}$2`);
if (appUpdated !== app) {
    writeFileSync(appPath, appUpdated);
    edits.push('js/app.js: APP_VERSION fallback updated');
}

console.log(edits.map(e => '  ' + e).join('\n'));
console.log(`\nNow rebuild styles if any classes changed:  npm run build:css`);
