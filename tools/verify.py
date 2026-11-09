#!/usr/bin/env python3
"""Check that the live site serves exactly the files of this checkout.

    python3 tools/verify.py [site]

The site defaults to the address in index.html's <link rel="canonical">. Run it from a
checkout of the release tag the site runs (the site's /version.json names it); it tells you
when the two differ.

For every file of the site in this checkout, it downloads the same file from the site, both
at its plain address and at the cache-busting address the pages use (?v=<version>), plus the
page addresses / and /app, and compares the SHA-256 hashes. It sends only GET requests, only
to that one site, and uploads nothing. Needs Python 3.8 or newer and nothing else.

Exit code 0 when every file matches, 1 otherwise.
"""
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# In the repository but not part of the site, so never fetched.
NOT_SERVED_FILES = {
    '.gitignore', 'README.md', 'LICENSE', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md',
    'package.json', 'package-lock.json', 'tailwind.config.js', 'images/README.md',
}
NOT_SERVED_DIRS = ('.github/', 'tools/', 'scripts/', 'node_modules/')

# Page addresses without .html, as the site and tools/serve.py serve them.
ROUTES = {'': 'index.html', 'app': 'app.html'}

# A browser's User-Agent: the point is to receive what a browser receives.
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/130.0 Safari/537.36',
    'Accept-Encoding': 'identity',
    'Cache-Control': 'no-cache',
}


def site_files():
    # In a git checkout: the files git knows of or would add, so nothing .gitignore excludes.
    # Elsewhere (an unpacked archive, say): every file that isn't hidden.
    try:
        out = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                             cwd=ROOT, capture_output=True, check=True)
        files = [f for f in out.stdout.decode().split('\0') if f]
    except (OSError, subprocess.CalledProcessError):
        files = []
        for dp, dn, fn in os.walk(ROOT):
            dn[:] = [d for d in dn if not d.startswith('.') and d != 'node_modules']
            files += [os.path.relpath(os.path.join(dp, f), ROOT).replace(os.sep, '/') for f in fn]
    return sorted(f for f in files
                  if f not in NOT_SERVED_FILES and not f.startswith(NOT_SERVED_DIRS)
                  and not os.path.basename(f).startswith('.'))


def sha256_file(rel):
    with open(os.path.join(ROOT, rel), 'rb') as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def fetch(url):
    """(status, body); status is an HTTP code, or an error name when there was no answer."""
    last = None
    for _ in range(2):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=HEADERS), timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, b''
        except Exception as e:      # network trouble: one retry
            last = type(e).__name__
    return last, b''


def main():
    if len(sys.argv) > 1:
        site = sys.argv[1]
    else:
        index = open(os.path.join(ROOT, 'index.html'), encoding='utf-8').read()
        site = re.search(r'<link rel="canonical" href="([^"]+)"', index).group(1)
    site = site.rstrip('/')

    local_version = json.load(open(os.path.join(ROOT, 'version.json')))['version']
    status, body = fetch(site + '/version.json')
    if status != 200:
        print(f'Could not read {site}/version.json ({status}).')
        return 1
    live_version = json.loads(body)['version']
    print(f'Site:     {site}  (version {live_version})')
    print(f'Checkout: {ROOT}  (version {local_version})')
    if live_version != local_version:
        print(f'\nThe site runs {live_version}, but this checkout is {local_version}. '
              f'Run "git checkout v{live_version}" and check again.')
        return 1

    checks = []   # (address on the site, file in this checkout)
    for rel in site_files():
        checks.append(('/' + rel, rel))
        checks.append((f'/{rel}?v={live_version}', rel))
    checks += [('/' + route, page) for route, page in ROUTES.items()]

    expected = {rel: sha256_file(rel) for _, rel in checks}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        answers = list(pool.map(lambda c: fetch(site + c[0]), checks))

    problems = []
    for (address, rel), (status, body) in zip(checks, answers):
        if status != 200:
            problems.append(f'  NOT SERVED  {address}  ({status})')
        elif hashlib.sha256(body).hexdigest() != expected[rel]:
            problems.append(f'  DIFFERENT   {address}  (not the same as {rel})')

    files = len(set(rel for _, rel in checks))
    print(f'\nChecked {len(checks)} addresses for {files} files.')
    if problems:
        print(f'{len(problems)} of them do not match this checkout:')
        print('\n'.join(problems))
        return 1
    print('All files match.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
