# Kerrigan NameSpace: website and web app

The website and web app of [Kerrigan NameSpace](https://kerrigan-name.space): short, readable names for Kerrigan addresses, on a registry anyone can rebuild from the Kerrigan blockchain.

- Live: https://kerrigan-name.space (the app is at https://kerrigan-name.space/app)
- Security and verification: https://kerrigan-name.space/security.html
- Documentation: https://docs.kerrigan-name.space

## Privacy in short

The app runs in your browser. Your seed phrase, password and private key never leave
it: the key is computed from the phrase locally, requests that need it are signed locally,
and the phrase is saved only in this browser, encrypted with your password (AES-GCM-256,
PBKDF2-SHA-256 with 600,000 rounds). The app talks to two hosts only, kerrigan-name.space and
registrar.kerrigan-name.space. The [security page](https://kerrigan-name.space/security.html) lists every request and
what it sends.

## Check that the site runs this code

Each release is tagged with its version (`v1.0.8`, …), and the site serves the files of that
tag byte for byte. The version the site runs is in https://kerrigan-name.space/version.json.

```bash
git clone https://github.com/alexxiy/kerrigan-namespace-front.git
cd kerrigan-namespace-front
git checkout vX.Y.Z              # the version from version.json
python3 tools/verify.py
```

`tools/verify.py` downloads every file of the site, at the same addresses the pages load them
from, and compares SHA-256 hashes with the checkout. It needs only Python 3.8+.
The [Verify live site](https://github.com/alexxiy/kerrigan-namespace-front/actions/workflows/verify-live.yml) workflow
runs the same check every day.

## Run your own copy

```bash
python3 tools/serve.py           # then open http://localhost:8080/app
```

A copy on `localhost`, an IP address or a file talks to the production registrar
(registrar.kerrigan-name.space), so it shows the same names, balance and history. Saved accounts are per
address in the browser: import yours with the seed phrase (Log In → Import Account) and keep
using the same address. Opening `app.html` straight from disk doesn't work, because browsers block module
scripts and `fetch` on `file://` pages.

## Layout

| Path | What |
|:---|:---|
| `index.html`, `js/landing.js`, `css/landing.css` | The landing page |
| `app.html`, `js/app.js`, `css/style.css`, `css/tailwind.css` | The app |
| `security.html`, `css/security.css` | The security page (it shares `js/landing.js`) |
| `js/dev-mock.js` | Test data for development, loaded only with `?mock=1` on a local copy |
| `js/vendor/` | Third-party libraries, see `THIRD_PARTY_NOTICES.md` |
| `lang/`, `lang/landing/`, `lang/security/` | Translations, 13 languages |
| `tools/` | `verify.py` and `serve.py` |
| `scripts/` | Tests and the version bump script |

## Development

There is no build step except Tailwind CSS for the app:

```bash
npm ci
npm run build:css                # or watch:css; rebuild when classes change
```

- **Test data without a backend:** run `tools/serve.py` and open
  http://localhost:8080/app?mock=1 (`?mock=0` switches it off). The page shows a label while it
  is on, and no request reaches the registrar.
- **Tests:** `node scripts/payaddr.test.js` and `node scripts/addr_corpus.test.mjs`
- **Release:** `npm run set-version X.Y.Z` (version.json, package.json, package-lock.json, `?v=` in
  app.html and security.html, the fallback in app.js), rebuild the CSS if classes changed, commit, tag
  `vX.Y.Z`, push, deploy the tagged files, then run `python3 tools/verify.py`.

## License

GPLv3, see [LICENSE](LICENSE). Third-party code and fonts keep their own licenses, listed
in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
