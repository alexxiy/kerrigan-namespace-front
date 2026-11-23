#!/usr/bin/env python3
"""Run this web app from your own copy of the repository.

    python3 tools/serve.py [port]        (default port 8080)

then open http://localhost:8080/app in your browser.

Serves the repository folder over plain HTTP to this computer only (127.0.0.1), the way the
production web server does: /app is app.html, / is index.html. It never serves hidden files
or folders (such as .git) and tells the browser not to cache, so an edit shows up on reload.
It answers only requests addressed to localhost, 127.0.0.1 or [::1], so a web page whose domain
was pointed at this computer (DNS rebinding) cannot read the folder through the browser.
The app itself then talks to the production registrar, exactly as the website does.

Needs Python 3.8 or newer and nothing else. Ctrl+C stops it.
"""
import functools
import http.server
import os
import re
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The Host a request for this computer carries, with or without the port.
LOCAL_HOST = re.compile(r'(localhost|127\.0\.0\.1|\[::1\])(:\d+)?', re.IGNORECASE)


class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        '.js': 'text/javascript',
        '.mjs': 'text/javascript',
        '.json': 'application/json',
        '.webmanifest': 'application/manifest+json',
        '.woff2': 'font/woff2',
        '.svg': 'image/svg+xml',
    }

    def send_head(self):
        if not LOCAL_HOST.fullmatch(self.headers.get('Host', '')):
            self.send_error(403)
            return None
        path = self.path.split('?', 1)[0].split('#', 1)[0]
        # Decoded first, as translate_path() decodes it: /%2egit is the /.git it would open.
        parts = [p for p in urllib.parse.unquote(path).split('/') if p]
        if any(p.startswith('.') for p in parts):
            self.send_error(404)
            return None
        # extensionless page addresses, as on the site: /app -> app.html
        if parts and '.' not in parts[-1]:
            candidate = os.path.join(ROOT, *parts) + '.html'
            if os.path.isfile(candidate):
                self.path = '/' + '/'.join(urllib.parse.quote(p) for p in parts) + '.html'
        return super().send_head()

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    handler = functools.partial(Handler, directory=ROOT)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', port), handler)
    print(f'Serving {ROOT}')
    print(f'Open http://localhost:{port}/app  (Ctrl+C to stop)')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
