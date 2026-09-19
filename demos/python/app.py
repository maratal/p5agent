#!/usr/bin/env python3
"""Hello World demo — Python, standard library only.

GET shows a name form; POST answers "Hello, <name>!" in the middle of the page.
GET /api/info answers the product info a control panel polls for liveness.
Listens on $HOST:$PORT (default 0.0.0.0:8080) and serves HTTPS when the
installer has put TLS_CERT_PATH / TLS_KEY_PATH in the environment.
"""
import html
import json
import os
import platform
import ssl
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RUNTIME = "Python"
VERSION = "1.0.0"
HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "hello.html"), encoding="utf-8") as fh:
    TEMPLATE = fh.read()

FORM = ('<h1>Hello World</h1><form method="post">'
        '<input name="name" placeholder="Your name" autofocus required>'
        '<button type="submit">Say hello</button></form>')


def greeting(name):
    return '<h1>Hello, %s!</h1><a href="/">Say hello again</a>' % html.escape(name)


def page(content):
    return TEMPLATE.replace("{{runtime}}", RUNTIME).replace("{{content}}", content)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?", 1)[0] == "/api/info":
            info = {"productName": "Hello " + RUNTIME, "version": VERSION,
                    "runtime": "Python " + platform.python_version()}
            return self.reply(json.dumps(info), "application/json")
        self.reply(page(FORM))

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        fields = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        name = (fields.get("name") or [""])[0].strip() or "World"
        self.reply(page(greeting(name)))

    def reply(self, text, content_type="text/html"):
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    host = os.environ.get("HOST") or "0.0.0.0"
    port = int(os.environ.get("PORT") or 8080)
    server = ThreadingHTTPServer((host, port), Handler)
    cert, key = os.environ.get("TLS_CERT_PATH"), os.environ.get("TLS_KEY_PATH")
    scheme = "http"
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    print("Hello World (%s) listening on %s://%s:%d" % (RUNTIME, scheme, host, port), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
