#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reference revocation responder over HTTP, for trying the live checks.

    python3 reference/server.py --port 8090 [--state STATE.json] [--mutant NAME]
    python3 run.py --role responder --url http://127.0.0.1:8090/revocation \
        --subject 7a1f3c9e5b2d4e8f9a0b1c2d3e4f5a6b

It serves the reference responder in ../vectors/generate.py. The state defaults to the
first responder vector's; --state takes a file in the same shape. For testing only: it has
no authentication.
"""
import argparse
import http.server
import json
import os
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adapter  # noqa: E402

g = adapter.g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--state")
    ap.add_argument("--mutant", choices=adapter.MUTANTS)
    a = ap.parse_args()
    if a.mutant:
        adapter.install(a.mutant)
    if a.state:
        with open(a.state, encoding="utf-8") as f:
            state = json.load(f)
    else:
        with open(os.path.join(HERE, "..", "vectors", "revocation-check.json"),
                  encoding="utf-8") as f:
            state = json.load(f)["responder"][0]["state"]

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            if url.path != "/revocation":
                self.send_response(404)
                self.end_headers()
                return
            # subject stays raw (percent-encoded): the responder decodes and checks it itself.
            query = {}
            for part in url.query.split("&") if url.query else []:
                k, _, v = part.partition("=")
                k = urllib.parse.unquote(k)
                query.setdefault(k, v if k == "subject" else urllib.parse.unquote(v))
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            out = adapter.response(g.respond(dict(state, now=now),
                                             {"method": "GET", "path": "/revocation",
                                              "query": query}))
            body = json.dumps(out["body"]).encode() if "body" in out else b""
            self.send_response(out["status"])
            for k, v in out.get("headers", {}).items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    http.server.ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
