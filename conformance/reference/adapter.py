#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reference adapter: connects the reference verifier, caller and responder in
../vectors/generate.py to the conformance suite.

    python3 run.py --role verifier --adapter "python3 reference/adapter.py"

It is also an example to copy: read one JSON request per line on stdin, write one JSON answer
per line on stdout. --mutant NAME breaks one rule on purpose, so the self-test can show the
suite catches it.
"""
import argparse
import copy
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vectors"))
import generate as g  # noqa: E402

MUTANTS = ("skip-signature", "fail-open-on-error", "absent-revoked-is-false",
           "ignore-unknown-scopes", "ignore-state-version", "404-for-unknown",
           "accept-both-forms", "choose-first-match",
           "accept-two-signatures", "ignore-crit", "accept-any-typ", "accept-duplicate-members",
           "ignore-revocation-uri-origin", "any-configured-key", "ignore-parent",
           "attribute-by-retrieval", "refetch-twice", "last-duplicate-wins-caller",
           "ignore-equal-state-version", "ignore-asked-subject", "lax-protected-header",
           "require-issuance-class", "case-sensitive-typ", "attribute-by-authority-name",
           "accept-string-authority", "responder-match-by-name", "reject-null-issuance-class",
           "last-max-age-wins", "ignore-age-without-cache-control", "any-issuer-may-bind",
           "trust-presenter-resolution", "fall-through-on-any-answer", "ignore-tenant",
           "caller-ignores-answer-issuer", "irreversible-full-reuse")


def install(mutant):
    """Replace one reference rule with a broken one."""
    caller, respond, verify = g.caller, g.respond, g.verify

    if mutant == "skip-signature":
        g.es256_verify = lambda *a: True
    if mutant == "ignore-crit":
        g.REJECTED_HEADER = ("b64",)
    if mutant == "accept-any-typ":
        g.typ_ok = lambda hdr: True
    if mutant == "accept-duplicate-members":
        g.strict_json = json.loads
    if mutant == "ignore-revocation-uri-origin":
        g.revocation_uri_ok = lambda *a: True
    if mutant == "any-configured-key":       # one pool of keys for every configured issuer
        g.anchor_for = lambda anchors, issuer: {
            "jwks": {"keys": [k for a in anchors.values() for k in a["jwks"]["keys"]]},
            "responders": [r for a in anchors.values() for r in a.get("responders", [])]}
    if mutant == "ignore-parent":
        g.parent_ok = lambda p: True
    if mutant == "lax-protected-header":
        g.header_json = json.loads
    if mutant == "reject-null-issuance-class":
        verify0 = g.verify
        g.verify = lambda inp, jwks, issuer: (("reject", "members")
            if isinstance(inp.get("passport"), dict) and "issuance_class" in inp["passport"]
            and inp["passport"]["issuance_class"] is None else verify0(inp, jwks, issuer))
        verify = g.verify
    if mutant == "fall-through-on-any-answer":     # the 404 fall-through of the earlier draft
        g.fell_through = lambda answer: True
    if mutant == "ignore-tenant":
        accepts0 = g.accepts
        g.accepts = lambda anchor, authority, tenant: accepts0(anchor, authority, tenant) or any(
            isinstance(a, dict) and a.get("id") == authority for a in anchor.get("authorities", []))
    if mutant == "trust-presenter-resolution":
        g.RESOLVERS = g.RESOLVERS + ("presenter_value",)
    if mutant == "any-issuer-may-bind":
        g.issuer_accepted = lambda *a: True
    if mutant == "last-max-age-wins":
        def last_max_age(cc):
            if not isinstance(cc, str):
                return None
            ds = [d.strip().lower() for d in cc.split(",") if d.strip().lower().startswith("max-age=")]
            return int(ds[-1][8:]) if ds and ds[-1][8:].isdigit() else None
        g.max_age = last_max_age
    if mutant == "require-issuance-class":   # the rule before issuance_class became optional
        g.REQUIRED = g.REQUIRED + ["issuance_class"]
    if mutant == "attribute-by-authority-name":
        g.binding_pair = lambda b: {"authority": b["authority"].get("id", b["authority"].get("name")),
                                    "identifier": b.get("identifier")}
    if mutant == "accept-string-authority":  # the binding shape before authority was an object
        binding_ok = g.binding_ok
        g.binding_ok = lambda b: (isinstance(b, dict) and isinstance(b.get("authority"), str)
                                  or binding_ok(b))
        g.binding_pair = lambda b: {"authority": b["authority"] if isinstance(
            b["authority"], str) else b["authority"].get("id"), "identifier": b.get("identifier")}
    if mutant == "responder-match-by-name":
        g.authority_matches = lambda b, a: a in (b["authority"].get("id"),
                                                 b["authority"].get("name"))
    if mutant == "case-sensitive-typ":
        g.typ_ok = lambda hdr: hdr.get("typ", "JOSE") in ("ai-passport+jws",
                                                          "application/ai-passport+jws", "JOSE",
                                                          "application/jose")

    def broken_verify(inp, jwks, issuer):
        i = copy.deepcopy(inp)
        p = i.get("passport")
        if mutant == "accept-two-signatures" and isinstance(p, dict) and p.get("signatures"):
            p["signatures"] = p["signatures"][:1]
        if mutant == "attribute-by-retrieval" and isinstance(i.get("presenter"), dict):
            i["presenter"].pop("authenticated", None)
        if mutant == "refetch-twice":
            i.pop("refetched", None)
            i.pop("fetched_by_presenter_identity", None)
        return verify(i, jwks, issuer)

    def broken_caller(received, held=None, previous=None, asked=None, now=None,
                      previous_expired=False):
        r = copy.deepcopy(received)
        if mutant == "fail-open-on-error" and ("error" in r or r.get("status") != 200):
            return "proceed"
        if mutant == "last-duplicate-wins-caller" and "body_text" in r:
            try:
                r["body"] = json.loads(r.pop("body_text"))
            except ValueError:
                return "deny"
        body = r.get("body")
        if isinstance(body, dict):
            if mutant == "absent-revoked-is-false":
                body.setdefault("revoked", False)
            if mutant == "ignore-unknown-scopes":
                body["revoked_scopes"] = []
        if mutant == "ignore-state-version":
            previous = None
        if mutant == "ignore-equal-state-version" and previous and isinstance(body, dict) \
                and body.get("state_version") == previous["state_version"]:
            previous = None
        if mutant == "ignore-asked-subject":
            asked = None
        if mutant == "caller-ignores-answer-issuer":
            r.pop("issuer", None)
        if mutant == "irreversible-full-reuse":
            r.pop("irreversible", None)
        if mutant == "ignore-age-without-cache-control" and isinstance(r.get("headers"), dict) \
                and not any(k.lower() == "cache-control" for k in r["headers"]):
            r["headers"] = {k: v for k, v in r["headers"].items() if k.lower() != "age"}
        return caller(r, held, previous, asked, now, previous_expired)

    def broken_respond(state, req):
        if mutant == "ignore-parent":
            state = dict(state, subjects={k: {m: v for m, v in s.items() if m != "parent"}
                                          for k, s in state["subjects"].items()})
        q = dict(req.get("query", {}))
        if mutant == "accept-both-forms" and "subject" in q:
            q.pop("authority", None)
            q.pop("identifier", None)
        if mutant == "choose-first-match" and "authority" in q and "identifier" in q:
            hits = [sid for sid, s in state["subjects"].items()
                    if any(g.authority_matches(b, q["authority"])
                           and b["identifier"] == q["identifier"]
                           and not b.get("withdrawn") for b in s.get("bindings", []))]
            state = dict(state, subjects={k: v for k, v in state["subjects"].items()
                                          if k not in hits[1:]})
        out = respond(state, dict(req, query=q))
        if mutant == "404-for-unknown" and out.get("body", {}).get("reason") == "no_passport_issued":
            return {"status": 404}
        return out

    g.caller, g.respond, g.verify = broken_caller, broken_respond, broken_verify


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is the answer's status, never followed (Revocation Check v1 §4, §5.2)."""

    def redirect_request(self, *args):
        return None


def fetch(url, timeout):
    """One revocation request, as the caller's `received` (an error when unable to ask)."""
    try:
        with urllib.request.build_opener(NoRedirect).open(url, timeout=timeout) as r:
            return {"status": r.status, "body_text": r.read().decode("utf-8", "replace"),
                    "headers": dict(r.headers)}
    except urllib.error.HTTPError as e:
        return {"status": e.code}
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError):
        return {"error": "timeout"}


def response(out):
    """The reference responder's result as the suite expects it: Cache-Control on every
    answer (Revocation Check v1 §5.3)."""
    r = {"status": out["status"]}
    if "body" in out:
        r["body"] = out["body"]
        r["headers"] = {"Cache-Control": "max-age=60"}
    return r


def handle(msg):
    role = msg.get("role")
    if role == "verifier":
        outcome, step = g.verify(msg["input"], msg["jwks"], msg.get("issuer"))
        return {"outcome": outcome, "step": step}
    if role == "caller" and msg.get("mode") == "http":
        received = fetch(msg["revocation_url"], msg.get("timeout_seconds", 2))
        asked = urllib.parse.parse_qs(urllib.parse.urlsplit(msg["revocation_url"]).query)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return {"outcome": g.caller(received, msg["holds_passport"],
                                    asked={"subject": asked["subject"][0]} if "subject" in asked
                                    else None, now=now)}
    if role == "caller":
        return {"outcome": g.call(msg["input"])}
    if role == "responder":
        return response(g.respond(msg["state"], msg["request"]))
    return {"error": f"unknown role {role!r}"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mutant", choices=MUTANTS)
    a = ap.parse_args()
    if a.mutant:
        install(a.mutant)
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            out = handle(json.loads(line))
        except Exception as e:  # report, keep serving the next case
            out = {"error": f"{type(e).__name__}: {e}"}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
