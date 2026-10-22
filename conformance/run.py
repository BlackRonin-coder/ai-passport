#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the AI Passport conformance suite against an implementation.

    python3 run.py --role verifier  --adapter "ADAPTER_COMMAND"         # 81 Passport vectors
    python3 run.py --role caller    --adapter "ADAPTER_COMMAND"         # 41 caller vectors + 33 responder answers
    python3 run.py --role caller    --adapter "ADAPTER_COMMAND" --http  # the same answers, served over HTTP
    python3 run.py --role responder --adapter "ADAPTER_COMMAND"         # 33 responder vectors
    python3 run.py --role responder --url URL [--subject S] [--header "Name: value"]
                                                             # live checks that need no test state
    python3 run.py --selftest                                # reference passes, broken variants fail

An adapter is a command that connects an implementation to the suite: it reads one JSON
request per line on stdin and writes one JSON answer per line on stdout. README.md describes
the messages. --adapter-mode exec runs the command once per case instead.

Standard library only. Exit status is 0 when every case passes.
"""
import argparse
import http.server
import json
import os
import queue
import re
import secrets
import shlex
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "vectors")
SUITE = "1.0-draft.1"
REQUIRED = {"subject": (str, type(None)), "revoked": (bool,), "revoked_scopes": (list,),
            "min_required_revision": (int,), "evaluated_at": (str,), "state_version": (int,)}
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


def load(name):
    with open(os.path.join(VECTORS, name), encoding="utf-8") as f:
        return json.load(f)


# --- adapter ------------------------------------------------------------------------------

class AdapterError(Exception):
    pass


class Adapter:
    def __init__(self, cmd, mode="lines", timeout=10.0):
        self.argv, self.mode, self.timeout = shlex.split(cmd), mode, timeout
        self.proc = None
        self.lines = queue.Queue()

    def _start(self):
        self.proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     text=True, bufsize=1)

        def pump(out, q):
            for line in out:
                q.put(line)
            q.put(None)
        threading.Thread(target=pump, args=(self.proc.stdout, self.lines), daemon=True).start()

    def call(self, msg):
        line = json.dumps(msg)
        if self.mode == "exec":
            try:
                r = subprocess.run(self.argv, input=line, capture_output=True, text=True,
                                   timeout=self.timeout)
            except subprocess.TimeoutExpired:
                raise AdapterError(f"no answer within {self.timeout}s")
            if r.returncode:
                raise AdapterError((r.stderr.strip() or f"exit status {r.returncode}")[-300:])
            out = r.stdout.strip()
        else:
            if self.proc is None:
                self._start()
            try:
                self.proc.stdin.write(line + "\n")
                self.proc.stdin.flush()
                out = self.lines.get(timeout=self.timeout)
            except (BrokenPipeError, queue.Empty):
                raise AdapterError(f"no answer within {self.timeout}s")
            if out is None:
                raise AdapterError("adapter exited")
        try:
            got = json.loads(out)
        except ValueError:
            raise AdapterError(f"not JSON: {out[:200]!r}")
        if not isinstance(got, dict):
            raise AdapterError("answer is not a JSON object")
        return got

    def close(self):
        if self.proc:
            self.proc.stdin.close()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# --- results ------------------------------------------------------------------------------

class Results:
    def __init__(self, role, quiet=False):
        self.role, self.quiet, self.rows = role, quiet, []

    def add(self, cid, ok, expected, got, note=None):
        self.rows.append({"id": cid, "result": "pass" if ok else "fail",
                          "expected": expected, "got": got, **({"note": note} if note else {})})
        if not ok and not self.quiet:
            print(f"  FAIL {cid}: expected {json.dumps(expected)}, got {json.dumps(got)}"
                  + (f" ({note})" if note else ""))

    def skip(self, cid, why):
        self.rows.append({"id": cid, "result": "skip", "note": why})

    def count(self, result):
        return sum(r["result"] == result for r in self.rows)

    def summary(self):
        s = f"{self.role}: {self.count('pass')} passed, {self.count('fail')} failed"
        return s + (f", {self.count('skip')} skipped" if self.count("skip") else "")


def ask(adapter, msg):
    try:
        return adapter.call(msg), None
    except AdapterError as e:
        return None, str(e)


# --- verifier -----------------------------------------------------------------------------

def run_verifier(adapter, res):
    jwks, pv = load("jwks.json"), load("passport-verification.json")
    for v in pv["vectors"]:
        exp = {"outcome": v["expected"]["outcome"], "step": v["expected"]["step"]}
        got, err = ask(adapter, {"role": "verifier", "id": v["id"], "jwks": jwks,
                                 "issuer": pv["issuer"], "input": v["input"]})
        if err:
            res.add(v["id"], False, exp, None, err)
            continue
        ok = got.get("outcome") == exp["outcome"]
        note = None
        if ok and "step" in got and got["step"] != exp["step"]:
            note = f"outcome right, deciding step {got['step']!r} (vector says {exp['step']!r})"
        res.add(v["id"], ok, exp, got, note)


# --- caller -------------------------------------------------------------------------------

def caller_cases():
    """(id, input, expected outcome): the caller vectors, then each responder vector's
    expected answer as seen by a caller."""
    rc = load("revocation-check.json")
    for v in rc["caller"]:
        yield v["id"], v["input"], v["expected"]["outcome"]
    for v in rc["responder"]:
        yield (v["id"] + "-caller",
               {"holds_passport": v["caller"]["holds_passport"], "previously_applied": None,
                "received": v["expected_response"]},
               v["caller"]["outcome"])


def run_caller(adapter, res):
    for cid, inp, outcome in caller_cases():
        got, err = ask(adapter, {"role": "caller", "id": cid, "input": inp})
        exp = {"outcome": outcome}
        res.add(cid, not err and got.get("outcome") == outcome, exp, got, err)


class MockResponder:
    """Serves each case's answer at /<id>/revocation; a timeout case answers too late. A 3xx
    points at /proceed/revocation on another origin (localhost rather than 127.0.0.1), which
    answers not revoked. Bodies carry the current time as evaluated_at."""

    def __init__(self, cases, delay):
        self.cases, self.delay = cases, delay
        mock = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                cid = self.path.split("/")[1]
                now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                if cid == "proceed":
                    q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                    body = json.dumps({"subject": q.get("subject", [""])[0], "revoked": False,
                                       "revoked_scopes": [], "min_required_revision": 1,
                                       "evaluated_at": now, "state_version": 99})
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Cache-Control", "max-age=60")
                    self.end_headers()
                    self.wfile.write(body.encode())
                    return
                rec = mock.cases.get(cid)
                if rec is None:
                    self.send_response(500)
                    self.end_headers()
                    return
                if rec.get("error") == "timeout":
                    time.sleep(mock.delay)
                    try:
                        self.send_response(503)
                        self.end_headers()
                    except OSError:
                        pass
                    return
                fresh = (dict(rec["body"], evaluated_at=now)
                         if isinstance(rec.get("body"), dict) and "evaluated_at" in rec["body"]
                         else rec.get("body"))
                body = (rec["body_text"] if "body_text" in rec
                        else json.dumps(fresh) if "body" in rec else "")
                self.send_response(rec["status"])
                self.send_header("Content-Type", "application/json")
                for k, v in rec.get("headers", {"Cache-Control": "max-age=60"}).items():
                    self.send_header(k, v)
                if 300 <= rec["status"] < 400:
                    port = mock.server.server_address[1]
                    self.send_header("Location", f"http://localhost:{port}/proceed/revocation?"
                                     + urllib.parse.urlsplit(self.path).query)
                self.end_headers()
                self.wfile.write(body.encode())

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def url(self, cid, subject):
        port = self.server.server_address[1]
        return f"http://127.0.0.1:{port}/{cid}/revocation?subject={urllib.parse.quote(subject)}"

    def close(self):
        self.server.shutdown()


def run_caller_http(adapter, res, timeout_seconds):
    served, http_cases = {}, []
    for cid, inp, outcome in caller_cases():
        rec = inp["received"]
        if inp["previously_applied"] is not None or rec.get("cache_expired") \
                or rec.get("reused") or "now" in inp or "issuer" in rec:
            res.skip(cid, "needs an earlier answer, a reused answer, a set clock or the "
                          "answering issuer; run without --http")
            continue
        served[cid] = rec
        http_cases.append((cid, inp, outcome))
    mock = MockResponder(served, delay=timeout_seconds * 2 + 1)
    try:
        for cid, inp, outcome in http_cases:
            held, asked = inp["holds_passport"], inp.get("asked") or {}
            sid = asked.get("subject") or (held["subject"] if held else "x")
            msg = {"role": "caller", "mode": "http", "id": cid, "holds_passport": held,
                   "revocation_url": mock.url(cid, sid),
                   "timeout_seconds": timeout_seconds}
            got, err = ask(adapter, msg)
            exp = {"outcome": outcome}
            res.add(cid, not err and got.get("outcome") == outcome, exp, got, err)
    finally:
        mock.close()


# --- responder ----------------------------------------------------------------------------

def compare_response(exp, got):
    """Every expected member must be present and equal; extra members are noted."""
    if not isinstance(got, dict) or got.get("status") != exp["status"]:
        return False, None
    if "body" in exp:
        body = got.get("body")
        if not isinstance(body, dict):
            return False, None
        for k, v in exp["body"].items():
            if k not in body or body[k] != v or type(body[k]) is not type(v):
                return False, f"member {k!r}"
        if "reason" not in exp["body"] and "reason" in body:
            return False, "unexpected reason"
        extra = sorted(set(body) - set(exp["body"]) - {"reason"})
        if extra:
            return True, f"extra members {extra}"
    names = {h.lower() for h in (got.get("headers") or {})}
    for h in exp.get("headers_present", []):
        if h.lower() not in names:
            return False, f"missing header {h}"
    return True, None


def run_responder(adapter, res, by_identity=True):
    for v in load("revocation-check.json")["responder"]:
        if not by_identity and "applies_to" in v:
            res.skip(v["id"], v["applies_to"])
            continue
        got, err = ask(adapter, {"role": "responder", "id": v["id"], "state": v["state"],
                                 "request": v["request"]})
        if err:
            res.add(v["id"], False, v["expected_response"], None, err)
            continue
        ok, note = compare_response(v["expected_response"], got)
        res.add(v["id"], ok, v["expected_response"], got, note)


def http_get(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def check_answer(status, headers, text, want_subject=...):
    """-> (problems, body) for a 200 answer under §5.1 and §5.3; no problems means none."""
    if status != 200:
        return [f"status {status}, expected 200"], None
    try:
        body = json.loads(text)
    except ValueError:
        return ["body is not JSON"], None
    if not isinstance(body, dict):
        return ["body is not an object"], None
    probs = []
    for m, types in REQUIRED.items():
        if m not in body:
            probs.append(f"{m} absent")
        elif not isinstance(body[m], types) or (types == (int,) and isinstance(body[m], bool)):
            probs.append(f"{m} has the wrong type")
    if isinstance(body.get("min_required_revision"), int) and body["min_required_revision"] < 0:
        probs.append("min_required_revision is negative")
    if isinstance(body.get("evaluated_at"), str) and not RFC3339.match(body["evaluated_at"]):
        probs.append("evaluated_at is not RFC 3339")
    if want_subject is not ... and body.get("subject") != want_subject:
        probs.append(f"subject is {body.get('subject')!r}, expected {want_subject!r}")
    if "cache-control" not in {h.lower() for h in headers}:
        probs.append("no Cache-Control header (§5.3)")
    return probs, body


def run_live(url, res, headers, subject=None, timeout=10.0):
    """Checks a running responder can pass whatever state it holds (§4, §5.1–§5.3)."""
    def get(query):
        return http_get(url + "?" + query, headers, timeout)

    def expect_400(cid, query, what):
        try:
            status, _, _ = get(query)
        except OSError as e:
            return res.add(cid, False, {"status": 400}, None, f"{what}: {e}")
        res.add(cid, status == 400, {"status": 400}, {"status": status}, what)

    unknown = secrets.token_hex(16)
    try:
        status, hdrs, text = get("subject=" + unknown)
        probs, body = check_answer(status, hdrs, text, want_subject=unknown)
        if body is not None:
            if body.get("revoked") is not True:
                probs.append("revoked is not true")
            if body.get("state_version") != 0:
                probs.append("state_version is not 0")
            if body.get("reason") != "no_passport_issued":
                probs.append(f"reason is {body.get('reason')!r}")
        res.add("L01", not probs, "200, revoked true, state_version 0, no_passport_issued",
                {"status": status}, "; ".join(probs) or "unknown subject (§5.2)")
    except OSError as e:
        res.add("L01", False, "200 for an unknown subject", None, str(e))

    expect_400("L02", "subject=" + unknown + "&authority=https%3A%2F%2Fexample.invalid"
               "&identifier=x", "subject together with authority and identifier (§4)")
    expect_400("L03", "", "no parameters (§4)")
    expect_400("L04", "subject=", "empty subject (§4)")
    expect_400("L05", "subject=%zz", "malformed percent-encoding (§4)")
    expect_400("L06", "authority=https%3A%2F%2Fexample.invalid", "authority without identifier (§4)")

    try:
        status, hdrs, text = get("authority=https%3A%2F%2Fexample.invalid%2F" + unknown
                                 + "&identifier=" + unknown)
        if status == 400:
            res.add("L07", True, "400, or 200 unresolved_identity", {"status": 400},
                    "responder does not answer by identity (§3.1)")
        else:
            probs, body = check_answer(status, hdrs, text, want_subject=None)
            if body is not None:
                if body.get("revoked") is not True:
                    probs.append("revoked is not true")
                if body.get("reason") != "unresolved_identity":
                    probs.append(f"reason is {body.get('reason')!r}")
                if body.get("state_version") != 0:
                    probs.append("state_version is not 0")
            res.add("L07", not probs, "400, or 200 unresolved_identity", {"status": status},
                    "; ".join(probs) or "unknown identity (§3.1)")
    except OSError as e:
        res.add("L07", False, "400, or 200 unresolved_identity", None, str(e))

    if subject is None:
        res.skip("L08", "pass --subject to check the answer for a known subject")
        return
    try:
        status, hdrs, text = get("subject=" + urllib.parse.quote(subject, safe=""))
        probs, _ = check_answer(status, hdrs, text, want_subject=subject)
        res.add("L08", not probs, "a complete 200 answer", {"status": status},
                "; ".join(probs) or "known subject (§5.1, §5.3)")
    except OSError as e:
        res.add("L08", False, "a complete 200 answer", None, str(e))


# --- self-test ----------------------------------------------------------------------------

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def selftest():
    ref = os.path.join(HERE, "reference")
    py = shlex.quote(sys.executable)
    adapter = f"{py} {shlex.quote(os.path.join(ref, 'adapter.py'))}"
    failures = []

    def run(role, mutant=None, http=False):
        a = Adapter(adapter + (f" --mutant {mutant}" if mutant else ""), timeout=20)
        r = Results(role, quiet=True)
        try:
            {"verifier": lambda: run_verifier(a, r),
             "caller": lambda: run_caller_http(a, r, 1.0) if http else run_caller(a, r),
             "responder": lambda: run_responder(a, r)}[role]()
        finally:
            a.close()
        return r

    for role, http in (("verifier", False), ("caller", False), ("caller", True),
                       ("responder", False)):
        r = run(role, http=http)
        label = role + (" over HTTP" if http else "")
        print(f"reference {label}: {r.summary()}")
        if r.count("fail"):
            failures.append(f"reference {label} failed {r.count('fail')} case(s)")

    # Each broken variant must be caught by at least one case.
    mutants = [("verifier", "skip-signature"), ("caller", "fail-open-on-error"),
               ("caller", "absent-revoked-is-false"), ("caller", "ignore-unknown-scopes"),
               ("caller", "ignore-state-version"), ("responder", "404-for-unknown"),
               ("responder", "accept-both-forms"), ("responder", "choose-first-match"),
               ("verifier", "accept-two-signatures"), ("verifier", "ignore-crit"),
               ("verifier", "accept-any-typ"), ("verifier", "accept-duplicate-members"),
               ("verifier", "ignore-revocation-uri-origin"), ("verifier", "any-configured-key"),
               ("verifier", "ignore-parent"), ("verifier", "attribute-by-retrieval"),
               ("verifier", "refetch-twice"), ("caller", "last-duplicate-wins-caller"),
               ("caller", "ignore-equal-state-version"), ("caller", "ignore-asked-subject"),
               ("responder", "ignore-parent"), ("verifier", "lax-protected-header"),
               ("verifier", "require-issuance-class"), ("verifier", "case-sensitive-typ"),
               ("verifier", "attribute-by-authority-name"),
               ("verifier", "accept-string-authority"), ("responder", "responder-match-by-name"),
               ("verifier", "reject-null-issuance-class"), ("caller", "last-max-age-wins"),
               ("caller", "ignore-age-without-cache-control"), ("verifier", "any-issuer-may-bind"),
               ("verifier", "trust-presenter-resolution"),
               ("verifier", "fall-through-on-any-answer"), ("verifier", "ignore-tenant"),
               ("caller", "caller-ignores-answer-issuer"), ("caller", "irreversible-full-reuse")]
    for role, m in mutants:
        r = run(role, m)
        caught = [x["id"] for x in r.rows if x["result"] == "fail"]
        print(f"broken {role} '{m}': caught by {len(caught)} case(s)"
              + (f" ({', '.join(caught[:6])}{', ...' if len(caught) > 6 else ''})" if caught else ""))
        if not caught:
            failures.append(f"broken {role} '{m}' was not caught")

    for mutant, must_pass in ((None, True), ("404-for-unknown", False)):
        port = free_port()
        cmd = [sys.executable, os.path.join(ref, "server.py"), "--port", str(port)]
        srv = subprocess.Popen(cmd + (["--mutant", mutant] if mutant else []),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            url = f"http://127.0.0.1:{port}/revocation"
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.05)
            r = Results("responder (live)", quiet=True)
            run_live(url, r, {}, subject="7a1f3c9e5b2d4e8f9a0b1c2d3e4f5a6b")
        finally:
            srv.terminate()
            srv.wait()
        label = "reference" if must_pass else f"broken '{mutant}'"
        print(f"{label} responder, live: {r.summary()}")
        if must_pass and r.count("fail"):
            failures.append("reference responder failed the live checks")
        if not must_pass and not r.count("fail"):
            failures.append(f"broken live responder '{mutant}' was not caught")

    if failures:
        print("SELF-TEST FAILED:\n  " + "\n  ".join(failures))
        return 1
    print("self-test passed")
    return 0


# --- main ---------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--role", choices=("verifier", "caller", "responder"))
    ap.add_argument("--adapter", metavar="ADAPTER_COMMAND",
                    help="command that starts the implementation's adapter")
    ap.add_argument("--adapter-mode", choices=("lines", "exec"), default="lines")
    ap.add_argument("--timeout", type=float, default=10.0, help="seconds per case")
    ap.add_argument("--http", action="store_true", help="caller: serve answers over HTTP")
    ap.add_argument("--caller-timeout", type=float, default=2.0,
                    help="caller over HTTP: the timeout the caller is told to use")
    ap.add_argument("--no-identity", action="store_true",
                    help="responder: it does not answer by identity (§3.1); skip those cases")
    ap.add_argument("--url", help="responder: a running revocation endpoint, without query")
    ap.add_argument("--subject", help="responder, live: a subject the responder knows")
    ap.add_argument("--header", action="append", default=[], help="live: 'Name: value'")
    ap.add_argument("--name", default="", help="implementation name, for the report")
    ap.add_argument("--report", help="write a JSON report to this file")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not a.role or (a.url is None) == (a.adapter is None) or (a.url and a.role != "responder"):
        ap.error("give --role with --adapter, or --role responder with --url")

    live = a.url is not None
    res = Results(a.role + (" (live)" if live else ""))
    print(f"AI Passport conformance suite {SUITE}: {res.role}")
    if live:
        hdrs = dict(h.split(":", 1) for h in a.header)
        run_live(a.url, res, {k.strip(): v.strip() for k, v in hdrs.items()}, a.subject, a.timeout)
    else:
        adapter = Adapter(a.adapter, a.adapter_mode, a.timeout)
        try:
            if a.role == "verifier":
                run_verifier(adapter, res)
            elif a.role == "caller":
                (run_caller_http(adapter, res, a.caller_timeout) if a.http
                 else run_caller(adapter, res))
            else:
                run_responder(adapter, res, by_identity=not a.no_identity)
        finally:
            adapter.close()
    print(res.summary())
    if a.report:
        report = {"suite": "AI Passport conformance suite", "suite_version": SUITE,
                  "implementation": a.name, "role": a.role,
                  "mode": "live" if live else ("http" if a.http else "adapter"),
                  "run_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  "passed": res.count("pass"), "failed": res.count("fail"),
                  "skipped": res.count("skip"), "cases": res.rows}
        with open(a.report, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
    return 1 if res.count("fail") else 0


if __name__ == "__main__":
    sys.exit(main())
