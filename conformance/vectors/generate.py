#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate and self-check the AI Passport v1 / Revocation Check v1 test vectors.

    python3 generate.py            # writes jwks.json, passport-verification.json,
                                   # revocation-check.json next to this file
    python3 generate.py --check    # verifies the files on disk, writes nothing

Standard library only. ES256 is implemented here (P-256, RFC 6979 deterministic nonces) so
the signatures are reproducible byte for byte by whoever holds the signing key.

Only the public key is published (jwks.json). Maintainers hold the private key outside the
repository's history: in .keys/ next to this file (ignored by git), or at
$AI_PASSPORT_VECTOR_KEY. keygen.py makes one. Writing the files needs it. --check does not: without the key it
compares the files with signatures and key coordinates masked, then runs the reference
verifier over the published signatures.

Every expected result below is written by hand. The reference verifier and responder in
this file then recompute each one and the run fails on any disagreement, so a vector
cannot be wrong in a way both halves agree on by construction.
"""
import base64
import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from datetime import datetime
from urllib.parse import unquote_to_bytes, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))

# --- P-256 / ES256 ------------------------------------------------------------------------

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k, pt):
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc


def _i2o(i):
    return i.to_bytes(32, "big")


def _rfc6979_k(d, h1):
    x, h = _i2o(d), _i2o(int.from_bytes(h1, "big") % N)
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def es256_sign(d, msg):
    h1 = hashlib.sha256(msg).digest()
    z = int.from_bytes(h1, "big")
    k = _rfc6979_k(d, h1)
    r = _mul(k, G)[0] % N
    s = pow(k, -1, N) * (z + r * d) % N
    return _i2o(r) + _i2o(s)


def es256_verify(q, msg, sig):
    if len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, N)
    pt = _add(_mul(z * w % N, G), _mul(r * w % N, q))
    return pt is not None and pt[0] % N == r


def _selftest():
    # RFC 6979 A.2.5, P-256, SHA-256, message "sample"
    d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    sig = es256_sign(d, b"sample")
    assert sig.hex().upper() == (
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"), "RFC 6979 KAT"
    assert es256_verify(_mul(d, G), b"sample", sig)


# --- encodings ----------------------------------------------------------------------------

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jcs(obj):
    """RFC 8785 for the value types these vectors use (objects, arrays, strings, integers,
    booleans, null; ASCII member names). Not a general JCS implementation: no floats."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate member {k!r}")
        out[k] = v
    return out


def _no_constant(name):
    raise ValueError(f"{name} is not JSON")


def strict_json(text):
    """Parse JSON, rejecting duplicate member names at any level (RFC 7493 §2.3) and the
    NaN / Infinity literals Python would otherwise accept."""
    return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)


SAFE_INT = 2 ** 53 - 1


def _bad_text(s):
    return any(0xD800 <= ord(c) <= 0xDFFF or 0xFDD0 <= ord(c) <= 0xFDEF
               or ord(c) & 0xFFFE == 0xFFFE for c in s)


def not_ijson(v):
    """True if `v` holds what RFC 7493 forbids: an integer outside ±(2^53-1), a non-finite
    number, or a surrogate or noncharacter in a string or member name (01 §4)."""
    if isinstance(v, bool) or v is None:
        return False
    if isinstance(v, int):
        return not -SAFE_INT <= v <= SAFE_INT
    if isinstance(v, float):
        return v != v or v in (float("inf"), float("-inf"))
    if isinstance(v, str):
        return _bad_text(v)
    if isinstance(v, list):
        return any(not_ijson(x) for x in v)
    if isinstance(v, dict):
        return any(_bad_text(k) or not_ijson(x) for k, x in v.items())
    return True


def origin(url):
    """The RFC 6454 origin (scheme, host, port) of an absolute URL, or None."""
    if not isinstance(url, str):
        return None
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        return None
    if not u.scheme or not u.hostname:
        return None
    scheme = u.scheme.lower()
    return scheme, u.hostname, port or {"https": 443, "http": 80}.get(scheme)


# --- the signing key and the running example ----------------------------------------------

KEY_PATH = os.environ.get("AI_PASSPORT_VECTOR_KEY",
                          os.path.join(HERE, ".keys", "vector-signing-key.jwk"))


def _load_key():
    """The maintainers' private key if present, else a throwaway one (check mode only)."""
    if not os.path.exists(KEY_PATH):
        return secrets.randbelow(N - 1) + 1, "k1", False
    with open(KEY_PATH, encoding="utf-8") as f:
        jwk = json.load(f)
    d = int.from_bytes(b64u_dec(jwk["d"]), "big")
    q = _mul(d, G)
    if (b64u(_i2o(q[0])), b64u(_i2o(q[1]))) != (jwk["x"], jwk["y"]):
        sys.exit(f"{KEY_PATH}: d does not match x, y")
    return d, jwk.get("kid", "k1"), True


TEST_D, KID, HAVE_KEY = _load_key()
TEST_Q = _mul(TEST_D, G)
JWKS = {"keys": [{"kty": "EC", "crv": "P-256", "kid": KID, "alg": "ES256", "use": "sig",
                  "x": b64u(_i2o(TEST_Q[0])), "y": b64u(_i2o(TEST_Q[1]))}]}

# A second issuer's key set, for the trust-anchor vectors. Nothing is signed with it.
_OTHER_Q = _mul(int.from_bytes(hashlib.sha256(b"ai-passport vectors: other issuer").digest(),
                               "big") % N, G)
OTHER_JWKS = {"keys": [{"kty": "EC", "crv": "P-256", "kid": "o1", "alg": "ES256", "use": "sig",
                        "x": b64u(_i2o(_OTHER_Q[0])), "y": b64u(_i2o(_OTHER_Q[1]))}]}

S = "7a1f3c9e5b2d4e8f9a0b1c2d3e4f5a6b"      # the invoice reconciler, subject_type agent
T = "9c4e2a7b1d3f5e6a8b0c2d4e6f8a1b3c"      # a tool server, used where a second subject is needed
D = "3e8b5d1f7a9c2e4b6d8f0a1c3e5b7d9f"      # a deployment of S (01 §3.4)
IDP = "https://login.example.net/tenant-42"
ISS = "https://issuer.example.com"
OTHER = "https://issuer.example.org"        # another issuer the verifier may be configured with
NOW = "2026-10-15T14:03:11Z"
SKEW = 300                                  # 01 §14: at most 5 minutes
IRREVERSIBLE_REUSE = 5                      # 02 §5.3: where the organisation sets no limit

def bd(authority_id, identifier, **extra):
    """A bindings entry (01 §3.3) whose authority carries an id."""
    return dict({"authority": {"id": authority_id}, "identifier": identifier}, **extra)


B_IDP = {"authority": {"id": IDP, "name": "Example IdP"}, "identifier": "4f1c9a2e-77b0",
         "type": "agent_id"}
B_ISS = bd(ISS, "agent-record-19")

# Identical to AI Passport v1 §1, without `signatures`.
BASE = {
    "schema_version": "1",
    "subject": S,
    "subject_type": "agent",
    "issuer": ISS,
    "issuance_class": "owned",
    "revision": 3,
    "name": "Supplier invoice reconciliation",
    "valid_from": "2026-10-01T00:00:00Z",
    "valid_to": "2026-12-30T00:00:00Z",
    "status": {"revocation_check": {"uri": ISS + "/revocation?subject={subject}"}},
    "bindings": [B_IDP, B_ISS],
    "business_context": {
        "accountable": [{"role": "owner", "principal": "urn:example:principal:5c2e"},
                        {"role": "manager", "principal": "urn:example:principal:7d41"}],
        "org_unit": {"id": "urn:example:org:finance-ops"},
        "vendor": {"entity": "urn:example:org:vendor-88"},
        "risk_classification": {"value": "high"},
        "purpose": {"additional_details": "reconcile supplier invoices",
                    "usage_area": ["finance_accounting"],
                    "autonomy_level": "semi_automated",
                    "human_involvement_level": "ai_initiated_with_approval"},
        "cost_center": {"id": "urn:example:cc:4410"},
        "composition": {
            "entries": [
                {"id": "urn:example:component:m-2", "kind": "model", "name": "example-model-2026-05",
                 "vendor": {"entity": "urn:example:org:vendor-88"},
                 "risk_classification": {"value": "medium"}},
                {"id": "urn:example:component:t-7", "kind": "tool", "name": "supplier ledger lookup"}],
            "complete": ["model"]},
    },
}
HEADER = {"alg": "ES256", "kid": KID, "typ": "ai-passport+jws"}      # 01 §4 SHOULD
REQUIRED = ["schema_version", "subject", "subject_type", "issuer",
            "revision", "valid_from", "valid_to", "status", "bindings", "business_context"]
REJECTED_HEADER = ("b64", "crit")       # 01 §4: no unencoded payload, no critical extension


def signed(payload, header=HEADER, over=None, header_text=None):
    """Sign `payload` (or the given bytes `over`, to model a non-canonical signer), under
    `header`, or the exact `header_text` where its bytes matter."""
    prot = b64u((header_text or json.dumps(header, separators=(",", ":"))).encode())
    body = over if over is not None else jcs(payload)
    sig = es256_sign(TEST_D, (prot + "." + b64u(body)).encode())
    out = copy.deepcopy(payload)
    out["signatures"] = [{"protected": prot, "signature": b64u(sig)}]
    return out


def with_(base=BASE, drop=(), **changes):
    p = copy.deepcopy(base)
    for k in drop:
        del p[k]
    p.update(changes)
    return p


def rev_body(subject=S, revoked=False, scopes=(), sv=12, reason=None, at=NOW, mr=1):
    b = {"subject": subject, "revoked": revoked, "revoked_scopes": list(scopes),
         "min_required_revision": mr, "evaluated_at": at, "state_version": sv}
    if reason:
        b["reason"] = reason
    return b


OK = {"status": 200, "body": rev_body()}

# --- reference caller (Revocation Check v1 §5, §6; AI Passport v1 C-rows) -----------------

def _count(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def valid_answer(body):
    """02 §5.1: every REQUIRED member, of its type."""
    if not isinstance(body, dict) or any(m not in body for m in
            ("subject", "revoked", "revoked_scopes", "min_required_revision", "evaluated_at",
             "state_version")):
        return False                                        # absent revoked is not false
    if not (body["subject"] is None or isinstance(body["subject"], str)) \
            or not _count(body["state_version"]) or not isinstance(body["evaluated_at"], str):
        return False
    try:
        ts(body["evaluated_at"])
    except ValueError:
        return False
    return True


def max_age(cache_control):
    """Freshness lifetime in seconds from a Cache-Control value; None if absent or not
    parseable. Of several max-age directives, the first counts (02 §5.3)."""
    if not isinstance(cache_control, str):
        return None
    life = None
    for d in (x.strip().lower() for x in cache_control.split(",") if x.strip()):
        if d in ("no-store", "no-cache"):
            return 0
        if d.startswith("max-age=") and life is None:
            if not d[8:].isdigit():
                return None
            life = int(d[8:])
    return life


def caller(received, held=None, previous=None, asked=None, now=None, previous_expired=False):
    """-> 'proceed' | 'deny' | 'refetch'. `held` = {subject, revision} of the Passport held;
    `asked` = the request's {subject} when asked by subject; `now` = the caller's clock."""
    if "error" in received or received.get("status") != 200:
        return "deny"                                       # 02 §5.2: listed or not, a timeout
    body = received.get("body")
    if "body_text" in received:
        try:
            body = strict_json(received["body_text"])
        except ValueError:
            return "deny"                                   # 02 §5.2: duplicate members included
    if not valid_answer(body):
        return "deny"
    mr = body["min_required_revision"]
    if not _count(mr):
        return "deny"                                       # 02 §5.6
    if received.get("cache_expired"):
        return "deny"                                       # 02 §5.3
    if "headers" in received or received.get("reused"):
        hdrs = {k.lower(): v for k, v in (received.get("headers") or {}).items()}
        life = max_age(hdrs.get("cache-control"))
        if received.get("reused") and life is None:
            return "deny"                                   # 02 §5.3: not reusable
        age = hdrs.get("age")
        if life is None and age is not None and str(age) != "0":
            return "deny"                                   # 02 §5.3: applied once only if Age is 0
        if life is not None and age is not None and (not str(age).isdigit() or int(age) >= life):
            return "deny"                                   # RFC 9111 §4.2: stale on arrival
        if now is not None and \
                (ts(now) - ts(body["evaluated_at"])).total_seconds() > (life or 0) + SKEW:
            return "deny"                                   # 02 §5.3: evaluated_at too old
        if received.get("reused") and received.get("irreversible") and (now is None or
                (ts(now) - ts(body["evaluated_at"])).total_seconds() > IRREVERSIBLE_REUSE):
            return "deny"                                   # 02 §5.3: irreversible action
    if previous and body["subject"] == previous["subject"]:
        if body["state_version"] < previous["state_version"]:
            if previous_expired:
                return "deny"                               # discarded, and nothing current
            body = previous                                 # 02 §5.4: discard the older answer
        elif body["state_version"] == previous["state_version"] and not previous_expired:
            body = dict(body,                               # 02 §5.4: the more restrictive
                        revoked=body["revoked"] is not False or previous["revoked"] is not False,
                        min_required_revision=max(mr, previous["min_required_revision"]),
                        revoked_scopes=list(previous["revoked_scopes"]) + list(body["revoked_scopes"]))
    if body["subject"] is None:
        return "deny"                                       # unresolved / ambiguous / binding_revoked
    if asked and "subject" in asked and body["subject"] != asked["subject"]:
        return "deny"                                       # 02 §5.1: not the subject asked about
    if held and "issuer" in held and "issuer" in received and received["issuer"] != held["issuer"]:
        return "deny"                                       # 02 §3.1: another issuer's answer
    if held and body["subject"] != held["subject"]:
        return "deny"                                       # 02 §3.1 subject mismatch
    if body["revoked"] is not False:
        return "deny"                                       # 02 §5.1: only the literal false
    if not isinstance(body["revoked_scopes"], list) or body["revoked_scopes"]:
        return "deny"                                       # 02 §6, §6.2: this version defines no entry
    if held is not None and held["revision"] < body["min_required_revision"]:
        return "refetch"                                    # 02 §5.6
    return "proceed"


def call(inp):
    """The reference caller on a caller vector's `input`."""
    return caller(inp["received"], inp["holds_passport"], inp["previously_applied"],
                  inp.get("asked"), inp.get("now"), inp.get("previously_applied_expired", False))


# --- reference verifier (AI Passport v1 §1, §3–§7) ----------------------------------------

def typ_ok(hdr):
    """01 §4: `typ` absent, or ai-passport+jws, application/ai-passport+jws, JOSE or
    application/jose, each compared case-insensitively."""
    if "typ" not in hdr:
        return True
    t = hdr["typ"]
    return isinstance(t, str) and t.lower() in ("ai-passport+jws", "application/ai-passport+jws",
                                                "jose", "application/jose")


def header_json(raw):
    """01 §4: the decoded protected header is I-JSON too."""
    return strict_json(raw)


def anchor_for(anchors, issuer):
    """01 §9.1: the trust anchor configured for this exact issuer string, never another's."""
    return anchors.get(issuer) if isinstance(issuer, str) else None


RESOLVERS = ("authentication", "configured_mapping")      # 01 §3.3: how an identifier is resolved


def accepts(anchor, authority, tenant):
    """01 §9.1: an anchor without `authorities` accepts every authority and tenant. An entry
    is an authority id, or {id, tenants} for a shared authority, whose tenant comes from
    authentication (the presenter's `tenant`)."""
    if "authorities" not in anchor:
        return True
    for a in anchor["authorities"]:
        if a == authority:
            return True
        if isinstance(a, dict) and a.get("id") == authority and tenant in a.get("tenants", []):
            return True
    return False


def fell_through(answer):
    """01 §9.1, 02 §5.5: only 200, subject null, reason unresolved_identity lets a verifier
    pass to a lower-ranked issuer."""
    if not isinstance(answer, dict) or answer.get("status") != 200:
        return False
    body = answer.get("body")
    return isinstance(body, dict) and body.get("subject") is None \
        and body.get("reason") == "unresolved_identity"


def issuer_accepted(anchors, issuer, authority, inp, tenant=None):
    """01 §9.1: the configuration accepts `authority` from `issuer`; where it accepts it from
    several issuers, they are ranked, and every higher-ranked one's responder answered
    unresolved_identity. `inp["higher_ranked_answers"]` maps an issuer to the answer it gave."""
    accepting = [i for i, a in anchors.items() if accepts(a, authority, tenant)]
    if issuer not in accepting:
        return False
    if len(accepting) == 1:
        return True
    rank = inp.get("issuer_rank") or []
    if any(i not in rank for i in accepting):
        return False                                        # shared and not ranked: deny
    higher = [i for i in rank[:rank.index(issuer)] if i in accepting]
    answers = inp.get("higher_ranked_answers") or {}
    return all(fell_through(answers.get(i)) for i in higher)


def names_party(obj, ref):
    """01 §8.3, §8.5: an object with neither its reference nor a `name` reads as absent."""
    return isinstance(obj, dict) and any(isinstance(obj.get(m), str) and obj[m] for m in (ref, "name"))


def has_manager(bc):
    """01 §8.5: `accountable` names at least one manager."""
    acc = bc.get("accountable") if isinstance(bc, dict) else None
    return isinstance(acc, list) and any(
        names_party(e, "principal") and e.get("role") == "manager" for e in acc)


ABSOLUTE_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s#]+$")    # RFC 3986 §4.3


def binding_ok(b):
    """01 §3.3: an object with an `authority` object naming its system by `id` (an absolute
    URI), `name`, or both, each a non-empty string; and a non-empty `identifier`."""
    if not isinstance(b, dict) or not isinstance(b.get("authority"), dict):
        return False
    a, ident = b["authority"], b.get("identifier")
    if not isinstance(ident, str) or not ident:
        return False
    if any(m in a and not (isinstance(a[m], str) and a[m]) for m in ("id", "name")):
        return False
    if "id" not in a and "name" not in a:
        return False
    return "id" not in a or bool(ABSOLUTE_URI.match(a["id"]))


def binding_pair(b):
    """The (authority, identifier) a binding attributes, or None: only `authority.id`,
    never `name` or `type` (01 §3.3)."""
    a = b.get("authority") if isinstance(b, dict) else None
    if not isinstance(a, dict) or "id" not in a:
        return None
    return {"authority": a["id"], "identifier": b.get("identifier")}


def authority_matches(b, authority):
    """02 §3.1: an identity query's `authority` matches `authority.id` only."""
    a = b.get("authority")
    return isinstance(a, dict) and a.get("id") == authority


def parent_ok(p):
    """01 §3.4: absent or null names none; otherwise both members, under the same issuer."""
    par = p.get("parent")
    return par is None or (isinstance(par, dict) and isinstance(par.get("subject"), str)
                           and par.get("issuer") == p["issuer"])


def revocation_uri_ok(uri, issuer, anchor):
    """01 §9.1: https on the issuer's origin, or a responder configured for the issuer."""
    o = origin(uri)
    if o is None:
        return False
    if o[0] == "https" and o == origin(issuer):
        return True
    return o in [origin(r) for r in anchor.get("responders", [])]


def verify(inp, jwks, issuer):
    """-> (outcome, step). outcome: accept | reject | deny | refetch. The verifier is
    configured with `issuer` and its key set `jwks`; `inp["trust_anchors"]`, where present,
    is the whole configuration instead: {issuer: {jwks, responders, authorities}}.
    `inp["issuer_rank"]` ranks issuers, highest first; `inp["higher_ranked_answers"]` maps
    each higher-ranked issuer to its responder's answer for the authenticated pair (01 §9.1)."""
    try:
        p = strict_json(inp["passport_text"]) if "passport_text" in inp else inp["passport"]
    except ValueError:
        return "reject", "signature"                        # 01 §4: duplicate member names
    if not isinstance(p, dict) or not_ijson(p):
        return "reject", "signature"                        # 01 §4: not I-JSON
    sigs = p.get("signatures")
    if not isinstance(sigs, list) or len(sigs) != 1 or not isinstance(sigs[0], dict):
        return "reject", "signature"                        # 01 §4: exactly one entry
    try:
        hdr = header_json(b64u_dec(sigs[0]["protected"]))
        sig = b64u_dec(sigs[0]["signature"])
    except (KeyError, TypeError, ValueError):
        return "reject", "signature"
    if not isinstance(hdr, dict) or not_ijson(hdr) or any(m in hdr for m in REJECTED_HEADER) \
            or not typ_ok(hdr):
        return "reject", "signature"
    anchors = inp.get("trust_anchors") or {issuer: {"jwks": jwks}}
    anchor = anchor_for(anchors, p.get("issuer"))
    if anchor is None:
        return "reject", "signature"                        # 01 §9.1: no anchor for this issuer
    keys = {k.get("kid"): k for k in anchor["jwks"]["keys"]}
    key = keys.get(hdr.get("kid"))
    if key is None:
        return "reject", "signature"
    if hdr.get("alg") != key.get("alg") or hdr.get("alg") != "ES256":
        return "reject", "signature"                        # 01 §4: the key's alg, and only it
    q = (int.from_bytes(b64u_dec(key["x"]), "big"), int.from_bytes(b64u_dec(key["y"]), "big"))
    unsigned = {k: v for k, v in p.items() if k != "signatures"}
    msg = (sigs[0]["protected"] + "." + b64u(jcs(unsigned))).encode()
    if not es256_verify(q, msg, sig):
        return "reject", "signature"
    if any(m not in p for m in REQUIRED):
        return "reject", "members"
    if p["schema_version"] != "1" \
            or p["subject_type"] not in ("agent", "harness", "tool_server", "model_endpoint") \
            or p.get("issuance_class") not in (None, "owned", "proxy"):
        return "reject", "members"                          # 01 §3: absent or null is unknown, not wrong
    if not has_manager(p["business_context"]):
        return "reject", "members"                          # 01 §8.5
    if not isinstance(p["bindings"], list) or not all(binding_ok(b) for b in p["bindings"]):
        return "reject", "members"                          # 01 §3.3: the entry's shape
    now = ts(inp["now"])
    if not ts(p["valid_from"]) <= now <= ts(p["valid_to"]):
        return "reject", "validity"
    refetched = inp.get("refetched") or inp.get("fetched_by_presenter_identity")
    pres = inp.get("presenter")
    pairs = [binding_pair(b) for b in p["bindings"]]       # unknown members ignored (01 §3)
    if pres:
        if pres.get("authenticated", True) is not True:
            return "deny", "bindings"                       # 01 §3.3: retrieval is not authentication
        if pres.get("resolved_by", "authentication") not in RESOLVERS:
            return "deny", "bindings"                       # 01 §3.3: never from the presenter's value
        if {"authority": pres.get("authority"), "identifier": pres.get("identifier")} not in pairs:
            return ("deny" if refetched else "refetch"), "bindings"
        if not issuer_accepted(anchors, p["issuer"], pres.get("authority"), inp,
                               pres.get("tenant")):
            return "deny", "bindings"                       # 01 §9.1: not this issuer's to bind
    if not parent_ok(p):
        return "deny", "parent"                             # 01 §3.4: treated as revoked
    rc = p["status"].get("revocation_check") if isinstance(p["status"], dict) else None
    if not isinstance(rc, dict) or not revocation_uri_ok(rc.get("uri"), p["issuer"], anchor):
        return "deny", "status"                             # 01 §7, §9.1: treated as revoked
    got = caller(inp["revocation"], held={"subject": p["subject"], "revision": p["revision"]})
    if got == "refetch" and refetched:
        got = "deny"                                        # 01 §10: one refetch per verification
    return {"proceed": "accept", "deny": "deny", "refetch": "refetch"}[got], "revocation"


# --- reference responder (Revocation Check v1 §1 pseudocode) ------------------------------

PCT = re.compile(r"%(?![0-9A-Fa-f]{2})")


def respond(state, req):
    now, subs = state["now"], state["subjects"]

    def ident_answer(reason):
        return {"status": 200, "headers_present": ["Cache-Control"],
                "body": rev_body(None, True, (), 0, reason, now, mr=0)}

    q = req.get("query", {})
    if "subject" in q and ("authority" in q or "identifier" in q):
        return {"status": 400}                              # 02 §4: one form or the other
    if "subject" not in q:
        if not state.get("answers_by_identity", True):
            return {"status": 400}                          # 02 §3.1: optional for a responder
        a, i = q.get("authority"), q.get("identifier")
        if not a or not i:
            return {"status": 400}
        def has(s, withdrawn):
            return any(authority_matches(b, a) and b.get("identifier") == i
                       and b.get("withdrawn", False) == withdrawn for b in s.get("bindings", []))
        active = [sid for sid, s in subs.items() if has(s, False)]
        if len(active) > 1:
            return ident_answer("ambiguous_identity")
        if not active:
            gone = any(has(s, True) for s in subs.values())
            return ident_answer("binding_revoked" if gone else "unresolved_identity")
        subject = active[0]
    else:
        raw = q["subject"]
        if not raw or PCT.search(raw):
            return {"status": 400}
        try:
            subject = unquote_to_bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            return {"status": 400}
    return {"status": 200, "headers_present": ["Cache-Control"], "body": answer(state, subject)}


def answer(state, subject, seen=()):
    """The answer for one subject, computed at read time; for a deployment, combined with
    its parent's answer (02 §3.2)."""
    now, s = state["now"], state["subjects"].get(subject)
    if not s or not s.get("passports"):
        return rev_body(subject, True, (), 0, "no_passport_issued", now, mr=0)
    rows = sorted((r for r in s.get("revocations", []) if "lifted_at" not in r),
                  key=lambda r: r["created_at"])
    floor = s.get("min_required_revision", 1)
    current = [p for p in s["passports"] if not p.get("superseded")]
    lapsed = all("valid_to" in p and ts(p["valid_to"]) <= ts(now) for p in current)  # 02 §5.7
    reason = (rows[-1]["reason"] if rows else "no_active_passport" if lapsed
              else "revision_withdrawn" if floor > 1 else None)
    own = rev_body(subject, bool(rows) or lapsed, [], s["state_version"], reason, now, mr=floor)
    par = s.get("parent")
    if par is None:
        return own
    if isinstance(par, str) and par not in seen + (subject,):
        pa = answer(state, par, seen + (subject,))
    else:                                                   # unresolvable, such as {}: revoked
        pa = rev_body(None, True, (), 0, "no_passport_issued", now, mr=0)
    # The floor is not inherited. The sum never decreases while each part only rises; when a
    # deployment's parent changes, the responder raises the deployment's own state_version
    # enough that the sum does not decrease (02 §3.2). The state here is after that write.
    return rev_body(subject, own["revoked"] or pa["revoked"],
                    own["revoked_scopes"] + pa["revoked_scopes"],
                    own["state_version"] + pa["state_version"],
                    reason if own["revoked"] else "parent_revoked" if pa["revoked"] else reason,
                    now, mr=floor)


# --- Passport verification vectors --------------------------------------------------------

P01 = signed(BASE)
_tampered = copy.deepcopy(P01)
_tampered["business_context"]["risk_classification"]["value"] = "medium"
_pretty = json.dumps(dict(reversed(list(P01.items()))), indent=2)
# P01 with a second risk_classification ahead of the real one: a last-wins parser reads the
# signed value and the signature verifies; a first-wins one reads "low" (01 §4).
_dup = json.dumps(P01).replace('"business_context": {',
                               '"business_context": {"risk_classification": {"value": "low"}, ', 1)
_owner = {"role": "owner", "principal": "urn:example:principal:5c2e"}
_bc = BASE["business_context"]
_other_uri = {"revocation_check": {"uri": "https://status.example.net/revocation?subject={subject}"}}
_deployment = with_(subject=D, name="Supplier invoice reconciliation, EU deployment",
                    bindings=[bd(IDP, "b3a0e6d2-19c4")],
                    parent={"issuer": ISS, "subject": S, "x_example_note": "ignored"})
_from_other = with_(issuer=OTHER,
                    status={"revocation_check": {"uri": OTHER + "/revocation?subject={subject}"}})
_both_anchors = {ISS: {"jwks": JWKS}, OTHER: {"jwks": OTHER_JWKS}}
_both_accept_idp = {ISS: {"jwks": JWKS, "authorities": [IDP, ISS]},
                    OTHER: {"jwks": OTHER_JWKS, "authorities": [IDP, OTHER]}}
THIRD = "https://issuer.example.net"
_three_accept_idp = dict(_both_accept_idp, **{THIRD: {"jwks": OTHER_JWKS, "authorities": [IDP]}})
_unresolved = {"status": 200, "body": rev_body(subject=None, revoked=True, sv=0,
                                               reason="unresolved_identity")}
_tenant_anchor = {ISS: {"jwks": JWKS, "authorities": [{"id": IDP, "tenants": ["tenant-42"]}, ISS]}}
_presenter = {"authority": IDP, "identifier": "4f1c9a2e-77b0"}
_stranger = {"authority": IDP, "identifier": "8e3b1f60-2a9d"}
_aws = {"authority": {"name": "Amazon Web Services"},
        "identifier": "arn:aws:bedrock:eu-west-1:123456789012:agent/AGENT7EXAMPLE"}

PASSPORT_VECTORS = [
    ("P01", "The AI Passport v1 §1 example, current and not revoked.",
     {"passport": P01, "now": NOW, "revocation": OK}, "accept", "revocation"),
    ("P02", "One business-context value changed after signing (risk_classification high -> "
            "medium).",
     {"passport": _tampered, "now": NOW, "revocation": OK}, "reject", "signature"),
    ("P03", "Signed with the test key but naming a kid absent from the JWKS.",
     {"passport": signed(BASE, dict(HEADER, kid="k9")), "now": NOW, "revocation": OK},
     "reject", "signature"),
    ("P04", "Protected header names ES384 for an ES256 key.",
     {"passport": signed(BASE, dict(HEADER, alg="ES384")), "now": NOW, "revocation": OK},
     "reject", "signature"),
    ("P05", "Protected header names alg none, empty signature.",
     {"passport": dict(BASE, signatures=[{"protected": b64u(b'{"alg":"none","kid":"k1"}'),
                                          "signature": ""}]), "now": NOW, "revocation": OK},
     "reject", "signature"),
    ("P06", "Protected header carries b64:false (RFC 7797 unencoded payload); v1 signs the "
            "base64url of the canonical form.",
     {"passport": signed(BASE, dict(HEADER, b64=False, crit=["b64"])), "now": NOW,
      "revocation": OK}, "reject", "signature"),
    ("P07", "The issuer signed a pretty-printed serialization instead of the RFC 8785 form.",
     {"passport": signed(BASE, over=json.dumps(BASE, indent=2).encode()), "now": NOW,
      "revocation": OK}, "reject", "signature"),
    ("P08", "The P01 Passport received with different whitespace and member order. The "
            "verifier canonicalizes, so transport formatting does not matter.",
     {"passport_text": _pretty, "now": NOW, "revocation": OK}, "accept", "revocation"),
    ("P09", "Checked after valid_to.",
     {"passport": P01, "now": "2026-12-30T00:00:01Z", "revocation": OK}, "reject", "validity"),
    ("P10", "Checked before valid_from.",
     {"passport": P01, "now": "2026-09-30T23:59:59Z", "revocation": OK}, "reject", "validity"),
    ("P11", "Validly signed but missing bindings.",
     {"passport": signed(with_(drop=["bindings"])), "now": NOW, "revocation": OK},
     "reject", "members"),
    ("P12", "Validly signed but missing business_context.",
     {"passport": signed(with_(drop=["business_context"])), "now": NOW, "revocation": OK},
     "reject", "members"),
    ("P13", "An unrecognized top-level member, signed. Ignored, not grounds for rejection.",
     {"passport": signed(with_(x_example_note="ignored by verifiers")), "now": NOW,
      "revocation": OK}, "accept", "revocation"),
    ("P14", "The presenter authenticated as a pair listed in bindings.",
     {"passport": P01, "now": NOW, "presenter": {"authority": IDP, "identifier": "4f1c9a2e-77b0"},
      "revocation": OK}, "accept", "revocation"),
    ("P15", "The presenter authenticated as a pair not in bindings: fetch the current Passport "
            "by that pair and start again.",
     {"passport": P01, "now": NOW, "presenter": {"authority": IDP, "identifier": "8e3b1f60-2a9d"},
      "revocation": OK}, "refetch", "bindings"),
    ("P16", "As P15, but this Passport was the one fetched by the presenter's pair and still "
            "does not list it.",
     {"passport": P01, "now": NOW, "presenter": {"authority": IDP, "identifier": "8e3b1f60-2a9d"},
      "fetched_by_presenter_identity": True, "revocation": OK}, "deny", "bindings"),
    ("P17", "status names no mechanism the verifier supports.",
     {"passport": signed(with_(status={"x_other": {"uri": ISS + "/elsewhere"}})), "now": NOW,
      "revocation": OK}, "deny", "status"),
    ("P18", "Valid Passport, subject revoked: the manager left (accountability_lapsed).",
     {"passport": P01, "now": NOW, "revocation": {"status": 200, "body": rev_body(
         revoked=True, sv=13, reason="accountability_lapsed")}}, "deny", "revocation"),
    ("P19", "Valid Passport, revocation check timed out.",
     {"passport": P01, "now": NOW, "revocation": {"error": "timeout"}}, "deny", "revocation"),
    ("P20", "Valid Passport at revision 3; min_required_revision is 5 after a major reissue. "
            "Withdrawn, not revoked: fetch the current Passport.",
     {"passport": P01, "now": NOW, "revocation": {"status": 200, "body": rev_body(
         mr=5, sv=14, reason="revision_withdrawn")}},
     "refetch", "revocation"),
    ("P21", "min_required_revision equals this Passport's revision: it is current.",
     {"passport": P01, "now": NOW, "revocation": {"status": 200, "body": rev_body(
         mr=3, sv=14, reason="revision_withdrawn")}},
     "accept", "revocation"),
    ("P22", "revoked_scopes carries an entry. This version defines none, so it revokes the "
            "whole subject (02 §6.2).",
     {"passport": P01, "now": NOW, "revocation": {"status": 200, "body": rev_body(
         scopes=[{"x_example_scope": "db.example.com"}], sv=15)}}, "deny", "revocation"),
    ("P23", "Asked by the presenter's identity, the responder resolved a different subject "
            "than the Passport held.",
     {"passport": P01, "now": NOW, "presenter": {"authority": IDP, "identifier": "4f1c9a2e-77b0"},
      "revocation": {"status": 200, "body": rev_body(subject=T, sv=4)}}, "deny", "revocation"),
    ("P24", "schema_version the verifier does not support (\"2\"): a major version, rejected.",
     {"passport": signed(with_(schema_version="2")), "now": NOW, "revocation": OK},
     "reject", "members"),
    ("P25", "Unrecognized subject_type value: the verifier cannot tell what the subject is.",
     {"passport": signed(with_(subject_type="x_example_workflow")), "now": NOW, "revocation": OK},
     "reject", "members"),
    ("P26", "Unrecognized issuance_class value: the verifier cannot tell who runs the subject.",
     {"passport": signed(with_(issuance_class="x_example_class")), "now": NOW, "revocation": OK},
     "reject", "members"),
    ("P27", "A bindings entry carries a member this version does not define; the presenter's "
            "pair still matches it (01 §3).",
     {"passport": signed(with_(bindings=[
         dict(B_IDP, x_example_proof="possession"), B_ISS])), "now": NOW,
      "presenter": {"authority": IDP, "identifier": "4f1c9a2e-77b0"}, "revocation": OK},
     "accept", "revocation"),
    ("P28", "bindings in a different order with a duplicated entry; the presenter matches the "
            "last one (01 §3: no assumed order or distinctness).",
     {"passport": signed(with_(bindings=[
         B_ISS, B_ISS, B_IDP])), "now": NOW,
      "presenter": {"authority": IDP, "identifier": "4f1c9a2e-77b0"}, "revocation": OK},
     "accept", "revocation"),
    ("P29", "status carries a second, unrecognized mechanism beside revocation_check: ignored.",
     {"passport": signed(with_(status={"revocation_check": {"uri": ISS + "/revocation?subject={subject}"},
                                       "x_example_status_list": {"idx": 7}})), "now": NOW,
      "revocation": OK}, "accept", "revocation"),
    ("P30", "Two entries in signatures, the second a copy of the first: v1 requires exactly "
            "one (01 §4).",
     {"passport": dict(P01, signatures=P01["signatures"] * 2), "now": NOW, "revocation": OK},
     "reject", "signature"),
    ("P31", "Protected header carries crit, naming an extension it also carries: this version "
            "defines none (01 §4).",
     {"passport": signed(BASE, dict(HEADER, crit=["x_example_ext"], x_example_ext=True)),
      "now": NOW, "revocation": OK}, "reject", "signature"),
    ("P32", "Protected header typ is JWT (01 §4).",
     {"passport": signed(BASE, dict(HEADER, typ="JWT")), "now": NOW, "revocation": OK},
     "reject", "signature"),
    ("P33", "Protected header typ is JOSE, as earlier drafts signed: still accepted (01 §4).",
     {"passport": signed(BASE, dict(HEADER, typ="JOSE")), "now": NOW, "revocation": OK},
     "accept", "revocation"),
    ("P34", "Protected header carries no typ: accepted (01 §4).",
     {"passport": signed(BASE, {"alg": "ES256", "kid": KID}), "now": NOW, "revocation": OK},
     "accept", "revocation"),
    ("P35", "typ is the full media type in mixed case, Application/AI-Passport+JWS: compared "
            "case-insensitively (01 §4, RFC 7515 §4.1.9).",
     {"passport": signed(BASE, dict(HEADER, typ="Application/AI-Passport+JWS")), "now": NOW,
      "revocation": OK}, "accept", "revocation"),
    ("P36", "passport_text repeats risk_classification inside business_context, \"low\" before "
            "the signed \"high\". A last-wins parser verifies it; I-JSON rejects it (01 §4).",
     {"passport_text": _dup, "now": NOW, "revocation": OK}, "reject", "signature"),
    ("P37", "revision is 2^53, outside the integers I-JSON allows; validly signed (01 §4).",
     {"passport_text": json.dumps(signed(with_(revision=2 ** 53))), "now": NOW, "revocation": OK},
     "reject", "signature"),
    ("P38", "name ends in the noncharacter U+FFFF; validly signed (01 §4, RFC 7493 §2.1).",
     {"passport_text": json.dumps(signed(with_(name=BASE["name"] + "￿"))), "now": NOW,
      "revocation": OK}, "reject", "signature"),
    ("P39", "accountable lists an owner and no manager (01 §8.5).",
     {"passport": signed(with_(business_context=dict(_bc, accountable=[_owner]))), "now": NOW,
      "revocation": OK}, "reject", "members"),
    ("P40", "The only manager entry carries neither principal nor name, so it reads as absent "
            "and there is no manager (01 §8.5).",
     {"passport": signed(with_(business_context=dict(_bc, accountable=[
         _owner, {"role": "manager"}]))), "now": NOW, "revocation": OK}, "reject", "members"),
    ("P41", "The manager and org_unit are named by name alone, as a Passport served only to "
            "authenticated callers may be (01 §8.3, §10). The verifier authenticated the "
            "presenter and retrieved it; accepted.",
     {"passport": signed(with_(business_context=dict(_bc, org_unit={"name": "Finance Operations"},
                                                     accountable=[_owner, {"role": "manager",
                                                     "name": "Accounts Payable Systems"}]))),
      "now": NOW, "presenter": _presenter, "revocation": OK}, "accept", "revocation"),
    ("P42", "parent is {}: a parent that cannot be resolved, treated as revoked (01 §3.4).",
     {"passport": signed(with_(parent={})), "now": NOW, "revocation": OK}, "deny", "parent"),
    ("P43", "parent is null: no parent (01 §3.4).",
     {"passport": signed(with_(parent=None)), "now": NOW, "revocation": OK}, "accept", "revocation"),
    ("P44", "parent.issuer differs from issuer: treated as revoked (01 §3.4).",
     {"passport": signed(with_(parent={"issuer": OTHER, "subject": S})), "now": NOW,
      "revocation": OK}, "deny", "parent"),
    ("P45", "A deployment's Passport naming its parent, with a member parent does not define: "
            "ignored, accepted (01 §3, §3.4).",
     {"passport": signed(_deployment), "now": NOW,
      "revocation": {"status": 200, "body": rev_body(subject=D, sv=3)}}, "accept", "revocation"),
    ("P46", "status.revocation_check.uri is on another origin than issuer, and no responder is "
            "configured for it: treated as revoked, never called (01 §9.1).",
     {"passport": signed(with_(status=_other_uri)), "now": NOW, "revocation": OK},
     "deny", "status"),
    ("P47", "status.revocation_check.uri is http on the issuer's host: not https, treated as "
            "revoked (01 §9.1).",
     {"passport": signed(with_(status={"revocation_check": {
         "uri": "http://issuer.example.com/revocation?subject={subject}"}})), "now": NOW,
      "revocation": OK}, "deny", "status"),
    ("P48", "As P46, but the verifier has configured that responder for this issuer (01 §9.1).",
     {"passport": signed(with_(status=_other_uri)), "now": NOW, "revocation": OK,
      "trust_anchors": {ISS: {"jwks": JWKS, "responders": ["https://status.example.net"]}}},
     "accept", "revocation"),
    ("P49", "issuer is another configured issuer, whose key set does not hold k1; k1 is in the "
            "first issuer's key set. A kid in another issuer's JWKS never verifies (01 §9.1).",
     {"passport": signed(_from_other), "now": NOW, "revocation": OK,
      "trust_anchors": _both_anchors}, "reject", "signature"),
    ("P50", "issuer is one the verifier is not configured with; the Passport names k1 (01 §9.1).",
     {"passport": signed(_from_other), "now": NOW, "revocation": OK}, "reject", "signature"),
    ("P51", "issuer differs from the configured issuer by a trailing slash: compared exactly, "
            "so no trust anchor (01 §9.1).",
     {"passport": signed(with_(issuer=ISS + "/")), "now": NOW, "revocation": OK},
     "reject", "signature"),
    ("P52", "The presenter claims a pair listed in bindings but was not authenticated; the "
            "Passport was retrieved by that pair. Retrieval does not replace authentication "
            "(01 §3.3).",
     {"passport": P01, "now": NOW, "presenter": dict(_presenter, authenticated=False),
      "revocation": OK}, "deny", "bindings"),
    ("P53", "This Passport is the one refetch after a revision floor, and the floor is still "
            "above its revision: deny (01 §10, 02 §5.6).",
     {"passport": P01, "now": NOW, "refetched": True, "revocation": {"status": 200, "body": rev_body(
         mr=5, sv=14, reason="revision_withdrawn")}}, "deny", "revocation"),
    ("P54", "This Passport is the one refetch after a revision floor; the presenter is not in "
            "bindings. One refetch per verification, whatever the trigger (01 §10).",
     {"passport": P01, "now": NOW, "refetched": True, "presenter": _stranger, "revocation": OK},
     "deny", "bindings"),
    ("P55", "issuance_class absent: optional, read as unknown, so a check that reads it does "
            "not pass (01 §3). Accepted. The kit has no policy step, so the unknown value is "
            "not exercised.",
     {"passport": signed(with_(drop=["issuance_class"])), "now": NOW, "revocation": OK},
     "accept", "revocation"),
    ("P56", "Protected header typ is jose, in lower case: compared case-insensitively (01 §4).",
     {"passport": signed(BASE, dict(HEADER, typ="jose")), "now": NOW, "revocation": OK},
     "accept", "revocation"),
    ("P57", "The decoded protected header repeats typ, JWT before ai-passport+jws. A last-wins "
            "parser accepts it; the header must be I-JSON (01 §4).",
     {"passport": signed(BASE, header_text='{"alg":"ES256","kid":"' + KID + '","typ":"JWT",'
                                           '"typ":"ai-passport+jws"}'), "now": NOW,
      "revocation": OK}, "reject", "signature"),
    ("P58", "purpose.autonomy_level carries a value this version does not define. The Passport "
            "is accepted; the value compares as fully_automated, the most restrictive (01 "
            "§8.5, §8.7). The kit has no policy step, so the ordering is not exercised.",
     {"passport": signed(with_(business_context=dict(_bc, purpose=dict(
         _bc["purpose"], autonomy_level="x_example_level")))), "now": NOW, "revocation": OK},
     "accept", "revocation"),
    ("P59", "A binding in the earlier shape, its authority a bare string: not an object, so "
            "the entry is malformed (01 §3.3).",
     {"passport": signed(with_(bindings=[{"authority": IDP, "identifier": "4f1c9a2e-77b0"},
                                         B_ISS])), "now": NOW, "revocation": OK},
     "reject", "members"),
    ("P60", "A binding whose authority carries neither id nor name (01 §3.3).",
     {"passport": signed(with_(bindings=[{"authority": {}, "identifier": "4f1c9a2e-77b0"},
                                         B_ISS])), "now": NOW, "revocation": OK},
     "reject", "members"),
    ("P61", "A binding whose authority.id is not an absolute URI, login.example.net/tenant-42 "
            "(01 §3.3).",
     {"passport": signed(with_(bindings=[bd("login.example.net/tenant-42", "4f1c9a2e-77b0"),
                                         B_ISS])), "now": NOW, "revocation": OK},
     "reject", "members"),
    ("P62", "The only binding for the presenter's identifier has authority.name alone, spelled "
            "like the authority the verifier authenticated. Retrieval by that URI compares it "
            "with authority.id only (01 §10), so this Passport came another way, as the one "
            "refetch; a binding without authority.id never attributes (01 §3.3).",
     {"passport": signed(with_(bindings=[{"authority": {"name": IDP},
                                          "identifier": "4f1c9a2e-77b0"}, B_ISS])),
      "now": NOW, "presenter": _presenter, "refetched": True, "revocation": OK},
     "deny", "bindings"),
    ("P63", "The presenter matches a binding by authority.id; its name is another system's "
            "URL. Matching is on id and identifier only (01 §3.3).",
     {"passport": signed(with_(bindings=[{"authority": {"id": IDP,
                                                        "name": "https://idp.example.org"},
                                          "identifier": "4f1c9a2e-77b0"}, B_ISS])),
      "now": NOW, "presenter": _presenter, "revocation": OK}, "accept", "revocation"),
    ("P64", "A binding's authority carries a member this version does not define: ignored "
            "(01 §3); the presenter matches it.",
     {"passport": signed(with_(bindings=[dict(B_IDP, authority=dict(
         B_IDP["authority"], x_example_region="eu")), B_ISS])), "now": NOW,
      "presenter": _presenter, "revocation": OK}, "accept", "revocation"),
    ("P65", "type carries a value this version does not define, on the binding the presenter "
            "matches. It is informative and never matched (01 §3.3).",
     {"passport": signed(with_(bindings=[dict(B_IDP, type="x_example_kind"), B_ISS])),
      "now": NOW, "presenter": _presenter, "revocation": OK}, "accept", "revocation"),
    ("P66", "A cloud resource name, an AWS ARN, listed with authority.name alone, beside the "
            "binding the presenter matches. It serves lookup only and does not make the "
            "Passport malformed (01 §3.3).",
     {"passport": signed(with_(bindings=[B_IDP, B_ISS, _aws])), "now": NOW,
      "presenter": _presenter, "revocation": OK}, "accept", "revocation"),
    ("P67", "issuance_class is null: read as absent, so unknown, not rejected (01 §3).",
     {"passport": signed(with_(issuance_class=None)), "now": NOW, "revocation": OK},
     "accept", "revocation"),
    ("P68", "Protected header typ is application/jose, the full form of JOSE (01 §4, RFC 7515 "
            "§4.1.9).",
     {"passport": signed(BASE, dict(HEADER, typ="application/jose")), "now": NOW,
      "revocation": OK}, "accept", "revocation"),
    ("P69", "The presenter matches a binding, but the configuration accepts from this issuer "
            "only its own instance URL as an authority, not the IdP (01 §9.1).",
     {"passport": P01, "now": NOW, "presenter": _presenter, "revocation": OK,
      "trust_anchors": {ISS: {"jwks": JWKS, "authorities": [ISS]}}}, "deny", "bindings"),
    ("P70", "Two trusted issuers are both configured to bind the IdP, and the configuration "
            "does not rank them: deny (01 §9.1).",
     {"passport": P01, "now": NOW, "presenter": _presenter, "revocation": OK,
      "trust_anchors": _both_accept_idp}, "deny", "bindings"),
    ("P71", "As P70, with this issuer ranked first: accepted (01 §9.1).",
     {"passport": P01, "now": NOW, "presenter": _presenter, "revocation": OK,
      "trust_anchors": _both_accept_idp, "issuer_rank": [ISS, OTHER]}, "accept", "revocation"),
    ("P72", "As P70, with the other issuer ranked first and not yet asked: deny (01 §9.1).",
     {"passport": P01, "now": NOW, "presenter": _presenter, "revocation": OK,
      "trust_anchors": _both_accept_idp, "issuer_rank": [OTHER, ISS]}, "deny", "bindings"),
    ("P73", "As P72, after the higher-ranked issuer's responder, asked by the pair, answered "
            "unresolved_identity: accepted (01 §9.1).",
     {"passport": P01, "now": NOW, "presenter": _presenter, "revocation": OK,
      "trust_anchors": _both_accept_idp, "issuer_rank": [OTHER, ISS],
      "higher_ranked_answers": {OTHER: _unresolved}}, "accept", "revocation"),
    ("P74", "The presenter's identifier was resolved by a mapping the verifier is configured "
            "to trust, from the credential it authenticated: accepted (01 §3.3).",
     {"passport": P01, "now": NOW, "revocation": OK,
      "presenter": dict(_presenter, resolved_by="configured_mapping")}, "accept", "revocation"),
    ("P75", "The presenter's identifier was taken from a value the presenter chose, such as a "
            "session name or a header: deny (01 §3.3).",
     {"passport": P01, "now": NOW, "revocation": OK,
      "presenter": dict(_presenter, resolved_by="presenter_value")}, "deny", "bindings"),
    ("P76", "As P73, but the higher-ranked issuer answered binding_revoked: it may hold the "
            "pair, so deny (01 §9.1).",
     {"passport": P01, "now": NOW, "presenter": _presenter, "revocation": OK,
      "trust_anchors": _both_accept_idp, "issuer_rank": [OTHER, ISS],
      "higher_ranked_answers": {OTHER: {"status": 200, "body": rev_body(
          subject=None, revoked=True, sv=0, reason="binding_revoked")}}}, "deny", "bindings"),
    ("P77", "As P73, but the higher-ranked issuer's responder timed out: deny (01 §9.1).",
     {"passport": P01, "now": NOW, "presenter": _presenter, "revocation": OK,
      "trust_anchors": _both_accept_idp, "issuer_rank": [OTHER, ISS],
      "higher_ranked_answers": {OTHER: {"error": "timeout"}}}, "deny", "bindings"),
    ("P78", "As P73, but the higher-ranked issuer answered 404 at retrieval: a lapse, a "
            "withdrawal or an ambiguity, not 'not mine', so deny (01 §9.1, §10).",
     {"passport": P01, "now": NOW, "presenter": _presenter, "revocation": OK,
      "trust_anchors": _both_accept_idp, "issuer_rank": [OTHER, ISS],
      "higher_ranked_answers": {OTHER: {"status": 404}}}, "deny", "bindings"),
    ("P79", "Three issuers accept the IdP, this one ranked third; only the first answered "
            "unresolved_identity: deny (01 §9.1).",
     {"passport": P01, "now": NOW, "presenter": _presenter, "revocation": OK,
      "trust_anchors": _three_accept_idp, "issuer_rank": [OTHER, THIRD, ISS],
      "higher_ranked_answers": {OTHER: _unresolved}}, "deny", "bindings"),
    ("P80", "A shared authority, accepted from this issuer for tenant-42 only; the presenter "
            "authenticated in tenant-7: deny (01 §9.1).",
     {"passport": P01, "now": NOW, "presenter": dict(_presenter, tenant="tenant-7"),
      "revocation": OK, "trust_anchors": _tenant_anchor}, "deny", "bindings"),
    ("P81", "As P80, the presenter authenticated in tenant-42: accepted (01 §9.1).",
     {"passport": P01, "now": NOW, "presenter": dict(_presenter, tenant="tenant-42"),
      "revocation": OK, "trust_anchors": _tenant_anchor}, "accept", "revocation"),
]

# --- Revocation Check vectors -------------------------------------------------------------

def sub_s(**kw):
    s = {"subject_type": "agent",
         "passports": [{"revision": 3, "issued_at": "2026-10-01T00:00:00Z"}],
         "state_version": 12, "revocations": [],
         "bindings": [B_IDP, B_ISS]}
    s.update(kw)
    return s


def sub_t(**kw):
    s = {"subject_type": "tool_server",
         "passports": [{"revision": 1, "issued_at": "2026-10-02T00:00:00Z"}],
         "state_version": 4, "revocations": [],
         "bindings": [bd(ISS, "tool-record-7")]}
    s.update(kw)
    return s


def sub_d(**kw):
    s = {"subject_type": "agent", "parent": S,
         "passports": [{"revision": 1, "issued_at": "2026-10-05T00:00:00Z"}],
         "state_version": 3, "revocations": [],
         "bindings": [bd(IDP, "b3a0e6d2-19c4")]}
    s.update(kw)
    return s


def st(**subjects):
    return {"now": NOW, "subjects": subjects or {S: sub_s(), T: sub_t()}}


def by_subject(sid=S):
    return {"method": "GET", "path": "/revocation", "query": {"subject": sid}}


def by_identity(a, i):
    return {"method": "GET", "path": "/revocation", "query": {"authority": a, "identifier": i}}


HELD_S3 = {"subject": S, "revision": 3}
HELD_D1 = {"subject": D, "revision": 1}
ROW_OP = {"reason": "withdrawn_by_operator", "created_at": "2026-10-14T08:00:00Z"}
WITHDRAWN = bd(IDP, "2d7e0b91-4c3a", withdrawn=True)


def ok200(body):
    return {"status": 200, "headers_present": ["Cache-Control"], "body": body}


def ident200(reason):
    return {"status": 200, "headers_present": ["Cache-Control"],
            "body": rev_body(None, True, (), 0, reason, mr=0)}


RESPONDER_VECTORS = [
    ("R01", "Asked by subject; nothing revoked.",
     st(), by_subject(), ok200(rev_body()), HELD_S3, "proceed"),
    ("R02", "Revoked by an authority permitted to write revocations (withdrawn_by_operator).",
     st(**{S: sub_s(state_version=13, revocations=[ROW_OP])}), by_subject(),
     ok200(rev_body(revoked=True, sv=13, reason="withdrawn_by_operator")), HELD_S3, "deny"),
    ("R03", "Lapsed manager: the only manager's user record went inactive with no replacement, "
            "and the issuer's trigger inserted a whole-subject revocation (AI Passport v1 §8.4(1)).",
     st(**{S: sub_s(state_version=13, cause="manager urn:example:principal:7d41 inactive "
                    "2026-10-15T09:00:00Z; no replacement manager",
                    revocations=[{"reason": "accountability_lapsed",
                                  "created_at": "2026-10-15T09:00:02Z"}])}),
     by_subject(), ok200(rev_body(revoked=True, sv=13, reason="accountability_lapsed")),
     HELD_S3, "deny"),
    ("R04", "Governance record retired the subject (AI Passport v1 §8.4(2)).",
     st(**{S: sub_s(state_version=13, cause="governance status moved to Offboarded",
                    revocations=[{"reason": "governance_withdrawn",
                                  "created_at": "2026-10-15T10:00:00Z"}])}),
     by_subject(), ok200(rev_body(revoked=True, sv=13, reason="governance_withdrawn")),
     HELD_S3, "deny"),
    ("R05", "Unknown subject: no Passport was ever issued. 200 and revoked, never 404.",
     st(), by_subject("0000c0ffee"),
     ok200(rev_body("0000c0ffee", True, (), 0, "no_passport_issued", mr=0)),
     {"subject": "0000c0ffee", "revision": 1}, "deny"),
    ("R06", "Major reissue raised the floor to 5; the caller holds revision 3.",
     st(**{S: sub_s(state_version=14, min_required_revision=5, passports=[
         {"revision": 3, "issued_at": "2026-10-01T00:00:00Z", "superseded": True},
         {"revision": 4, "issued_at": "2026-10-08T00:00:00Z", "superseded": True},
         {"revision": 5, "issued_at": "2026-10-15T11:00:00Z", "major": True}])}),
     by_subject(), ok200(rev_body(mr=5, sv=14, reason="revision_withdrawn")),
     HELD_S3, "refetch"),
    ("R07", "Same state as R06; the caller holds revision 5.",
     st(**{S: sub_s(state_version=14, min_required_revision=5, passports=[
         {"revision": 5, "issued_at": "2026-10-15T11:00:00Z", "major": True}])}),
     by_subject(), ok200(rev_body(mr=5, sv=14, reason="revision_withdrawn")),
     {"subject": S, "revision": 5}, "proceed"),
    ("R08", "Floor raised and the subject revoked (withdrawn_by_operator): revoked wins, nothing to "
            "fetch.",
     st(**{S: sub_s(state_version=15, min_required_revision=5, revocations=[ROW_OP], passports=[
         {"revision": 5, "issued_at": "2026-10-13T00:00:00Z", "major": True}])}),
     by_subject(), ok200(rev_body(revoked=True, mr=5, sv=15, reason="withdrawn_by_operator")),
     {"subject": S, "revision": 5}, "deny"),
    ("R09", "Revoke, then reissue: revision 4 was issued after the revocation. Revocation is on "
            "the subject, so it survives; a single stored status would have un-revoked here.",
     st(**{S: sub_s(state_version=13, revocations=[ROW_OP], passports=[
         {"revision": 3, "issued_at": "2026-10-01T00:00:00Z", "superseded": True},
         {"revision": 4, "issued_at": "2026-10-15T00:00:00Z"}])}),
     by_subject(), ok200(rev_body(revoked=True, sv=13, reason="withdrawn_by_operator")),
     {"subject": S, "revision": 4}, "deny"),
    ("R10", "Explicit restore lifted the withdrawn_by_operator revocation; state_version moved on.",
     st(**{S: sub_s(state_version=14, revocations=[dict(ROW_OP, lifted_at="2026-10-15T12:00:00Z")])}),
     by_subject(), ok200(rev_body(sv=14)), HELD_S3, "proceed"),
    ("R11", "Asked by an authenticated identity that resolves to one subject.",
     st(), by_identity(IDP, "4f1c9a2e-77b0"), ok200(rev_body()), HELD_S3, "proceed"),
    ("R12", "Asked by an identity bound to no subject.",
     st(), by_identity(IDP, "ffffffff-0000"), ident200("unresolved_identity"), None, "deny"),
    ("R13", "Asked by an identity bound to two subjects. The responder never picks one.",
     st(**{S: sub_s(), T: sub_t(bindings=[bd(IDP, "4f1c9a2e-77b0")])}),
     by_identity(IDP, "4f1c9a2e-77b0"), ident200("ambiguous_identity"), HELD_S3, "deny"),
    ("R14", "Asked by a binding the issuer withdrew (a rotated workload credential).",
     st(**{S: sub_s(state_version=13, min_required_revision=4, bindings=sub_s()["bindings"] + [WITHDRAWN],
                    passports=[{"revision": 4, "issued_at": "2026-10-10T00:00:00Z", "major": True}])}),
     by_identity(IDP, "2d7e0b91-4c3a"), ident200("binding_revoked"), None, "deny"),
    ("R15", "Same state as R14, asked by one of the subject's active bindings: the asset is "
            "unaffected.",
     st(**{S: sub_s(state_version=13, min_required_revision=4, bindings=sub_s()["bindings"] + [WITHDRAWN],
                    passports=[{"revision": 4, "issued_at": "2026-10-10T00:00:00Z", "major": True}])}),
     by_identity(ISS, "agent-record-19"),
     ok200(rev_body(mr=4, sv=13, reason="revision_withdrawn")),
     {"subject": S, "revision": 4}, "proceed"),
    ("R16", "Caller subject mismatch: the authenticated identity resolves to the tool server, "
            "but the caller holds the invoice reconciler's Passport.",
     st(), by_identity(ISS, "tool-record-7"), ok200(rev_body(subject=T, sv=4)), HELD_S3, "deny"),
    ("R17", "Rebind: the pair was withdrawn from the tool server and is now active on the "
            "invoice reconciler. An active binding resolves; the withdrawn one is ignored.",
     st(**{S: sub_s(bindings=sub_s()["bindings"] + [bd(ISS, "tool-record-7")]),
           T: sub_t(bindings=[bd(ISS, "tool-record-7", withdrawn=True)])}),
     by_identity(ISS, "tool-record-7"), ok200(rev_body()), HELD_S3, "proceed"),
    ("R18", "Resolves to a subject that has bindings but no Passport was ever issued.",
     st(**{S: sub_s(), T: sub_t(passports=[], state_version=0)}),
     by_identity(ISS, "tool-record-7"),
     ok200(rev_body(T, True, (), 0, "no_passport_issued", mr=0)), None, "deny"),
    ("R19", "Malformed percent-encoding in the subject parameter.",
     st(), by_subject("7a1f%ZZ"), {"status": 400}, HELD_S3, "deny"),
    ("R20", "Empty subject.",
     st(), by_subject(""), {"status": 400}, HELD_S3, "deny"),
    ("R21", "Asked by identity with the identifier missing.",
     st(), {"method": "GET", "path": "/revocation", "query": {"authority": IDP}},
     {"status": 400}, HELD_S3, "deny"),
    ("R22", "A responder that does not answer by identity (optional, 02 §3.1) is asked by "
            "identity: 400, which the caller treats as revoked. The caller resolves through "
            "/passports and asks by subject instead.",
     dict(st(), answers_by_identity=False), by_identity(IDP, "4f1c9a2e-77b0"),
     {"status": 400}, HELD_S3, "deny"),
    ("R23", "Same responder as R22, asked by subject: answers normally.",
     dict(st(), answers_by_identity=False), by_subject(), ok200(rev_body()), HELD_S3, "proceed"),
    ("R24", "Asked by subject and by identity in one request: 400, never an answer for either "
            "(02 §4).",
     st(), {"method": "GET", "path": "/revocation",
            "query": {"subject": S, "authority": IDP, "identifier": "4f1c9a2e-77b0"}},
     {"status": 400}, HELD_S3, "deny"),
    ("R25", "The current Passport is past its valid_to and no successor was issued: revoked, "
            "no_active_passport, and state_version moved on (02 §5.7).",
     st(**{S: sub_s(state_version=13, passports=[
         {"revision": 3, "issued_at": "2026-07-01T00:00:00Z", "valid_to": "2026-10-01T00:00:00Z"}])}),
     by_subject(), ok200(rev_body(revoked=True, sv=13, reason="no_active_passport")),
     HELD_S3, "deny"),
    ("R26", "A deployment whose parent was revoked (withdrawn_by_operator): revoked, parent_revoked, "
            "state_version the sum of both (02 §3.2).",
     st(**{S: sub_s(state_version=13, revocations=[ROW_OP]), D: sub_d()}), by_subject(D),
     ok200(rev_body(D, True, (), 16, "parent_revoked")), HELD_D1, "deny"),
    ("R27", "A deployment whose own floor was raised to 2, parent clear: the deployment's "
            "floor and reason (02 §3.2).",
     st(**{S: sub_s(), D: sub_d(state_version=4, min_required_revision=2, passports=[
         {"revision": 2, "issued_at": "2026-10-12T00:00:00Z", "major": True}])}),
     by_subject(D), ok200(rev_body(D, False, (), 16, "revision_withdrawn", mr=2)),
     {"subject": D, "revision": 2}, "proceed"),
    ("R28", "A deployment whose parent cannot be resolved ({} in the issuer's records): "
            "revoked (02 §3.2).",
     st(**{S: sub_s(), D: sub_d(parent={})}), by_subject(D),
     ok200(rev_body(D, True, (), 3, "parent_revoked")), HELD_D1, "deny"),
    ("R29", "The parent's floor was raised to 5; the deployment holds revision 1. The floor is "
            "not inherited (02 §3.2).",
     st(**{S: sub_s(state_version=14, min_required_revision=5, passports=[
         {"revision": 5, "issued_at": "2026-10-15T11:00:00Z", "major": True}]), D: sub_d()}),
     by_subject(D), ok200(rev_body(D, False, (), 17)), HELD_D1, "proceed"),
    ("R30", "Deployment and parent both revoked: the deployment's own reason (02 §3.2).",
     st(**{S: sub_s(state_version=13, revocations=[ROW_OP]),
           D: sub_d(state_version=4, revocations=[{"reason": "governance_withdrawn",
                                                   "created_at": "2026-10-15T10:00:00Z"}])}),
     by_subject(D), ok200(rev_body(D, True, (), 17, "governance_withdrawn")), HELD_D1, "deny"),
    ("R31", "parent null in the issuer's records: no parent, the subject's own answer "
            "(02 §3.2).",
     st(**{S: sub_s(state_version=13, revocations=[ROW_OP]), D: sub_d(parent=None)}),
     by_subject(D), ok200(rev_body(D, False, (), 3)), HELD_D1, "proceed"),
    ("R32", "Asked by identity; the only binding with that identifier has authority.name "
            "alone, equal to the authority asked. Not reachable by identity (02 §3.1).",
     st(**{S: sub_s(), T: sub_t(bindings=[{"authority": {"name": "Example Ledger"},
                                           "identifier": "ledger-agent-5"}])}),
     by_identity("Example Ledger", "ledger-agent-5"), ident200("unresolved_identity"),
     None, "deny"),
    ("R33", "Asked by identity matching authority.id of a binding that also carries a name, "
            "an unknown authority member and a type: resolves (02 §3.1).",
     st(**{S: sub_s(), T: sub_t(bindings=[{"authority": {"id": ISS, "name": "Example Issuer",
                                                         "x_example_region": "eu"},
                                           "identifier": "tool-record-7",
                                           "type": "x_example_kind"}])}),
     by_identity(ISS, "tool-record-7"), ok200(rev_body(subject=T, sv=4)),
     {"subject": T, "revision": 1}, "proceed"),
]

# Vectors that apply only to a responder that answers by identity (02 §3.1).
BY_IDENTITY = {"R11", "R12", "R13", "R14", "R15", "R16", "R17", "R18", "R21", "R32", "R33"}

CALLER_VECTORS = [
    ("C01", "403: not authorized to read.", {"status": 403}, None, "deny"),
    ("C02", "429: rate limited.", {"status": 429}, None, "deny"),
    ("C03", "503: responder unavailable.", {"status": 503}, None, "deny"),
    ("C04", "No response: timeout.", {"error": "timeout"}, None, "deny"),
    ("C05", "404 from a non-conformant responder.", {"status": 404}, None, "deny"),
    ("C06", "200 with an unparseable body.", {"status": 200, "body_text": "{\"subject\": "},
     None, "deny"),
    ("C07", "200 with revoked absent. Absent is not false.",
     {"status": 200, "body": {k: v for k, v in rev_body().items() if k != "revoked"}}, None, "deny"),
    ("C08", "A not-revoked answer reused after its Cache-Control directive expired.",
     {"status": 200, "body": rev_body(), "cache_expired": True}, None, "deny"),
    ("C09", "A stale not-revoked answer (state_version 12) arriving after a revoked one (13) "
            "was applied: discarded.",
     {"status": 200, "body": rev_body()},
     rev_body(revoked=True, sv=13, reason="withdrawn_by_operator"), "deny"),
    ("C10", "A newer not-revoked answer (14) after a revoked one (13): the restore applies.",
     {"status": 200, "body": rev_body(sv=14)},
     rev_body(revoked=True, sv=13, reason="withdrawn_by_operator"), "proceed"),
    ("C11", "Unrecognized reason with revoked false and no entries: revoked alone decides.",
     {"status": 200, "body": rev_body(reason="x_example_reason")}, None, "proceed"),
    ("C12", "Unrecognized reason with revoked true.",
     {"status": 200, "body": rev_body(revoked=True, sv=13, reason="x_example_reason")},
     None, "deny"),
    ("C13", "The floor sent the old way, as a revoked_scopes entry: an entry this version does "
            "not define, so the whole subject is revoked (§6.2).",
     {"status": 200, "body": rev_body(scopes=[{"min_revision": 2}], sv=14)}, None, "deny"),
    ("C14", "revoked is the string \"false\", not a boolean.",
     {"status": 200, "body": dict(rev_body(), revoked="false")}, None, "deny"),
    ("C15", "min_required_revision satisfied, but revoked_scopes carries an unrecognized "
            "entry: the entry revokes the whole subject (§6.2).",
     {"status": 200, "body": rev_body(scopes=[{"x_example_scope": {}}], sv=14, mr=2)},
     None, "deny"),
    ("C16", "An entry that is not an object is an unrecognized entry (§6).",
     {"status": 200, "body": rev_body(scopes=["min_required_revision"], sv=14)}, None, "deny"),
    ("C17", "min_required_revision absent (§5.1, §5.6).",
     {"status": 200, "body": {k: v for k, v in rev_body().items()
                              if k != "min_required_revision"}}, None, "deny"),
    ("C18", "min_required_revision is the string \"3\", not an integer (§5.6).",
     {"status": 200, "body": rev_body(mr="3")}, None, "deny"),
    ("C19", "min_required_revision is negative (§5.6).",
     {"status": 200, "body": rev_body(mr=-1)}, None, "deny"),
    ("C20", "min_required_revision above the held revision 3, nothing revoked: fetch the "
            "current Passport (§5.6).",
     {"status": 200, "body": rev_body(mr=4, sv=13, reason="revision_withdrawn")}, None, "refetch"),
    ("C21", "A body with revoked twice, true then false: not a valid answer, even though a "
            "last-wins parser reads false (02 §5.2).",
     {"status": 200, "body_text": json.dumps(rev_body(revoked=True, sv=13)).replace(
         '"revoked": true,', '"revoked": true, "revoked": false,', 1)}, None, "deny"),
    ("C22", "revoked is 0, a number that some languages read as false (02 §5.1).",
     {"status": 200, "body": dict(rev_body(), revoked=0)}, None, "deny"),
    ("C23", "Asked by subject, holding no Passport; the answer is for another subject "
            "(02 §5.1).",
     {"status": 200, "body": rev_body(subject=T, sv=4)}, None, "deny",
     {"holds_passport": None, "asked": {"subject": S}}),
    ("C24", "Asked by subject, holding no Passport; the answer is for that subject, nothing "
            "revoked (02 §5.6: nothing more to apply).",
     {"status": 200, "body": rev_body()}, None, "proceed",
     {"holds_passport": None, "asked": {"subject": S}}),
    ("C25", "302, a status 02 §5.2 does not list. Over HTTP it points at another origin that "
            "answers not revoked; a caller follows no cross-origin redirect (02 §4).",
     {"status": 302}, None, "deny"),
    ("C26", "201 with a well-formed not-revoked body: an unlisted status (02 §5.2).",
     {"status": 201, "body": rev_body()}, None, "deny"),
    ("C27", "Equal state_version (13): the applied answer is revoked, the new one is not. The "
            "more restrictive applies (02 §5.4).",
     {"status": 200, "body": rev_body(sv=13)},
     rev_body(revoked=True, sv=13, reason="withdrawn_by_operator"), "deny"),
    ("C28", "Equal state_version (14): the applied answer has min_required_revision 5, the new "
            "one 1. The higher floor applies, so fetch the current Passport (02 §5.4).",
     {"status": 200, "body": rev_body(sv=14)},
     rev_body(mr=5, sv=14, reason="revision_withdrawn"), "refetch"),
    ("C29", "As C27, but the applied revoked answer is past its directive: only answers within "
            "their directive count, so the new one applies (02 §5.4).",
     {"status": 200, "body": rev_body(sv=13)},
     rev_body(revoked=True, sv=13, reason="withdrawn_by_operator"), "proceed",
     {"previously_applied_expired": True}),
    ("C30", "Just received with max-age=60, but evaluated_at is 10 minutes old: older than the "
            "freshness lifetime plus the 5-minute skew, so expired (02 §5.3).",
     {"status": 200, "body": rev_body(), "headers": {"Cache-Control": "max-age=60"}},
     None, "deny", {"now": "2026-10-15T14:13:11Z"}),
    ("C31", "As C30 with evaluated_at 4 minutes old: within lifetime plus skew (02 §5.3).",
     {"status": 200, "body": rev_body(), "headers": {"Cache-Control": "max-age=60"}},
     None, "proceed", {"now": "2026-10-15T14:07:11Z"}),
    ("C32", "Delivered by a cache with Age 120 against max-age=60: stale on arrival (02 §5.3, "
            "RFC 9111 §4.2).",
     {"status": 200, "body": rev_body(), "headers": {"Cache-Control": "max-age=60", "Age": "120"}},
     None, "deny"),
    ("C33", "An answer reused for a later action that came with no Cache-Control (02 §5.3).",
     {"status": 200, "body": rev_body(), "headers": {}, "reused": True},
     None, "deny", {"now": "2026-10-15T14:03:41Z"}),
    ("C34", "An answer reused whose Cache-Control cannot be parsed, max-age=sixty (02 §5.3).",
     {"status": 200, "body": rev_body(), "headers": {"Cache-Control": "max-age=sixty"},
      "reused": True}, None, "deny", {"now": "2026-10-15T14:03:41Z"}),
    ("C35", "An answer reused 30 seconds after it was evaluated, within max-age=60 (02 §5.3).",
     {"status": 200, "body": rev_body(), "headers": {"Cache-Control": "max-age=60"},
      "reused": True}, None, "proceed", {"now": "2026-10-15T14:03:41Z"}),
    ("C36", "Just received with no Cache-Control but Age 30: applied once only if Age is 0 "
            "(02 §5.3).",
     {"status": 200, "body": rev_body(), "headers": {"Age": "30"}},
     None, "deny", {"now": "2026-10-15T14:03:41Z"}),
    ("C37", "Cache-Control max-age=60, max-age=3600, reused 10 minutes after evaluation: the "
            "first max-age counts, so expired (02 §5.3).",
     {"status": 200, "body": rev_body(), "headers": {"Cache-Control": "max-age=60, max-age=3600"},
      "reused": True}, None, "deny", {"now": "2026-10-15T14:13:11Z"}),
    ("C38", "Holding another issuer's Passport with the same subject string; the answer came "
            "from this issuer's responder: deny (02 §3.1).",
     {"status": 200, "body": rev_body(), "issuer": ISS}, None, "deny",
     {"holds_passport": {"subject": S, "revision": 3, "issuer": OTHER}}),
    ("C39", "As C38, the answer from the held Passport's own issuer: proceed (02 §3.1).",
     {"status": 200, "body": rev_body(), "issuer": OTHER}, None, "proceed",
     {"holds_passport": {"subject": S, "revision": 3, "issuer": OTHER}}),
    ("C40", "An irreversible action reuses an answer 3 seconds after evaluation, within the "
            "default 5-second limit (02 §5.3).",
     {"status": 200, "body": rev_body(), "headers": {"Cache-Control": "max-age=60"},
      "reused": True, "irreversible": True}, None, "proceed", {"now": "2026-10-15T14:03:14Z"}),
    ("C41", "As C40, 30 seconds after evaluation: within max-age, but past the limit for "
            "irreversible actions (02 §5.3).",
     {"status": 200, "body": rev_body(), "headers": {"Cache-Control": "max-age=60"},
      "reused": True, "irreversible": True}, None, "deny", {"now": "2026-10-15T14:03:41Z"}),
]


# --- assemble, self-check, write ----------------------------------------------------------

def build():
    _selftest()
    errs = []

    pv = []
    for vid, desc, inp, outcome, step in PASSPORT_VECTORS:
        got = verify(inp, JWKS, ISS)
        if got != (outcome, step):
            errs.append(f"{vid}: expected {(outcome, step)}, reference verifier says {got}")
        exp = {"outcome": outcome, "step": step}
        if outcome == "accept":
            p = json.loads(inp["passport_text"]) if "passport_text" in inp else inp["passport"]
            c = jcs({k: v for k, v in p.items() if k != "signatures"})
            exp["canonical"] = c.decode()
            exp["content_hash_sha256"] = b64u(hashlib.sha256(c).digest())
        pv.append({"id": vid, "description": desc, "input": inp, "expected": exp})

    rv = []
    for vid, desc, state, req, resp, held, outcome in RESPONDER_VECTORS:
        got = respond(state, req)
        if got != resp:
            errs.append(f"{vid}: response mismatch\n  expected {resp}\n  reference {got}")
        c = caller(resp, held)
        if c != outcome:
            errs.append(f"{vid}: expected caller {outcome}, reference caller says {c}")
        v = {"id": vid, "description": desc, "state": state, "request": req,
             "expected_response": resp,
             "caller": {"holds_passport": held, "outcome": outcome}}
        if vid in BY_IDENTITY:
            v["applies_to"] = "responders that answer by identity (02 §3.1, optional)"
        rv.append(v)

    cv = []
    for vid, desc, received, previous, outcome, *extra in CALLER_VECTORS:
        inp = {"holds_passport": HELD_S3, "previously_applied": previous, "received": received}
        inp.update(extra[0] if extra else {})
        c = call(inp)
        if c != outcome:
            errs.append(f"{vid}: expected {outcome}, reference caller says {c}")
        cv.append({"id": vid, "description": desc, "input": inp,
                   "expected": {"outcome": outcome}})

    if errs:
        sys.exit("self-check FAILED:\n" + "\n".join(errs))

    note = ("Generated by generate.py. Signed with the vector key in jwks.json, for testing only. Outcomes: accept | reject (the Passport "
            "itself fails) | deny (revoked, or unable to tell) | refetch (fetch the current "
            "Passport and start again).")
    return {
        "jwks.json": JWKS,
        "passport-verification.json": {"note": note, "jwks": "jwks.json", "issuer": ISS,
                                       "vectors": pv},
        "revocation-check.json": {
            "note": note.replace("accept | reject (the Passport itself fails) | ", "proceed | "),
            "responder": rv, "caller": cv},
    }


def _masked(obj):
    """The files with every signature value and key coordinate blanked, including inside
    Passports carried as text (P08)."""
    if isinstance(obj, str):
        return re.sub(r'("signature":\s*")[^"]*"', r'\1"', obj)
    if isinstance(obj, dict):
        return {k: "" if k in ("signature", "x", "y") and isinstance(v, str) else _masked(v)
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [_masked(v) for v in obj]
    return obj


def main():
    check = "--check" in sys.argv
    if not check and not HAVE_KEY:
        sys.exit(f"no signing key at {KEY_PATH}: run keygen.py, or set AI_PASSPORT_VECTOR_KEY")
    files = build()
    bad = 0
    for name, obj in files.items():
        text = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
        path = os.path.join(HERE, name)
        if check:
            on_disk = open(path, encoding="utf-8").read() if os.path.exists(path) else None
            same = (on_disk == text if HAVE_KEY else
                    on_disk is not None and _masked(json.loads(on_disk)) == _masked(obj))
            if not same:
                print(f"DIFFERS: {name}")
                bad += 1
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
    if check and not HAVE_KEY and not bad:
        with open(os.path.join(HERE, "jwks.json"), encoding="utf-8") as f:
            jwks = json.load(f)
        with open(os.path.join(HERE, "passport-verification.json"), encoding="utf-8") as f:
            pvf = json.load(f)
            for v in pvf["vectors"]:
                exp = (v["expected"]["outcome"], v["expected"]["step"])
                if verify(v["input"], jwks, pvf["issuer"]) != exp:
                    print(f"SIGNATURE: {v['id']} does not give {exp} against jwks.json")
                    bad += 1
    n = len(PASSPORT_VECTORS) + len(RESPONDER_VECTORS) + len(CALLER_VECTORS)
    mode = "checked" if check else "wrote"
    how = "" if HAVE_KEY or not check else " (public key only)"
    if bad:
        print(f"{mode} {len(files)} files{how}: {bad} problem(s)")
    else:
        print(f"{mode} {len(files)} files, {n} vectors, self-check passed{how}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
