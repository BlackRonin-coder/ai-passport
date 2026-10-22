# Instructions for coding agents

This repository holds two specifications, AI Passport v1 and AI Passport Revocation Check v1,
and a conformance suite. If you are implementing either, these notes tell you where to start
and which rules implementations most often get wrong.

## Read first

1. §1 of [spec/passport-v1.md](spec/passport-v1.md) and §1 of
   [spec/revocation-check-v1.md](spec/revocation-check-v1.md). Together they are the whole
   happy path.
2. [conformance/examples/gateway_check.py](conformance/examples/gateway_check.py): the core of
   a gateway's check in about 50 lines. It covers a single issuer only, with no refetch,
   ranking or caching.
3. Read the rest of a spec only for the section a failing test case names.

## Commands

```
python3 conformance/run.py --selftest                       # the suite checks itself
python3 conformance/vectors/generate.py --check             # the vector files are consistent
python3 conformance/run.py --role verifier --adapter "CMD"  # or caller, responder
python3 conformance/run.py --role responder --url URL       # a running revocation endpoint
```

Standard library only. An adapter is a small command that reads one JSON request per line
on stdin and writes one JSON answer per line on stdout; see
[conformance/README.md](conformance/README.md). An implementation is done when every case
passes, not when the example's checks pass.

## Rules implementations get wrong

- **Fail closed.** A timeout, an error, any status other than 200, an invalid body or a
  body with duplicate member names means deny (Revocation Check v1 §5.2).
- **Only the literal `revoked: false` proceeds.** A missing `revoked`, `"false"` or `0` is
  revoked. In v1, any entry in `revoked_scopes` revokes the whole subject (Revocation Check
  v1 §6.2).
- **A Passport is not authentication.** Use it only for a party you authenticated, matching
  a binding's `authority.id` and `identifier` exactly to what your authentication resolved
  to (Passport §3.3).
- **Never match on `authority.name` or `type`,** and never take an identifier from a value
  the presenter chose, such as a header or a session name (Passport §3.3).
- **Trust anchors are configured, never read from a Passport:** the issuer, its JWKS URI and
  any responder. The revocation URI must have the issuer's origin or be a configured
  responder (Passport §9.1).
- **Signature:** canonicalize the Passport without `signatures` per RFC 8785 and verify the
  detached JWS. Require exactly one signature, reject `crit`, and reject duplicate member
  names at any level (Passport §4).
- **Absent means least favourable.** A missing business-context attribute never passes a
  check, and `unassessed` compares as `critical` (Passport §8.5).
- **Refetch at most once per verification** (Passport §10).
- **Don't reuse a revocation answer beyond its `Cache-Control`** (Revocation Check v1
  §5.3).

## Changing this repository

- If a test vector and a spec disagree, the spec is right; report the vector as a bug.
- Do not edit the vector JSON files by hand. Change `conformance/vectors/generate.py` and
  run `generate.py --check`; the maintainers re-sign the vectors.
- Never commit a private key. `conformance/vectors/jwks.json` holds the public test key
  only.
- Changes to normative text say which section they change and why, and update the vectors
  in the same change ([CONTRIBUTING.md](CONTRIBUTING.md)).
