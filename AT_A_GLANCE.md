# AI Passport at a glance

A one-page summary for reviewers. The specifications are normative; this page is not.

## The problem

Gateways and policy engines need to know two things about an AI agent before letting it act:
what it is and who answers for it, and whether it has been stopped. Today each one answers
that differently, and what each does when it cannot tell varies, so the same agent can be
allowed at one and denied at the next. See [FAQ.md](FAQ.md).

## The two specifications

| | AI Passport v1 | AI Passport Revocation Check v1 |
|---|---|---|
| What | a signed JSON credential about an AI asset | one HTTP check: may this asset still act? |
| Call | `GET /passports/{subject}` | `GET /revocation?subject={subject}` |
| Carries | identity bindings, business context (accountable owner and manager, vendor, risk classification, purpose), validity, revision | `revoked`, `revoked_scopes`, `min_required_revision`, `state_version`, `reason` |
| Rule that matters most | a verifier rejects anything it cannot verify | unable to ask, or any error, means deny |
| Conformance roles | issuer, verifier | responder, caller |

## Built on

RFC 8785 JSON canonicalization, ES256 detached JWS (RFC 7515), JWKS for keys, RFC 3339
times. No new cryptography.

## Deliberately out of scope

Policy languages and decisions, how an issuer derives business context, risk methodology,
authentication, and how revocations are written. Any policy engine can read a Passport;
the specs do not compete with one.

## What is settled and what may change

| Area | Expect |
|---|---|
| Signing, canonical form, key publication | stable |
| Revocation answer members and fail-closed behaviour | stable |
| Required Passport members | stable; new optional members may be added |
| Business context attributes (Passport §8) | likely to evolve; every value is an object, so members can be added |
| Where each value came from, and how far to rely on it | not in v1; planned for a later version |
| Personal data | a v1 Passport may carry people's names; one that does is served only to authenticated callers. The revocation check never carries any |
| Public Passports without personal data, selective disclosure | not in v1; planned for a later version |
| `composition` (Passport §8.6) | likely to evolve |
| Asking revocation by identity (Revocation Check §3.1) | optional; may evolve |
| Retrieval paths | illustrative; the Passport names the revocation URL to call |
| Scoped revocation entry types | none defined in v1; a later spec adds them |
| Constraint-based checks (what a subject may do) | not in v1: this release covers the Passport format and revocation of a subject as a whole |
| How often to fetch and check | suggested in Revocation Check §5.3: Passport `max-age=3600`, revocation `max-age=60`, one check per subject per directive |

Every change follows [VERSIONING.md](VERSIONING.md). Open questions and planned work are listed in
Passport §12 and Revocation Check §8.

## Licences

Specifications: Community Specification License 1.0, so anyone can implement them
royalty-free. Code and test data: Apache License 2.0. See [LICENSE.md](LICENSE.md).

## Reviewing in 15 minutes

1. Read section 1 of each spec, "The smallest thing that works".
2. Run the suite on itself: `python3 conformance/run.py --selftest`.
3. Read the open questions and planned work. That is where feedback helps most.
