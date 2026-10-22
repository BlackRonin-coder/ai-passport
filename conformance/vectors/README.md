# AI Passport v1 test vectors

Test vectors for AI Passport v1 and AI Passport Revocation Check v1. They are informative:
where a vector and a spec disagree, the spec is right and the vector is a bug.

## Files

| File | What it holds |
|---|---|
| `jwks.json` | the public verification key for the vectors, `kid` `k1`, ES256 |
| `passport-verification.json` | 81 signed Passports, each with the time of checking, the presenter's identity if any, and the revocation answer the verifier receives; expected outcome and the step that decides it. `issuer` names the issuer the verifier is configured with, whose key set is `jwks` |
| `revocation-check.json` | `responder`: 33 cases of responder state plus request, with the exact response and the caller's outcome. `caller`: 41 cases of what a caller receives, with its outcome |
| `generate.py` | writes the three JSON files; `--check` verifies them without writing |
| `keygen.py` | makes the private signing key, for maintainers who re-sign the vectors |

**Only the public key is published.** The vectors are signed with a private key that the
maintainers hold and never commit; `jwks.json` carries its public half, which is all a
verifier needs. Anyone can run `generate.py --check`: without the private key it checks
everything except the signature bytes, then verifies every published signature against
`jwks.json`. Re-signing needs the private key, in `.keys/` (ignored by git) or at
`$AI_PASSPORT_VECTOR_KEY`; `keygen.py` makes a new one. Signatures use deterministic nonces
(RFC 6979), so the holder of the key reproduces them byte for byte. Never trust `k1`
outside a test.

## Conventions

- **Outcomes.** `accept` · `reject` (the Passport itself fails: signature, members,
  validity) · `deny` (revoked, or unable to tell) · `refetch` (fetch the current Passport
  and start again) · `proceed` (caller side of a revocation answer).
- **Step** names the check that decides a Passport vector: `signature`, `members`,
  `validity`, `bindings`, `parent`, `status` or `revocation`, in that order. `signature`
  covers all of 01 §4 and the trust anchor of §9.1: I-JSON, exactly one signature, the
  protected header, the key configured for the exact `issuer`, and the signature itself.
  `members` includes the `manager` that 01 §8.5 requires, a structural check made before
  revocation. `issuance_class` is optional: absent passes `members`, an unrecognized value
  fails it. `parent` and `status` deny
  without asking the responder: the Passport is treated as revoked (01 §3.4, §9.1).
- **Configured issuers.** Unless a vector carries `trust_anchors`, the verifier trusts one
  issuer, the file's `issuer`, with the key set `jwks.json`. `trust_anchors` maps each
  configured issuer to its `jwks` and, where configured, its `responders` (origins) and the
  `authorities` it may bind (01 §9.1; absent means every authority and tenant). An entry of
  `authorities` is an authority id, or `{id, tenants}` for a shared authority.
  `issuer_rank` ranks issuers that share an authority, highest first; it is a single list
  for the vectors, though ranking is per authority. `higher_ranked_answers` maps each
  higher-ranked issuer to the answer its responder gave to the presenter's pair; only 200
  with `subject` null and `reason` `unresolved_identity` lets the verifier fall through.
- **No policy step.** The verifier's answer is an outcome and a step, never a reading of
  business context. Orders of 01 §8.5 (`risk_classification`, `purpose.autonomy_level`,
  `purpose.human_involvement_level`), unknown values comparing as most restrictive, and an
  absent `issuance_class` read as unknown are described by P55 and P58 but not exercised.
- **Bindings** have the 01 §3.3 shape `{authority: {id, name}, identifier, type}`. A
  malformed entry (authority not an object, neither `id` nor `name`, `id` not an absolute
  URI, no `identifier`) fails `members`. The presenter matches a binding only by
  `authority.id` and `identifier`.
- **No retrieval.** The kit hands the verifier a Passport and models no `/passports`
  endpoint, so retrieval by binding (01 §10: a URI `authority` compared with `id` only, any
  other value with the `name` of bindings without `id`) and the issuer's uniqueness of
  (`id` or `name`, `identifier`) are not tested. P62 models a Passport that reached the
  verifier with only a name-only binding for the presenter, which never attributes.
- **`presenter`** was authenticated unless it carries `"authenticated": false`. Its
  `resolved_by` says how the identifier was resolved (01 §3.3): `authentication` (the
  default) or `configured_mapping` match; `presenter_value` never does. P74 and P75 check
  only that a presenter-chosen value is never trusted. `tenant` is the tenant or account
  the authentication established, for a shared authority.
- **Caller:** `holds_passport` may carry the held Passport's `issuer`, and `received` the
  `issuer` whose responder answered; an answer from another issuer's responder denies
  (02 §3.1). Those cases are skipped over HTTP.
  `refetched: true` marks a Passport that is already the verification's one refetch.
- **Signing input** is `protected` + "." + base64url(RFC 8785 form of the Passport without
  `signatures`). The protected header of P01 is
  `{"alg":"ES256","kid":"k1","typ":"ai-passport+jws"}`, and P01 is the 01 §1 example,
  signature included. Accepted vectors carry the canonical form and its SHA-256 (the entity
  tag) so you can compare bytes before comparing signatures.
- **`evaluated_at`** equals `state.now` in every responder vector. `headers_present` lists
  headers whose value is the responder's choice; only their presence is tested.
- **Responder state** is illustrative, not a storage schema: per subject, the Passports
  issued, `state_version`, active and lifted revocation rows, `min_required_revision`
  (1 when never raised), bindings in the 01 §3.3 shape (with `withdrawn`; an identity query
  matches `authority.id` only), and for a deployment its `parent`:
  the parent's subject identifier under the same issuer, where null or absent means none and
  anything else, such as `{}`, cannot be resolved. When a deployment's parent changes, the
  responder raises the deployment's own `state_version` so that the reported sum does not
  decrease (02 §3.2); vector state is always after that write. A `cause` member explains how a row came
  to exist. `answers_by_identity: false` models a responder that does not answer
  by identity.
- **Optional behaviour.** Responder vectors marked `applies_to` test answering by identity,
  which is optional for a responder (02 §3.1). A responder that does not offer it skips them
  and must pass R22 instead.
- **Caller inputs.** `received.headers` and `received.reused` model `Cache-Control`, `Age`
  and reuse; `asked` is the subject the caller asked about; `now` is the caller's clock;
  `previously_applied_expired` marks an applied answer past its directive.
- **`revoked_scopes` is always empty** in a conforming answer: this version defines no entry
  type. Vectors that carry an entry test that the caller revokes the whole subject.
- Members prefixed `x_example_` stand for anything a verifier does not recognize.

## Case index

**Passport verification.** P01 the §1 example, with `name`, `purpose`, `cost_center` and `composition` · P02 tampered business context · P03
unknown `kid` · P04 wrong `alg` · P05 `alg` none · P06 `b64:false` header · P07 signed over
a non-canonical serialization · P08 non-canonical transport, accepted · P09/P10 outside the
validity window · P11/P12 missing required member · P13 unknown top-level member, accepted
· P14 presenter in `bindings` · P15 presenter not in `bindings`, refetch · P16 still not in
`bindings` after refetch · P17 no supported status mechanism · P18 lapsed manager · P19
revocation check timed out · P20 `min_required_revision` above this revision · P21
`min_required_revision` equal · P22 any `revoked_scopes` entry · P23 caller subject mismatch · P24 unsupported `schema_version` · P25 unknown
`subject_type` · P26 unknown `issuance_class` · P27 unknown member inside a binding,
accepted · P28 bindings reordered and duplicated, accepted · P29 unknown status mechanism
beside a supported one, accepted · P30 two signatures · P31 `crit` · P32 `typ` `JWT` · P33
`typ` `JOSE`, accepted · P34 no `typ`, accepted · P35 `typ` as a mixed-case media type,
accepted · P36 duplicate member in `passport_text` · P37 integer outside ±(2^53−1) · P38
noncharacter in a string · P39 no `manager` · P40 a manager entry with neither reference nor
name, read as absent · P41 manager and `org_unit` named by name alone, authenticated
presenter, accepted · P42 `parent` `{}` · P43 `parent` null, accepted · P44 `parent.issuer`
differs · P45 a deployment naming its parent, accepted · P46 revocation URI on another
origin · P47 revocation URI over http · P48 revocation URI at a configured responder,
accepted · P49 `kid` found only in another configured issuer's key set · P50 issuer not
configured · P51 issuer differing by a trailing slash · P52 presenter not authenticated,
Passport retrieved by its pair · P53 floor still above after the one refetch · P54 presenter
not in `bindings` after the one refetch · P55 `issuance_class` absent, accepted · P56 `typ`
`jose`, accepted · P57 duplicate member in the protected header · P58 unrecognized
`purpose.autonomy_level`, accepted · P59 binding authority a bare string (the earlier
shape) · P60 authority with neither `id` nor `name` · P61 `authority.id` not an absolute URI
· P62 presenter matches only a name-only authority, deny · P63 matched by `authority.id`,
another `name`, accepted · P64 unknown member in `authority`, accepted · P65 unknown `type`,
accepted · P66 an ARN under a name-only authority beside the presenter's binding, accepted ·
P67 `issuance_class` null, accepted · P68 `typ` `application/jose`, accepted · P69 authority
not configured for this issuer · P70 two issuers accept the authority, unranked · P71 this
issuer ranked first, accepted · P72 another issuer ranked first, not asked · P73 the
higher-ranked issuer answered `unresolved_identity`, accepted · P74 identifier resolved by a configured mapping,
accepted · P75 identifier taken from a value the presenter chose, deny · P76 higher-ranked
issuer answered `binding_revoked` · P77 it timed out · P78 it answered 404 at retrieval ·
P79 three ranked issuers, only the first asked · P80 shared authority, tenant not accepted ·
P81 tenant accepted.

**Responder.** R01 clear · R02 `withdrawn_by_operator` · R03 lapsed manager · R04 governance
withdrawn · R05 unknown subject · R06/R07 `min_required_revision`, held revision below / at
it · R08 floor and revoked together · R09 revoke, then reissue · R10 restore · R11 resolved
by identity · R12 unresolved · R13 ambiguous · R14 `binding_revoked` · R15 other binding of
the same subject still resolves · R16 caller subject mismatch · R17 rebind · R18 resolved,
never issued · R19–R21 malformed requests · R22 responder without answering by identity,
asked by identity · R23 the same responder, asked by subject · R24 asked by subject and by
identity in one request · R25 current Passport past `valid_to`, `no_active_passport` · R26 deployment of a revoked
parent · R27 deployment's own floor · R28 parent that cannot be resolved · R29 parent's floor
not inherited · R30 deployment and parent both revoked, own reason · R31 `parent` null ·
R32 identity matching only `authority.name`, unresolved · R33 identity matching
`authority.id` beside a `name`, an unknown member and a `type`, resolved. R11–R18, R21, R32
and R33 apply only to a responder that answers by identity.

**Caller.** C01–C05 non-200 and timeout · C06 unparseable body · C07 `revoked` absent · C08
expired answer · C09 stale `state_version` discarded · C10 newer restore applied · C11/C12
unrecognized `reason` · C13 the floor sent the old way, as a `revoked_scopes` entry · C14
`revoked` not a boolean · C15 floor satisfied but an entry present · C16 an entry that is
not an object · C17 `min_required_revision` absent · C18 not an integer · C19 negative ·
C20 above the held revision, refetch · C21 duplicate `revoked` members · C22 `revoked` 0 ·
C23 asked by subject, answer for another · C24 asked by subject, no Passport held, proceed ·
C25 302 (over HTTP, a redirect to another origin) · C26 201 · C27 equal `state_version`,
revoked wins · C28 equal `state_version`, higher floor wins · C29 equal `state_version`, the
applied answer expired · C30 `evaluated_at` older than lifetime plus skew · C31 within it ·
C32 `Age` past `max-age` · C33 reused without `Cache-Control` · C34 reused with an
unparseable one · C35 reused within `max-age` · C36 no `Cache-Control` and `Age` above 0 ·
C37 two `max-age` directives, the first counts · C38 another issuer's responder answered for
the same subject string · C39 the held Passport's own issuer answered · C40 an irreversible
action reuses an answer within 5 seconds · C41 past them. `received.irreversible` marks an
irreversible action.

## Running

```
python3 generate.py --check
```

The script needs only the Python 3.8+ standard library. It carries a reference verifier,
responder and caller, and fails if any of them disagrees with a hand-written expected
result.

## Using the vectors in your tests

The JSON files are meant to drive integration tests for an implementation, alongside
`--check`. Write one data-driven test per file that loops over every case and asserts on its
`id`, so a failure names the case. Trust `jwks.json` (`k1`) in the test environment only.

**Verifier** (`passport-verification.json`, `vectors[]`). For each case, configure the
file's `issuer` with `jwks.json`, or `input.trust_anchors` where present. Verify
`input.passport` (or parse `input.passport_text`) at time `input.now`, with
`input.presenter` as the presenter when present. Wherever your code would call the revocation endpoint, return
`input.revocation` instead (`{"error": "timeout"}` means the call timed out). Assert that the
outcome equals `expected.outcome`, and if your verifier reports which check decided, that
the step equals `expected.step`.

**Issuer.** Build the P01 Passport from fixture records, without `signatures`. Assert that
its RFC 8785 form equals `expected.canonical`, byte for byte, and that its SHA-256 equals
`expected.content_hash_sha256`. Then sign it and check that the signature verifies against
the key. The signature only matches P01's value byte for byte if you sign with `k1` using
deterministic nonces. Your own Passports cover different records, so assert on their shape
and run them through the verifier test above.

**Revocation endpoint** (`revocation-check.json`, `responder[]`). For each case, load
`state` as fixtures: one subject record per key of `state.subjects`, with its Passports,
`state_version`, revocation rows, `min_required_revision` and bindings. Freeze the clock at
`state.now`. Send `request`, then assert:
- the status equals `expected_response.status`;
- the body equals `expected_response.body`;
- each header in `headers_present` is present.

Cases marked `applies_to` test answering by identity. A V1 build doesn't answer by identity,
so it skips them, sets `answers_by_identity: false` and must pass R22. Each case's `caller`
member is the outcome a caller holding `holds_passport` should reach from that answer, so it
can also be checked end to end.

**Caller** (`revocation-check.json`, `caller[]`). For each case, hand `input.received` (a
status, and a body when there is one) to the code that interprets revocation answers. The
caller holds `input.holds_passport` and has `input.previously_applied` as the last answer it
applied. Assert that the outcome (`proceed`, `deny` or `refetch`) equals `expected.outcome`.

When a vector fails, read its `description` and the spec section it names before changing
code. If the vector is wrong, fix `generate.py` and regenerate; never edit the JSON by hand.
