# AI Passport v1

**Version:** 1.0-draft.1 (2026-10-22) · **Status:** Draft · **Conformance:** issuer, verifier ·
**Licence:** Community Specification License 1.0 ([LICENSE.md](LICENSE.md)); sample code Apache 2.0

An AI Passport is a signed credential about an AI asset — an agent, a harness, a tool
server or a model endpoint — that carries the **business context** the asset operates
under: who answers for it, where it sits in the organisation, who built it, how risky it is
assessed to be, and what it is for. Whether the asset may still act is answered separately,
by AI Passport Revocation Check v1.

> **Draft.** Details of this specification may change before implementations reach general
> availability. After that, changes are additive, and a breaking change arrives only in a new
> major version. Every change is recorded in the changelog and follows the versioning policy
> (`VERSIONING.md`). No change makes a conforming verifier allow something an earlier version
> denied.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, REQUIRED, RECOMMENDED and MAY are to be
interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear
in all capitals.

---

## 1. The smallest thing that works

Retrieve the signed Passport for a subject:

```
GET /passports/7a1f3c9e5b2d4e8f9a0b1c2d3e4f5a6b
```

```json
{
  "schema_version": "1",
  "subject": "7a1f3c9e5b2d4e8f9a0b1c2d3e4f5a6b",
  "subject_type": "agent",
  "issuer": "https://issuer.example.com",
  "issuance_class": "owned",
  "revision": 3,
  "name": "Supplier invoice reconciliation",
  "valid_from": "2026-10-01T00:00:00Z",
  "valid_to": "2026-12-30T00:00:00Z",
  "status": { "revocation_check": { "uri": "https://issuer.example.com/revocation?subject={subject}" } },
  "bindings": [
    { "authority": { "id": "https://login.example.net/tenant-42", "name": "Example IdP" },
      "identifier": "4f1c9a2e-77b0", "type": "agent_id" },
    { "authority": { "id": "https://issuer.example.com" }, "identifier": "agent-record-19" }
  ],
  "business_context": {
    "accountable": [ { "role": "owner",   "principal": "urn:example:principal:5c2e" },
                     { "role": "manager", "principal": "urn:example:principal:7d41" } ],
    "org_unit":    { "id": "urn:example:org:finance-ops" },
    "vendor":      { "entity": "urn:example:org:vendor-88" },
    "risk_classification": { "value": "high" },
    "purpose":     { "additional_details": "reconcile supplier invoices",
                     "usage_area": ["finance_accounting"],
                     "autonomy_level": "semi_automated",
                     "human_involvement_level": "ai_initiated_with_approval" },
    "cost_center": { "id": "urn:example:cc:4410" },
    "composition": {
      "entries": [
        { "id": "urn:example:component:m-2", "kind": "model", "name": "example-model-2026-05",
          "vendor": { "entity": "urn:example:org:vendor-88" },
          "risk_classification": { "value": "medium" } },
        { "id": "urn:example:component:t-7", "kind": "tool", "name": "supplier ledger lookup" } ],
      "complete": [ "model" ] }
  },
  "signatures": [ { "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiYWktcGFzc3BvcnQrandzIn0",
                    "signature": "Nsb6UZlYe78n4Y_U29siQnP9IRfqEQ3msVBWndVzfQX9eqhPRpeJflxxUQC09SOj5T2vE2QDMO9YlYIIynnd6w" } ]
}
```

To verify:

```
1. reject unless it is I-JSON with exactly one signature, and the JWS verifies
   over its RFC 8785 form with the key your configured JWKS for this exact
   issuer names (§4, §9.1)
2. reject if a REQUIRED member is missing, a binding is malformed, or
   accountable has no manager (§3, §3.3, §8.5)
3. reject if now is outside valid_from..valid_to (§6)
4. use it for the presenter only if your authentication of the presenter
   resolved to one of its bindings, exactly (§3.3)
5. check revocation at status.revocation_check.uri (§7, §9.1):
   anything but revoked: false with an empty revoked_scopes, or no answer -> deny
6. only then read business_context (§8)
```

Three cases add a step:

- the presenter's identity is not in `bindings`, or the revocation answer's
  `min_required_revision` is above this Passport's `revision`: fetch the current Passport
  once and start again; if it still fails, deny (§3.3, §10, Revocation Check v1 §5.6);
- the presenter was not authenticated: do not use this Passport for it (§3.3);
- you trust more than one issuer: §9.2 decides which one may vouch for the presenter.

A verified signature proves the issuer said this. It does not prove the issuer still means
it. The revocation check is not optional.

## 2. Scope

This document specifies the structure of an AI Passport, how it is signed, revised,
retrieved and verified, and the business context it carries. It specifies no policy: a
Passport gives every policy engine the same attributes, with the same names and vocabulary,
for every subject, and leaves the rule to the policy author.

This release specifies the Passport format and revocation of a subject as a whole.
Constraint-based checks — what a subject may do, and revoking part of it — are planned for
a later release. Until then a Passport describes a subject; it never says what the subject
may do.

The issuer is a role, not a component. An issuer MAY be built from separate parts, for
example one that assembles the payload and a signing service that signs what it is given.
The obligations in this document fall on the issuer as a whole. They require two things:
- whatever is signed contains every core member (§3) and the business context (§8);
- every party that can have content signed under the issuer's key is part of the issuer.

### 2.1 Terminology

- **Issuer**: the authority that signs Passports and holds the records behind them (§2).
- **Verifier**: a party that verifies a Passport and acts on it. A verifier checking
  revocation acts as a caller.
- **Caller**: a party that asks a responder for a revocation answer (Revocation Check v1).
- **Responder**: the service that answers revocation checks for an issuer's subjects.
- **Subject**: the AI asset a Passport is about, identified by (`issuer`, `subject`) (§3.2).
- **Binding**: an entry of `bindings`: an `authority` and an `identifier` by which another
  system knows the subject (§3.3).
- **Deployment**: a durable, configured placement of an asset with its own Passport (§3.4).
- **Organisation**: the party under whose authority the subject is used (§8.1).
- **Directive**: the limit on reuse that comes with a response. For a Passport, the
  `Cache-Control` of the retrieval response (§10); for a revocation answer, as Revocation
  Check v1 §5.3 defines.

## 3. Members

A Passport is a JSON object (RFC 8259). These members are REQUIRED; a verifier MUST reject a Passport
missing any of them.

| Member | Type | Meaning |
|---|---|---|
| `schema_version` | string | `"1"` for this version |
| `subject` | string | the issuer's identifier for the AI asset. See §3.2 |
| `subject_type` | string | `agent`, `harness`, `tool_server` or `model_endpoint`. See §3.1 |
| `issuer` | string: an https URL; compared exactly (§9.1) | the authority that issued the Passport |
| `revision` | integer | monotonic within the subject's lineage, starting at 1 |
| `valid_from`, `valid_to` | RFC 3339 | the validity window |
| `status` | object | where to check revocation. See §7 |
| `bindings` | array | the identities by which other systems know the subject. See §3.3 |
| `business_context` | object | see §8 |

Five members are OPTIONAL: `issuance_class` (below), `parent` (§3.4), `name` and
`description` (§3.5), and `issued_at`, the RFC 3339 time the issuer signed the Passport.
`issued_at` is informative: a verifier MUST NOT use it in place of `valid_from`.

`issuance_class` is a string saying where the subject runs: `owned` — under the
organisation's control, in its cloud or on its premises; `proxy` — another party hosts it
for the organisation, such as the vendor or a hosting provider (§8.1). Absent, or `null`,
means unknown: a check that reads it, whether it would allow or deny, MUST NOT pass.
Removing or changing it is a major revision (§5.1).

**Extensibility.** Later versions add members and values; a verifier written against this
version keeps parsing them, and nothing it does not understand widens what the subject may do:

- `schema_version` stays `"1"` for every addition that keeps this version's rules. A
  verifier MUST reject a `schema_version` it does not support.
- A verifier MUST ignore, and MUST NOT reject because of, a member it does not recognize at
  the top level or inside `status`, `parent`, an entry of `bindings` or its `authority`. Inside
  `business_context`, §8.5 applies.
- A verifier MUST reject an unrecognized value of `subject_type` or `issuance_class`.
- A verifier MUST NOT assume the number, order or distinctness of entries in any array
  (`signatures` aside, §4), and MUST evaluate every entry.
- A verifier MUST canonicalize and verify every member received, recognized or not (§4).

An ignored member cannot restrict a verifier. For a restriction to bind every verifier, it
has to sit where the unrecognized denies: `business_context`, or Revocation Check v1 §6.2.

### 3.1 `subject_type`

Different kinds of AI asset have different enforcement points, and the same restriction
means different things on each: a restriction on a tool concerns *calling* it when the
subject is an agent and *serving* it when the subject is a tool server. A verifier MUST NOT
infer the subject type from the identifier and MUST NOT default it. An issuer MUST state in
its conformance statement (§11) which subject types it issues.

### 3.2 `subject`

The subject identifier is assigned by the issuer and is unique within that issuer. It is not
globally unique, so the canonical subject is the pair (`issuer`, `subject`): a verifier MUST
treat it as such, including when checking revocation. Verifiers MUST treat the identifier as
opaque and MUST NOT parse it for meaning.

The subject identifies the asset, not a record of it. An issuer MUST keep the same subject
when the asset is changed, re-approved or recorded anew, and MUST NOT issue a new subject for
an asset that already has one. Otherwise any change would shed the subject's revocations.

A caller need not know the subject identifier in advance. It retrieves the Passport by the
identity it authenticated (§3.3, §10) and learns the subject from it.

### 3.3 `bindings`

An AI asset is known to other systems by their own identifiers: an identity provider's
client or agent identifier, a workload certificate, a cloud resource name, a record in the
platform that hosts it. `bindings` lists them. Each entry is an object:

| Member | Required | Meaning |
|---|---|---|
| `authority` | yes | `{id, name}` — the system that issued the identifier; `id` or `name`, at least one. It is an object so that later versions can add members |
| `identifier` | yes | a non-empty string: the identifier within that authority |
| `type` | no | informative: the kind of identifier, such as `agent_id`. This version defines no values. A verifier MUST NOT match a binding because of `type`; it MAY decline to match one whose `type` names a kind of identifier different from the one it authenticated |

A verifier MUST reject a Passport with an entry of `bindings` that does not have this
shape. A member of `authority`, or `identifier`, that is present but not a non-empty string
makes the entry malformed.

`authority.id` MUST be an absolute URI (RFC 3986) naming the system that issued the
identifier, as that system names itself: an https URL, a token's `iss`, or a trust domain
such as `spiffe://example.org`. Under a token issuer, `identifier` is the token's `sub`
claim; under a SPIFFE trust domain, it is the full SPIFFE ID.

An identifier with no such issuing system, such as a cloud resource name (an AWS ARN, a GCP
resource name, an OCI OCID), is listed with `authority.name` only, such as
`{"name": "Amazon Web Services"}`. It serves retrieval and lookup only (§12 q13).

`authority.name` labels the issuing system, such as "Example IdP" or "Amazon Web Services".
On its own it does not make a binding unique beyond the issuer's namespace.

`authority.id` and `identifier` together have the shape of the `iss_sub` subject
identifier of RFC 9493, and an identifier is meaningful only together with its authority.

- An issuer MUST list every binding it holds for the subject at the time of signing, and
  only bindings it established from a system of record or an accountable party of the
  organisation — never one the subject asserted about itself.
- A binding read from the organisation's system of record counts as established from it,
  even where a discovery connector populated that record. A sighting by an enforcement point or
  a monitoring tool never establishes a binding: a binding widens what a verifier relies on,
  and a sighting may only tighten.
- An issuer MUST NOT list a binding that it also holds for another subject, comparing
  `authority.id` where present, otherwise `authority.name`, together with `identifier`. The
  issuer is the namespace (§8.3): it ensures that pair is unique among the bindings it
  holds. A pair that identifies two subjects identifies neither.
- A verifier MUST match an authenticated party only to a binding whose `authority.id`
  equals, exactly, an authority the verifier authenticates against and its configuration
  accepts from that `issuer` (§9.2), and whose `identifier` equals, exactly, the identifier
  resolved for that party as below: the authenticated pair. A binding whose `authority` has no `id` MUST NOT be used to
  attribute a Passport; it serves retrieval and lookup only (§10).
- An identifier is resolved by the authentication itself, or by a mapping the verifier is
  configured to trust, such as the hosting platform's own record of which resource holds an
  authenticated credential. Such a mapping MUST be keyed only on values the authentication
  verified; MUST be maintained by the authority that issued the authenticated credential or
  by the organisation's system of record, never populated from what the presenter or the
  subject asserts; MUST yield, at the time of the decision, at most one identifier for that
  value, the verifier denying where it yields several; and MUST yield a pair whose
  `authority.id` the verifier's configuration accepts from that `issuer` (§9.2). An
  identifier is never resolved from a value the presenter chose, such as a session name or
  a header, nor from the syntax of another value.
- A verifier that has authenticated the AI asset in front of it MUST NOT rely on a Passport
  whose `bindings` do not include the authenticated pair. It MAY fetch the current Passport
  by that pair, from the highest-ranked issuer its configuration accepts that authority
  from (§9.2), and check again, within the refetch limit of §10; if the pair still does not
  appear, it MUST deny.
- **A Passport is not an authentication credential.** A verifier MUST NOT use a Passport
  for the party in front of it unless it authenticated that party and the authentication
  resolved to a binding in `bindings`, as above. Fetching the Passport by that binding
  (§10) is a lookup and does not satisfy this rule. Holding or presenting a Passport proves nothing about the
  presenter.
- Withdrawing a binding, or removing its `authority.id`, is a major revision (§5.1): the
  predecessor names an identity that no longer identifies the subject.

### 3.4 `parent`

An asset may run as several deployments, each a durable, configured placement with its own
Passport. A deployment's Passport names the asset it deploys as `parent`: `{issuer, subject}`.

- `parent.issuer` MUST equal `issuer`. A verifier MUST treat as revoked a Passport whose
  `parent.issuer` differs from `issuer`. The relation is data the issuer holds; a verifier
  MUST NOT infer it from either identifier (§3.2).
- Revoking the parent revokes every deployment of it. The responder resolves this
  (Revocation Check v1 §3.2); a verifier checks the deployment's revocation only.
- A running instance is not a subject and has no Passport.
- A Passport of a subject with no parent MUST omit `parent` or set it to `null`. A `parent`
  without both `issuer` and `subject`, such as `{}`, names a parent that cannot be
  resolved: an issuer MUST NOT emit one, and a verifier MUST treat such a Passport as
  revoked (Revocation Check v1 §3.2).

An issuer need not issue deployment Passports. How business context divides between an
asset and its deployments is not specified in this version.

### 3.5 `name` and `description`

`name` and `description` are strings that tell a person what the subject is, as the
organisation's system of record names and describes it.

- A verifier MAY use `name` in a decision; `description` is informative only. Except as
  §8.3 provides, a name is not an identifier: the organisation is responsible for keeping the names it relies on
  unique, and a name may change at any revision. A name used as a reference in business
  context is governed by §8.3. A rule that keys on a name SHOULD deny
  when the name is absent or different, so that a rename denies more, never less.
- An issuer MUST take them from the organisation's records, never from what the subject
  asserts about itself. Either can carry personal data, which §8.3 and §10 govern.
- Changing either alone is a minor revision.

## 4. Canonical form and signature

- The canonical form is the Passport with `signatures` removed, serialized per RFC 8785.
  It is what is hashed and signed. An issuer MUST NOT treat a non-canonical serialization as
  authoritative.
- The content hash is SHA-256 over the canonical form.
- The signature is a JWS with detached content (RFC 7515, Appendix F) over the canonical
  form. Each entry of `signatures` carries the JWS `protected` header and `signature`, both
  base64url; the signing input is `protected` + "." + base64url(canonical form). The
  protected header carries `alg` and `kid`, and does not carry `b64`. It SHOULD carry `typ`
  with the value `ai-passport+jws`. A verifier MUST accept a `typ` that is absent or that
  equals `ai-passport+jws`, `application/ai-passport+jws`, `JOSE` or `application/jose`, each compared
  case-insensitively (RFC 7515 §4.1.9), and MUST reject any other value. `ES256` (RFC 7518) is mandatory to
  implement. A verifier MUST NOT accept an algorithm it did not expect for the key, and MUST
  NOT accept one other than the `alg` of the key (§9).
- A verifier MUST reject a protected header that contains `crit`. This version defines no
  critical extension.
- `signatures` is an array; an issuer conforming to this version emits exactly one entry. A
  verifier MUST reject a Passport whose `signatures` does not contain exactly one entry.
- The signed form and the decoded protected header MUST be I-JSON (RFC 7493). A verifier
  MUST reject a Passport, or a protected header, with duplicate member names at any level,
  with surrogates or noncharacters (RFC 7493 §2.1), or with an integer outside the range
  -(2^53-1) to 2^53-1, the integers IEEE 754 double precision represents exactly.
- The object a verifier passes to policy MUST be the one it verified: parsed from the same
  bytes it canonicalized, never re-read or re-parsed from another copy.

## 5. Revision

A successor Passport for the same subject MUST set `revision` to the predecessor's value
plus one, and MUST be persisted before the predecessor is marked superseded, so that the
subject is never without a current Passport.

An issuer MUST NOT return a signed superseded revision. An issuer that signs at retrieval
time MUST check that the revision is current before signing: a signature attests the bytes,
not their currency, and a superseded revision signed afresh is indistinguishable from the
current one.

### 5.1 Minor and major revisions

Superseded is not revoked. When the issuer issues a successor, it classifies it:

- **Major** — the successor is more restrictive than its predecessor on any attribute
  ordered in §8.5, it changes `accountable`, `org_unit` or `vendor`
  other than in a `name` member (a name standing alone as the reference is the
  reference: §8.3), it changes a member of `purpose` other than `additional_details`, it adds an entry to `composition` or changes one
  other than by removing it (§8.6), it removes an entry from `bindings` or the
  `authority.id` of one, it removes or changes `issuance_class` (§3), or it adds, removes or
  changes `parent` (§3.4). The predecessor
  now overstates what the subject may do. The issuer MUST withdraw every earlier revision
  at the same time, by
  raising the subject's minimum revision per AI Passport Revocation Check v1 §5.6. The
  subject may continue to act under the successor.
- **Minor** — any other change. The predecessor remains usable until its `valid_to`; a
  verifier that holds it SHOULD refresh it within the directive that came with it (§2.1,
  §10).

The classification is computed by the issuer from the two revisions, never asserted by
hand. An issuer MAY treat any revision as major.

## 6. Validity

The issuer MUST set `valid_from` and `valid_to`; a verifier MUST reject a Passport outside
its window, allowing at most the clock skew of §14. Validity is a property of the artifact, checked offline; revocation is a property
of the holder, known only by asking. A Passport may be valid and revoked at the same time.

## 7. `status` — where to check revocation

```json
"status": { "revocation_check": { "uri": "https://issuer.example.com/revocation?subject={subject}" } }
```

`status` holds one member per status mechanism. This version defines `revocation_check`,
whose `uri` is either a template in which `{subject}` is replaced by the percent-encoded
subject, every reserved character included, as in RFC 6570 simple expansion, or the URI
already filled in for this Passport's subject. A filled-in `uri` MUST use the `subject` form
(Revocation Check v1 §4). §9.1 governs which `uri` a verifier calls.
A verifier MUST check revocation per AI Passport Revocation Check v1 before acting on a
Passport, and MUST treat a Passport whose `status` names no mechanism it supports as revoked.
Caching a Passport never defers the revocation check: a verifier MUST NOT reuse a revocation
answer beyond the directive that came with it.

## 8. Business context

`business_context` is REQUIRED, and it is what distinguishes an AI Passport from an identity
credential. It records what is known about the subject before it takes its first action.

### 8.1 Attributes

| Member | Value | Required |
|---|---|---|
| `accountable` | array of `{role, principal, name}`; `role` is `owner` or `manager`; `principal` or `name`, at least one (§8.3) | yes — at least one `manager` |
| `org_unit` | `{id, name}` — the organisational unit the subject serves; `id` or `name`, at least one (§8.3) | no |
| `vendor` | `{entity, name}` — who built the subject; `entity` or `name`, at least one (§8.3) | no |
| `risk_classification` | `{value}` — `low`, `medium`, `high`, `critical` or `unassessed` | no |
| `purpose` | `{intended_outcome, usage_area, output_type, people_affected, data_used, interaction_type, human_involvement_level, autonomy_level, additional_details}` — what the subject is for and how it is used; every member OPTIONAL. See §8.7 | no |
| `cost_center` | `{id, name}` — the cost center the subject is charged to; `id` or `name`, at least one (§8.3) | no |
| `composition` | `{entries, complete}` — what the subject is built from: models, tools, prompts and sub-systems. See §8.6 | no |

- A `manager` maintains the subject and answers for it day to day. An `owner` answers for
  it financially and for the decision to keep it running. Both are people or teams inside
  the organisation that uses the subject, named by references (§8.3). An issuer
  MUST list every owner and manager the organisation's records name for the subject.
- Each of these objects names its party by a reference (`principal`, `id` or `entity`),
  by a `name`, or by both. Each member is OPTIONAL, but at least one MUST be present (§8.3).
  A verifier MAY use `name` in a decision, under the rules of §3.5.
- Three parties are named separately, because any two may differ: who answers for the
  subject (`accountable`), who built it (`vendor`), and who hosts it (`issuance_class`, which may be unstated). The organisation is the one under whose authority the subject is
  used, never defined by who builds or hosts it.
- Only `accountable` is required, because it is the only attribute without which nobody
  answers for the subject. An organisation MAY require more of the
  issuer it uses; a verifier reads any attribute that is absent as its least favourable
  value (§8.5), so an attribute left out denies wherever a policy reads it and never widens
  what the subject may do.

### 8.2 Values are objects

Every attribute of §8.1 is a JSON object, or for `accountable` an array of objects, never a
bare string or number. The members of an attribute may be strings, as those of `purpose` are
(§8.7). Later versions can then add members beside a value without changing
its type. This version defines none, and under §8.5 a member a verifier does not recognize
never satisfies a check.

### 8.3 Issuer obligations

An issuer MUST NOT issue a Passport:

- without at least one `manager` taken from the organisation's records or named by an
  accountable party inside the organisation. A vendor cannot name the accountable party
  inside the organisation, and a subject cannot name its own;
- whose `risk_classification`, or the `risk_classification` of an entry of `composition`, where carried, was not
  assessed by the organisation. Risk is assessed by the organisation, never asserted by the
  party assessed or inferred from what it was seen doing;
- for a subject the organisation has assessed as presenting unacceptable risk. That is not a
  tier; it is grounds to refuse.

*Informative.* A classification still to be determined corresponds to `unassessed`.

Every object that names a party or a component (an `accountable` entry, `org_unit`,
`cost_center`, `vendor`, a `composition` entry) MUST carry a reference (`principal`, `id` or
`entity`), a `name`, or both, and at least one of them. A reference or `name` counts as
present only if it is a non-empty string. A reference SHOULD be an opaque
identifier, resolvable only inside the organisation or by verifiers it authorizes. Where
both are present, the reference identifies the party and `name` labels it.

Where only `name` is present, the name is the reference. A Passport served without
authentication MUST carry a reference in every such object; one served only to
authenticated callers (§10) MAY carry the name alone. Where it does:

- the issuer MUST ensure, at the time of signing, that the name identifies exactly one
  record of its kind among the organisation's records behind this `issuer`: one principal
  (person or team) among its principals, one department among its departments, one component of that `kind`
  among its components. A name that is not unique MUST NOT stand alone; the issuer adds a
  reference for it instead;
- the issuer is the namespace: a verifier MUST compare a name standing alone together with
  the `issuer`, the attribute it appears in and, for a `composition` entry, its `kind`. The
  `vendor` of a `composition` entry shares the namespace of `vendor`. The same name from
  another issuer, or in another attribute, is a different reference;
- a change of the name is a change of the reference, classified as §5.1 classifies a change
  of that reference;
- the issuer MUST still resolve the name to the party's record wherever this specification
  relies on that record, such as §8.4.

The issuer MUST NOT carry a vendor's raw risk score. A Passport MAY carry personal data, such as a person's name in a `name` member (§8.1); one
that does, or that carries other data the organisation treats as sensitive, is served only
as §10 requires.

### 8.4 Revocation follows context

An issuer SHOULD revoke the subject, per Revocation Check v1, when:

1. every `manager` named in the current Passport has become inactive in the organisation's
   system of record and none has been designated in replacement — reason
   `accountability_lapsed`; or
2. the organisation's governance record withdraws approval for the subject, retires it, or
   assesses it as presenting unacceptable risk — reason `governance_withdrawn`.

Revocation attaches to the subject, not to a revision, so issuing a new revision never lifts
it. For these two reasons, the issuer MAY lift the revocation once the condition no longer
holds and a revision satisfying §8.3 has been issued. Any other revocation record is lifted
only by an authority permitted to write revocations. A lapse (Revocation Check v1 §5.7) is
not a revocation record; it ends when a successor is issued.

### 8.5 Reading business context

For comparisons, verifiers use these orders, least to most restrictive:

| Attribute | Order |
|---|---|
| `risk_classification`, `risk_classification` of a `composition` entry | `low` < `medium` < `high` < `critical` = `unassessed` |
| `purpose.autonomy_level` | `assistive` < `semi_automated` < `condition_based` < `event_triggered` < `fully_automated` |
| `purpose.human_involvement_level` | `full_user_control` < `user_guided` < `shared_control` < `ai_initiated_with_approval` < `fully_automated` |

- `unassessed` compares equal to `critical`. Absence of an assessment is not an assessment
  of low risk.
- A verifier MUST read an absent optional attribute as its least favourable value.
- An unrecognized member or value of `business_context` MUST NOT satisfy a check; an
  unrecognized value of an ordered attribute compares as its most restrictive value.
- A verifier MUST reject a Passport whose `accountable` contains no `manager` entry. This
  is a structural check, like a missing REQUIRED member (§3), made before revocation is
  checked. A verifier MUST read an object carrying neither a reference nor a `name` (§8.3)
  as absent.

### 8.6 `composition`

`composition` describes what the subject is built from, as the organisation's system of record
links it: the models it runs on, the tools it uses, the prompts it carries and the
sub-systems it contains. It gives a policy the same inputs about those parts for every
subject, such as "no agent on a model assessed `high`". It is an object so that later
versions can add members beside `entries`.

| Member | Required | Meaning |
|---|---|---|
| `entries` | yes | array of components, below |
| `complete` | no | the `kind` values for which `entries` lists every component the issuer's records link. Absent means none |

Each entry is an object with these members:

| Member | Required | Meaning |
|---|---|---|
| `id` | no; `id` or `name`, at least one (§8.3) | the issuer's identifier for the component, a reference; unique within the Passport, and the same in every revision that lists the component |
| `kind` | yes | `model`, `tool`, `prompt` or `sub_system` |
| `name` | no; `id` or `name`, at least one (§8.3) | as in §3.5; the component's reference where `id` is absent |
| `vendor` | no | `{entity, name}` — who built the component |
| `risk_classification` | no | `{value}` — the organisation's assessment of the component, in the `risk_classification` vocabulary |

- **It describes; it never grants or withdraws.** Listing a component never permits calling
  or using it, and leaving one out never withdraws it. What the subject may not do is
  withdrawn through Revocation Check v1; what it may do is decided by policy.
- **Enforcement never depends on it.** No revocation answer, and no check of one, requires
  resolving a `composition` entry. A reference to an entry from elsewhere, such as a scope
  entry, is informative only.
- **Read for the whole set only where complete.** A check about every component of a kind,
  such as "no model assessed `high`", MUST NOT pass unless that kind is in `complete`.
  An entry without `risk_classification` reads as `unassessed`.
- An issuer SHOULD carry inline what policy reads at the point of decision, and SHOULD keep
  `id` stable so that a fuller description published later can refer to the same
  components.

### 8.7 `purpose`

`purpose` says what the subject is for and how it is used. It is an object (§8.2); every
member is OPTIONAL, and each is a string or an array of strings, as below. Its members form
a use-and-purpose vocabulary maintained by this specification, changed only under its
versioning policy (`VERSIONING.md`). Later versions add values; until then, an unrecognized
value never satisfies a check (§8.5).

| Member | Form | Values |
|---|---|---|
| `intended_outcome` | string | `efficiency_boost` saves time or effort; `quality_enhancement` improves accuracy or quality; `decision_guidance` informs a person's decision; `task_automation` performs tasks in place of a person; `customer_experience` improves the customer's experience; `insight_generation` produces insights from data |
| `usage_area` | array | `internal_operations`; `customer_services`; `sales_marketing`; `finance_accounting`; `it_security`; `supply_chain`; `hr_workforce`; `external_partner_ecosystem` partners and the wider ecosystem |
| `output_type` | array | `simple_alerts` alerts or flags; `insights_summaries` insights or summaries; `rankings_scores` rankings or scores; `recommendations` recommendations to a person; `generated_content` generated text, images or code; `automated_decisions` decisions taken without a person; `system_actions` actions on other systems |
| `people_affected` | array | `internal_team` the organisation's own staff; `specific_customer_groups` particular groups of customers; `general_customer_base` customers in general; `external_partners` partners; `public` the general public |
| `data_used` | array | `public_info` publicly available information; `business_operational` operational business data; `customer_interaction` records of interactions with customers; `behavioral_usage` behavioural or usage data; `profile_account` profile or account data; `sensitive_business` sensitive business data |
| `interaction_type` | string | `no_direct_interaction` no person interacts with it; `background_support` supports people in the background; `notifications_prompts` sends notifications or prompts; `user_facing_recommendations` shows recommendations to a user; `chat` converses with people; `interactive_experience` a richer interactive experience |
| `human_involvement_level` | string, ordered (§8.5) | `full_user_control` a person makes every decision; `user_guided` a person directs, the AI assists; `shared_control` the person and the AI share decisions; `ai_initiated_with_approval` the AI initiates, a person approves; `fully_automated` no person is involved |
| `autonomy_level` | string, ordered (§8.5) | `assistive` the AI suggests; `semi_automated` acts with confirmation; `condition_based` acts automatically when set conditions hold; `event_triggered` acts automatically on events; `fully_automated` fully automated execution |
| `additional_details` | string | free text: what the subject is for |

- A classification of "not applicable" is expressed by omitting the member, never by a
  value.
- `additional_details` is informative only, as `description` is (§3.5).
- An issuer MAY use an absolute URI (RFC 3986) as a value of an unordered member, for a value
  this version does not define.
- The ordered members compare per §8.5. An ordered member whose value is not one of its
  defined strings is unrecognized, and an absent one reads as its most restrictive value.
- An empty array reads as the member being absent. A check that passes because a value is
  not in an array MUST NOT pass when the array is absent. How a check reads an absent
  unordered member otherwise is §12 q12. An unrecognized value never satisfies a check
  (§8.5).

## 9. Key publication

An issuer MUST publish its verification keys as a JWKS (RFC 7517) at a stable URI reachable
without authentication. Every key MUST carry a `kid` and an `alg`, and the `kid` in a
Passport's protected header MUST identify a key in that set. The key set SHOULD be
cacheable. An issuer MUST use its Passport signing keys to sign nothing but Passports, so
that no other object it signs can be presented as one. An issuer MUST publish a key before signing with it, and MUST retain a retired key
in the set while any unexpired Passport bears its `kid`.

### 9.1 Trust anchors

- A verifier MUST be configured, out of band, with each issuer it trusts and that issuer's
  JWKS URI. It MUST NOT discover either from a Passport.
- `issuer` is compared exactly, as a string. The verifying key MUST come from the JWKS
  configured for the Passport's exact `issuer` value. A `kid` found in another issuer's JWKS
  never verifies it.
- A verifier MUST treat a Passport as revoked unless `status.revocation_check.uri` is https
  and has the same origin (RFC 6454) as `issuer`, or names a responder the verifier has
  configured for that issuer, matched by scheme, host, port and path prefix. A caller MUST
  NOT follow a redirect to another origin.
- A verifier MUST retrieve a Passport only from the origin of its `issuer` or from an
  endpoint it has configured for that issuer, and MUST NOT follow a cross-origin redirect
  from the JWKS URI or the retrieval endpoint.

Otherwise a party able to produce a verifying Passport would also choose who answers its
revocation check, and a Passport could point a gateway at internal hosts.

### 9.2 Which issuer may bind which identity

The first two rules apply to every verifier; the rest apply only where it trusts several
issuers.

- A verifier MUST be configured, for each issuer it trusts, with the authorities whose
  identifiers that issuer may bind and, where an authority is shared by several
  organisations, the tenants or accounts within it. It MUST decide from that configuration,
  never from a Passport or how it was obtained, which issuer it accepts a binding from, and
  MUST NOT attribute a Passport through a binding its configuration does not accept from
  that Passport's `issuer` (§3.3). A configuration MAY accept every authority, and every
  tenant or account within it, from an issuer.
- A verifier MUST treat an authority as shared unless it knows that only one
  organisation's identifiers are issued under it. For a shared authority it MUST establish
  the tenant or account from its authentication, such as a verified tenant claim, never from
  the syntax of `identifier`; where it cannot, it MUST NOT attribute through that
  authority.
- Where its configuration accepts the authenticated authority (and, for a shared
  authority, tenant or account) from more than one issuer, the configuration MUST rank
  those issuers for it; where it does not, the verifier MUST NOT attribute through any of
  them. Ranking is per authority, and per tenant or account where shared.
- A verifier MAY attribute through a lower-ranked issuer's Passport only after it has asked
  each higher-ranked issuer's responder, once, by the authenticated pair (Revocation Check
  v1 §3.1), and each answered 200 with `subject` null and `reason` `unresolved_identity`.
  Any other outcome means that issuer may hold the pair, and the verifier MUST NOT attribute
  through a lower-ranked issuer: a retrieval 404 (§10), `binding_revoked`,
  `ambiguous_identity`, an answer for a subject, an absent `reason`, 400, any other status,
  a redirect or a timeout. A verifier MUST NOT reuse such an answer beyond its directive
  (Revocation Check v1 §5.3).

Otherwise any trusted issuer could claim an identity another trusted issuer's subject
authenticates as.

## 10. Retrieval

The signed form is the Passport with `signatures`. A verifier MUST NOT act on any other
form. An issuer MUST support retrieving the current signed Passport by any binding, and
SHOULD support retrieving it by subject:

```
GET /passports/{subject}
GET /passports?authority={authority}&identifier={identifier}
```

A verifier MUST percent-encode every value it places in these paths and query parameters
(`subject`, `authority`, `identifier`) per RFC 3986, every reserved character included, as
in RFC 6570 simple expansion. The issuer compares an `authority` parameter that is an absolute URI with
`authority.id` only, and any other value with `authority.name` of bindings that carry no
`id` only. A verifier asking with an authority it authenticated, which is a URI, therefore
finds only bindings that carry `id`. An issuer SHOULD send `Cache-Control` (RFC 9111) with a
retrieved Passport; it is the Passport's directive (§2.1, §5.1). Revocation Check v1 §5.3
suggests how often to retrieve a Passport and to check revocation.

A verifier MUST NOT refetch a Passport more than once per verification, whatever the
trigger (§3.3; Revocation Check v1 §3.1, §5.6). A first retrieval of any kind, made after
the verifier has authenticated the party in front of it, counts as that one refetch. The
asks of §9.2 are revocation checks, not retrievals, made at most once per issuer per
verification.

When there is no Passport within its validity window to return, the issuer answers 404: for
a subject with no Passport, one whose current Passport is past its `valid_to`, and a binding
that resolves to no subject, to several, or is a withdrawn binding, compared as in §3.3. Unlike a revocation answer (Revocation
Check v1 §5.2), a 404 here cannot widen anything: it leaves the verifier with nothing to act
on. Conditional requests SHOULD be supported with the content hash as entity tag.

A Passport may carry personal data, such as people's names (§8.3), and the organisation's
view of the subject, including its assessment of the vendor, which the organisation may not
want every verifier, or the vendor, to see. An issuer MUST return a signed Passport that
carries personal or otherwise sensitive data, or names a party by `name` alone (§8.3), only to
authenticated callers the organisation
has authorized to read it, and SHOULD do so for every Passport. That authority is distinct
from the authority to read revocation state. A verifier SHOULD NOT keep a Passport that
carries personal data past its `valid_to`. An issuer MAY offer a display form for people;
it MUST be identifiable as unsigned, and a verifier MUST NOT use it for any decision.

## 11. Conformance

An implementation MUST state whether it is an issuer, a verifier or both, and an issuer
MUST state which `subject_type` values it issues.

**Issuer** (§3 to §10):

- every REQUIRED member; `bindings` per §3.3, with `authority.id` an absolute URI naming
  the issuing system;
- canonical form and signature (§4);
- revision: no signed superseded revision, and the §5.1 classification;
- validity (§6) and `status` (§7);
- business context, including §8.3;
- key publication (§9) and restricted retrieval (§10).

**Verifier:**

- applies the extensibility rules of §3;
- rejects a Passport that is missing a REQUIRED member, has a malformed entry of `bindings`
  (§3.3) or no `manager` (§8.5), is outside its window, is not I-JSON, has a `typ` or
  `crit` §4 rejects, does not have exactly one signature, or fails signature verification
  against a configured trust anchor (§4, §9.1);
- calls only a revocation `uri`, JWKS URI and retrieval endpoint §9.1 allows;
- uses a Passport for the party in front of it only through a binding whose `authority.id`
  and identifier match what its authentication resolved to per §3.3, exactly: never from a
  value the presenter chose, never on `authority.name` or `type`, never through a binding
  without `id`;
- where it trusts several issuers, applies §9.2: only bindings its configuration accepts
  from that issuer, ranked, falling through only on `unresolved_identity`, with the tenant
  or account of a shared authority taken from authentication;
- percent-encodes request values (§10);
- checks revocation before acting;
- reads business context only afterwards, per §8.5, reading an object with neither
  reference nor `name` as absent, and an absent or `null` `issuance_class` as unknown
  whichever way a check reads it (§3).

## 12. Open questions and planned work

Each item is a question this version leaves open, or work planned for a later version.
Feedback on any of them is welcome.

1. **Several issuers, one asset.** Each issuer has its own subject for an asset; bindings
   tie them to the same identities, and §9.2 decides which issuer a verifier relies on.
   Should a revocation at one issuer reach the others, for verifiers that rank them
   differently or trust only one of them? A deployment and its parent must share an issuer
   (§3.4).
2. **Several signers.** Whether a later version accepts endorsements from several parties,
   and how, is open. This version rejects any `signatures` without exactly one entry (§4).
3. **Proxy issuance.** Worked examples of what a vendor running the subject may assert.
4. **Holder binding.** The Passport does not bind to a key the subject holds; binding the
   presenter is left to authentication.
5. **Public Passports and selective disclosure.** A public form that carries no personal or
   sensitive data, for verifiers that do not authenticate, is planned for a later version,
   as is disclosing only some values to a given verifier. A verifier that saw less would
   deny at least as much.
6. **Large compositions.** A complex asset may list more components than belong in every
   Passport. A signed, digest-bound reference to a fuller external description is
   planned for a companion specification, the Business Context Profile; this version
   carries `composition` inline.
7. **Provenance.** Where each value came from, and how far a verifier can rely on it, is left
   to a later version. Values are objects (§8.2) so it can be added without changing them.
8. **Forged content after a key compromise.** A compromised key can sign altered content for
   a real subject at a revision at or above its floor, and the revocation check does not
   detect it. Recovery today is removing the key from the JWKS. The responder
   could instead return the current revision or its content hash.
9. **Configuring issuers' authorities.** §9.2 requires a verifier to know which
   authorities each trusted issuer may bind, and to rank issuers that share one. A format
   for that configuration, or a way for an organisation to publish it, is not specified.
10. **Scope of name uniqueness.** A name standing alone is unique per issuer and attribute
    (§8.3). Whether several issuers of one organisation should share that namespace is not
    specified.
11. **Further major-revision triggers.** Whether a change of `subject_type`, `status` or
    `cost_center` should also be a major revision (§5.1).
12. **Least favourable value of unordered attributes.** §8.5 orders only
    `risk_classification`, `purpose.autonomy_level` and `purpose.human_involvement_level`.
    For `vendor`, `org_unit` and the unordered members of `purpose` (`intended_outcome`,
    `usage_area`, `output_type`, `people_affected`, `data_used`, `interaction_type`),
    whether a check reading an absent value should simply not pass is to be stated.
13. **Attribution by cloud resource identifiers.** Which authenticated value resolves, per
    provider, to a bound cloud resource name (for AWS, an STS assumed-role ARN is not the
    resource ARN), by which trusted mapping (§3.3), and which `authority.id` names it. A
    later profile; in this version such bindings carry `authority.name` only and serve lookup
    only (§3.3).
14. **Registries.** Registries for `reason` values, scope entry types, status mechanisms
    (§7) and a media type for the Passport are not yet defined.
15. **Signed answers, stapling and push.** See Revocation Check v1 §8.
16. **Further subject types.** Workflows, skills and other AI assets that run inside or
    across agents. Each needs a definition of its enforcement point (§3.1) before it is
    added; a verifier written against this version rejects a `subject_type` it does not
    recognize (§3).

## 13. Not specified here

- **Revocation answers.** AI Passport Revocation Check v1.
- **Authentication** of issuer, holder or verifier.
- **How business context is obtained**, where each value came from, and **risk assessment
  methodology.**
- **Policy.** No policy language, evaluation model or decision.
- **Transport.** The paths shown are illustrative.

## 14. Security considerations

- **Trust anchoring.** A verifier trusts only issuers, JWKS URIs and responders it was
  configured with, never ones a Passport names (§9.1).
- **Key compromise.** Removing a `kid` from the JWKS invalidates every Passport it signed
  for verifiers that refetch the JWKS; verifiers caching it stay exposed until their cache
  expires. A verifier SHOULD bound how long it caches a JWKS and, on an unknown `kid`,
  SHOULD refetch it at a limited rate. A compromised key can sign altered content for a real
  subject at or above its floor; that is recovered by removing the key (§12 q8). Algorithm
  handling follows RFC 8725.
- **Name-only authorities.** A binding whose `authority` has only a `name` is for lookup
  only and never attributes a Passport (§3.3), because a label is not unique across
  organisations.
- **Claimed identities.** Any trusted issuer can list any identity in its own Passports. A
  verifier accepts a binding from an issuer only as its configuration allows, and ranks
  issuers that share an authority (§9.2).
- **Bearer exposure.** A Passport is not an authentication credential (§3.3). Anyone who
  holds a copy can present it; it binds to the presenter only through authentication.
- **Freshness and time of use.** A verifier acts on state no older than the directive
  allows (§2.1). An irreversible action uses an answer no older than the organisation's short limit
  (Revocation Check v1 §5.3). A
  verifier serving a long-running session SHOULD re-check revocation during it, not only at
  its start.
- **Clock skew.** A verifier MAY allow a skew of at most 5 minutes when comparing the
  current time with `valid_from` and `valid_to` (§6).
- **Availability.** Failing closed makes the responder a denial-of-service target. A caller
  bounds the time it waits for an answer and treats a timeout as revoked (Revocation Check
  v1 §5.2, §8 q2).
- **Cooperative revocation.** A check run inside the subject's own trust boundary can be
  skipped (Revocation Check v1 §8 q1).
- **Names as references.** A name standing alone is only as strong as the record behind it
  (§8.3, §12 q10).
- **Several responders.** *Informative.* Replicas answering for one issuer share one
  `state_version` sequence per subject, as Revocation Check v1 §5.4 implies.
- **Canonicalisation.** A verifier rejects the inputs parsers most often read differently
  (§4) and passes to policy only what it verified.

## 15. Privacy considerations

- **Subject enumeration.** `no_passport_issued`, `no_active_passport`, `binding_revoked`,
  `unresolved_identity` and `ambiguous_identity` tell a caller whether a subject or binding
  exists, as does 200 against 404 at retrieval (§10).
- **Personnel inference.** `accountability_lapsed` can reveal that a person has left.
- **Churn.** `state_version` reveals how often a subject's revocation state changes.
- **Who checks whom.** A responder sees which verifiers check which subjects, and when.

A responder SHOULD authenticate callers, and MAY omit `reason` for a caller not authorized
to see it. §10 limits who reads a Passport and how long a verifier keeps one.

## 16. Relation to other work

*Informative.*

- **OAuth Token Introspection (RFC 7662)** asks an authorization server whether a token is
  active. The revocation check asks the same of a subject, keyed on (`issuer`, `subject`),
  and never grants.
- **OAuth Token Status List (draft-ietf-oauth-status-list)**, and status lists for SD-JWT
  VC and W3C Verifiable Credentials, publish signed, compressed status for many credentials
  at once. They suit offline checks; this check suits a gateway that asks per action.
- **OCSP (RFC 6960)** answers for one certificate at a time. Stapling, where the presenter
  carries a signed recent answer, is Revocation Check v1 §8 q2.
- **SCIM's Enterprise User extension (RFC 7643 §4.3)** carries organisation, division,
  cost center and manager for people. `business_context` carries the same kind of
  attributes for AI assets.
- **WIMSE** addresses workload identity and proof of possession. A Passport delegates both
  to authentication (§3.3).
- **Shared Signals and CAEP** push security events between parties. This check pulls;
  push is Revocation Check v1 §8 q4.

This specification differs from these mainly in its business-context vocabulary and in
revocation semantics that only withdraw: an unknown subject is revoked, a revision floor
withdraws older Passports, unrecognized scope entries deny, and answers are ordered by
`state_version`. A Passport is JSON signed with JCS (RFC 8785) and a detached JWS rather
than a JWT, so that policy engines read it as plain JSON; §4 limits the canonicalisation
risk this brings.

## 17. References

**Normative.**

- RFC 2119, Key words for use in RFCs to Indicate Requirement Levels.
- RFC 3339, Date and Time on the Internet: Timestamps.
- RFC 3986, Uniform Resource Identifier (URI): Generic Syntax.
- RFC 6454, The Web Origin Concept.
- RFC 6570, URI Template.
- RFC 7493, The I-JSON Message Format.
- RFC 7515, JSON Web Signature (JWS).
- RFC 7517, JSON Web Key (JWK).
- RFC 7518, JSON Web Algorithms (JWA).
- RFC 8174, Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.
- RFC 8259, The JavaScript Object Notation (JSON) Data Interchange Format.
- RFC 8725, JSON Web Token Best Current Practices.
- RFC 8785, JSON Canonicalization Scheme (JCS).
- RFC 9111, HTTP Caching.
- RFC 9493, Subject Identifiers for Security Event Tokens.
- AI Passport Revocation Check v1.

**Informative.**

- RFC 6960, X.509 Internet Public Key Infrastructure Online Certificate Status Protocol
  (OCSP).
- RFC 7643, System for Cross-domain Identity Management: Core Schema.
- RFC 7662, OAuth 2.0 Token Introspection.
- draft-ietf-oauth-status-list, Token Status List.
- draft-ietf-oauth-sd-jwt-vc, SD-JWT-based Verifiable Credentials.
- W3C, Verifiable Credentials Data Model.
- IETF WIMSE working group documents.
- OpenID Shared Signals Framework and Continuous Access Evaluation Profile (CAEP).
