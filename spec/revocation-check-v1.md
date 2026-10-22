# AI Passport Revocation Check v1

**Version:** 1.0-draft.1 (2026-10-22) · **Status:** Draft · **Conformance:** responder, caller ·
**Licence:** Community Specification License 1.0 ([LICENSE.md](LICENSE.md)); sample code Apache 2.0

An AI Passport says what an AI asset is and the business context it operates under. This
document says how to ask whether it may still act. The two are separate: a Passport may be
valid and revoked at the same time.

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

```
GET /revocation?subject=7a1f3c9e5b2d4e8f9a0b1c2d3e4f5a6b
```

A subject that may act:

```json
{ "subject": "7a1f3c9e5b2d4e8f9a0b1c2d3e4f5a6b", "revoked": false, "revoked_scopes": [],
  "min_required_revision": 1, "evaluated_at": "2026-10-15T14:03:11Z",
  "state_version": 12 }
```

A subject whose manager has left:

```json
{ "subject": "7a1f3c9e5b2d4e8f9a0b1c2d3e4f5a6b", "revoked": true, "revoked_scopes": [],
  "min_required_revision": 1, "evaluated_at": "2026-10-15T14:03:11Z",
  "state_version": 13, "reason": "accountability_lapsed" }
```

A subject whose Passports below revision 5 have been withdrawn — the subject may act, but
only under revision 5 or later, which the caller fetches:

```json
{ "subject": "7a1f3c9e5b2d4e8f9a0b1c2d3e4f5a6b", "revoked": false, "revoked_scopes": [],
  "min_required_revision": 5, "evaluated_at": "2026-10-15T14:03:11Z",
  "state_version": 14, "reason": "revision_withdrawn" }
```

A caller that knows only the identity it authenticated, such as the agent's workload
credential, can retrieve the Passport by that identity (AI Passport v1 §10) and then ask by
subject. Where the responder supports it (§3.1), the caller can instead ask by that identity
and learn the subject in the same round trip:

```
GET /revocation?authority=https%3A%2F%2Flogin.example.net%2Ftenant-42&identifier=4f1c9a2e-77b0
```

```json
{ "subject": "7a1f3c9e5b2d4e8f9a0b1c2d3e4f5a6b", "revoked": false, "revoked_scopes": [],
  "min_required_revision": 1, "evaluated_at": "2026-10-15T14:03:11Z",
  "state_version": 12 }
```

The caller proceeds if and only if `revoked` is the JSON literal `false`, the Passport it
holds has a `revision` of at least `min_required_revision`, and no entry of
`revoked_scopes` matches what it is about to do (§6). Anything else, including being unable
to ask, denies. Proceeding means nothing has been withdrawn, not that the action is
permitted. `revoked: true` means stop. A held revision below `min_required_revision`
withdraws the caller's Passport, not the subject: fetch the current revision and check
again, once (§5.6).

Responder, in full:

```
on GET /revocation?subject=S  or  GET /revocation?authority=A&identifier=I:
    if S is given together with A or I: return 400
    if asked by identity:
        if A or I is absent or empty: return 400
        matches = subjects with an active binding whose authority.id = A
                  and identifier = I
        if several:   return 200 { subject: null, revoked: true, revoked_scopes: [],
                                   min_required_revision: 0, evaluated_at: now(),
                                   state_version: 0, reason: "ambiguous_identity" }
        if none and some subject has a withdrawn binding whose
                  authority.id = A and identifier = I:
                      return 200 { ...same..., reason: "binding_revoked" }
        if none:      return 200 { ...same..., reason: "unresolved_identity" }
        subject = the single match
    else:
        subject = percent-decode(subject)
        if subject is absent or malformed: return 400
    if no Passport was ever issued for (this issuer, subject):
        return 200 { subject, revoked: true, revoked_scopes: [], min_required_revision: 0,
                     evaluated_at: now(), state_version: 0, reason: "no_passport_issued" }
                     (or the subject's own floor and state_version, where it has them: §5.2)
    rows  = active revocation records for (this issuer, subject)
    floor = minimum acceptable revision for (this issuer, subject); 1 if never raised
    lapsed = the current Passport for (this issuer, subject) is past its valid_to
    return 200 { subject,
                 revoked:               rows is not empty or lapsed,
                 revoked_scopes:        [],
                 min_required_revision: floor,
                 evaluated_at:          now(),
                 state_version:         current version for subject,
                 reason:                reason of the most recent row if any,
                                        else "no_active_passport" if lapsed,
                                        else "revision_withdrawn" if floor > 1 }
      combined with the parent's answer if the subject has a parent (§3.2)
      with Cache-Control set
```

Revocation is computed at read time from revocation records, the revision floor, the
current Passport's validity and, for a deployment, its parent's answer. A responder MAY keep flags derived from them for its own use,
such as choosing which subjects to reissue, but MUST NOT answer from them.

## 2. Scope

This document specifies one operation: asking whether a single subject has been revoked, and
what the answer means (§9 lists what it does not specify).

This check is not authorization. It only withdraws; it never grants. What a subject that is
not revoked may do is decided by the caller's own authorization, which may read the
subject's Passport.

This release specifies the Passport format and revocation of a subject as a whole.
Constraint-based checks — what a subject may do, and revoking part of it — are planned for
a later release. Until then a Passport describes a subject; it never says what the subject
may do. Scoped entries (§6) are the place for revoking part of what a subject may do.

## 3. The subject

- The check is keyed on the pair (`issuer`, `subject`) of the Passport. A check against any
  other identifier answers a different question.
- Revocation attaches to the subject, not to any one Passport revision. It survives
  reissuance, supersession and expiry of every Passport for that subject. Whether the
  caller's revision is current or within its window is checked by the verifier (AI
  Passport v1 §5, §6) and never reported by this check. The check reports only whether the
  subject has a current Passport inside its window (§5.7).
- The responder MUST treat the identifier as opaque and MUST NOT parse it to infer
  authority, tenancy or scope.
- A caller MUST percent-encode every query parameter value (`subject`, `authority`,
  `identifier`) per RFC 3986, every reserved character included, as in RFC 6570 simple
  expansion; expanding a `{subject}` template (AI Passport v1 §7) does the same. The
  response's `subject` member MUST carry the decoded identifier.

### 3.1 Asking by the identity the caller authenticated

A caller rarely holds the issuer's subject identifier. It holds whatever identity it
authenticated for the AI asset in front of it: a token's issuer and subject, or a workload
certificate. It can always retrieve the Passport by that identity
(AI Passport v1 §10) and ask by subject. A responder MAY also answer by identity directly
(§4); the rest of this section applies to a responder that does. A responder that does not
answers a request by identity with 400, which the caller treats as revoked (§5.2).

- `authority` identifies the system that issued the identifier, as that system names
  itself — for a token, its `iss`; for a workload certificate, its trust domain.
  `identifier` is the identifier within it: the token's `sub`, or the full SPIFFE ID.
  Together they have the shape of the `iss_sub` subject identifier of RFC 9493. An
  identifier is meaningful only together with its authority. Cloud resource names are not
  asked by identity in this version (AI Passport v1 §12 q13).
- The responder MUST match `authority` against `authority.id` only, and `identifier`
  against `identifier`, both exactly (AI Passport v1 §3.3). A binding without
  `authority.id` is not reachable by an identity query, and an `authority` that is not an
  absolute URI matches no binding (`unresolved_identity`).
- A caller asks by identity only a responder AI Passport v1 §9.1 allows, for an issuer its
  configuration accepts that authority from (AI Passport v1 §9.2). Where several are
  accepted, it asks them in ranked order and passes to the next only as AI Passport v1
  §9.2 allows. An answer applies
  only to (the issuer whose responder gave it, `subject`).
- The responder resolves the pair against the bindings the issuer holds for its subjects
  (AI Passport v1 §3.3) and answers for the resolved subject. The response is unchanged;
  its `subject` member carries the resolved subject.
- **A pair that resolves to no subject, or to more than one, is answered as revoked**,
  with `reason` `unresolved_identity` or `ambiguous_identity` and `subject` null. A
  responder MUST NOT choose among several matches.
- A binding the issuer has withdrawn no longer resolves. Asked by a withdrawn binding, matched
  as above, that
  is not also an active binding of some subject, the responder MUST answer revoked with
  `reason` `binding_revoked` and `subject` null, even while the subject's other bindings
  resolve normally. This withdraws one identity of an asset without withdrawing the asset.
- Answers with `reason` `unresolved_identity`, `ambiguous_identity` or `binding_revoked`
  carry `state_version` 0: they describe an identity, not a subject's revocation state.
- Resolution and the revocation answer are evaluated together, in one request: an answer
  can never pair a binding that was valid at one instant with a revocation state read at
  another.

A caller MUST ask only by a pair it resolved per AI Passport v1 §3.3, never by an identifier
the AI asset asserts about itself. A caller that also holds the subject's Passport MUST ask
the responder AI Passport v1 §9.1 allows for that Passport's `issuer`, and MUST deny if the
answer came from another issuer's responder or the resolved (`issuer`, `subject`) differs
from the Passport's: the identity in front of it does not belong to that Passport. It MAY instead retrieve the Passport by that identity and
start again, within the refetch limit of AI Passport v1 §10.

### 3.2 Deployments

A subject whose Passport names a `parent` (AI Passport v1 §3.4) is a deployment of it. A
`parent` that is absent or `null` names none. Its
revocation state includes its parent's. A responder serving a subject that has a parent
MUST answer:

| Member | Value |
|---|---|
| `revoked` | `true` if the subject is revoked or its parent's answer is revoked |
| `revoked_scopes` | the subject's entries, plus the entries of its parent's answer |
| `min_required_revision` | the subject's own floor; the parent's is not inherited |
| `state_version` | the subject's `state_version` plus its parent's |
| `reason` | the subject's own reason if it is revoked, else `parent_revoked` when the parent is, else the subject's own reason, if any |

- The parent's answer is computed by this same rule, in the same request.
- A parent the responder cannot resolve, or for which no Passport was ever issued, is
  revoked.
- `min_required_revision` is not inherited: a floor withdraws revisions of the subject that
  set it, and a deployment's revisions are numbered separately.
- The parent relation is data the issuer holds; the responder MUST NOT infer it from either
  identifier.
- When a deployment's parent changes, including being added or removed, the responder MUST raise the deployment's own
  `state_version` by enough that the reported `state_version` does not decrease (§5.4).

A responder that ignores `parent` fails open for every deployment of a revoked asset.
Restoring a deployment never lifts its parent's revocation.

## 4. Request

```
GET /revocation?subject={subject}
GET /revocation?authority={authority}&identifier={identifier}      (where supported, §3.1)
```

A request MUST carry either `subject` or both `authority` and `identifier`, never both. A
responder MUST answer any other combination with 400. In a request by identity,
`authority` is matched against a binding's `authority.id` only (§3.1).

A caller MUST obtain the responder URL as AI Passport v1 §9.1 requires, and MUST NOT follow
a redirect to another origin. A caller that holds no Passport MUST use a responder it has
configured for the issuer.

The check MUST be idempotent and side-effect-free. A responder MUST NOT require the caller to
say what it is about to do: the answer is complete for the subject, and the caller decides
locally. This is what keeps a check before every action affordable.

The authority to read revocation state MUST be distinct from the authority to write it.

## 5. Response

### 5.1 Members

| Member | Type | Required | Meaning |
|---|---|---|---|
| `subject` | string or null | yes | the subject this answer is about; null when an identity could not be resolved (§3.1) |
| `revoked` | boolean | yes | whole-subject revocation: the subject may not act at all |
| `revoked_scopes` | array | yes | narrower revocations; see §6 |
| `min_required_revision` | integer | yes | the lowest Passport `revision` a caller may act under; see §5.6 |
| `evaluated_at` | RFC 3339 | yes | when this answer was determined |
| `state_version` | integer | yes | monotonic version of the subject's revocation state; see §5.4 |
| `reason` | string | no | why, when revoked or when `min_required_revision` is above 1; informative only |

A responder MUST emit every REQUIRED member on every successful response. An absent `revoked`
is not `false`: a caller proceeds only if `revoked` is the JSON literal `false`. When asking
by subject, a caller MUST deny if the answer's `subject` differs from the subject asked
about.

A response MUST NOT carry personal data. `subject` is the issuer's opaque identifier, and
`reason` is one of §5.5.

### 5.2 Status codes

| Code | When | Caller |
|---|---|---|
| 200 | an answer was determined, including "no Passport was ever issued" | uses the body |
| 400 | identifier absent or malformed, or a request form the responder does not support (§3.1) | MUST treat as revoked |
| 401, 403 | caller not authorized to read | MUST treat as revoked |
| 429, 5xx | responder unable to answer | MUST treat as revoked |

A caller MUST treat as revoked any status not listed, and a 200 whose body is not a valid
answer under §5.1. A body with duplicate member names is not a valid answer. A caller MUST
bound the time it waits for an answer and treat a timeout as revoked.

A responder MUST return **200 with `revoked: true`**, `state_version` 0 and `reason`
`no_passport_issued` for a subject it has no record of, and MUST NOT return 404. An
unknown subject is what a forged, withdrawn or wrong-environment credential looks like, so
"no news" never reads as "proceed". For a subject it holds a record of but has issued no
Passport for, the responder MAY instead carry that subject's own `state_version` and
`min_required_revision`; the answer is still revoked.

### 5.3 Freshness

The response MUST carry an explicit `Cache-Control` directive. A caller MUST NOT reuse an
answer beyond it, and MUST treat an expired answer as absent — that is, as revoked. A caller
MUST NOT infer how long a revocation answer stays good from the caching of the Passport
itself. A caller MAY apply an answer that has no `Cache-Control`, or one whose
`Cache-Control` it cannot parse, once, to the request it answered, and MUST NOT reuse it. A caller MUST compute freshness per RFC 9111, including
`Age`, and MUST treat as expired an answer whose `evaluated_at` is older than its freshness
lifetime plus the clock skew of AI Passport v1 §14.

The directive is an upper limit, set by the responder, which knows the subject and can
give a higher-risk one a shorter limit. The caller, which knows the action, MAY reuse an
answer for less time, never more.

A caller gating an action it knows to be irreversible MUST NOT reuse an answer older than
the organisation's limit for irreversible actions: 5 seconds where the organisation sets
none. With a limit of 0, it obtains an answer for that action. A caller SHOULD treat an
action as irreversible in two cases:
- its side effect is unknown, or known only from the subject's own description;
- it returns data the organisation does not treat as freely shareable within it, since a
  disclosure cannot be undone.

*Informative.* Otherwise: short reuse when undoable at a cost; up to the limit when
read-only on data the organisation treats as freely shareable within it. The reuse times
are the organisation's to set. A planned companion specification, the Business Context
Profile, is expected to let a tool server carry a `surface` classification a caller could
use as its source. The request never names the action (§4).

#### Call frequency

*Informative.* Checks are frequent, so callers and responders keep the load predictable:

- **Passport retrieval.** A verifier retrieves a subject's Passport when it first meets the
  subject, and afterwards only on a refetch trigger (AI Passport v1 §3.3, §10) or when the
  Passport's directive expires, revalidating with its content hash as entity tag
  (`If-None-Match`). An issuer might send `max-age=3600`: a major revision is caught
  sooner, by the floor of §5.6.
- **Revocation.** A responder might default to `max-age=60`, within 30 to 300 seconds,
  shorter for a higher-risk subject. A caller makes one check per subject per directive,
  however many actions it gates, and combines concurrent checks for the same subject into
  one request.
- **Backoff.** On 429 or 503 a caller denies, as §5.2 requires, honours `Retry-After`, and
  does not retry in a tight loop.

### 5.4 Monotonicity

The responder MUST maintain per subject a `state_version` that increases whenever the
subject's revocation state changes, revocation lifted included, and never decreases.
The one exception is a lapse (§5.7), which a responder MAY answer without increasing it. A
caller that retains answers MUST discard one whose `state_version` is lower than one it has
already applied for the same subject. Of two answers with equal `state_version` for the
same subject, both still within their directive, a caller MUST apply the more restrictive:
the one with `revoked: true`; otherwise the one with the higher `min_required_revision`;
otherwise both, applying the union of their `revoked_scopes`.

Without this rule, any system with more than one path to the caller — a cache, a retry, a
second responder — will eventually deliver a stale "not revoked" over a fresh "revoked".

### 5.5 Reasons

`reason` is informative. Values defined by this version:

| `reason` value | Meaning |
|---|---|
| "no_passport_issued" | no Passport was ever issued for the subject |
| "no_active_passport" | the subject's current Passport is past its `valid_to` and no successor has been issued (§5.7) |
| "withdrawn_by_operator" | revoked by an authority permitted to write revocations. "Operator" names that authority, not a business-context role |
| "accountability_lapsed" | no `manager` of the subject is in force any longer (AI Passport v1 §8.4) |
| "governance_withdrawn" | the organisation's governance record withdrew approval, retired the subject, or assessed it as unacceptable risk (AI Passport v1 §8.4) |
| "revision_withdrawn" | Passports below the subject's minimum revision are withdrawn after a major revision (AI Passport v1 §5.1); the subject may act under the current one |
| "unresolved_identity" | the identity asked about resolves to no subject (§3.1) |
| "ambiguous_identity" | the identity asked about resolves to more than one subject (§3.1) |
| "binding_revoked" | the identity asked about was a binding of the subject and has been withdrawn (§3.1) |
| "parent_revoked" | the subject is a deployment and its parent is revoked (§3.2) |

A caller MUST NOT treat an unrecognized `reason` as grounds to proceed; `revoked` alone
decides. `unresolved_identity` is relied on in one place: under AI Passport v1 §9.2 it lets
a caller pass to a lower-ranked issuer. A caller MUST NOT read any other value, or an absent
`reason`, as permitting that.

### 5.6 `min_required_revision`

`min_required_revision` withdraws every Passport for the subject whose `revision` is lower
than it. The subject itself is not revoked: a caller holding a lower revision fetches the
current Passport and, if its `revision` is `min_required_revision` or greater, acts under
it. A caller that holds no Passport and acts on this answer alone applies nothing more.
A caller MUST NOT refetch more than once (AI Passport v1 §10): if the Passport it then
holds still has a `revision` below `min_required_revision`, it MUST deny.

- The issuer raises the floor to the new revision when it issues a major revision (AI
  Passport v1 §5.1). The floor never decreases, and raising it increments `state_version`.
- A subject whose floor was never raised answers `1`, its first revision. Answers with
  `state_version` 0 (§3.1, §5.2) answer `0`: they describe no subject's Passports.
- A caller MUST treat an answer with no `min_required_revision`, or one that is not a
  non-negative integer, as revoked.

`min_required_revision` is not an entry of `revoked_scopes`. A scope entry withdraws actions
of the subject and can be lifted; the floor withdraws older credentials and only rises.

### 5.7 Lapsed Passports

When the subject's current Passport is past its `valid_to` and no successor has been
issued, the responder MUST answer `revoked: true` with `reason` `no_active_passport`.
Because the lapse follows from the Passport itself, the responder MAY leave `state_version`
unchanged (§5.4): a stale "not revoked" answer cannot outlive it for a caller holding that
Passport, which rejects it after `valid_to` (AI Passport v1 §6), beyond the skew of AI
Passport v1 §14; for a caller holding no Passport, the directive bounds it (§5.3). Issuing a successor lifts the
lapse, unless another revocation is in force.

This asks nothing new of a caller, which already rejects a Passport outside its window
(AI Passport v1 §6). It tells a caller that asks by identity, or holds no Passport, that the
subject has nothing current to act under.

## 6. `revoked_scopes`

`revoked_scopes` carries revocations narrower than the whole subject: the subject may act,
except where an entry matches. This version defines and registers no entry type, so a responder that
implements this version alone always emits an empty array. A caller still MUST apply §6.2:
any entry it finds revokes the whole subject.

Later versions and registered entry types add entries to this array, so a caller written
against this version relies on its shape and nothing more:

- **The array holds zero or more entries.** A caller MUST NOT assume a maximum number of
  entries, an order, that entries are distinct, or which types appear and how many of each.
  It MUST evaluate every entry.
- **The entries are a union.** No entry modifies, excepts or overrides another. An action is
  denied if any entry matches it, whatever the other entries say.
- **Each entry is a JSON object with exactly one member, whose name is the entry's type.** An
  entry that is not an object, or has no member or several, is an entry the caller does not
  recognize (§6.2).
- **A caller that cannot evaluate the whole array**, whatever the reason, MUST treat the
  subject as revoked. It MUST NOT act on a part of the array.

The order of entries carries no meaning, and a responder MAY emit them in any order.

### 6.1 Entry types

No entry type is defined or registered in this version, and no registry exists yet (§8).
Entry types are planned for a companion specification, Scoped Revocation. A caller
recognizes only the types it implements; under this version, every entry is unrecognized.

### 6.2 Entries a caller does not recognize

**A caller that does not recognize an entry of `revoked_scopes`, or any member or value
within one, MUST treat that entry as matching every action — which is to say, as revoking the
whole subject.**

A caller that understands less than the responder emits denies more than necessary, never
less. Ignoring an entry would turn every narrower revocation into a silent permission.

## 7. Conformance

**Responder** (§3 to §6):

- keyed on (`issuer`, `subject`);
- where it answers by identity, does so per §3.1: matching `authority.id` only, and
  revoked when unresolved or ambiguous;
- resolves a deployment with its parent (§3.2);
- every REQUIRED member, and no personal data (§5.1);
- 400 for a request carrying both forms (§4);
- 200 with `revoked: true` for an unknown subject;
- `Cache-Control`, `state_version`, and `min_required_revision` per §5.6;
- lapsed Passports answered revoked (§5.7);
- revocation computed at read time, never answered from a stored status;
- read authority distinct from write authority.

**Caller:**

- checks before acting on a Passport, and percent-encodes every query value (§3);
- asks by identity only with a pair it resolved per AI Passport v1 §3.3, only of a
  responder whose issuer its configuration accepts that authority from, in ranked order
  (AI Passport v1 §9.2);
- denies when the answer came from another issuer's responder, when the resolved
  (`issuer`, `subject`) differs from the Passport it holds, or when the answer's `subject`
  differs from the subject asked about (§5.1);
- obtains the responder URL per AI Passport v1 §9.1, uses a configured responder when it
  holds no Passport, and follows no cross-origin redirect (§4);
- treats every failure mode of §5.2, any unlisted status, any invalid body (including
  duplicate member names) and any timeout as revoked, bounding the time it waits (§5.2);
- reuses no answer without a parseable `Cache-Control`, computes freshness with `Age` and
  `evaluated_at`, and honours §5.3 and §5.4;
- evaluates `min_required_revision` against the revision it holds (§5.6);
- evaluates every entry of `revoked_scopes`, assuming nothing about their number or order
  (§6), and applies §6.2 to every entry it does not recognize.

## 8. Open questions and planned work

Each item is a question this version leaves open, or work planned for a later version.
Feedback on any of them is welcome.

1. **Revocation is cooperative unless enforcement sits outside the subject.** The check
   reports revocation; it does not stop anything. Where the component that declines to act
   runs inside the subject's own trust boundary, a compromised host can simply not ask.
   Withdrawing the subject's credentials at the authority that issues them — so it fails
   authentication everywhere — is the stronger primitive where total withdrawal is wanted.
2. **Surviving an outage.** A caller that cannot reach the responder denies, so the network
   path is a denial-of-service surface. Whether a signed, short-lived "not revoked" assertion
   should let a caller ride out a brief outage without failing open is undecided. Signed
   answers would also allow stapling, where the presenter carries a recent answer: the
   trade-off made by OCSP stapling and by the OAuth Token Status List, between privacy and
   availability on one side and freshness on the other.
3. **Granularity.** The running instances of one subject are revoked together. Withdrawing
   one needs a scope entry naming it, planned for the companion Scoped Revocation
   specification.
4. **Push.** Whether revocation should also be pushed to callers through Shared Signals and
   CAEP, beside batching (§9), is undecided.
5. **Forged content after a key compromise.** A responder could return the current revision
   or its content hash, so that a caller detects a Passport signed with a compromised key
   (AI Passport v1 §12 q8).
6. **Registries.** Registries for `reason` values and scope entry types are not yet
   defined.

## 9. Not specified here

- **Issuance and structure of the Passport.** AI Passport v1.
- **Authentication** of caller or holder.
- **Writing revocations.** Separate, and deliberately so: read and write authority differ.
- **Scope entry types.** None in this version; planned for a companion specification,
  Scoped Revocation.
- **Reuse times, batching and push.** §5.3 bounds reuse; the values are the organisation's.
- **What to do about a revoked subject** beyond declining to act.

## 10. Security considerations

AI Passport v1 §14 applies. In particular:

- **Trust anchoring.** A caller calls only a responder AI Passport v1 §9.1 allows, and
  follows no cross-origin redirect (§4).
- **Availability.** Failing closed makes the responder a denial-of-service target; §5.2
  bounds how long a caller waits (§8 q2).
- **Several responders.** *Informative.* Replicas answering for one issuer share one
  `state_version` sequence per subject (§5.4).

## 11. Privacy considerations

AI Passport v1 §15 applies: `no_passport_issued`, `no_active_passport`, `binding_revoked`,
`unresolved_identity` and `ambiguous_identity` allow enumeration; `accountability_lapsed` can reveal that a person
has left; `state_version` reveals churn; and the responder sees who checks whom. A responder
SHOULD authenticate callers, and MAY omit `reason` for a caller not authorized to see it.

## 12. References

**Normative.**

- RFC 2119, Key words for use in RFCs to Indicate Requirement Levels.
- RFC 3339, Date and Time on the Internet: Timestamps.
- RFC 3986, Uniform Resource Identifier (URI): Generic Syntax.
- RFC 6570, URI Template.
- RFC 8174, Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.
- RFC 9111, HTTP Caching.
- AI Passport v1.

**Informative.**

- RFC 9493, Subject Identifiers for Security Event Tokens.
