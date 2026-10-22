# Versioning

The specifications are published early, as drafts, so implementers can review and build
against them while they settle. This page says what can change, how changes are numbered,
and what never changes.

## Version identifiers

| Form | Meaning |
|---|---|
| `1.0-draft.N` (dated) | a working draft. Anything may still change; see "Drafts" below |
| `1.0` | the first final version |
| `1.1`, `1.2`, … | additive revisions: new members, values or optional features. Existing conforming implementations stay conforming |
| `2.0` | a breaking change. It gets a new `schema_version`, so a v1 verifier rejects it rather than misreading it |

Each specification carries its version and date at the top. The test vectors are versioned
with the specification they test.

## Drafts

- We aim for additive changes even in drafts. When a draft change does break existing
  implementations, the changelog says so, explains why, and gives migration notes.
- Each draft that changes normative text gets a new draft number. Editorial fixes (wording,
  examples, typos) do not.
- Before a draft becomes final there is a public feedback window of at least 30 days.

## Rules that hold in every version

1. **No version makes a verifier allow more.** No change makes a conforming verifier allow
   something an earlier version denied. This is a design rule we apply to every change.
2. **Unknown restrictions deny.** A restriction a verifier does not understand denies at
   least as much as needed (AI Passport v1 §8.5, Revocation Check v1 §6.2). Unknown
   informational members are ignored (AI Passport v1 §3).
3. **Unable to ask means deny.** A caller that cannot get a revocation answer treats the
   subject as revoked (Revocation Check v1 §5.2).

## After a version is final

- Additive changes ship as minor versions, with changelog entries.
- Removing or changing behaviour is announced at least 6 months before it takes effect, with
  migration notes, and arrives only in a new major version.
- Preview specifications are labelled as previews and carry no compatibility promise.
