# FAQ

Informative. The specifications are normative; this page is not.

## How does AI Passport relate to other work?

Most of these are complementary: AI Passport uses them, or sits beside them.

| | What it does | How AI Passport relates |
|---|---|---|
| **OAuth, OIDC, SPIFFE, WIMSE, mTLS** | authenticate a workload or agent: *which* one is calling | A Passport is not authentication. It binds to the identities these produce (`bindings`), and a gateway uses it only for a party it has authenticated. Use both |
| **JWT** | a signed token format | A JWT would work as an envelope. A Passport is plain JSON with a detached signature (RFC 8785 and JWS), so a policy engine reads the document as it is, with no decoding step |
| **W3C Verifiable Credentials, SD-JWT VC** | a general model for signed credentials, with selective disclosure | v1 keeps the envelope minimal so that a gateway needs no credential stack. A Passport's content could be carried as a credential subject, but no profile for that is written yet. Selective disclosure is an open question (Passport §12 q5). Feedback welcome |
| **OAuth Token Introspection (RFC 7662)** | asks whether a *token* is active | The revocation check asks the same of an *asset*, keyed on its issuer and subject, and it never grants |
| **Token Status List, status lists for VCs** | signed, compressed status for many credentials at once | They suit offline checks; the revocation check suits a gateway that asks per action. Signed answers are an open question (Revocation Check §8 q2) |
| **Shared Signals, CAEP** | push security events between parties | The revocation check pulls. Push is an open question (Revocation Check §8 q4) |
| **OPA, Cedar and other policy engines** | evaluate policy | A Passport is an input to them, not a replacement. The specs define no policy language |
| **AI bills of materials (CycloneDX, SPDX)** | list what a system is built from | `composition` carries the few parts policy reads inline. A reference to a fuller description is planned (Passport §12 q6) |

## Don't policy engines already deny by default?

The final decision usually does. What a single rule does with a missing value or an error is
a separate question, and each engine and gateway answers it differently:

- **Cedar** is deny by default, but a policy that errors is skipped: "a policy that results
  in an error is ignored, meaning that a `permit` policy might unexpectedly fail to allow
  access, or a `forbid` policy might unexpectedly fail to block access." Reading an
  attribute that is not present is such an error, unless the policy tests for it with `has`
  first ([Cedar operators](https://docs.cedarpolicy.com/policies/syntax-operators.html)).
- **Rego** (Open Policy Agent): "Expressions that refer to undefined values are also
  undefined." A deny rule that tests a missing value is therefore undefined, so it does not
  deny; the final decision depends on how the policy is written and on its `default`
  ([Policy language](https://www.openpolicyagent.org/docs/policy-language)).
- **Envoy**'s external authorisation filter rejects requests when the authorisation service
  fails, unless `failure_mode_allow` is set, in which case it "will `accept` the client
  request even if communication with the authorization service has failed"
  ([ext_authz](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto)).

Each is reasonable on its own. Together they mean the same missing input can be denied at
one enforcement point and allowed at the next. AI Passport fixes the reading once, in the
specification: an absent attribute reads as its least favourable value, an unrecognized
value never satisfies a check, and unable to ask means deny.

## Who issues Passports?

The organisation that uses the AI asset, from its own records: the registry, CMDB or
governance system that knows who owns the asset and what it is approved for. The asset never
issues its own Passport, and a vendor cannot name the organisation's accountable manager.
ServiceNow is building one issuer; the specifications are open to any.

## Isn't a Passport just a bearer document?

Holding a Passport proves nothing. A gateway uses it only for a party it has authenticated,
and only when that authentication resolved to one of the Passport's bindings (Passport
§3.3). Binding a Passport to a key the asset holds is an open question (Passport §12 q4).

## What happens when the revocation responder is down?

The gateway denies. Unable to ask means deny (Revocation Check §5.2). Answers can be
reused for a short time, suggested at 60 seconds (Revocation Check §5.3), so a brief outage
is absorbed. Surviving a longer one with signed or stapled answers is an open question
(Revocation Check §8 q2).

## What if the issuer's signing key is compromised?

Removing the key from the issuer's key set invalidates every Passport it signed, for
verifiers that refetch the key set. A compromised key can sign altered content for a real
asset until then; a stronger recovery is an open question (Passport §12 q8).

## Why is `revoked_scopes` always empty in v1?

It is reserved. v1 defines no scoped entries, but a v1 caller already treats any entry it
finds as revoking the whole asset. When a later release adds scoped revocation, existing
callers deny more, never less.

## Does a gateway have to check revocation on every request?

No. It checks once per asset per answer lifetime, however many requests it gates, and
retrieves the Passport when it first meets the asset and when its cache expires. Revocation
Check §5.3 suggests values. An irreversible action uses an answer no more than a few seconds
old.

## Is it only for agents?

No. v1 defines four subject types: agent, harness, tool server and model endpoint (Passport
§3.1). Others, such as workflows and skills, are planned. Each needs its own definition of
where it is enforced.

## What is not in v1?

Constraints that say what an asset may do; signed revocation answers; holder binding;
selective disclosure; a format for configuring several issuers; provenance of each value.
Each is listed in the open questions of the two specifications, which is where feedback
helps most.
