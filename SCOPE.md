# Scope

This Working Group develops open interfaces that let any gateway, policy engine or other
verifier learn what an AI asset is, the business context it operates under, and whether it
may still act. The Scope covers:

1. **AI Passport:** the format of a signed credential about an AI asset, its identity
   bindings, business context members, validity, revisions, canonical form, signature, key
   publication and retrieval, and the rules issuers and verifiers follow, as stated in the
   specifications.
2. **AI Passport Revocation Check:** the request and response of the revocation check, its
   reasons, freshness and error handling, and the rules responders and callers follow, as
   stated in the specifications.
3. Later versions of these specifications, and companion specifications this Working Group
   publishes that extend them.

The Scope does not cover anything the specifications leave to implementations, including:

- how an issuer gathers or derives business context, or assesses risk;
- how and when an issuer or responder decides to revoke, beyond what the specifications
  state;
- the policy decisions a verifier makes from a Passport or a revocation answer;
- user interfaces, storage, administration and other product features of an
  implementation.

Any changes of Scope are not retroactive.
