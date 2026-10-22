# Contributing

Feedback on the drafts is welcome. Open an issue for a question, an unclear passage or a
proposed change. If a test vector and a spec disagree, the spec is right and the vector is
a bug; please report it.

Pull requests that change normative text should say which section they change and why, and
update the vectors in the same change. Run `python3 conformance/vectors/generate.py --check`
before submitting. It works without the signing key; the maintainers re-sign the vectors
when a change needs it.

By contributing, you agree that:

- contributions to the specifications and their supporting documents are made under the
  Community Specification License 1.0 ([spec/LICENSE.md](spec/LICENSE.md)), within the
  bounds of [SCOPE.md](SCOPE.md);
- contributions to code and test data in `conformance/` are made under the Apache License
  2.0 ([conformance/LICENSE](conformance/LICENSE)).

See [LICENSE.md](LICENSE.md). A contributor licence agreement check will be enabled before
publication.
