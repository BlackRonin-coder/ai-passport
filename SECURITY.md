# Security

Please report suspected vulnerabilities in the specifications or the reference code
privately, not in a public issue.

**How to report:** use GitHub's private vulnerability reporting: the **Report a
vulnerability** button under this repository's **Security** tab. Reports are visible only
to the maintainers. Please include what you found, how to reproduce it, and which version
of which specification or file it affects.

The key in `conformance/vectors/jwks.json` signs the test vectors only. Never trust it
outside a test. Its private half is held by the maintainers and never committed.
