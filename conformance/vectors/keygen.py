#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Make the private key that signs the test vectors.

    python3 keygen.py                 # writes .keys/vector-signing-key.jwk (ignored by git)
    python3 keygen.py --out PATH      # or somewhere else (then set AI_PASSPORT_VECTOR_KEY)
    python3 keygen.py --kid k2        # key id; default k1

The key is never committed. After making a new one, run generate.py to re-sign
the vectors and rewrite jwks.json, and commit only the JSON files.
"""
import json
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from generate import G, N, _i2o, _mul, b64u  # noqa: E402


def main():
    args = sys.argv[1:]
    out = os.path.join(HERE, ".keys", "vector-signing-key.jwk")
    kid = "k1"
    if "--out" in args:
        out = args[args.index("--out") + 1]
    if "--kid" in args:
        kid = args[args.index("--kid") + 1]
    if os.path.exists(out) and "--force" not in args:
        sys.exit(f"{out} exists; pass --force to replace it")
    d = secrets.randbelow(N - 1) + 1
    q = _mul(d, G)
    jwk = {"kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig",
           "x": b64u(_i2o(q[0])), "y": b64u(_i2o(q[1])), "d": b64u(_i2o(d))}
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(jwk, f, indent=2)
        f.write("\n")
    print(f"wrote {out} (kid {kid}); now run generate.py")


if __name__ == "__main__":
    main()
