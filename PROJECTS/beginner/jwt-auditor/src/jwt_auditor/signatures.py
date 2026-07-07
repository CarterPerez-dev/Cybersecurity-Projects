"""
signatures.py

HMAC signing, verification, secret cracking, and the RS/HS confusion test.

Everything here is standard library. There is no PyJWT dependency on
purpose. Computing an HS256 signature is nine lines of hmac, and doing it
by hand is the point of the project. You learn far more about why the
alg confusion attack works when you can see that "verify" is just
"recompute the HMAC and compare".

Key exports:
  supported_hmac_algs - the HS algs this tool understands
  hmac_sign - compute an HMAC signature for a signing input
  verify_hmac - constant time check of a token against a candidate secret
  crack_hmac_secret - try a wordlist against an HS signed token
  key_confusion_secret - test whether a public key doubles as the HMAC secret

Connects to:
  decoder.py - operates on DecodedToken.signing_input and .signature
  checks.py - the weak secret and confusion checks call in here
"""

import hmac
from collections.abc import Iterable

from jwt_auditor.decoder import DecodedToken


# alg name -> the hashlib digest name RFC 7518 pairs it with. hmac.new accepts
# the digest as a string, so there is no need to import hashlib here.
_HASH_BY_ALG: dict[str,
                   str] = {
                       "HS256": "sha256",
                       "HS384": "sha384",
                       "HS512": "sha512",
                   }


def supported_hmac_algs() -> frozenset[str]:
    """Return the set of HMAC algorithms this module can compute."""
    return frozenset(_HASH_BY_ALG)


def hmac_sign(signing_input: bytes, secret: bytes, alg: str) -> bytes:
    """
    Compute the raw HMAC signature bytes for a signing input.

    Raises KeyError style ValueError if alg is not an HS variant so callers
    do not silently sign with the wrong primitive.
    """
    digest_name = _HASH_BY_ALG.get(alg)
    if digest_name is None:
        raise ValueError(f"{alg} is not an HMAC algorithm")
    return hmac.new(secret, signing_input, digest_name).digest()


def verify_hmac(
    token: DecodedToken,
    secret: bytes,
    alg: str | None = None
) -> bool:
    """
    Return True if secret produces the token's signature under alg.

    Uses hmac.compare_digest so a wrong guess takes the same time as a
    right one up to the mismatch. Timing a naive == comparison is a real
    way secrets leak, so we never do that here. alg defaults to the token's
    declared algorithm, but callers can force one to model the confusion
    attack where an attacker rewrites the header to HS256.
    """
    chosen = alg or token.algorithm
    if chosen not in _HASH_BY_ALG:
        return False
    if not token.signature:
        return False
    expected = hmac_sign(token.signing_input, secret, chosen)
    return hmac.compare_digest(expected, token.signature)


def crack_hmac_secret(
    token: DecodedToken,
    candidates: Iterable[str],
) -> str | None:
    """
    Return the first candidate secret that verifies the token, or None.

    Only meaningful for HS signed tokens. For anything else there is no
    shared secret to guess, so we return None immediately rather than
    burning through the wordlist.
    """
    if token.algorithm not in _HASH_BY_ALG:
        return None
    for candidate in candidates:
        if verify_hmac(token, candidate.encode("utf-8")):
            return candidate
    return None


def key_confusion_secret(
    token: DecodedToken,
    public_key_pem: bytes,
) -> str | None:
    """
    Test whether the token verifies with a public key used as an HMAC secret.

    This is the RS256 to HS256 confusion attack. A server that accepts the
    algorithm from the token header will, for an HS256 token, verify with
    HMAC using whatever it thinks the key is. If that key is the RSA public
    key (which is not secret), an attacker can forge tokens.

    We try the PEM as given and with trailing whitespace variants, because
    servers differ on whether the stored key has a trailing newline and a
    one byte difference changes the whole HMAC.

    Returns a short label describing which form matched, or None.
    """
    variants: dict[str,
                   bytes] = {
                       "public key PEM as stored": public_key_pem,
                       "public key PEM without trailing newline":
                       public_key_pem.rstrip(b"\n"),
                       "public key PEM with trailing newline":
                       public_key_pem.rstrip(b"\n") + b"\n",
                   }
    for alg in _HASH_BY_ALG:
        for label, material in variants.items():
            if verify_hmac(token, material, alg = alg):
                return f"{label} (verified as {alg})"
    return None
