#!/usr/bin/env python3
"""Python verifier for Registry/Passport/Agent Card profile vectors."""

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


IDENTITY_EXTENSION = "urn:cha2a:ext:agent-identity:v1"
SHA256_URI = re.compile(r"^sha256:[0-9a-f]{64}$")
FORBIDDEN = {"trust_level", "trustLevel", "revoked", "admission", "rating"}


def is_did(value):
    return isinstance(value, str) and value.startswith("did:") and len(value.split(":")) >= 3


def absolute_http(value):
    return isinstance(value, str) and (
        value.startswith("http://") or value.startswith("https://")
    )


def check_card(card):
    if not isinstance(card, dict):
        return False, "card-object"
    for name in ("name", "description", "version"):
        if not isinstance(card.get(name), str) or not card[name]:
            return False, "card-required"
    if not isinstance(card.get("supported_interfaces"), list):
        return False, "card-interfaces"
    caps = card.get("capabilities")
    if not isinstance(caps, dict) or not isinstance(caps.get("extensions"), list):
        return False, "card-extensions"
    matches = [
        item
        for item in caps["extensions"]
        if isinstance(item, dict) and item.get("uri") == IDENTITY_EXTENSION
    ]
    if len(matches) != 1:
        return False, "extension-count"
    extension = matches[0]
    if not isinstance(extension.get("required"), bool):
        return False, "extension-required"
    params = extension.get("params")
    if not isinstance(params, dict):
        return False, "extension-params"
    if FORBIDDEN.intersection(params):
        return False, "dynamic-trust-field"
    if set(params) - {"agent_did", "registry_did", "passport"}:
        return False, "unknown-param"
    if not is_did(params.get("agent_did")) or not is_did(params.get("registry_did")):
        return False, "identity-did"
    passport = params.get("passport")
    if passport is not None:
        if not isinstance(passport, dict):
            return False, "passport-object"
        if set(passport) - {"uri", "digest", "media_type", "profile"}:
            return False, "unknown-passport-field"
        if not absolute_http(passport.get("uri")):
            return False, "passport-uri"
        if not isinstance(passport.get("digest"), str) or not SHA256_URI.fullmatch(
            passport["digest"]
        ):
            return False, "passport-digest"
        if passport.get("media_type") not in {
            None,
            "application/vnd.cha2a.passport+json",
        }:
            return False, "passport-media-type"
    return True, "valid"


def canonical_json(value):
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False, separators=(",", ":"))
                + ":"
                + canonical_json(value[key])
                for key in sorted(value)
            )
            + "}"
        )
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def b64url_encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def check_card_signature(card, public_keys):
    signatures = card.get("signatures") if isinstance(card, dict) else None
    if not isinstance(signatures, list) or not signatures:
        return False, "signature_missing"
    unsigned = dict(card)
    unsigned.pop("signatures", None)
    payload = b64url_encode(canonical_json(unsigned).encode("utf-8"))
    for signature in signatures:
        if not isinstance(signature, dict):
            continue
        protected = signature.get("protected")
        signature_value = signature.get("signature")
        if not isinstance(protected, str) or not isinstance(signature_value, str):
            continue
        try:
            header = json.loads(b64url_decode(protected).decode("utf-8"))
            if header.get("alg") != "EdDSA":
                continue
            kid = header.get("kid")
            if not isinstance(kid, str) or not kid.endswith("#agent-key"):
                continue
            jwk = public_keys.get(kid) if isinstance(public_keys, dict) else None
            if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                continue
            public_key = Ed25519PublicKey.from_public_bytes(
                b64url_decode(jwk.get("x", ""))
            )
            public_key.verify(
                b64url_decode(signature_value),
                (protected + "." + payload).encode("ascii"),
            )
            return True, "valid"
        except Exception:
            continue
    return False, "signature_invalid"


def normalize_registry(raw):
    if not isinstance(raw, dict):
        return {"state": "unknown", "timeBasis": "adapter-observation"}
    if raw.get("revoked") is True:
        state = "revoked"
    elif raw.get("state") in {"active", "suspended", "revoked", "expired", "unknown"}:
        state = raw["state"]
    elif raw.get("active") is True:
        state = "active"
    else:
        state = "unknown"
    time_basis = (
        "source" if isinstance(raw.get("observedAt"), str) else "adapter-observation"
    )
    return {"state": state, "timeBasis": time_basis}


def evaluate(case):
    kind = case.get("fixtureType")
    value = case.get("input", {})
    if kind == "agent-card":
        ok, detail = check_card(value.get("card"))
        return ("ACCEPT" if ok else "REJECT"), {"detail": detail}
    if kind == "card-signature":
        ok, detail = check_card_signature(
            value.get("card"),
            value.get("publicKeys", {}),
        )
        return ("ACCEPT" if ok else "REJECT"), {"detail": detail}
    if kind == "registry":
        result = normalize_registry(value.get("raw"))
        return "ACCEPT", result
    if kind == "identity-chain":
        ok = True
        ok = ok and value.get("agentDid") == value.get("passportSubject")
        ok = ok and value.get("cardRegistryDid") == value.get("statusRegistryDid")
        ok = ok and value.get("digestExpected") == value.get("digestActual")
        ok = ok and value.get("statusState") == "active"
        return ("ACCEPT" if ok else "REJECT"), {
            "state": value.get("statusState")
        }
    if kind == "federation":
        source = value.get("source", "")
        peers = value.get("peers", [])
        ok = False
        if value.get("localRegistered"):
            ok = source == "local"
        elif source.startswith("peer:") and source[5:] in peers:
            ok = value.get("upstream") == "ok"
        return ("ACCEPT" if ok else "REJECT"), {
            "source": source,
            "state": value.get("state"),
        }
    return "REJECT", {"detail": "unknown-fixture-type"}


def verify_manifest(directory, manifest):
    line = manifest.read_text(encoding="utf-8").strip().splitlines()
    if len(line) != 1:
        raise SystemExit("registry-agent-card MANIFEST must contain one entry")
    expected, relative = line[0].split(None, 1)
    relative = relative.lstrip("*")
    actual = hashlib.sha256((directory / relative).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit("registry-agent-card MANIFEST mismatch")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--manifest")
    args = parser.parse_args()
    directory = Path(args.directory)
    if args.manifest:
        verify_manifest(directory, Path(args.manifest))
    cases = json.loads((directory / "vectors.json").read_text(encoding="utf-8"))
    failures = 0
    for case in cases:
        verdict, result = evaluate(case)
        expected = case.get("expected", {})
        ok = verdict == expected.get("verdict")
        for key, value in expected.items():
            if key != "verdict":
                ok = ok and result.get(key) == value
        if not ok:
            failures += 1
        print(
            json.dumps(
                {
                    "name": case["name"],
                    "verdict": verdict,
                    "result": result,
                    "pass": ok,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
    print(f"PASS {len(cases) - failures}/{len(cases)}")
    raise SystemExit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()
