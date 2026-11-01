# Registry / Passport / Agent Card Profile Vectors

Status: draft v0.1, independent from the 68 did:cha2a method vectors.

This suite tests the L4 profiles:

- Registry observations used by Passport verification;
- A2A Agent Card CHA2A identity extension;
- Card, Passport and Registry binding;
- explicit-peer revocation and fail-closed behavior.

## Vectors

`vectors.json` contains 15 cases:

- Agent Card positive and negative validation;
- Agent Card EdDSA signature and tamper rejection;
- active, unknown and revoked Registry observations;
- Card/Passport subject, digest and Registry DID binding;
- explicit peer revocation;
- unavailable peer and implicit peer rejection.

Eight cases are rejection cases.

## Run

```bash
python3 registry-agent-card/verify.py registry-agent-card \
  --manifest registry-agent-card/MANIFEST.sha256
node registry-agent-card/verify.mjs registry-agent-card \
  --manifest registry-agent-card/MANIFEST.sha256
python3 registry-agent-card/parity.py
```

The suite is deliberately outside `fixtures/` so the existing did:cha2a method
count, version checks and coverage matrix remain unchanged.

## Boundary

These vectors test Profile semantics. They do not verify a live Registry, fetch
a network Agent Card, verify an A2A Card signature, or establish external
operator recognition.
