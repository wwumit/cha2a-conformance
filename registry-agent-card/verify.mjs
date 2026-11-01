#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const IDENTITY_EXTENSION = "urn:cha2a:ext:agent-identity:v1";
const SHA256_URI = /^sha256:[0-9a-f]{64}$/;
const FORBIDDEN = new Set(["trust_level", "trustLevel", "revoked", "admission", "rating"]);

function isDid(value) {
  return typeof value === "string" && value.startsWith("did:") && value.split(":").length >= 3;
}

function absoluteHttp(value) {
  return typeof value === "string" && (value.startsWith("http://") || value.startsWith("https://"));
}

function checkCard(card) {
  if (!card || typeof card !== "object" || Array.isArray(card)) return [false, "card-object"];
  for (const name of ["name", "description", "version"]) {
    if (typeof card[name] !== "string" || !card[name]) return [false, "card-required"];
  }
  if (!Array.isArray(card.supported_interfaces)) return [false, "card-interfaces"];
  const caps = card.capabilities;
  if (!caps || typeof caps !== "object" || !Array.isArray(caps.extensions)) return [false, "card-extensions"];
  const matches = caps.extensions.filter((item) => item && item.uri === IDENTITY_EXTENSION);
  if (matches.length !== 1) return [false, "extension-count"];
  const extension = matches[0];
  if (typeof extension.required !== "boolean") return [false, "extension-required"];
  const params = extension.params;
  if (!params || typeof params !== "object" || Array.isArray(params)) return [false, "extension-params"];
  if ([...FORBIDDEN].some((name) => Object.hasOwn(params, name))) return [false, "dynamic-trust-field"];
  if (Object.keys(params).some((name) => !["agent_did", "registry_did", "passport"].includes(name))) {
    return [false, "unknown-param"];
  }
  if (!isDid(params.agent_did) || !isDid(params.registry_did)) return [false, "identity-did"];
  const passport = params.passport;
  if (passport !== undefined) {
    if (!passport || typeof passport !== "object" || Array.isArray(passport)) return [false, "passport-object"];
    if (Object.keys(passport).some((name) => !["uri", "digest", "media_type", "profile"].includes(name))) {
      return [false, "unknown-passport-field"];
    }
    if (!absoluteHttp(passport.uri)) return [false, "passport-uri"];
    if (passport.digest !== undefined && !SHA256_URI.test(passport.digest)) return [false, "passport-digest"];
    if (passport.media_type !== undefined && passport.media_type !== "application/vnd.cha2a.passport+json") {
      return [false, "passport-media-type"];
    }
  }
  return [true, "valid"];
}

function canonicalJson(value) {
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map(
      (key) => JSON.stringify(key) + ":" + canonicalJson(value[key]),
    ).join(",") + "}";
  }
  return JSON.stringify(value);
}

function b64urlEncode(value) {
  return Buffer.from(value).toString("base64url");
}

function checkCardSignature(card, publicKeys) {
  const signatures = card && Array.isArray(card.signatures) ? card.signatures : [];
  if (!signatures.length) return [false, "signature_missing"];
  const unsigned = { ...card };
  delete unsigned.signatures;
  const payload = b64urlEncode(canonicalJson(unsigned));
  for (const signature of signatures) {
    if (!signature || typeof signature !== "object") continue;
    try {
      const header = JSON.parse(Buffer.from(signature.protected, "base64url").toString("utf8"));
      if (header.alg !== "EdDSA") continue;
      const jwk = publicKeys && publicKeys[header.kid];
      if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519") continue;
      const publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
      const ok = crypto.verify(
        null,
        Buffer.from(signature.protected + "." + payload, "ascii"),
        publicKey,
        Buffer.from(signature.signature, "base64url"),
      );
      if (ok) return [true, "valid"];
    } catch {
      continue;
    }
  }
  return [false, "signature_invalid"];
}

function normalizeRegistry(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { state: "unknown", timeBasis: "adapter-observation" };
  }
  let state;
  if (raw.revoked === true) state = "revoked";
  else if (["active", "suspended", "revoked", "expired", "unknown"].includes(raw.state)) state = raw.state;
  else if (raw.active === true) state = "active";
  else state = "unknown";
  return {
    state,
    timeBasis: typeof raw.observedAt === "string" ? "source" : "adapter-observation",
  };
}

function evaluate(item) {
  const value = item.input || {};
  if (item.fixtureType === "agent-card") {
    const [ok, detail] = checkCard(value.card);
    return [ok ? "ACCEPT" : "REJECT", { detail }];
  }
  if (item.fixtureType === "card-signature") {
    const [ok, detail] = checkCardSignature(value.card, value.publicKeys || {});
    return [ok ? "ACCEPT" : "REJECT", { detail }];
  }
  if (item.fixtureType === "registry") {
    return ["ACCEPT", normalizeRegistry(value.raw)];
  }
  if (item.fixtureType === "identity-chain") {
    const ok = value.agentDid === value.passportSubject &&
      value.cardRegistryDid === value.statusRegistryDid &&
      value.digestExpected === value.digestActual &&
      value.statusState === "active";
    return [ok ? "ACCEPT" : "REJECT", { state: value.statusState }];
  }
  if (item.fixtureType === "federation") {
    const peers = value.peers || [];
    let ok = false;
    if (value.localRegistered) ok = value.source === "local";
    else if (String(value.source || "").startsWith("peer:") && peers.includes(value.source.slice(5))) {
      ok = value.upstream === "ok";
    }
    return [ok ? "ACCEPT" : "REJECT", { source: value.source, state: value.state }];
  }
  return ["REJECT", { detail: "unknown-fixture-type" }];
}

function verifyManifest(directory, manifest) {
  const lines = fs.readFileSync(manifest, "utf8").trim().split(/\r?\n/);
  if (lines.length !== 1) throw new Error("registry-agent-card MANIFEST must contain one entry");
  const [expected, rawName] = lines[0].trim().split(/\s+/, 2);
  const relative = rawName.replace(/^\*/, "");
  const actual = crypto.createHash("sha256").update(fs.readFileSync(path.join(directory, relative))).digest("hex");
  if (actual !== expected) throw new Error("registry-agent-card MANIFEST mismatch");
}

const [directoryArg, ...rest] = process.argv.slice(2);
if (!directoryArg) throw new Error("vectors directory required");
const directory = path.resolve(directoryArg);
const manifestIndex = rest.indexOf("--manifest");
if (manifestIndex >= 0 && rest[manifestIndex + 1]) {
  verifyManifest(directory, path.resolve(rest[manifestIndex + 1]));
}
const cases = JSON.parse(fs.readFileSync(path.join(directory, "vectors.json"), "utf8"));
let failures = 0;
for (const item of cases) {
  const [verdict, result] = evaluate(item);
  let ok = verdict === item.expected.verdict;
  for (const [key, value] of Object.entries(item.expected)) {
    if (key !== "verdict") ok = ok && result[key] === value;
  }
  if (!ok) failures += 1;
  console.log(JSON.stringify({ name: item.name, verdict, result, pass: ok }));
}
console.log(`PASS ${cases.length - failures}/${cases.length}`);
if (failures) process.exit(1);
