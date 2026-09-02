#!/usr/bin/env node
/**
 * did:cha2a conformance 参考验证器 2（Node，独立实现——与 Python 验证器互锁）
 * 覆盖：§3.1 did-syntax / §4.5 outbound-sig / §5.2 discovery
 * 用法：node verify.mjs <fixtures_dir> [--manifest MANIFEST.sha256]
 * 输出：每向量 PASS/FAIL + 汇总（格式与 Python 验证器一致，供 parity 比较）
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

// ---- §3.1 ABNF（独立正则实现） ----
const TYPE_RE = /^[a-z][a-z_]*$/;                       // ALPHA-LOWER *(ALPHA-LOWER/_)
const ID_CHAR = "A-Za-z0-9._~-";
const ID_RE = new RegExp(`^[${ID_CHAR}]+(:[${ID_CHAR}]+)*$`);

function checkDidSyntax(did) {
  if (typeof did !== "string" || !did.startsWith("did:cha2a:")) return false;
  let rest = did.slice("did:cha2a:".length);
  if (rest.includes("#")) {
    const [r, frag] = rest.split("#", 2);
    if (!new RegExp(`^[${ID_CHAR}]+$`).test(frag)) return false;
    rest = r;
  }
  const parts = rest.split(":");
  if (parts.length < 2) return false;
  const t = parts[0], rid = parts.slice(1).join(":");
  if (!TYPE_RE.test(t)) return false;
  if (!ID_RE.test(rid)) return false;
  return true;
}

// ---- §4.5 Ed25519 验签（raw 32B → SPKI DER，node:crypto） ----
function rawToSpkiDer(rawHex) {
  // Ed25519 SPKI 前缀：302a300506032b6570032100
  return Buffer.from("302a300506032b6570032100" + rawHex, "hex");
}

function verifyEd25519(pkHex, msg, sigHex) {
  try {
    const key = crypto.createPublicKey({
      key: rawToSpkiDer(pkHex), format: "der", type: "spki",
    });
    return crypto.verify(null, Buffer.from(msg, "utf8"), key, Buffer.from(sigHex, "hex"));
  } catch {
    return false;
  }
}

// ---- §5.2 discovery 结构 ----
function checkDiscovery(doc) {
  if (!doc || typeof doc !== "object") return false;
  if (!doc.registryDid || !doc.supportedMethods || !doc.publicKeys) return false;
  if (!Array.isArray(doc.publicKeys) || doc.publicKeys.length === 0) return false;
  return true;
}

// ---- 逐向量判定（与 Python 验证器语义一致，独立实现） ----

// ---- §4.6 L0-L4 判定（独立实现） ----
const PREDICATE_SUBJECT = {
  "identity-anchor": ["agent"], "owner-binding": ["agent"],
  "number-binding": ["agent"], "delegation": ["agent"],
  "number-range-grant": ["org"],
};

function computeLevel(metadata, verifiedBy, registeredVerifiers, revoked) {
  if (revoked) return 0;
  let lv = 0;
  if (metadata.contentIdentity || metadata.contentHash) lv = 1;
  if (lv >= 1 && metadata.author) lv = 2;
  if (lv >= 2 && metadata.publisher) lv = 3;
  if (lv >= 3) {
    const entries = (verifiedBy || []).filter(
      (v) => registeredVerifiers.includes(v.verifier) && v.evidenceRef);
    const distinct = new Set(entries.map((v) => v.verifier));
    if (distinct.size >= 2) lv = 4;
  }
  return lv;
}

function checkEvidence(subject, ev) {
  if (!ev.predicateType || !ev.verifier || !ev.result) return [false, "缺必填字段"];
  if (!ev.evidenceRef) return [false, "缺 evidenceRef"];
  const parts2 = ev.predicateType.replace(/\/$/, "").split("/");
  const pt = parts2.length >= 2 ? parts2[parts2.length - 2] : parts2[parts2.length - 1]; // .../predicate/<name>/v1
  const parts = subject.split(":");
  const subjType = parts.length > 2 ? parts[2] : "";
  const allowed = PREDICATE_SUBJECT[pt] || [];
  if (allowed.length && !allowed.includes(subjType)) return [false, `predicate ${pt} 不允许 subject ${subjType}`];
  return [true, ""];
}


// ---- §4.1-4.4 CRUD + §5 DID 文档（独立实现） ----
const VALID_TYPES = new Set(["registry","authority","publisher","agent","skill","package",
  "org","provider","verifier","mcp_server","ai_tool","llm"]);

function checkDidDoc(doc) {
  if (!doc || typeof doc !== "object") return [false, "非对象"];
  if (!doc.id) return [false, "缺 id"];
  const ctx = Array.isArray(doc["@context"]) ? doc["@context"] : [doc["@context"]];
  if (!ctx.some((c) => String(c).includes("w3.org/ns/did/v1"))) return [false, "缺 @context did/v1"];
  if (!Array.isArray(doc.verificationMethod) || !doc.verificationMethod.length) return [false, "缺 verificationMethod"];
  for (const m of doc.verificationMethod) {
    if (m.type !== "Ed25519VerificationKey2020") return [false, "密钥类型非 Ed25519"];
    if (!m.controller || !m.publicKeyMultibase) return [false, "controller/publicKeyMultibase 缺失"];
  }
  return [true, ""];
}

function evalCrud(fx) {
  const kind = fx.fixtureType, inp = fx.input || {};
  const exp = (fx.expected || {}).verdict;
  const reg = (fx.verifierState || {}).registeredResources || [];
  if (kind === "create") {
    const t = inp.type || "", rid = inp.id || "";
    let ok = !!(t && rid);
    if (ok && reg.includes(`did:cha2a:${t}:${rid}`)) ok = false;
    if (ok && !VALID_TYPES.has(t)) ok = false;
    if (ok && !checkDidSyntax(`did:cha2a:${t}:${rid}`)) ok = false;
    const v = ok ? "ACCEPT" : "REJECT";
    return [v === exp ? "PASS" : "FAIL", v, `expect=${exp}`];
  }
  if (kind === "resolve") {
    const did = inp.did || "";
    if (!checkDidSyntax(did)) return ["REJECT" === exp ? "PASS" : "FAIL", "REJECT", "syntax"];
    if (inp.deactivated) return ["REJECT" === exp ? "PASS" : "FAIL", "REJECT", "deactivated"];
    const ok = reg.includes(did);
    const v = ok ? "ACCEPT" : "REJECT";
    return [v === exp ? "PASS" : "FAIL", v, `registered=${ok}`];
  }
  if (kind === "update") {
    const ok = reg.includes(inp.did || "");
    const v = ok ? "ACCEPT" : "REJECT";
    return [v === exp ? "PASS" : "FAIL", v, `registered=${ok}`];
  }
  if (kind === "did-doc") {
    const [ok, det] = checkDidDoc(inp.document);
    const v = ok ? "ACCEPT" : "REJECT";
    return [v === exp ? "PASS" : "FAIL", v, `${det} expect=${exp}`];
  }
  return null;
}

function evalFixture(fx) {
  const crud = evalCrud(fx);
  if (crud) return crud;
  const kind = fx.fixtureType, inp = fx.input || {};
  const exp = (fx.expected || {}).verdict;
  let ok = false;
  if (kind === "did-syntax") {
    ok = checkDidSyntax(inp.did);
  } else if (kind === "outbound-sig") {
    ok = verifyEd25519(inp.publicKeyHex || "", inp.message || "", inp.signatureHex || "");
  } else if (kind === "discovery") {
    ok = checkDiscovery(inp.document);
  } else if (kind === "level") {
    const lv = computeLevel(inp.metadata || {}, inp.verifiedBy || [],
      (fx.verifierState || {}).registeredVerifiers || [], Boolean(inp.revoked));
    const expLevel = (fx.expected || {}).level;
    const m = lv === expLevel;
    return [m ? "PASS" : "FAIL", m ? "ACCEPT" : "REJECT", `level=${lv} expect=${expLevel}`];
  } else if (kind === "evidence") {
    const [okE, det] = checkEvidence(inp.subject || "", inp);
    const v = okE ? "ACCEPT" : "REJECT";
    return [v === exp ? "PASS" : "FAIL", v, `${det} expect=${exp}`];
  } else if (kind === "revocation") {
    const v = Boolean(inp.revoked) ? "ACCEPT" : "REJECT";
    return [v === exp ? "PASS" : "FAIL", v, `revoked=${inp.revoked}`];
  } else {
    return ["SKIP", "", "未知 fixtureType"];
  }
  const verdict = ok ? "ACCEPT" : "REJECT";
  const match = verdict === exp;
  return [match ? "PASS" : "FAIL", verdict, `expect=${exp}`];
}

function checkManifest(fixDir, manifestPath) {
  if (!manifestPath || !fs.existsSync(manifestPath)) {
    console.log("  [warn] MANIFEST.sha256 不存在（未校验字节钉住）");
    return;
  }
  let bad = 0;
  for (const line of fs.readFileSync(manifestPath, "utf8").split("\n")) {
    const l = line.trim();
    if (!l) continue;
    const [sha, file] = l.split(/\s+/);
    const full = path.join(fixDir, path.basename(file));
    if (fs.existsSync(full)) {
      const got = crypto.createHash("sha256").update(fs.readFileSync(full)).digest("hex");
      if (got !== sha) { console.log(`  [FAIL] MANIFEST 不匹配: ${file}`); bad++; }
    }
  }
  if (bad) process.exit(2);
}

function main() {
  const fixDir = process.argv[2] || path.join(path.dirname(new URL(import.meta.url).pathname), "..", "..", "fixtures");
  const mi = process.argv.indexOf("--manifest");
  const manifest = mi > -1 ? process.argv[mi + 1] : null;
  const files = fs.readdirSync(fixDir).filter((f) => f.endsWith(".json")).sort();
  if (!files.length) { console.log("无 fixtures"); process.exit(1); }
  checkManifest(fixDir, manifest);
  let passed = 0, failed = 0, skipped = 0;
  for (const fn of files) {
    const fx = JSON.parse(fs.readFileSync(path.join(fixDir, fn), "utf8"));
    const [status, verdict, detail] = evalFixture(fx);
    if (status === "SKIP") { skipped++; console.log(`[SKIP] ${fn} (${detail})`); }
    else if (status === "PASS") { passed++; console.log(`[PASS] ${fn} -> ${verdict}`); }
    else { failed++; console.log(`[FAIL] ${fn} -> ${verdict} (${detail})`); }
  }
  console.log(`\n汇总: ${passed} PASS / ${failed} FAIL / ${skipped} SKIP（共 ${files.length}）`);
  process.exit(failed ? 1 : 0);
}

main();
