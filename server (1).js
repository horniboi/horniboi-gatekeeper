"use strict";
/*
 * Proof Gatekeeper agent — zkVerify Agent Games, Season 01.
 *
 * Protocol (from https://agentgames.zkverify.io/build + /rules + measured circuit semantics):
 *  - Platform POSTs signed tasks to the registered endpoint (POST /agent).
 *  - Every request/response is HMAC-signed: header `x-agent-games-signature` over the RAW body.
 *  - Per task: decide APPROVE/REJECT deterministically, generate a Groth16 proof locally
 *    (snarkjs, bundled gatekeeper.wasm + gatekeeper_final.zkey), return
 *    { decision, reason_code, proof, public_signals, proof_tx } signed.
 *  - The circuit itself asserts decision == computed validity (measured), so an honest
 *    decision is always provable — except PROOF_REUSED-only rejects, which are unprovable
 *    by design and are answered without a proof (event page exempts them).
 *
 * Secrets come ONLY from env: AGENT_GAMES_HMAC_SECRET (platform "Rotate Secret"),
 * KURIER_API_KEY (optional). Nothing is logged that contains a secret.
 */
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const PORT = process.env.PORT || 8080;
const SECRET_RAW = process.env.AGENT_GAMES_HMAC_SECRET || "";
const KURIER_API_KEY = process.env.KURIER_API_KEY || "";
const KURIER_URL = "https://api.kurier.xyz/api/v1";
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const PRIME = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617"); // BN254 scalar field
const SEEN_PATH = process.env.SEEN_PATH || path.join(__dirname, "data", "seen.json");
const _artDir = require("fs").existsSync(path.join(__dirname, "artifacts", "gatekeeper.wasm")) ? path.join(__dirname, "artifacts") : __dirname;
const WASM = path.join(_artDir, "gatekeeper.wasm");
const ZKEY = path.join(_artDir, "gatekeeper_final.zkey");
const DEADLINE_MS = 50000; // hard guard; platform deadline is 60 s

if (!SECRET_RAW) console.error("[boot] WARNING: AGENT_GAMES_HMAC_SECRET is not set — all signed requests will fail verification.");

/* ---------------- HMAC helpers ----------------
 * The platform's secret is a 32-byte value shown once as plaintext (likely hex).
 * Verification is tolerant: tries the secret as a hex-decoded key and as a UTF-8 key,
 * and accepts a bare hex digest or a `sha256=<hex>` prefixed one.
 * Signing uses ONE primary form (hex-decoded key if the secret is 64-hex, else UTF-8; bare hex digest).
 * If preflight fails on signature format, flip HMAC_SIGN_MODE / check practice feedback. */
const keyCandidates = [];
if (/^[0-9a-fA-F]{64}$/.test(SECRET_RAW)) keyCandidates.push(Buffer.from(SECRET_RAW, "hex"));
if (SECRET_RAW) keyCandidates.push(Buffer.from(SECRET_RAW, "utf8"));
/* Signing key: the platform is a JS service that holds the secret as the exact
 * text string it displayed; it verifies response signatures with that string as
 * the (UTF-8) HMAC key. (First live preflight, 15 Nov 14:14 WIB, failed with the
 * hex-decoded key as signer while request verification accepted both forms.) */
const SIGN_KEY = SECRET_RAW ? Buffer.from(SECRET_RAW, "utf8") : Buffer.alloc(0);

function hmacHex(key, raw) {
  return crypto.createHmac("sha256", key).update(raw).digest("hex");
}
function verifySignature(rawBody, headerValue) {
  if (!headerValue || !keyCandidates.length) return false;
  const presented = String(headerValue).trim().replace(/^sha256=/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(presented)) return false;
  const p = Buffer.from(presented, "hex");
  return keyCandidates.some((k) => {
    const d = crypto.createHmac("sha256", k).update(rawBody).digest();
    return d.length === p.length && crypto.timingSafeEqual(d, p);
  });
}
function signBody(rawBody) {
  return hmacHex(SIGN_KEY, rawBody);
}

/* ---------------- Field encodings (see FEASIBILITY.md §4 — practice-mode unknowns) ---------------- */
function fromHexField(hex) {
  const v = BigInt(hex);
  return (v % PRIME).toString();
}
function encodeTaskId(taskId) {
  // UNKNOWN — default: sha256(utf8(task_id)) mod prime. One-line fix after practice feedback.
  const h = crypto.createHash("sha256").update(String(taskId), "utf8").digest("hex");
  return (BigInt("0x" + h) % PRIME).toString();
}
function deriveSalt(taskId) {
  // Deterministic per task: platform retries (same task_id) reproduce the identical proof.
  const h = crypto.createHmac("sha256", SIGN_KEY).update("salt:" + String(taskId)).digest("hex");
  return (BigInt("0x" + h) % PRIME).toString();
}

/* ---------------- Seen-set (PROOF_REUSED) ---------------- */
let seen = new Set();
try {
  if (fs.existsSync(SEEN_PATH)) seen = new Set(JSON.parse(fs.readFileSync(SEEN_PATH, "utf8")));
} catch (e) { console.error("[boot] seen-set load failed:", e.message); }
function persistSeen() {
  try {
    fs.mkdirSync(path.dirname(SEEN_PATH), { recursive: true });
    const tmp = SEEN_PATH + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify([...seen]));
    fs.renameSync(tmp, SEEN_PATH);
  } catch (e) { console.error("[seen] persist failed:", e.message); }
}

/* ---------------- Decision logic (FEASIBILITY.md §3) ---------------- */
function evaluate(input) {
  // Returns { decision, reason, circuitInputs } — checks in priority order.
  const registeredVkHash = fromHexField(input.registered_vk);
  const proofVkHash = fromHexField(input.proof_vk);
  const minimum = BigInt(input.minimum);
  const publicBalance = BigInt(input.public_balance);
  const expiryBlock = BigInt(input.expiry_block);
  const currentBlock = BigInt(input.current_block);
  const recipient = BigInt(input.recipient);
  const conditionRecipient = BigInt(input.condition_recipient);
  const amount = BigInt(input.amount);
  const maxTransfer = BigInt(input.max_transfer);

  let decision = "APPROVE", reason = "VALID_CONDITION";
  if (proofVkHash !== registeredVkHash) { decision = "REJECT"; reason = "VK_SUBSTITUTION"; }
  else if (publicBalance < minimum) { decision = "REJECT"; reason = "THRESHOLD_MISMATCH"; }
  else if (currentBlock >= expiryBlock) { decision = "REJECT"; reason = "EXPIRED_CONDITION"; } // measured: == is expired
  else if (recipient !== conditionRecipient) { decision = "REJECT"; reason = "RECIPIENT_MISMATCH"; }
  else if (amount > maxTransfer) { decision = "REJECT"; reason = "AMOUNT_OVERFLOW"; }

  return {
    decision, reason,
    fields: {
      registeredVkHash, proofVkHash,
      minimum: minimum.toString(), publicBalance: publicBalance.toString(),
      expiryBlock: expiryBlock.toString(), currentBlock: currentBlock.toString(),
      recipient: recipient.toString(), conditionRecipient: conditionRecipient.toString(),
      amount: amount.toString(), maxTransfer: maxTransfer.toString(),
    },
  };
}

/* ---------------- Proving ---------------- */
async function prove(taskId, fields, decision) {
  const input = {
    taskId: encodeTaskId(taskId),
    salt: deriveSalt(taskId),
    registeredVkHash: fields.registeredVkHash,
    proofVkHash: fields.proofVkHash,
    minimum: fields.minimum,
    publicBalance: fields.publicBalance,
    expiryBlock: fields.expiryBlock,
    currentBlock: fields.currentBlock,
    recipient: fields.recipient,
    conditionRecipient: fields.conditionRecipient,
    amount: fields.amount,
    maxTransfer: fields.maxTransfer,
    decision: decision === "APPROVE" ? "1" : "0",
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  return { proof, publicSignals };
}

/* ---------------- Kurier (optional, never blocks past budget) ---------------- */
async function kurierFinalize(proof, publicSignals, budgetMs) {
  if (!KURIER_API_KEY) return null;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), budgetMs);
  try {
    const res = await fetch(`${KURIER_URL}/submit-proof/${KURIER_API_KEY}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: ctrl.signal,
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: VK_HASH },
      }),
    });
    const job = await res.json();
    if (!job.jobId) return null;
    const deadline = Date.now() + budgetMs;
    while (Date.now() < deadline) {
      const s = await fetch(`${KURIER_URL}/job-status/${KURIER_API_KEY}/${job.jobId}`, { signal: ctrl.signal });
      const st = await s.json();
      if (st.status === "Finalized") return st.txHash || null;
      if (st.status === "Failed") return null;
      await new Promise((r) => setTimeout(r, 2000));
    }
    return null;
  } catch (e) {
    return null; // Kurier is evidence/belt-and-braces; the response proof is the scored artifact.
  } finally { clearTimeout(timer); }
}

/* ---------------- Task handling ---------------- */
const responseCache = new Map(); // task_id -> raw signed response {body, sig}
let stats = { tasks: 0, approved: 0, rejected: 0, proofs: 0, reused: 0, startedAt: new Date().toISOString() };

async function handleTask(env) {
  const taskId = env.task_id;
  if (responseCache.has(taskId)) return responseCache.get(taskId);
  const input = env.input || {};
  const proofTx = String(input.proof_tx || "");
  const ev = evaluate(input);
  const isReused = proofTx && seen.has(proofTx.toLowerCase());

  let decision = ev.decision, reason = ev.reason, proof = null, publicSignals = null;
  if (isReused && ev.decision === "APPROVE") {
    // Reuse-only reject: unprovable by design (circuit would assert decision=1). No proof.
    decision = "REJECT"; reason = "PROOF_REUSED"; stats.reused++;
  } else {
    if (isReused && ev.decision === "REJECT") { /* keep circuit-trap reason; proof still generated */ }
    const p = await prove(taskId, ev.fields, decision);
    proof = p.proof; publicSignals = p.publicSignals; stats.proofs++;
    // Optional Kurier finalize with whatever budget remains (best effort, result not required).
    await kurierFinalize(proof, publicSignals, 15000).catch(() => null);
  }

  if (proofTx) { seen.add(proofTx.toLowerCase()); persistSeen(); }
  stats.tasks++; if (decision === "APPROVE") stats.approved++; else stats.rejected++;

  const bodyObj = { decision, reason_code: reason, proof_tx: input.proof_tx ?? null };
  if (proof) { bodyObj.proof = proof; bodyObj.public_signals = publicSignals; }
  const body = JSON.stringify(bodyObj);
  const signed = { body, sig: signBody(body) };
  responseCache.set(taskId, signed);
  console.log(`[task] ${taskId} -> ${decision} ${reason} proof=${proof ? "yes" : "no"}`);
  return signed;
}

function sendSigned(res, body, sig, code = 200) {
  res.writeHead(code, { "content-type": "application/json", "x-agent-games-signature": sig });
  res.end(body);
}
function sendJson(res, obj, code = 200, sign = true) {
  const body = JSON.stringify(obj);
  if (sign) return sendSigned(res, body, signBody(body), code);
  res.writeHead(code, { "content-type": "application/json" });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (req.method === "GET" && (url.pathname === "/health" || url.pathname === "/")) {
    return sendJson(res, { ok: true, service: "proof-gatekeeper", ...stats }, 200, false);
  }
  if (req.method !== "POST" || url.pathname !== "/agent") {
    return sendJson(res, { error: "not found" }, 404, false);
  }
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
    // 1) HMAC over RAW body BEFORE parsing.
    if (!verifySignature(raw, req.headers["x-agent-games-signature"])) {
      console.log(`[auth] signature rejected (header ${req.headers["x-agent-games-signature"] ? "present" : "missing"}, body ${raw.length}B)`);
      return sendJson(res, { error: "bad signature" }, 401, false);
    }
    let env;
    try { env = JSON.parse(raw.toString("utf8")); } catch { return sendJson(res, { error: "bad json" }, 400, false); }

    // 2) Preflight handshake.
    if (env.type === "agent-games.preflight.v1") {
      const body = JSON.stringify({ ok: true, protocolVersion: "v1" });
      console.log("[preflight] request verified — sending signed v1 response");
      return sendSigned(res, body, signBody(body));
    }
    // 3) Gatekeeper task — with a fail-closed deadline guard.
    if (env.type === "agent-games.proof-gatekeeper.v1") {
      const guard = new Promise((resolve) => setTimeout(() => resolve("TIMEOUT"), DEADLINE_MS));
      try {
        const out = await Promise.race([handleTask(env), guard]);
        if (out === "TIMEOUT") throw new Error("deadline guard");
        return sendSigned(res, out.body, out.sig);
      } catch (e) {
        console.error("[task] fail-closed:", e.message);
        const body = JSON.stringify({ decision: "REJECT", reason_code: "INTERNAL_ERROR", proof_tx: env.input?.proof_tx ?? null });
        return sendSigned(res, body, signBody(body));
      }
    }
    return sendJson(res, { error: "unknown type" }, 400, false);
  });
});

server.listen(PORT, async () => {
  console.log(`[boot] proof-gatekeeper listening on :${PORT} (kurier=${KURIER_API_KEY ? "on" : "off"}, seen=${seen.size})`);
  // Warm the prover so the first scored task doesn't pay cold-start.
  try {
    const t = Date.now();
    await prove("warmup", {
      registeredVkHash: "5", proofVkHash: "5", minimum: "1", publicBalance: "2",
      expiryBlock: "10", currentBlock: "1", recipient: "7", conditionRecipient: "7",
      amount: "1", maxTransfer: "2",
    }, "APPROVE");
    console.log(`[boot] prover warm in ${Date.now() - t} ms`);
  } catch (e) { console.error("[boot] warmup failed:", e.message); }
});
