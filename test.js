"use strict";
/* Local test harness: synthetic tasks for every trap type + preflight + HMAC + idempotency.
 * Run: AGENT_GAMES_HMAC_SECRET=<test> node test.js   (spawns server.js on a test port) */
const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const PORT = 18099;
const SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // 64-hex test secret
const KEY = Buffer.from(SECRET, "hex");
const VK = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "work", "vk_gatekeeper.json"), "utf8"));

const sign = (raw) => crypto.createHmac("sha256", KEY).update(raw).digest("hex");
let failures = 0;
function check(name, cond, extra = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? " — " + extra : ""}`);
  if (!cond) failures++;
}
async function post(obj, { badSig = false } = {}) {
  const raw = JSON.stringify(obj);
  const res = await fetch(`http://127.0.0.1:${PORT}/agent`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": badSig ? "0".repeat(64) : sign(raw) },
    body: raw,
  });
  const bodyText = await res.text();
  return { status: res.status, bodyText, json: JSON.parse(bodyText), sig: res.headers.get("x-agent-games-signature") };
}
const BASE = {
  registered_vk: "0x1111111111111111111111111111111111111111111111111111111111111111",
  proof_vk: "0x1111111111111111111111111111111111111111111111111111111111111111",
  minimum: "1000", public_balance: "1460",
  expiry_block: 19842201, current_block: 19832000,
  recipient: "0xDe429f0100000000000000000000000000000001",
  condition_recipient: "0xDe429f0100000000000000000000000000000001",
  amount: "500", max_transfer: "1000",
  proof_tx: "0xa4c1000000000000000000000000000000000000000000000000000000000001",
};
let seq = 0;
const task = (over = {}, txSuffix = null) => ({
  type: "agent-games.proof-gatekeeper.v1",
  task_id: "gk_test_" + (++seq),
  mode: "competition",
  issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60000).toISOString(),
  input: { ...BASE, ...over, ...(txSuffix ? { proof_tx: "0xa4c1" + txSuffix.padStart(60, "0") } : {}) },
});
async function verifyProof(r) {
  if (!r.json.proof) return false;
  return snarkjs.groth16.verify(VK, r.json.public_signals, r.json.proof);
}

(async () => {
  const seenFile = path.join(__dirname, "data", "seen.json");
  fs.rmSync(seenFile, { force: true });
  const srv = spawn("node", ["server.js"], {
    cwd: __dirname,
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, SEEN_PATH: seenFile },
    stdio: ["ignore", "pipe", "pipe"],
  });
  srv.stderr.on("data", (d) => process.stderr.write("[srv] " + d));
  await new Promise((r) => { srv.stdout.on("data", (d) => { if (String(d).includes("listening")) r(); }); });
  await new Promise((r) => setTimeout(r, 2500)); // warmup prove

  // health
  const h = await (await fetch(`http://127.0.0.1:${PORT}/health`)).json();
  check("health ok", h.ok === true);

  // preflight
  const pf = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
  check("preflight shape", pf.json.ok === true && pf.json.protocolVersion === "v1");
  check("preflight response signed", pf.sig === sign(pf.bodyText));

  // bad HMAC
  const bad = await post(task(), { badSig: true });
  check("bad HMAC -> 401", bad.status === 401);

  // VALID -> APPROVE + verified proof
  const valid = await post(task({}, "aa01"));
  check("VALID decision", valid.json.decision === "APPROVE" && valid.json.reason_code === "VALID_CONDITION");
  check("VALID proof verifies", await verifyProof(valid));
  check("VALID response signed", valid.sig === sign(valid.bodyText));

  // VK_SUBSTITUTION
  const vk = await post(task({ proof_vk: "0x2222222222222222222222222222222222222222222222222222222222222222" }, "aa02"));
  check("VK_SUBSTITUTION", vk.json.decision === "REJECT" && vk.json.reason_code === "VK_SUBSTITUTION" && (await verifyProof(vk)));

  // THRESHOLD_MISMATCH
  const th = await post(task({ public_balance: "999" }, "aa03"));
  check("THRESHOLD_MISMATCH", th.json.decision === "REJECT" && th.json.reason_code === "THRESHOLD_MISMATCH" && (await verifyProof(th)));

  // EXPIRED_CONDITION — boundary: current == expiry is expired (measured)
  const ex = await post(task({ current_block: 19842201 }, "aa04"));
  check("EXPIRED at ==expiry", ex.json.decision === "REJECT" && ex.json.reason_code === "EXPIRED_CONDITION" && (await verifyProof(ex)));

  // RECIPIENT_MISMATCH
  const rc = await post(task({ recipient: "0xDe429f0100000000000000000000000000000002" }, "aa05"));
  check("RECIPIENT_MISMATCH", rc.json.decision === "REJECT" && rc.json.reason_code === "RECIPIENT_MISMATCH" && (await verifyProof(rc)));

  // AMOUNT_OVERFLOW
  const am = await post(task({ amount: "1001" }, "aa06"));
  check("AMOUNT_OVERFLOW", am.json.decision === "REJECT" && am.json.reason_code === "AMOUNT_OVERFLOW" && (await verifyProof(am)));

  // PROOF_REUSED: reuse the VALID task's proof_tx with otherwise-valid fields
  const ru = await post(task({}, "aa01"));
  check("PROOF_REUSED (no proof)", ru.json.decision === "REJECT" && ru.json.reason_code === "PROOF_REUSED" && !ru.json.proof);

  // Idempotency: resend the exact VALID task_id -> identical body
  const again = await post(JSON.parse(JSON.stringify({ ...task({}, "aa01"), task_id: "gk_test_2" })));
  check("idempotent retry returns cached response", again.bodyText === valid.bodyText);

  srv.kill();
  console.log(failures === 0 ? "\nALL TESTS PASSED" : `\n${failures} FAILURES`);
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
