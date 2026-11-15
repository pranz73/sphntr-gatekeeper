"use strict";
/**
 * Proof Gatekeeper agent — zkVerify Agent Games (protocol v1)
 *
 * POST a signed task envelope, get a signed decision (+ Groth16 proof when provable).
 *
 * Envelope:  { type:"agent-games.proof-gatekeeper.v1", task_id, mode, issued_at, deadline_at,
 *              input:{ registered_vk, proof_vk, minimum, public_balance, expiry_block,
 *                      current_block, recipient, condition_recipient, amount, max_transfer, proof_tx } }
 * Request header:  x-agent-games-signature = HMAC-SHA256 hex of the RAW body, keyed with the agent secret.
 * Response:        { decision:"APPROVE"|"REJECT", reason_code, proof_tx, proof?, public_signals? }
 * Response header: x-agent-games-signature = HMAC-SHA256 hex of the RAW response body.
 * Health/preflight (any signed non-task POST): { ok:true, protocolVersion:"v1" }
 *
 * Env: PORT (default 8792), GATEKEEPER_HMAC_SECRET (agent HMAC secret; placeholder for local tests),
 *      GATEKEEPER_SEEN_FILE (default ./seen-proofs.json)
 */
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { decide, buildCircuitInputs, normHex } = require("./lib");

const PORT = parseInt(process.env.PORT || "8792", 10);
const SECRET = process.env.GATEKEEPER_HMAC_SECRET || "";
const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const WASM = path.join(__dirname, "circuits", "gatekeeper.wasm");
const ZKEY = path.join(__dirname, "circuits", "gatekeeper_final.zkey");
const SEEN_FILE = process.env.GATEKEEPER_SEEN_FILE || path.join(__dirname, "seen-proofs.json");

// ---------------------------------------------------------------- seen-set store
function loadSeen() {
  try {
    const j = JSON.parse(fs.readFileSync(SEEN_FILE, "utf8"));
    return new Set((j.seen || []).map((s) => String(s).toLowerCase()));
  } catch {
    return new Set();
  }
}
const seen = loadSeen();
function recordSeen(proofTx) {
  seen.add(normHex(proofTx));
  const tmp = SEEN_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify({ seen: [...seen] }, null, 2));
  fs.renameSync(tmp, SEEN_FILE);
}

// ---------------------------------------------------------------- HMAC helpers
function hmacHex(secret, raw) {
  return crypto.createHmac("sha256", secret).update(raw).digest("hex");
}
function signatureValid(secret, raw, headerValue) {
  if (!secret || !headerValue) return false;
  const expected = Buffer.from(hmacHex(secret, raw), "utf8");
  const given = Buffer.from(String(headerValue).trim().toLowerCase(), "utf8");
  return expected.length === given.length && crypto.timingSafeEqual(expected, given);
}

/**
 * Try to prove the decision. The circuit asserts the decision matches the checks,
 * so a wrong decision makes witness generation fail. On ANY proving failure we
 * fail closed: the caller still answers with decision + reason_code, but no proof.
 * (This is also the only possible path for PROOF_REUSED, a local-only check the
 * circuit cannot see: all circuit conditions hold there, so decision=0 cannot prove.)
 */
async function tryProve(task, decision) {
  try {
    const inputs = buildCircuitInputs(task, decision);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
    return { proof, publicSignals };
  } catch (e) {
    console.error(`[gatekeeper] proof failed for task ${task && task.task_id}: ${e.message || e}`);
    return null;
  }
}

// ---------------------------------------------------------------- HTTP plumbing
function sendSigned(res, status, obj) {
  const raw = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "x-agent-games-signature": hmacHex(SECRET, raw),
  });
  res.end(raw);
}

const server = http.createServer((req, res) => {
  if (req.method === "GET" && (req.url === "/health" || req.url === "/")) {
    // Unsigned liveness probe (handy for tunnel checks). The platform's signed
    // preflight is handled on POST below.
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, protocolVersion: "v1" }));
    return;
  }
  if (req.method !== "POST") {
    res.writeHead(405, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "method_not_allowed" }));
    return;
  }
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
    // 1) Verify the signature over the RAW body BEFORE parsing anything.
    if (!signatureValid(SECRET, raw, req.headers["x-agent-games-signature"])) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_signature" }));
      return;
    }
    let body;
    try {
      body = JSON.parse(raw.toString("utf8"));
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_json" }));
      return;
    }
    // 2) Signed preflight / health check: anything that is not a task envelope.
    if (!body || body.type !== TASK_TYPE) {
      sendSigned(res, 200, { ok: true, protocolVersion: "v1" });
      return;
    }
    // 3) Task flow.
    const task = body;
    try {
      const { decision, reason_code } = decide(task.input || {}, seen);
      const proved = await tryProve(task, decision);
      const out = { decision, reason_code, proof_tx: task.input.proof_tx };
      if (proved) {
        out.proof = proved.proof;
        out.public_signals = proved.publicSignals;
        // Record every accepted (approved + proven) proof_tx against replay.
        if (decision === "APPROVE") recordSeen(task.input.proof_tx);
      }
      sendSigned(res, 200, out);
    } catch (e) {
      console.error(`[gatekeeper] task error: ${e.message || e}`);
      // Fail closed: reject without a proof rather than crash or approve.
      try {
        sendSigned(res, 200, { decision: "REJECT", reason_code: "INVALID_INPUT", proof_tx: task.input && task.input.proof_tx });
      } catch {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "internal_error" }));
      }
    }
  });
});

server.listen(PORT, () => {
  console.log(`[gatekeeper] listening on :${PORT} (seen-set: ${SEEN_FILE}, ${seen.size} entries)`);
});
