"use strict";
/**
 * Local verification for the Proof Gatekeeper agent.
 * Part A: circuit-level tests with snarkjs (documented sample + every trap rule).
 * Part B: end-to-end HTTP tests against server.js (HMAC, health, decisions, seen-set).
 * Run: node test.js   (output is tee'd to test-results.txt by the runner command)
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync, spawn } = require("child_process");
const snarkjs = require("snarkjs");
const { decide, buildCircuitInputs } = require("./lib");

const DIR = __dirname;
const WASM = path.join(DIR, "circuits", "gatekeeper.wasm");
const ZKEY = path.join(DIR, "circuits", "gatekeeper_final.zkey");
const VKEY = require("./circuits/verification_key.json");
const SNARKJS = path.join(DIR, "node_modules", ".bin", "snarkjs");
const TMP = path.join(DIR, ".test-tmp");
fs.mkdirSync(TMP, { recursive: true });

const VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"; // official registered vkHash
const ADDR = "0xDe42000000000000000000000000000000009f01";
const TEST_SALT = "4242424242424242424242424242424242424242";
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let failures = 0;
function check(name, cond, extra) {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${extra ? " — " + extra : ""}`);
  if (!cond) failures++;
}

function sampleTask(overrides = {}, inputOverrides = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "sample-task-1",
    mode: "live",
    issued_at: "2026-11-15T09:00:00.000Z",
    deadline_at: "2026-11-15T09:01:00.000Z",
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: 1000,
      public_balance: 1460,
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: ADDR,
      condition_recipient: ADDR,
      amount: 500,
      max_transfer: 1000,
      proof_tx: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      ...inputOverrides,
    },
    ...overrides,
  };
}

async function prove(task, decision) {
  const inputs = buildCircuitInputs(task, decision, TEST_SALT);
  return snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
}
async function proveThrows(task, decision) {
  try {
    await prove(task, decision);
    return false;
  } catch {
    return true;
  }
}
function cliVerify(proof, publicSignals, tag) {
  const pf = path.join(TMP, `proof-${tag}.json`);
  const sf = path.join(TMP, `public-${tag}.json`);
  fs.writeFileSync(pf, JSON.stringify(proof));
  fs.writeFileSync(sf, JSON.stringify(publicSignals));
  const out = execFileSync(SNARKJS, ["groth16", "verify", path.join(DIR, "circuits", "verification_key.json"), sf, pf], { encoding: "utf8" });
  return out;
}

(async () => {
  const snarkjsVersion = JSON.parse(fs.readFileSync(path.join(DIR, "node_modules", "snarkjs", "package.json"), "utf8")).version;
  console.log("=== PART A: circuit-level tests (snarkjs " + snarkjsVersion + ") ===");

  // A1: documented sample task, APPROVE
  const sample = sampleTask();
  const d0 = decide(sample.input, new Set());
  check("A1 sample decide()", d0.decision === "APPROVE" && d0.reason_code === "VALID_CONDITION", JSON.stringify(d0));
  const t0 = Date.now();
  const { proof, publicSignals } = await prove(sample, "APPROVE");
  console.log(`     fullProve took ${Date.now() - t0} ms; ${publicSignals.length} public signals`);
  check("A1 sample fullProve(APPROVE) succeeds", !!proof);
  const okInProc = await snarkjs.groth16.verify(VKEY, publicSignals, proof);
  check("A1 sample verify (in-process)", okInProc === true);
  const cliOut = cliVerify(proof, publicSignals, "sample");
  check("A1 sample `snarkjs groth16 verify` CLI", /OK/.test(cliOut), cliOut.trim().split("\n").pop());
  check("A1 sample fullProve(REJECT) must fail", await proveThrows(sample, "REJECT"));
  console.log("     public signals:", JSON.stringify(publicSignals));

  // A2: trap cases — correct decision (REJECT) proves+verifies, wrong decision (APPROVE) fails.
  const traps = [
    ["VK_SUBSTITUTION", { proof_vk: "0x2222222222222222222222222222222222222222222222222222222222222222" }],
    ["THRESHOLD_MISMATCH", { public_balance: 999 }],
    ["EXPIRED_CONDITION", { current_block: 19842202 }],
    ["RECIPIENT_MISMATCH", { condition_recipient: "0xDe42000000000000000000000000000000009f02" }],
    ["AMOUNT_OVERFLOW", { amount: 1001 }],
  ];
  for (const [code, over] of traps) {
    const task = sampleTask({}, { ...over, proof_tx: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" });
    const d = decide(task.input, new Set());
    check(`A2 ${code} decide()`, d.decision === "REJECT" && d.reason_code === code, JSON.stringify(d));
    const pr = await prove(task, "REJECT");
    const okv = await snarkjs.groth16.verify(VKEY, pr.publicSignals, pr.proof);
    check(`A2 ${code} fullProve(REJECT) + verify`, okv === true);
    check(`A2 ${code} fullProve(APPROVE) must fail`, await proveThrows(task, "APPROVE"));
    if (code === "VK_SUBSTITUTION") {
      const regRed = (BigInt(VK) % P).toString(10);
      const proofRed = (BigInt(over.proof_vk) % P).toString(10);
      console.log(`     signal layout probe: [1]=${pr.publicSignals[1]} [2]=${pr.publicSignals[2]}`);
      console.log(`     registeredVkHash mod p = ${regRed} -> index ${pr.publicSignals.indexOf(regRed)}`);
      console.log(`     proofVkHash      mod p = ${proofRed} -> index ${pr.publicSignals.indexOf(proofRed)}`);
    }
  }

  // A3: rule-order / seen-set unit checks (no proving needed)
  const seenSet = new Set(["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
  const dReused = decide(sampleTask().input, seenSet);
  check("A3 PROOF_REUSED decide()", dReused.decision === "REJECT" && dReused.reason_code === "PROOF_REUSED", JSON.stringify(dReused));
  const dOrder = decide(sampleTask({}, { proof_vk: "0x2222222222222222222222222222222222222222222222222222222222222222", public_balance: 1 }).input, new Set());
  check("A3 order: VK check precedes THRESHOLD", dOrder.reason_code === "VK_SUBSTITUTION");

  console.log("\n=== PART B: HTTP end-to-end (server.js) ===");
  const TEST_SECRET = "local-placeholder-secret-for-tests-only";
  const seenFile = path.join(TMP, "seen-test.json");
  const PORT = 8799;
  const child = spawn("node", [path.join(DIR, "server.js")], {
    env: { ...process.env, PORT: String(PORT), GATEKEEPER_HMAC_SECRET: TEST_SECRET, GATEKEEPER_SEEN_FILE: seenFile },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stderr.on("data", (d) => process.stdout.write("[server] " + d));
  await new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error("server start timeout")), 15000);
    child.stdout.on("data", (d) => { if (String(d).includes("listening")) { clearTimeout(to); resolve(); } });
  });
  const sign = (raw) => crypto.createHmac("sha256", TEST_SECRET).update(raw).digest("hex");
  async function post(obj, { badSig = false } = {}) {
    const raw = typeof obj === "string" ? obj : JSON.stringify(obj);
    const r = await fetch(`http://127.0.0.1:${PORT}/`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-agent-games-signature": badSig ? "0".repeat(64) : sign(raw) },
      body: raw,
    });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: r.status, json, text, sig: r.headers.get("x-agent-games-signature") };
  }
  try {
    // B1: signed preflight / health
    const health = await post({ type: "agent-games.health.v1", task_id: "preflight" });
    check("B1 signed health -> {ok:true, protocolVersion:v1}", health.status === 200 && health.json && health.json.ok === true && health.json.protocolVersion === "v1", health.text);
    check("B1 health response signature valid", health.sig === sign(health.text));

    // B2: bad signature rejected before parsing
    const bad = await post({ type: "agent-games.health.v1" }, { badSig: true });
    check("B2 bad signature -> 401", bad.status === 401, "status " + bad.status);

    // B3: valid task over HTTP
    const task = sampleTask({}, { proof_tx: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" });
    const r1 = await post(task);
    check("B3 valid task -> APPROVE/VALID_CONDITION", r1.json && r1.json.decision === "APPROVE" && r1.json.reason_code === "VALID_CONDITION", r1.text.slice(0, 160));
    check("B3 proof_tx echoed", r1.json && r1.json.proof_tx === task.input.proof_tx);
    check("B3 response signature valid", r1.sig === sign(r1.text));
    if (r1.json && r1.json.proof) {
      const okp = await snarkjs.groth16.verify(VKEY, r1.json.public_signals, r1.json.proof);
      check("B3 response proof verifies", okp === true);
    } else {
      check("B3 response proof verifies", false, "no proof in response");
    }

    // B4: replay of the same proof_tx -> PROOF_REUSED, no proof (local-only check cannot prove decision=0)
    const r2 = await post(task);
    check("B4 replay -> REJECT/PROOF_REUSED", r2.json && r2.json.decision === "REJECT" && r2.json.reason_code === "PROOF_REUSED", r2.text.slice(0, 160));
    check("B4 replay response has no proof", r2.json && !("proof" in r2.json));

    // B5: VK trap over HTTP carries a verifiable REJECT proof
    const vkTask = sampleTask({}, { proof_vk: "0x3333333333333333333333333333333333333333333333333333333333333333", proof_tx: "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" });
    const r3 = await post(vkTask);
    check("B5 VK trap -> REJECT/VK_SUBSTITUTION", r3.json && r3.json.decision === "REJECT" && r3.json.reason_code === "VK_SUBSTITUTION", r3.text.slice(0, 160));
    if (r3.json && r3.json.proof) {
      const okp = await snarkjs.groth16.verify(VKEY, r3.json.public_signals, r3.json.proof);
      check("B5 VK trap proof verifies", okp === true);
    } else {
      check("B5 VK trap proof verifies", false, "no proof in response");
    }

    // B6: seen-set persisted on disk with exactly the approved proof_tx
    const onDisk = JSON.parse(fs.readFileSync(seenFile, "utf8"));
    check("B6 seen-set file persisted", Array.isArray(onDisk.seen) && onDisk.seen.includes(task.input.proof_tx) && onDisk.seen.length === 1, JSON.stringify(onDisk));
  } finally {
    child.kill("SIGTERM");
  }

  console.log(failures === 0 ? "\nALL TESTS PASSED" : `\n${failures} TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error("TEST ERROR:", e); process.exit(1); });
