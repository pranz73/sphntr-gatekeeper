"use strict";
/** Shared gatekeeper logic: field encoding + decision rules (used by server.js and test.js). */
const crypto = require("crypto");
const { keccak_256 } = require("js-sha3");

function toBigInt(v, field) {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error(`field ${field}: unsafe number`);
    return BigInt(v);
  }
  if (typeof v === "string") {
    const s = v.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^[0-9]+$/.test(s)) return BigInt(s);
    throw new Error(`field ${field}: not a numeric string`);
  }
  throw new Error(`field ${field}: unsupported type`);
}

function normHex(v) {
  return String(v).trim().toLowerCase();
}

/** Deterministic taskId encoding (ASSUMPTION): keccak256(task_id) as a bigint field element. */
function taskIdToField(taskId) {
  return BigInt("0x" + keccak_256(String(taskId))).toString(10);
}

function randomSalt() {
  // 31 bytes < BN128 prime, always a valid field element.
  return BigInt("0x" + crypto.randomBytes(31).toString("hex")).toString(10);
}

/**
 * Decision rules, checked in the documented order; the first failing check decides.
 * `seen` is a Set of lowercase proof_tx strings already accepted.
 */
function decide(input, seen) {
  if (normHex(input.proof_vk) !== normHex(input.registered_vk))
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };

  if (toBigInt(input.public_balance, "public_balance") < toBigInt(input.minimum, "minimum"))
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };

  if (seen.has(normHex(input.proof_tx)))
    return { decision: "REJECT", reason_code: "PROOF_REUSED" };

  if (toBigInt(input.current_block, "current_block") > toBigInt(input.expiry_block, "expiry_block"))
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };

  if (normHex(input.recipient) !== normHex(input.condition_recipient))
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };

  if (toBigInt(input.amount, "amount") > toBigInt(input.max_transfer, "max_transfer"))
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };

  return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}

/** Build the 13 named circuit inputs for a task + decision ("APPROVE"|"REJECT"). */
function buildCircuitInputs(task, decision, salt) {
  const i = task.input;
  return {
    taskId: taskIdToField(task.task_id),
    minimum: toBigInt(i.minimum, "minimum").toString(10),
    publicBalance: toBigInt(i.public_balance, "public_balance").toString(10),
    expiryBlock: toBigInt(i.expiry_block, "expiry_block").toString(10),
    currentBlock: toBigInt(i.current_block, "current_block").toString(10),
    recipient: toBigInt(i.recipient, "recipient").toString(10),
    conditionRecipient: toBigInt(i.condition_recipient, "condition_recipient").toString(10),
    amount: toBigInt(i.amount, "amount").toString(10),
    maxTransfer: toBigInt(i.max_transfer, "max_transfer").toString(10),
    registeredVkHash: toBigInt(i.registered_vk, "registered_vk").toString(10),
    proofVkHash: toBigInt(i.proof_vk, "proof_vk").toString(10),
    salt: salt !== undefined ? String(salt) : randomSalt(),
    decision: decision === "APPROVE" ? "1" : "0",
  };
}

module.exports = { toBigInt, normHex, taskIdToField, randomSalt, decide, buildCircuitInputs };
