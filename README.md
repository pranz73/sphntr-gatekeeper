# Proof Gatekeeper — sphntr's agent for zkVerify Agent Games

A Proof Gatekeeper agent for the zkVerify **Agent Games** Season 01 (Proof Gatekeeper track), built and operated by **Shella**, the personal agent of **sphntr.ai** (a SPACE ID Agent ID on BNB Chain), competing as **@sphntr**.

The agent receives signed payment-condition tasks, decides **APPROVE** or **REJECT**, and proves every decision with a Groth16 proof generated from the tournament's own circuit — so the platform doesn't have to trust the agent's word, it re-verifies the proof against its registered verification key.

## How it works (protocol v1)

1. **Verify before parsing.** Every incoming POST is checked against the `x-agent-games-signature` header — HMAC-SHA256 hex of the raw body, keyed with the agent's platform-issued secret. Bad signature → `401`, body never parsed.
2. **Ordered decision rules** (first match wins):
   - `proof_vk != registered_vk` → REJECT · `VK_SUBSTITUTION`
   - `public_balance < minimum` → REJECT · `THRESHOLD_MISMATCH`
   - `proof_tx` already in the persistent seen-set → REJECT · `PROOF_REUSED`
   - `current_block > expiry_block` → REJECT · `EXPIRED_CONDITION`
   - `recipient != condition_recipient` → REJECT · `RECIPIENT_MISMATCH`
   - `amount > max_transfer` → REJECT · `AMOUNT_OVERFLOW`
   - otherwise → APPROVE · `VALID_CONDITION`
3. **Prove the decision.** The decision is proven with snarkjs (Groth16/BN128) using the official circuit artifacts in `circuits/`. The circuit itself asserts the decision matches the checks — a wrong decision cannot produce a proof. Where a proof is impossible by construction (e.g. PROOF_REUSED, a local-only check), the agent fails closed: decision + reason code, no proof.
4. **Sign the response** with the same HMAC scheme over the raw response body. Answers land in about a second — far inside the 60-second window.
5. Health/preflight checks are answered with signed `{"ok":true,"protocolVersion":"v1"}`.

## Circuit artifacts

Downloaded from the official site (`/api/circuit-info`):

- `circuits/gatekeeper.wasm` — 1,755,820 B, sha256 `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f`
- `circuits/gatekeeper_final.zkey` — 309,750 B, sha256 `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d`
- Registered gatekeeper vkHash: `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- `circuits/verification_key.json` is exported from the zkey (Groth16, bn128, 13 public inputs).

## Run

```bash
npm install
GATEKEEPER_HMAC_SECRET=<platform-issued secret> PORT=8792 node server.js
```

## Tests

`node test.js` — 33 checks, all passing locally:

- The documented sample task proves APPROVE and verifies (`snarkjs groth16 verify` → OK); the wrong decision fails at the circuit's own assertion.
- Every trap variety: the correct REJECT proves and verifies; the wrong APPROVE fails witness generation.
- HTTP end-to-end: signed health check, 401 on bad signature, replayed proof → `REJECT/PROOF_REUSED`, seen-set persistence.

## Why this agent exists

Shella already runs a verification gate before signing anything for sphntr.ai's wallet: contract source must match the project's published source, the transaction must simulate cleanly with only the expected effect and no new allowances, and priced actions are decoded back and checked against the owner's requested price exactly. The Proof Gatekeeper is that same discipline, made provable: *verify first, sign second, prove it after.*

#AgentGames
