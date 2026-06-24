#!/usr/bin/env node
// SAIHM erasure receipt — a runnable proof of cryptographic erasure (GDPR Art. 17).
//
//   npm install
//   node demo.mjs            # runs offline against a local blind sandbox; no account, no key
//
// It seals two records, erases one by destroying its wrapped key, then emits a tamper-evident,
// reproducible erasure receipt and verifies it. The other record is left untouched — erasure is
// targeted, not a wipe. Every cryptographic operation runs client-side; the endpoint only ever
// holds ciphertext.
//
// Go live (paid membership, no free tier) against the hosted, blind endpoint:
//   export SAIHM_ENDPOINT_URL=https://saihm.coti.global/mcp
//   export SAIHM_AUTH_HEADER="Bearer <your-onboard-JWT>"
//   export SAIHM_MASTER_SECRET_HEX=<at least 64 hex chars, generated and held only by you>
// Your master secret never leaves your machine; the endpoint only ever sees ciphertext.

import { randomBytes } from 'node:crypto';
import { deriveIdentity, toHex, fromHex } from '@saihm/client-pro';
import { SaihmProClient } from '@saihm/mcp-server-pro';
import { startSandbox } from './sandbox.mjs';
import { buildErasureReceipt, verifyReceipt } from './receipt.mjs';

// Build the sealing client: hosted blind endpoint if configured, else a local in-process blind sandbox.
async function makeClient() {
  if (process.env.SAIHM_ENDPOINT_URL) {
    return {
      client: SaihmProClient.bootFromEnv(),
      endpoint: new URL(process.env.SAIHM_ENDPOINT_URL).host,
      close: async () => {},
    };
  }
  const { url, close } = await startSandbox();
  const master = process.env.SAIHM_MASTER_SECRET_HEX
    ? fromHex(process.env.SAIHM_MASTER_SECRET_HEX.trim())
    : randomBytes(32);
  const client = new SaihmProClient(url, `Bearer ${toHex(deriveIdentity(master).agentIdHash)}`, master, { tier: 'SANDBOX' });
  return { client, endpoint: 'local blind sandbox', close };
}

const rule = () => console.log('-'.repeat(72));

async function main() {
  const { client, endpoint, close } = await makeClient();
  try {
    rule(); console.log('SAIHM erasure receipt — prove a record was crypto-erased (GDPR Art. 17)'); rule();
    const s = await client.status();
    console.log('endpoint :', endpoint);
    console.log('status   :', `tier=${s.tier} records=${s.activeShardCount} custody=${s.custody}`);
    console.log('custody  : non-custodial (the endpoint stores ciphertext only; it holds no key)\n');

    // Baseline count so the targeted-erasure check holds even on a live account with pre-existing records.
    const before = (await client.recall()).length;

    // 1) Seal two records. One is the personal data a data subject will request be erased.
    //    (Illustrative synthetic data only -- never paste real personal data into the throwaway sandbox.)
    rule(); console.log('(1) seal two records (each sealed client-side before it leaves this process):'); rule();
    const pii = await client.remember('Subject: Dana Okafor (synthetic). Personal data: documented allergy to penicillin.');
    const keep = await client.remember('Operational note: clinic cafeteria serves soup on Fridays.');
    console.log(`sealed PII record    cellId=${pii.cellId}`);
    console.log(`sealed second record cellId=${keep.cellId}`);
    // The record's public commitment, as reported by the endpoint. Offline (the sandbox) this is the
    // client-sealed sha256 of the ciphertext; against a hosted endpoint it is endpoint-reported and this
    // demo does not independently re-verify it (verifyEnvelope() in @saihm/client-pro does that).
    console.log(`  commitment (public, endpoint-reported): ${pii.commitmentHash ?? '(n/a)'}`);
    console.log(`records readable now : ${(await client.recall()).length}\n`);

    // 2) Erasure request: destroy the wrapped key for the PII record only.
    rule(); console.log('(2) erase the PII record — destroy its wrapped key (not de-index):'); rule();
    const forget = await client.forget(pii.cellId);
    console.log('forget result:', JSON.stringify({ complete: forget.complete, steps: forget.steps }));

    // 3) Verify the outcome by re-reading the store: the PII id is gone, the other record survives,
    //    and exactly one record was removed -- this holds whether the store started empty (sandbox)
    //    or already held records (a live account).
    const after = await client.recall();
    const copiesRemaining = after.filter((r) => r.cellId === pii.cellId).length;
    const keepSurvives = after.some((r) => r.cellId === keep.cellId);
    const netRemoved = (before + 2) - after.length;   // sealed 2, erased 1 => exactly 1 net removal
    console.log(`copies of the erased record remaining: ${copiesRemaining}`);
    console.log(`the unrelated record still readable  : ${keepSurvives} (erasure is targeted, not a wipe)`);
    console.log(`net records removed                  : ${netRemoved} (exactly one)\n`);

    // 4) Emit a public, tamper-evident erasure receipt and verify it.
    rule(); console.log('(3) erasure receipt (public, tamper-evident, reproducible):'); rule();
    const receipt = buildErasureReceipt({
      cellId: pii.cellId,
      commitmentHash: pii.commitmentHash,
      forget,
      copiesRemaining,
      endpoint,
    });
    console.log(JSON.stringify(receipt, null, 2));
    const check = verifyReceipt(receipt);
    console.log('\nverifyReceipt:', check.valid ? 'VALID' : `INVALID (${check.reasons.join('; ')})`);

    // Assertions — the demo fails loudly if any guarantee is not met.
    if (copiesRemaining !== 0) throw new Error('erasure failed: a copy of the record survived');
    if (!keepSurvives) throw new Error('targeted-erasure failed: the unrelated sealed record was destroyed');
    if (netRemoved !== 1) throw new Error('targeted-erasure failed: exactly one record should have been removed');
    if (!check.valid) throw new Error('receipt did not verify');

    rule();
    console.log(endpoint === 'local blind sandbox'
      ? 'Cryptographic erasure, proven offline: wrapped key destroyed, zero copies survive, receipt verifies.'
      : 'Cryptographic erasure: the endpoint attests the wrapped key was destroyed, the client confirms zero readable copies, and the receipt verifies.');
    console.log('Go live (paid): https://saihm.coti.global/join');
    rule();
  } finally {
    await close();
  }
}

main().catch((e) => { console.error('demo failed:', e?.message ?? e); process.exit(1); });
