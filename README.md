# saihm-erasure-receipt

**Prove a record was erased — not hidden. A runnable proof of cryptographic erasure (GDPR Art. 17), with a receipt you can verify.**

> ⭐ **[Star SAIHM on GitHub](https://github.com/SAIHM-Admin/saihm-mcp)** and share it — help every agent get portable, provable memory. [Share on X](https://x.com/intent/tweet?text=Prove%20a%20record%20was%20erased%2C%20not%20hidden%20-%20cryptographic%20erasure%20with%20a%20verifiable%20receipt%2C%20via%20SAIHM.&url=https%3A%2F%2Fgithub.com%2Fcitw2%2Fsaihm-erasure-receipt).

A runnable demo of [SAIHM](https://saihm.coti.global) erasure. It seals two records, then honours an erasure request on one of them by **destroying its wrapped key** — the stored ciphertext becomes unrecoverable noise, so the record is *gone*, not merely de-indexed. It then emits a small, portable **erasure receipt** and verifies it. The other record is left untouched: erasure is targeted, not a wipe.

"Right to be forgotten" is hard to *prove*. Soft-deleting a row or dropping it from a search index leaves the data sitting there. SAIHM erases by key-destruction and hands you a receipt a compliance reviewer can read, re-verify, and archive.

## Run it

```
git clone https://github.com/citw2/saihm-erasure-receipt
cd saihm-erasure-receipt

npm install                                  # the sealing client + a local blind sandbox

node demo.mjs                                # offline blind sandbox; no account, no key
```

You'll see two records sealed, one erased by destroying its wrapped key, a re-read of the store proving **zero copies survive** (while the unrelated record remains), and a verifiable erasure receipt printed and checked.

## What's in the receipt

The receipt carries only **public** material — no plaintext, no secret — and a verifiable outcome:

```json
{
  "schema": "saihm.erasure-receipt/v1",
  "action": "cryptographic-erasure",
  "basis": "GDPR Art. 17 (right to erasure)",
  "record": { "cellId": "9c29fce8…", "commitmentHash": "c3999ac2…" },
  "result": { "keyDestroyed": true, "copiesRemaining": 0, "irreversible": true },
  "erasedAt": "2026-06-24T05:28:08.000Z",
  "endpoint": "local blind sandbox",
  "note": "The endpoint holds ciphertext only; destroying the wrapped key leaves the stored bytes as unrecoverable noise…",
  "receiptHash": "31228b4b…"
}
```

- **`record.commitmentHash`** is the record's public commitment, as reported by the endpoint, that anchors the receipt to a specific record. Offline (the sandbox) it is the client-sealed SHA-256 of the ciphertext; against a hosted endpoint it is endpoint-reported and this demo does not independently re-verify it (`verifyEnvelope()` in `@saihm/client-pro` does that). The erasure guarantee below does not depend on it.
- **`result`** is the claim: the wrapped key was destroyed and **zero copies remain** (verified by re-reading the store after erasure).
- **`receiptHash`** is a SHA-256 over a **canonical (key-sorted) serialization** of the receipt body, so the receipt is **tamper-evident** — any change to the body changes the hash. Verify it with `verifyReceipt()` (which re-serializes canonically); don't re-hash the pretty-printed JSON above. The core claim is also **reproducible**: re-read the store with this `cellId` and confirm nothing survives. (Offline this is a self-checking, reproducible proof; against the hosted endpoint the key-destruction is attested by the endpoint and you reproduce the zero-copies check the same way.)

## Use it in your code

`receipt.mjs` is dependency-free (just `node:crypto`). Build a receipt from your own seal + forget results, and verify any receipt you're handed:

```js
import { buildErasureReceipt, verifyReceipt } from './receipt.mjs';

const receipt = buildErasureReceipt({
  cellId,                 // the erased record's id
  commitmentHash,         // the record's public commitment, e.g. remember().commitmentHash (endpoint-reported)
  forget,                 // the forget() result
  copiesRemaining,        // count of this id still readable after erasure (you verify == 0)
  endpoint,               // 'local blind sandbox' or your hosted endpoint host
});

const { valid, reasons } = verifyReceipt(receipt);   // checks hash + irreversible erasure
```

`verifyReceipt` returns `{ valid: false, reasons: [...] }` if the hash doesn't match the body, if any copy survives, or if the wrapped key was not destroyed.

## Why this matters

For real personal data, "removed from search" is not erasure — the bytes are still there. SAIHM erases the way GDPR Art. 17 actually asks for:

1. **Key-destruction, not de-indexing.** `forget` destroys the wrapped key for that record; the ciphertext that remains is unrecoverable noise. The record stops being readable because it is *gone*.
2. **Targeted.** Only the requested record is erased; the rest of your memory is untouched.
3. **Provable.** You get a portable, tamper-evident, reproducible receipt — something security and compliance teams can actually audit, not a log line that says "deleted."
4. **Non-custodial.** Every record is sealed client-side; the endpoint only ever holds ciphertext and never sees your keys.

## Go live against the real SAIHM service

The local sandbox is a throwaway stand-in so you can try the protocol offline — it is **not** the SAIHM service and stores nothing beyond the current process. To run against the real, hosted, blind endpoint:

1. **Join SAIHM** at **[saihm.coti.global/join](https://saihm.coti.global/join)** and onboard to obtain your JWT. (Going live requires a paid membership — there is no free tier.)
2. Set the environment before running, and the same code goes live:

   ```
   export SAIHM_ENDPOINT_URL=https://saihm.coti.global/mcp
   export SAIHM_AUTH_HEADER="Bearer <your-onboard-JWT>"
   export SAIHM_MASTER_SECRET_HEX=<at least 64 hex chars, generated and held only by you>
   node demo.mjs
   ```

Your master secret never leaves your machine; the endpoint only ever receives ciphertext. Offline, the demo is fully self-checking; against the hosted endpoint, the receipt records the endpoint's key-destruction and the client's verified zero-copies re-read — the same guarantee, attested by the endpoint and verified client-side.

## How it works

- Records are sealed with [`@saihm/client-pro`](https://www.npmjs.com/package/@saihm/client-pro): an **ML-DSA-65** identity signs each one, a per-record **AES-256-GCM** key encrypts it, and that key is wrapped under a key-encryption key derived from *your* master secret. Erasure destroys the wrapped key. (Sharing, elsewhere in SAIHM, uses **ML-KEM-768**.)
- [`sandbox.mjs`](./sandbox.mjs) is a complete, readable *blind operator* for offline use: it stores and returns ciphertext and **never holds a key** — the same non-custodial property as the hosted service.
- [`receipt.mjs`](./receipt.mjs) turns the protocol's seal + forget results into the public receipt above. [`server.mjs`](./server.mjs) is included too, so you can also run this sidecar as an MCP server (`npm run serve`) for Claude Code, Cursor, or any MCP host.

## Built on / see also

- **[saihm-rag](https://github.com/citw2/saihm-rag)** — a LlamaIndex `BaseRetriever` for RAG over a knowledge base you own.
- **[saihm-langchain](https://github.com/citw2/saihm-langchain)** — LangChain (`BaseChatMessageHistory`) + LlamaIndex chat memory.
- **[saihm-crewai](https://github.com/citw2/saihm-crewai)** · **[saihm-autogen](https://github.com/citw2/saihm-autogen)** · **[saihm-langgraph](https://github.com/citw2/saihm-langgraph)** — the same store as a CrewAI / AutoGen / LangGraph backend.
- **[demo-claude-code](https://github.com/citw2/demo-claude-code)** — the same sidecar as an MCP server for Claude Code, Cursor, and any MCP host.
- **[All demos + landing page](https://citw2.github.io/saihm-demos/)**.
- **Join the protocol:** [saihm.coti.global/join](https://saihm.coti.global/join).

## License

Apache-2.0 © SAIHM
