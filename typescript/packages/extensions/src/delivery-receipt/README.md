# x402 Delivery-Receipt Extension

Spec: [`specs/extensions/delivery-receipt.md`](../../../../../specs/extensions/delivery-receipt.md) (draft v0.2.1,
test vectors in Appendix A and `delivery-receipt.vectors.json`)

After a successful settle, the resource server signs a receipt that binds the settlement
(`network`, `transaction`, `logIndex`, `asset`, `payTo`, `amount`, `payer`) to the content it served:
the SHA-256 of the response body, or, for SSE routes, the frame count and running digest of the frames.

Every receipt carries two signatures over the same 88-byte message
(`"x402-delivery-receipt/1\n" + receiptId`, where `receiptId` is the hex SHA-256 of `JCS(payload)`):

- `ed25519` — the **session** path: clients verify it in the x402 session, with WebCrypto on Workers, Edge,
  Deno and browsers.
- `ml-dsa-65` (FIPS 204) — the **archival** path: required for anything kept as long-term evidence.

The verdict says which path was taken (`path`, `longTermEvidence`). The payload names the key-directory
epoch and digest it was signed under; the directory lives at a stable URL with immutable archives at
`<keyDirectory>/epoch/<n>`.

By default `PAYMENT-RESPONSE` carries only a reference `{ receiptId, receiptUrl, digest }` (under 300
octets; the spec's budget is 1 KB) and the receipt is served, immutable, as `JCS(receipt)` at
`receiptUrl`; the client checks `digest` on the fetched octets before parsing them. Nothing is added
to the response body.

## Server

```ts
import { x402ResourceServer } from "@x402/core/server";
import {
  createDeliveryReceiptExtension,
  declareDeliveryReceiptExtension,
  createLocalReceiptSigner,
  generateReceiptKeyPair,
  buildKeyDirectory,
  activeKeyEntry,
  createMemoryReceiptStore,
} from "@x402/extensions/delivery-receipt";

// Persist the seeds; keep the governance seeds offline.
const keys = [
  await generateReceiptKeyPair("ed25519", edSeed),
  await generateReceiptKeyPair("ml-dsa-65", pqSeed),
];
const governance = [
  await generateReceiptKeyPair("ed25519", govEdSeed),
  await generateReceiptKeyPair("ml-dsa-65", govPqSeed),
];
const now = Math.floor(Date.now() / 1000);

// Serve at https://api.example.com/.well-known/x402-receipt-keys AND at .../epoch/1 (immutable).
const directory = await buildKeyDirectory({
  issuer: "https://api.example.com",
  publishedAt: now,
  governance,
  keys: keys.map(k => activeKeyEntry(k, now)),
});

// Receipts by reference (default): any store that serves the exact document, immutable, at
// https://api.example.com/x402/receipts/<receiptId>. The memory store is for tests and examples.
const receiptStore = createMemoryReceiptStore("https://api.example.com");
// app.get("/x402/receipts/:id", req => receiptStore.handle(req));

const server = new x402ResourceServer(facilitatorClient).registerExtension(
  createDeliveryReceiptExtension({
    issuer: "https://api.example.com",
    signers: keys.map(createLocalReceiptSigner),
    directory, // or () => currentDirectory()
    receiptStore, // or receiptTransport: "inline" if every hop accepts an ~8 KB PAYMENT-RESPONSE
  }),
);

// Route config
const routes = {
  "GET /premium-data": {
    accepts: { scheme: "exact", network: "eip155:8453", payTo, price: "$0.01" },
    extensions: declareDeliveryReceiptExtension(),
  },
};
```

The body is hashed from the buffer the HTTP middleware already keeps for settlement. Routes that
settle before the handler runs get no body-mode receipt.

### Streams (SSE)

```ts
import { createSseReceiptWriter } from "@x402/extensions/delivery-receipt";

const writer = createSseReceiptWriter(config, { resourceUrl, method: "GET", requirements, settle });
for await (const event of source) res.write(await writer.frame(JSON.stringify(event)));
res.end((await writer.finish()).event); // terminal `x402-delivery-receipt` event
```

Frames are what `EventSource` dispatches as `MessageEvent.data`. The terminal event carries
`frameCount`, the stream digest and the receipt reference (`{ frameCount, digest, reference }`), and
the signed payload binds the same two values. Nothing travels in HTTP trailers.

## Client

`withDeliveryReceipts` wraps the base `fetch` given to `wrapFetchWithPayment`, so it sees both the
`PAYMENT-SIGNATURE` it sent and the `PAYMENT-RESPONSE` and body it received:

```ts
import { wrapFetchWithPayment } from "@x402/fetch";
import { withDeliveryReceipts, getDeliveryReceiptResult } from "@x402/extensions/delivery-receipt";

const fetchWithPayment = wrapFetchWithPayment(
  withDeliveryReceipts(fetch, { pinnedGovernanceKeys: [govEdB64] }),
  client,
);
const res = await fetchWithPayment("https://api.example.com/premium-data");
const verdict = getDeliveryReceiptResult(res);
// { valid, path: "session", longTermEvidence: false, levels, trustBasis, reasons, ... }
```

Without `pinnedGovernanceKeys` the directory is trusted on first use over TLS and the verdict
reports `trustBasis: "tls"`. When an `offer-receipt` receipt is in the same settle response, the
verdict also checks that both describe the same payment. For streamed routes, call
`verifySseDelivery(text, options)` on the event stream once it has been consumed.

## Offline / archival verification

```ts
import { verifyDeliveryReceipt } from "@x402/extensions/delivery-receipt";

const verdict = await verifyDeliveryReceipt(receipt, {
  directories, // saved copy of the epoch the receipt names (plus later epochs, if any)
  directoryTrust: { pinnedGovernanceKeys: [govPqB64] },
  path: "archival", // default
  expected: { responseBody }, // optional: the bytes you kept
});
// verdict.longTermEvidence === true only on the archival path
```

A valid receipt proves the issuer's authorized key signed that settlement locator and content
commitment. It does not prove the content is correct; check `transaction`/`logIndex` on chain to
confirm the transfer itself.
