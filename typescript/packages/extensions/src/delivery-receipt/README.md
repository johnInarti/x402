# x402 Delivery-Receipt Extension

Spec: [`specs/extensions/delivery-receipt.md`](../../../../../specs/extensions/delivery-receipt.md)

After a successful settle, the resource server signs a receipt that binds the settlement
(`network`, `transaction`, `logIndex`, `asset`, `payTo`, `amount`, `payer`) to the SHA-256 of the
response body it served. Keys are published in a signed key directory
(`/.well-known/x402-receipt-keys`), so a receipt can be verified offline later.

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
} from "@x402/extensions/delivery-receipt";

const receiptKey = await generateReceiptKeyPair("ml-dsa-65", receiptSeed); // persist the seed
const governanceKey = await generateReceiptKeyPair("ml-dsa-65", governanceSeed); // keep offline

// Serve this JSON at https://api.example.com/.well-known/x402-receipt-keys
const directory = await buildKeyDirectory({
  issuer: "https://api.example.com",
  governance: governanceKey,
  keys: [activeKeyEntry(receiptKey, Math.floor(Date.now() / 1000))],
});

const server = new x402ResourceServer(facilitatorClient).registerExtension(
  createDeliveryReceiptExtension({
    issuer: "https://api.example.com",
    signer: createLocalReceiptSigner(receiptKey),
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
settle before the handler runs get no receipt.

## Client

`withDeliveryReceipts` wraps the base `fetch` given to `wrapFetchWithPayment`, so it sees both the
`PAYMENT-SIGNATURE` it sent and the `PAYMENT-RESPONSE` and body it received:

```ts
import { wrapFetchWithPayment } from "@x402/fetch";
import { withDeliveryReceipts, getDeliveryReceiptResult } from "@x402/extensions/delivery-receipt";

const fetchWithPayment = wrapFetchWithPayment(
  withDeliveryReceipts(fetch, { pinnedGovernanceKeys: [governanceKeyB64] }),
  client,
);
const res = await fetchWithPayment("https://api.example.com/premium-data");
const verdict = getDeliveryReceiptResult(res);
// { valid, levels: { integrity, authentic, trusted, settlement, delivery }, trustBasis, reasons }
```

Without `pinnedGovernanceKeys` the directory is trusted on first use over TLS and the verdict
reports `trustBasis: "tls"`.

## Offline verification

```ts
import { verifyDeliveryReceipt } from "@x402/extensions/delivery-receipt";

const verdict = await verifyDeliveryReceipt(receipt, {
  directory, // saved copy of the issuer's key directory
  directoryTrust: { pinnedGovernanceKeys: [governanceKeyB64] },
  expected: { responseBody }, // optional: the bytes you kept
});
```

A valid receipt proves the issuer's authorized key signed that settlement locator and body digest.
It does not prove the content is correct; check `transaction`/`logIndex` on chain to confirm the
transfer itself.
