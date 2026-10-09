# Extension: `delivery-receipt`

| | |
|---|---|
| Status | Draft (v0.1) |
| Extension key | `delivery-receipt` |
| x402 versions | v2 (the signed payload itself is version-agnostic) |
| Transports | HTTP (normative). MCP / A2A: see §11 |
| Related | [`offer-receipt`](./extension-offer-and-receipt.md), [`payment-identifier`](./payment_identifier.md) |

## 1. Summary

The `delivery-receipt` extension lets a resource server commit, at the moment it settles a payment, to **what it
delivered for that payment**. After a successful settle the server returns a signed receipt that binds, in one
signed object:

- the settlement locator — `network`, `transaction` and, when known, the `logIndex` of the transfer;
- the economic terms that were paid — `scheme`, `asset`, `payTo`, `amount`, `payer`;
- the resource — `resourceUrl`, HTTP `method`;
- the served bytes — `responseSha256`, the SHA-256 of the exact response body the client received, plus the
  response status;
- the issuance time and the issuer.

Receipts are signed with a declared algorithm. `ml-dsa-65` (NIST FIPS 204) is the baseline every verifier MUST
implement, so receipts can be kept as long-lived evidence without depending on signature schemes that a
cryptographically relevant quantum computer would break. Other algorithms (e.g. `ed25519`) are allowed and
registered in §6.

Signing keys are published in a **signed key directory** discovered from the 402 response (and by convention at
`/.well-known/x402-receipt-keys`), with an explicit lifecycle per key. With a copy of the directory, a receipt can be
verified **offline**, by anyone, long after the HTTP exchange.

## 2. Relationship to `offer-receipt`

[`offer-receipt`](./extension-offer-and-receipt.md) defines signed offers and a privacy-minimal receipt
(`network`, `resourceUrl`, `payer`, `issuedAt`, optional `transaction`) signed with EIP-712 or JWS. It intentionally
omits transaction details and says nothing about the content that was served.

`delivery-receipt` addresses a different requirement: **non-repudiable evidence of delivery** for audit, dispute
and agent-to-agent accounting, where the verifier needs to know *which bytes* were delivered *for which on-chain
transfer*. The two extensions are independent and MAY be declared together on the same route. A server that
only needs reputation-style receipts SHOULD use `offer-receipt`; a server that wants its customers to be able to
prove what they were served SHOULD use `delivery-receipt`.

Maintainers may prefer to fold these fields into a future `offer-receipt` payload version; the payload, signed
message and key directory in this document are designed so that this remains possible (§13).

## 3. Terminology

- **Receipt payload** (`payload`): the JSON object of §5.2.
- **JCS**: JSON Canonicalization Scheme, RFC 8785. Signed JSON in this extension MUST contain only strings,
  booleans, `null`, arrays, objects and integers in the IEEE-754 safe range (|n| ≤ 2^53 − 1). Floating-point
  numbers are not allowed anywhere in a signed object.
- **Receipt id**: `lowercase_hex(SHA-256(JCS(payload)))`.
- **Signed message**: the exact octets passed to the signature algorithm (§5.3).
- **Issuer**: the origin (`scheme://host[:port]`) that owns the key directory and signs receipts.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 / RFC 8174.

## 4. `PaymentRequired` — declaration

A server that will issue delivery receipts for a route declares it in the 402 response:

```json
{
  "extensions": {
    "delivery-receipt": {
      "info": {
        "version": 1,
        "issuer": "https://api.example.com",
        "keyDirectory": "https://api.example.com/.well-known/x402-receipt-keys",
        "algorithms": ["ml-dsa-65"],
        "delivery": "inline"
      },
      "schema": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
          "version": { "type": "integer", "const": 1 },
          "issuer": { "type": "string" },
          "keyDirectory": { "type": "string", "format": "uri" },
          "algorithms": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
          "delivery": { "type": "string", "enum": ["inline", "reference"] }
        },
        "required": ["version", "issuer", "keyDirectory", "algorithms"]
      }
    }
  }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | integer | Yes | Receipt payload version the server will sign. Currently `1`. |
| `issuer` | string | Yes | Origin of the signer. MUST equal the origin of `keyDirectory`. |
| `keyDirectory` | string | Yes | HTTPS URL of the signed key directory (§7). |
| `algorithms` | string[] | Yes | Algorithms the server may sign with, in preference order (§6). |
| `delivery` | string | No | `inline` (default) or `reference` (§5.5). |

The declaration is a **promise, not a proof**: a client MUST NOT treat the presence of the declaration as evidence
that a receipt will be returned, and the absence of a receipt after a successful settle does not invalidate the
settlement (§8.4).

## 5. Receipt

### 5.1 Placement

On a successful settle the server adds the receipt to the `SettleResponse` it returns to the client (on HTTP, the
`PAYMENT-RESPONSE` header), under the v2 extension structure:

```
SettleResponse.extensions["delivery-receipt"].info.receipt
```

A receipt MUST NOT be returned for a failed settle (`success: false`).

### 5.2 Receipt payload (version 1)

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | integer | Yes | `1` |
| `issuer` | string | Yes | Same value as the declaration. |
| `resourceUrl` | string | Yes | Absolute URL of the paid resource as requested. |
| `method` | string | Yes | Upper-case HTTP method of the paid request. |
| `scheme` | string | Yes | Payment scheme of the accepted requirements (e.g. `exact`). |
| `network` | string | Yes | CAIP-2 network of the settlement (e.g. `eip155:8453`). |
| `asset` | string | Yes | Asset of the accepted requirements. |
| `payTo` | string | Yes | Recipient of the accepted requirements. |
| `amount` | string | Yes | Settled amount in atomic units: `SettleResponse.amount` when present, otherwise the accepted requirements' `amount`. |
| `payer` | string | Yes | `SettleResponse.payer`. |
| `transaction` | string | Yes | `SettleResponse.transaction`. MUST be non-empty. |
| `logIndex` | integer \| null | Yes | Block-level index of the transfer log of `transaction` that paid `payTo`, when the server resolved it; otherwise `null`. |
| `paymentId` | string \| null | Yes | The `payment-identifier` extension `id` sent by the client, if any; otherwise `null`. |
| `responseStatus` | integer | Yes | HTTP status code of the served response. |
| `responseSha256` | string | Yes | Lowercase hex SHA-256 of the response body bytes (§5.4). |
| `responseContentType` | string \| null | Yes | `Content-Type` of the served response, or `null`. |
| `issuedAt` | integer | Yes | Unix time (seconds) at which the receipt was signed. |

All fields are present in every receipt (optional values are `null`), so the signed bytes never depend on how a
serializer treats absent keys. Network identifiers MUST be CAIP-2 even when the exchange used x402 v1 names.

Servers MUST derive every field from data they hold at settle time: the verified payment payload, the accepted
requirements, the facilitator's `SettleResponse` and the response produced by the handler. Fields MUST NOT be
copied from client-supplied text, except `paymentId`.

### 5.3 Wire object and signed message

```json
{
  "alg": "ml-dsa-65",
  "kid": "86c139c960bb274c",
  "payload": { "version": 1, "...": "..." },
  "signature": "<base64>"
}
```

| Field | Type | Description |
|---|---|---|
| `alg` | string | Algorithm identifier from §6. |
| `kid` | string | Identifier of the signing key in the issuer's key directory. |
| `payload` | object | The receipt payload of §5.2. |
| `signature` | string | Canonical base64 (RFC 4648 §4, padded) of the signature. |

The signed message is the UTF-8 encoding of:

```
"x402-delivery-receipt/1" || "\n" || receiptId
```

where `receiptId = lowercase_hex(SHA-256(JCS(payload)))`. The fixed first line provides domain separation: a
signature over this message cannot be confused with a signature produced by the same key for any other purpose,
provided other protocols using the key also domain-separate. Implementations MUST NOT sign or verify any other
representation (for example the transmitted JSON text).

For `ml-dsa-65` the context string is empty and the pure (non-pre-hash) variant of FIPS 204 is used.

### 5.4 Body digest

`responseSha256` is computed over the exact octets of the response body that the server hands to the transport
for this request, **before** any content-coding is applied (i.e. the identity representation). A client computes
the digest over the body after removing content-coding (what `fetch()` returns from `arrayBuffer()`).

A server MUST NOT issue a receipt when it cannot observe the body — for example when the payment flow settles
before the handler runs, or when the response is streamed and not buffered. Such routes SHOULD NOT declare the
extension.

### 5.5 Delivery by reference

An ML-DSA-65 signature is 3,309 bytes. Inline receipts therefore make the `PAYMENT-RESPONSE` header roughly 7 KB.
Servers whose infrastructure limits header size MAY declare `"delivery": "reference"` and return instead:

```json
{ "info": { "receiptId": "<hex>", "receiptUrl": "https://api.example.com/x402/receipts/<hex>" } }
```

`receiptUrl` MUST be same-origin with `issuer` and MUST return the wire object of §5.3 as `application/json` without
payment. The client MUST recompute the receipt id from the fetched payload and reject it if it differs from
`receiptId` (this prevents a store from substituting another genuine receipt). Servers SHOULD keep referenced
receipts retrievable for at least 30 days.

## 6. Algorithms

| `alg` | Scheme | Public key | Signature | Status |
|---|---|---|---|---|
| `ml-dsa-65` | ML-DSA-65, FIPS 204, pure, empty context | 1952 bytes | 3309 bytes | REQUIRED for verifiers, RECOMMENDED for signers |
| `ml-dsa-87` | ML-DSA-87, FIPS 204, pure, empty context | 2592 bytes | 4627 bytes | OPTIONAL |
| `ed25519` | Ed25519, RFC 8032 | 32 bytes | 64 bytes | OPTIONAL (not post-quantum) |

Keys and signatures are transmitted as canonical base64 (padded, standard alphabet, no whitespace; decoding then
re-encoding MUST reproduce the input). Verifiers MUST reject an `alg` they do not implement, an `alg` that differs
from the directory entry of `kid`, and lengths that do not match the table.

New algorithms are added by amending this table. A hybrid composite (e.g. classical + post-quantum) is expressed as
a new `alg` identifier with its own fixed encoding, not as two receipts.

## 7. Key directory

### 7.1 Discovery

The directory URL is the declaration's `keyDirectory`. By convention, issuers SHOULD also serve it at
`<issuer>/.well-known/x402-receipt-keys`. It is fetched with `GET`, without payment, over HTTPS.

### 7.2 Format

```json
{
  "spec": "x402-receipt-key-directory/1",
  "issuer": "https://api.example.com",
  "epoch": 2,
  "prevRoot": "8f1c…",
  "governanceKey": { "alg": "ml-dsa-65", "publicKey": "<base64>" },
  "keys": [
    {
      "kid": "86c139c960bb274c",
      "alg": "ml-dsa-65",
      "publicKey": "<base64>",
      "use": "x402-delivery-receipt",
      "status": "active",
      "notBefore": 1790470800,
      "notAfter": null,
      "revokedAt": null
    }
  ],
  "root": "<hex>",
  "signature": "<base64>"
}
```

| Field | Description |
|---|---|
| `spec` | `x402-receipt-key-directory/1` |
| `issuer` | Origin that owns the directory. MUST equal the origin of the URL it was fetched from. |
| `epoch` | Positive integer, incremented on every change. |
| `prevRoot` | `root` of the previous epoch; 64 zeros for epoch 1. |
| `governanceKey` | Key that signs the directory. It MUST NOT appear in `keys`. |
| `keys[]` | 1–256 entries. `kid` unique; `use` MUST be `x402-delivery-receipt` for receipt keys; `status` ∈ `reserved`, `active`, `retiring`, `retired`, `revoked`; times are unix seconds or `null`. |
| `root` | `lowercase_hex(SHA-256(JCS({spec, issuer, epoch, prevRoot, governanceKey, keys})))` with `keys` sorted by `kid`. |
| `signature` | Signature by `governanceKey` over the UTF-8 message `"x402-receipt-key-directory/1\n" || root`. |

`kid` is opaque to verifiers (≤ 64 characters, `[A-Za-z0-9._-]`). Issuers SHOULD derive it as the first 16 hex
characters of SHA-256 over the base64 public key text, which keeps identifiers stable across epochs.

### 7.3 Verifying a directory

A verifier MUST check, in order: the `spec`; field types; that `root` recomputes; that `signature` verifies under
`governanceKey`; that `issuer` equals the fetch origin (or the expected issuer for an offline copy). It then decides
**why it trusts the governance key**, and MUST report that basis:

- `pinned` — the governance key (or a directory root) was configured out of band. RECOMMENDED for long-lived
  verification. A verifier that pins SHOULD also remember the highest `(epoch, root)` it has accepted and reject a
  lower epoch (rollback) or a different root for the same epoch (equivocation).
- `tls` — the key is accepted because the directory was fetched over HTTPS from the issuer's origin. This is
  trust-on-first-use and MUST be reported as such.

Anchoring directory roots in a public log or on-chain is compatible with this format and out of scope of v0.1.

### 7.4 Key lifecycle

A key authorizes a receipt only if, at `T = payload.issuedAt`:

- `use` is `x402-delivery-receipt` and `alg` equals the receipt's `alg`;
- `status` is `active` and `notBefore ≤ T` and (`notAfter` is `null` or `T ≤ notAfter`); or
- `status` is `retiring` or `retired` and `notBefore ≤ T ≤ notAfter` (both set);
- `reserved` never authorizes. `revoked` never authorizes in v0.1: a holder of a revoked key can choose any
  `issuedAt`, so the signed time alone cannot show that a receipt predates revocation. (An independent time proof,
  e.g. a timestamp anchor, could lift this restriction in a later version.)

A verifier MUST also reject `issuedAt` more than its clock-skew allowance (default 300 s) in the future.

Directories are append-only across epochs: a key once listed stays listed (with a later status) so that old
receipts remain verifiable.

## 8. Verification

### 8.1 Levels

A verifier evaluates, and reports separately:

| Level | Meaning |
|---|---|
| `integrity` | The wire object is well-formed; payload types and canonical encodings are valid. |
| `authentic` | The signature verifies over the signed message under the public key of `kid` in the directory. |
| `trusted` | The directory verifies (§7.3), the key authorizes the receipt (§7.4), and the issuer is authorized for the resource (§8.2). |
| `settlement` | The payload matches the settlement the client observed (§8.3). |
| `delivery` | `responseSha256` equals the digest of the body the client received, and `responseStatus` equals the observed status. |

A receipt is **valid for the client** only if all five levels pass. An offline third party that has the receipt,
the directory and the body can evaluate `integrity`, `authentic`, `trusted` and `delivery`; `settlement` can then be
checked against the chain (`transaction`, `logIndex`, `payTo`, `amount`, `asset`).

### 8.2 Issuer authorization

The issuer MUST be authorized to sign for `payload.resourceUrl`. By default, a verifier accepts only an issuer
whose origin equals the origin of `resourceUrl`. A verifier MAY be configured with additional accepted issuers
(for example an independent notary that attests on behalf of a resource server); this MUST be explicit
configuration, never inferred from the receipt.

### 8.3 Settlement binding (client side)

Inside the x402 session the client MUST check:

- `payload.transaction` = `SettleResponse.transaction` and `payload.network` = `SettleResponse.network`;
- `payload.payer` = `SettleResponse.payer` (case-insensitive for EVM addresses);
- `payload.scheme`, `payload.asset`, `payload.payTo` equal the requirements the client accepted;
- `payload.amount` = `SettleResponse.amount` when present, otherwise the accepted `amount`;
- `payload.resourceUrl` and `payload.method` equal the request the client made;
- `payload.paymentId` equals the `payment-identifier` id the client sent, if any.

### 8.4 Failure handling

Receipts are issued after settlement, so a failed or missing receipt cannot undo a payment. A client that required
a receipt and did not get a valid one SHOULD record the failure (with the `SettleResponse`) as evidence for dispute
resolution, and MAY stop using the server. It MUST NOT retry the payment automatically.

## 9. Example (x402 v2, HTTP)

`PAYMENT-RESPONSE` (decoded):

```json
{
  "success": true,
  "transaction": "0x5c6e…a1",
  "network": "eip155:8453",
  "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
  "extensions": {
    "delivery-receipt": {
      "info": {
        "receipt": {
          "alg": "ml-dsa-65",
          "kid": "86c139c960bb274c",
          "payload": {
            "version": 1,
            "issuer": "https://api.example.com",
            "resourceUrl": "https://api.example.com/premium-data",
            "method": "GET",
            "scheme": "exact",
            "network": "eip155:8453",
            "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "amount": "10000",
            "payer": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
            "transaction": "0x5c6e…a1",
            "logIndex": 312,
            "paymentId": null,
            "responseStatus": 200,
            "responseSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "responseContentType": "application/json",
            "issuedAt": 1790473960
          },
          "signature": "<base64, 3309 bytes decoded>"
        }
      },
      "schema": { "$ref": "§10" }
    }
  }
}
```

## 10. JSON Schema of the settle-response `info`

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "receipt": {
      "type": "object",
      "properties": {
        "alg": { "type": "string" },
        "kid": { "type": "string" },
        "payload": { "type": "object" },
        "signature": { "type": "string" }
      },
      "required": ["alg", "kid", "payload", "signature"]
    },
    "receiptId": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "receiptUrl": { "type": "string", "format": "uri" }
  },
  "oneOf": [{ "required": ["receipt"] }, { "required": ["receiptId", "receiptUrl"] }]
}
```

## 11. Other transports

For MCP and A2A, where the `SettleResponse` travels in transport metadata, the extension is carried the same way.
Until those transport specs define a body representation, `responseSha256` SHOULD be computed over
`JCS(result)` of the paid tool/task result, `method` SHOULD be the transport method name (e.g. `tools/call`) and
`responseStatus` SHOULD be `200` for a non-error result. Implementations MUST document what they hash.

## 12. Security and privacy considerations

- **What a receipt proves.** A valid receipt proves that the issuer's authorized key signed the stated settlement
  locator and body digest at `issuedAt`. It does not prove that the content is correct, lawful or useful, and it
  does not by itself prove that the transfer happened — check `transaction`/`logIndex` on chain for that.
- **Self-issued.** The issuer is normally the seller. A receipt is therefore an admission by the seller, which is
  what a buyer needs in a dispute; it is not an independent witness. Independent attestation requires a
  third-party issuer accepted by explicit verifier policy (§8.2).
- **Post-quantum scope.** ML-DSA is believed to resist known classical and quantum attacks; "post-quantum" is not
  "unbreakable". Use of the FIPS 204 algorithm does not make an implementation a CMVP-validated module.
- **Canonicalization.** Only the subset of §3 is signed, so every conforming JCS implementation produces identical
  bytes. Verifiers SHOULD parse the receipt with a parser that rejects duplicate keys.
- **Replay.** A receipt is bound to a single `transaction` (and `logIndex`). Verifiers that count receipts (e.g. for
  accounting) MUST de-duplicate by `(network, transaction, logIndex)`.
- **Privacy.** Unlike the privacy-minimal `offer-receipt` receipt, a delivery receipt links the payer, the
  transaction and a digest of the content. Clients that share receipts publicly reveal that link. The digest does
  not reveal the content, but low-entropy responses can be confirmed by guessing.
- **Resource limits.** Verifiers SHOULD bound the size of fetched directories (e.g. 1 MiB) and receipts, and
  SHOULD NOT follow redirects when fetching a directory.

## 13. Design notes (non-normative)

- *Why a new key instead of extending `offer-receipt`?* The fields, the signed message and the trust model differ
  (body digest, settlement locator, algorithm agility with a signed key directory). Keeping them separate avoids a
  breaking change to an approved extension. If maintainers prefer, the payload of §5.2 can become `offer-receipt`
  receipt payload version 2 with an additional `format` value; nothing here prevents that.
- *Why hash-then-sign?* The signed message is short and fixed-shape, so verification does not depend on
  transmitting JCS text, and the receipt id doubles as a stable content address for storage and anchoring.

## 14. Version history

| Version | Date | Changes | Author |
|---|---|---|---|
| 0.1 | 2026-10-09 | Initial draft. | FractalAI (FRACTAL AI S.A.S.) |
