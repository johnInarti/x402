import { describe, it, expect, beforeAll, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { x402ResourceServer } from "@x402/core/server";
import {
  encodePaymentResponseHeader,
  encodePaymentSignatureHeader,
  type FacilitatorClient,
  type HTTPTransportContext,
} from "@x402/core/http";
import type {
  PaymentPayload,
  PaymentRequirements,
  SettleResponse,
  SettleResultContext,
  PaymentRequiredContext,
} from "@x402/core/types";
import {
  DELIVERY_RECEIPT,
  RECEIPT_KEY_USE,
  STREAM_TRAILER_EVENT,
  activeKeyEntry,
  buildKeyDirectory,
  MAX_REFERENCE_EXTENSION_BYTES,
  canonicalJson,
  computeReceiptDigest,
  computeReceiptId,
  computeStreamDigest,
  createDeliveryReceiptExtension,
  createMemoryReceiptStore,
  createLocalReceiptSigner,
  createReceiptPayload,
  createSseReceiptWriter,
  declareDeliveryReceiptExtension,
  extractDeliveryReceipt,
  fetchKeyDirectoryChain,
  formatSseEvent,
  fromCanonicalBase64,
  generateReceiptKeyPair,
  getDeliveryReceiptResult,
  keyAuthorizationError,
  keyDirectoryEpochUrl,
  offerReceiptFacts,
  parseSse,
  receiptSignedMessage,
  resolveDeliveryReceipt,
  sha256Hex,
  signDeliveryReceipt,
  verifyDeliveryReceipt,
  verifyKeyDirectory,
  verifyKeyDirectoryChain,
  verifySseDelivery,
  withDeliveryReceipts,
  type DeliveryReceipt,
  type DeliveryReceiptServerConfig,
  type KeyDirectory,
  type KeyDirectoryEntry,
  type ReceiptKeyPair,
  type ReceiptSigner,
  type StreamTrailer,
} from "../src/delivery-receipt";
import {
  OFFER_RECEIPT,
  createJWSOfferReceiptIssuer,
  createOfferReceiptExtension,
  declareOfferReceiptExtension,
} from "../src/offer-receipt";
import { createES256Signer, generateES256KeyPair } from "./offer-receipt-test-utils";

const ISSUER = "https://api.example.com";
const RESOURCE = `${ISSUER}/premium-data`;
const DIR_URL = `${ISSUER}/.well-known/x402-receipt-keys`;
const NOW = 1_790_473_960;
const BODY = new TextEncoder().encode(JSON.stringify({ price: "64012.55", source: "example" }));

const requirements: PaymentRequirements = {
  scheme: "exact",
  network: "eip155:8453",
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
  amount: "10000",
  maxTimeoutSeconds: 60,
  extra: {},
};

const settle: SettleResponse = {
  success: true,
  transaction: "0x5c6e0000000000000000000000000000000000000000000000000000000000a1",
  network: "eip155:8453",
  payer: "0x857b06519E91e3A54538791bDbb0E22373e36b66",
};

const seed = (n: number) => new Uint8Array(32).fill(n);

let govEd: ReceiptKeyPair;
let govPq: ReceiptKeyPair;
let keyEd: ReceiptKeyPair;
let keyPq: ReceiptKeyPair;
let directory: KeyDirectory;
let signers: ReceiptSigner[];

const pinnedPq = () => ({ pinnedGovernanceKeys: [govPq.publicKeyB64] });
const pinnedBoth = () => ({ pinnedGovernanceKeys: [govEd.publicKeyB64, govPq.publicKeyB64] });

/**
 * Builds a transport context the way the HTTP middlewares do after buffering the body.
 *
 * @param body - Response body bytes
 * @param url - Request URL
 * @returns HTTP transport context
 */
function transport(body: Uint8Array = BODY, url = RESOURCE): HTTPTransportContext {
  return {
    request: {
      adapter: {
        getHeader: () => undefined,
        getMethod: () => "GET",
        getPath: () => new URL(url).pathname,
        getUrl: () => url,
        getAcceptHeader: () => "application/json",
        getUserAgent: () => "vitest",
      },
      path: new URL(url).pathname,
      method: "GET",
    },
    responseBody: Buffer.from(body),
    responseHeaders: { "content-type": "application/json" },
  } as unknown as HTTPTransportContext;
}

/**
 * Settle-result context as passed to enrichSettlementResponse.
 *
 * @param overrides - Fields to override
 * @returns Context
 */
function settleContext(overrides: Partial<SettleResultContext> = {}): SettleResultContext {
  return {
    paymentPayload: {
      x402Version: 2,
      accepted: requirements,
      payload: {},
      extensions: {},
    } as unknown as PaymentPayload,
    requirements,
    declaredExtensions: { [DELIVERY_RECEIPT]: {} },
    phase: "after-handler",
    transportContext: transport(),
    result: settle,
    ...overrides,
  } as SettleResultContext;
}

/**
 * Server configuration with the baseline signer pair and the epoch-1 directory.
 *
 * @param overrides - Fields to override
 * @returns Configuration
 */
function config(overrides: Partial<DeliveryReceiptServerConfig> = {}): DeliveryReceiptServerConfig {
  return {
    issuer: ISSUER,
    signers,
    directory,
    now: () => NOW,
    receiptTransport: "inline",
    ...overrides,
  };
}

/**
 * Issues a receipt through the extension hook.
 *
 * @param ctx - Settle context
 * @param overrides - Config overrides
 * @returns The receipt
 */
async function issue(
  ctx: SettleResultContext = settleContext(),
  overrides: Partial<DeliveryReceiptServerConfig> = {},
): Promise<DeliveryReceipt> {
  const ext = createDeliveryReceiptExtension(config(overrides));
  const out = (await ext.enrichSettlementResponse!({}, ctx)) as {
    info: { receipt: DeliveryReceipt };
  };
  return out.info.receipt;
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const sigOf = (r: DeliveryReceipt, alg: string) => r.signatures.find(s => s.alg === alg)!;
const flip = (b64: string, i = 10) => {
  const bytes = fromCanonicalBase64(b64)!;
  bytes[i] ^= 0xff;
  return Buffer.from(bytes).toString("base64");
};
const codes = (v: { reasons: { code: string }[] }) => v.reasons.map(r => r.code);

beforeAll(async () => {
  govEd = await generateReceiptKeyPair("ed25519", seed(1));
  govPq = await generateReceiptKeyPair("ml-dsa-65", seed(1));
  keyEd = await generateReceiptKeyPair("ed25519", seed(2));
  keyPq = await generateReceiptKeyPair("ml-dsa-65", seed(2));
  signers = [createLocalReceiptSigner(keyEd), createLocalReceiptSigner(keyPq)];
  directory = await buildKeyDirectory({
    issuer: ISSUER,
    publishedAt: NOW - 86_400,
    governance: [govEd, govPq],
    keys: [activeKeyEntry(keyEd, NOW - 86_400), activeKeyEntry(keyPq, NOW - 86_400)],
  });
});

describe("delivery-receipt: encoding", () => {
  it("canonicalizes the safe subset and rejects floats/undefined", () => {
    expect(canonicalJson({ b: 1, a: [true, null, "x"] })).toBe('{"a":[true,null,"x"],"b":1}');
    expect(() => canonicalJson({ a: 1.5 })).toThrow();
    expect(() => canonicalJson({ a: undefined })).toThrow();
    expect(() => canonicalJson({ a: 2 ** 60 })).toThrow();
  });

  it("accepts only canonical base64", () => {
    expect(fromCanonicalBase64("AAEC")).toEqual(new Uint8Array([0, 1, 2]));
    expect(fromCanonicalBase64("AAEC\n")).toBeNull();
    expect(fromCanonicalBase64("AAE=")).not.toBeNull();
    expect(fromCanonicalBase64("AAF=")).toBeNull(); // non-zero pad bits
    expect(fromCanonicalBase64(42)).toBeNull();
  });

  it("signs the 64-character hex text of the receipt id, not the raw digest", async () => {
    const receipt = await issue();
    const id = await computeReceiptId(receipt.payload);
    const msg = receiptSignedMessage(id);
    expect(new TextDecoder().decode(msg)).toBe(`x402-delivery-receipt/1\n${id}`);
    expect(msg.length).toBe(24 + 64);
    const ed = fromCanonicalBase64(sigOf(receipt, "ed25519").signature)!;
    expect(ed25519.verify(ed, msg, keyEd.publicKey)).toBe(true);
    // The other reading of the issue text (domain line + raw 32-byte digest) must not verify.
    const raw = new Uint8Array([
      ...new TextEncoder().encode("x402-delivery-receipt/1\n"),
      ...Buffer.from(id, "hex"),
    ]);
    expect(ed25519.verify(ed, raw, keyEd.publicKey)).toBe(false);
  });
});

describe("delivery-receipt: stream digest", () => {
  it("chains frames in order with a length prefix", async () => {
    const empty = await computeStreamDigest([]);
    expect(empty).toEqual({
      frameCount: 0,
      digest: await sha256Hex("x402-delivery-stream/1"),
    });
    const a = await computeStreamDigest(["ab", "c"]);
    const b = await computeStreamDigest(["a", "bc"]);
    const c = await computeStreamDigest(["c", "ab"]);
    expect(a.frameCount).toBe(2);
    expect(new Set([a.digest, b.digest, c.digest]).size).toBe(3);
  });

  it("parses SSE the way EventSource dispatches it", () => {
    const text = `: comment\nretry: 10\n\nevent: tick\nid: 1\ndata: line1\ndata: line2\n\ndata:x\r\n\r\n`;
    expect(parseSse(text)).toEqual([
      { event: "tick", data: "line1\nline2", id: "1" },
      { event: "message", data: "x", id: "1" },
    ]);
    expect(formatSseEvent("a\nb", "e")).toBe("event: e\ndata: a\ndata: b\n\n");
  });
});

describe("delivery-receipt: key directory", () => {
  it("verifies a freshly built directory on both paths (tls and pinned)", async () => {
    for (const path of ["session", "archival"] as const) {
      const tls = await verifyKeyDirectory(directory, { expectedIssuer: ISSUER, path });
      expect(tls, path).toMatchObject({ ok: true, trustBasis: "tls" });
      const pinned = await verifyKeyDirectory(directory, {
        expectedIssuer: ISSUER,
        path,
        ...pinnedBoth(),
      });
      expect(pinned, path).toMatchObject({ ok: true, trustBasis: "pinned" });
    }
  });

  it("pins only the governance key whose signature was verified on the path", async () => {
    // Pinning the ML-DSA governance key does not vouch for an Ed25519 signature.
    const r = await verifyKeyDirectory(directory, {
      expectedIssuer: ISSUER,
      path: "session",
      ...pinnedPq(),
    });
    expect(r.code).toBe("DIRECTORY_SIGNER_NOT_PINNED");
  });

  it("checks each governance signature on its own path", async () => {
    const badPq = clone(directory);
    badPq.signatures = badPq.signatures.map(s =>
      s.alg === "ml-dsa-65" ? { ...s, signature: flip(s.signature) } : s,
    );
    expect((await verifyKeyDirectory(badPq, { expectedIssuer: ISSUER, path: "session" })).ok).toBe(
      true,
    );
    expect((await verifyKeyDirectory(badPq, { expectedIssuer: ISSUER })).code).toBe(
      "DIRECTORY_SIGNATURE_INVALID",
    );
  });

  it("requires both governance algorithms", async () => {
    const one = clone(directory);
    one.governanceKeys = one.governanceKeys.filter(g => g.alg === "ml-dsa-65");
    expect((await verifyKeyDirectory(one, { expectedIssuer: ISSUER })).detail).toBe(
      "governanceKeys",
    );
  });

  it("rejects a tampered directory, a foreign issuer and an unpinned governance key", async () => {
    const tampered = clone(directory);
    tampered.keys[0].status = "retired";
    expect((await verifyKeyDirectory(tampered, { expectedIssuer: ISSUER })).code).toBe(
      "DIRECTORY_ROOT_MISMATCH",
    );
    expect(
      (await verifyKeyDirectory(directory, { expectedIssuer: "https://evil.example" })).code,
    ).toBe("DIRECTORY_ISSUER_MISMATCH");
    const forged = await buildKeyDirectory({
      issuer: ISSUER,
      publishedAt: NOW - 10,
      governance: [
        await generateReceiptKeyPair("ed25519", seed(9)),
        await generateReceiptKeyPair("ml-dsa-65", seed(9)),
      ],
      keys: [activeKeyEntry(keyEd, NOW - 10), activeKeyEntry(keyPq, NOW - 10)],
    });
    expect((await verifyKeyDirectory(forged, { expectedIssuer: ISSUER, ...pinnedPq() })).code).toBe(
      "DIRECTORY_SIGNER_NOT_PINNED",
    );
    expect(
      (await verifyKeyDirectory(forged, { expectedIssuer: ISSUER, requirePinned: true })).code,
    ).toBe("DIRECTORY_SIGNER_NOT_PINNED");
    const listedGov = clone(directory);
    listedGov.keys.push(activeKeyEntry(govPq, 0));
    expect((await verifyKeyDirectory(listedGov, { expectedIssuer: ISSUER })).detail).toBe(
      "governance key listed",
    );
    expect((await verifyKeyDirectory(null, { expectedIssuer: ISSUER })).ok).toBe(false);
  });

  it("applies the key lifecycle at issuedAt", () => {
    const e = activeKeyEntry(keyPq, 100);
    expect(keyAuthorizationError(e, "ml-dsa-65", 150, 200)).toBeNull();
    expect(keyAuthorizationError(e, "ml-dsa-65", 50, 200)).toBe("KEY_NOT_YET_VALID");
    expect(keyAuthorizationError(e, "ed25519", 150, 200)).toBe("KEY_ALG_MISMATCH");
    expect(keyAuthorizationError(e, "ml-dsa-65", 10_000, 200)).toBe("ISSUED_AT_IN_FUTURE");
    expect(keyAuthorizationError({ ...e, use: "other" }, "ml-dsa-65", 150, 200)).toBe(
      "KEY_USE_MISMATCH",
    );
    expect(
      keyAuthorizationError({ ...e, status: "retiring", notAfter: 160 }, "ml-dsa-65", 150, 200),
    ).toBeNull();
    expect(
      keyAuthorizationError({ ...e, status: "retired", notAfter: 140 }, "ml-dsa-65", 150, 200),
    ).toBe("KEY_EXPIRED");
    expect(
      keyAuthorizationError({ ...e, status: "revoked", revokedAt: 999 }, "ml-dsa-65", 150, 200),
    ).toBe("KEY_REVOKED");
    expect(keyAuthorizationError({ ...e, status: "reserved" }, "ml-dsa-65", 150, 200)).toBe(
      "KEY_NOT_ACTIVE",
    );
  });
});

describe("delivery-receipt: directory epochs and chaining", () => {
  let e2: KeyDirectory;
  let e3: KeyDirectory;
  let keyPq2: ReceiptKeyPair;
  const T2 = NOW + 1000;
  const T3 = NOW + 2000;
  const retiring = (k: ReceiptKeyPair, until: number): KeyDirectoryEntry => ({
    ...activeKeyEntry(k, NOW - 86_400),
    status: "retiring",
    notAfter: until,
  });

  beforeAll(async () => {
    keyPq2 = await generateReceiptKeyPair("ml-dsa-65", seed(4));
    // Epoch 2 adds a new ML-DSA key and retires the first one at T2.
    e2 = await buildKeyDirectory({
      issuer: ISSUER,
      epoch: 2,
      prevRoot: directory.root,
      publishedAt: T2,
      governance: [govEd, govPq],
      keys: [activeKeyEntry(keyEd, NOW - 86_400), retiring(keyPq, T2), activeKeyEntry(keyPq2, T2)],
    });
    e3 = await buildKeyDirectory({
      issuer: ISSUER,
      epoch: 3,
      prevRoot: e2.root,
      publishedAt: T3,
      governance: [govEd, govPq],
      keys: [
        activeKeyEntry(keyEd, NOW - 86_400),
        { ...retiring(keyPq, T2), status: "retired" },
        activeKeyEntry(keyPq2, T2),
      ],
    });
  });

  it("binds the epoch and digest of the directory in force", async () => {
    const r = await issue();
    expect(r.payload.keyDirectoryEpoch).toBe(1);
    expect(r.payload.keyDirectoryDigest).toBe(directory.root);
  });

  it("verifies an old receipt against archives chained to the current directory (tls)", async () => {
    const r = await issue();
    const v = await verifyDeliveryReceipt(r, {
      directories: [e3, directory, e2],
      now: T3 + 10,
      offline: true,
    });
    expect(v.reasons).toEqual([]);
    expect(v).toMatchObject({
      valid: true,
      trustBasis: "tls",
      directoryEpoch: 1,
      latestDirectoryEpoch: 3,
    });
  });

  it("refuses a gap in the chain under tls trust, but accepts a pinned saved copy", async () => {
    const r = await issue();
    const gap = await verifyDeliveryReceipt(r, { directories: [directory, e3], now: T3 + 10 });
    expect(codes(gap)).toContain("DIRECTORY_CHAIN_BROKEN");
    const pinned = await verifyDeliveryReceipt(r, {
      directory,
      directoryTrust: pinnedPq(),
      now: T3 + 10,
      offline: true,
    });
    expect(pinned.valid).toBe(true);
    expect(pinned.longTermEvidence).toBe(true);
  });

  it("detects a broken link, a dropped key and a status regression", async () => {
    const r = await issue();
    const fakePrev = await buildKeyDirectory({
      issuer: ISSUER,
      epoch: 2,
      prevRoot: "ab".repeat(32),
      publishedAt: T2,
      governance: [govEd, govPq],
      keys: [activeKeyEntry(keyEd, NOW - 86_400), retiring(keyPq, T2)],
    });
    expect(
      codes(await verifyDeliveryReceipt(r, { directories: [directory, fakePrev], now: T2 })),
    ).toContain("DIRECTORY_CHAIN_BROKEN");
    const dropped = await buildKeyDirectory({
      issuer: ISSUER,
      epoch: 2,
      prevRoot: directory.root,
      publishedAt: T2,
      governance: [govEd, govPq],
      keys: [activeKeyEntry(keyEd, NOW - 86_400)],
    });
    expect(
      codes(await verifyDeliveryReceipt(r, { directories: [directory, dropped], now: T2 })),
    ).toContain("DIRECTORY_CHAIN_KEY_DROPPED");
    const regressed = await buildKeyDirectory({
      issuer: ISSUER,
      epoch: 4,
      prevRoot: e3.root,
      publishedAt: T3,
      governance: [govEd, govPq],
      keys: [
        activeKeyEntry(keyEd, NOW - 86_400),
        activeKeyEntry(keyPq, NOW - 86_400),
        activeKeyEntry(keyPq2, T2),
      ],
    });
    const chain = await verifyKeyDirectoryChain([directory, e2, e3, regressed], 1, {
      expectedIssuer: ISSUER,
    });
    expect(chain.code).toBe("DIRECTORY_CHAIN_STATUS_REGRESSED");
  });

  it("reads revocation from the latest chained epoch", async () => {
    const r = await issue();
    const revoked = await buildKeyDirectory({
      issuer: ISSUER,
      epoch: 2,
      prevRoot: directory.root,
      publishedAt: NOW + 50,
      governance: [govEd, govPq],
      keys: [
        activeKeyEntry(keyEd, NOW - 86_400),
        { ...activeKeyEntry(keyPq, NOW - 86_400), status: "revoked", revokedAt: NOW + 50 },
      ],
    });
    const v = await verifyDeliveryReceipt(r, { directories: [directory, revoked], now: NOW + 60 });
    expect(v.levels.authentic).toBe(true);
    expect(v.levels.trusted).toBe(false);
    expect(codes(v)).toContain("KEY_REVOKED");
    // The session path uses the Ed25519 key, which was not revoked.
    const s = await verifyDeliveryReceipt(r, {
      directories: [directory, revoked],
      path: "session",
      now: NOW + 60,
      offline: true,
    });
    expect(s.valid).toBe(true);
  });

  it("rejects a digest that does not name the directory, and stale or future epochs", async () => {
    const r = await issue();
    const wrongDigest = (
      await signDeliveryReceipt({ ...r.payload, keyDirectoryDigest: "cd".repeat(32) }, signers)
    ).receipt;
    expect(codes(await verifyDeliveryReceipt(wrongDigest, { directory, now: NOW }))).toContain(
      "KEY_DIRECTORY_DIGEST_MISMATCH",
    );
    // Issued under epoch 1 although epoch 2 was already in force.
    const stale = (await signDeliveryReceipt({ ...r.payload, issuedAt: T2 + 600 }, signers))
      .receipt;
    expect(
      codes(await verifyDeliveryReceipt(stale, { directories: [directory, e2], now: T2 + 600 })),
    ).toContain("KEY_DIRECTORY_SUPERSEDED");
    const early = (await signDeliveryReceipt({ ...r.payload, issuedAt: NOW - 90_000 }, signers))
      .receipt;
    expect(codes(await verifyDeliveryReceipt(early, { directory, now: NOW }))).toContain(
      "KEY_DIRECTORY_NOT_IN_FORCE",
    );
    expect(
      codes(await verifyDeliveryReceipt(r, { directories: [e2], directoryTrust: pinnedPq() })),
    ).toContain("DIRECTORY_EPOCH_UNAVAILABLE");
  });

  it("fetches the stable URL and the per-epoch archives it needs", async () => {
    const served: string[] = [];
    const docs: Record<string, KeyDirectory> = {
      [DIR_URL]: e3,
      [keyDirectoryEpochUrl(DIR_URL, 1)]: directory,
      [keyDirectoryEpochUrl(DIR_URL, 2)]: e2,
    };
    const f = (async (url: string) => {
      served.push(url);
      return docs[url]
        ? new Response(JSON.stringify(docs[url]))
        : new Response("not found", { status: 404 });
    }) as unknown as typeof fetch;
    const chain = await fetchKeyDirectoryChain(DIR_URL, 1, f);
    expect(served).toEqual([DIR_URL, `${DIR_URL}/epoch/1`, `${DIR_URL}/epoch/2`]);
    expect(chain).toHaveLength(3);
    const v = await verifyDeliveryReceipt(await issue(), {
      directories: chain,
      now: T3,
      offline: true,
    });
    expect(v.valid).toBe(true);
    served.length = 0;
    expect(await fetchKeyDirectoryChain(DIR_URL, 3, f)).toHaveLength(1);
    expect(served).toEqual([DIR_URL]);
  });
});

describe("delivery-receipt: server extension", () => {
  it("declares itself in the 402 response", async () => {
    const ext = createDeliveryReceiptExtension(config());
    const out = (await ext.enrichPaymentRequiredResponse!({}, {} as PaymentRequiredContext)) as {
      info: Record<string, unknown>;
    };
    expect(out.info).toEqual({
      version: 1,
      issuer: ISSUER,
      keyDirectory: DIR_URL,
      algorithms: ["ed25519", "ml-dsa-65"],
      deliveryMode: "body",
      receiptTransport: "inline",
    });
    expect(declareDeliveryReceiptExtension()).toEqual({ [DELIVERY_RECEIPT]: {} });
    expect(() =>
      createDeliveryReceiptExtension(config({ keyDirectory: "https://other.example/keys" })),
    ).toThrow(/same-origin/);
  });

  it("refuses to run without the ed25519 + ml-dsa-65 pair", () => {
    expect(() => createDeliveryReceiptExtension(config({ signers: [signers[1]] }))).toThrow(
      /ed25519 and ml-dsa-65/,
    );
    expect(() =>
      createDeliveryReceiptExtension(config({ signers: [signers[0], signers[0]] })),
    ).toThrow(/ed25519 and ml-dsa-65/);
  });

  it("refuses to sign with a key that is not in the directory epoch", async () => {
    const stray = createLocalReceiptSigner(await generateReceiptKeyPair("ml-dsa-65", seed(5)));
    await expect(issue(settleContext(), { signers: [signers[0], stray] })).rejects.toThrow(
      /not in directory/,
    );
  });

  it("binds settlement, resource, body digest and directory into the signed payload", async () => {
    const receipt = await issue(
      settleContext({
        paymentPayload: {
          x402Version: 2,
          accepted: requirements,
          payload: {},
          extensions: { "payment-identifier": { info: { id: "pay_7d5d747be160e280504c" } } },
        } as unknown as PaymentPayload,
      }),
    );
    expect(receipt.signatures.map(s => [s.alg, s.kid])).toEqual([
      ["ed25519", keyEd.kid],
      ["ml-dsa-65", keyPq.kid],
    ]);
    expect(fromCanonicalBase64(sigOf(receipt, "ml-dsa-65").signature)!.length).toBe(3309);
    expect(fromCanonicalBase64(sigOf(receipt, "ed25519").signature)!.length).toBe(64);
    expect(receipt.payload).toEqual({
      version: 1,
      issuer: ISSUER,
      resourceUrl: RESOURCE,
      method: "GET",
      scheme: "exact",
      network: "eip155:8453",
      asset: requirements.asset,
      payTo: requirements.payTo,
      amount: "10000",
      payer: settle.payer,
      transaction: settle.transaction,
      logIndex: null,
      paymentId: "pay_7d5d747be160e280504c",
      responseStatus: null,
      responseContentType: "application/json",
      delivery: { mode: "body", sha256: await sha256Hex(BODY) },
      keyDirectoryEpoch: 1,
      keyDirectoryDigest: directory.root,
      issuedAt: NOW,
    });
  });

  it("signs the client-facing URL when the server sits behind a TLS-terminating proxy", async () => {
    const receipt = await issue(
      settleContext({
        transportContext: transport(BODY, "http://api.example.com/premium-data?q=1"),
      }),
    );
    expect(receipt.payload.resourceUrl).toBe(`${RESOURCE}?q=1`);
    const foreign = await issue(
      settleContext({ transportContext: transport(BODY, "http://other.example/premium-data") }),
    );
    expect(foreign.payload.resourceUrl).toBe("http://other.example/premium-data");
  });

  it("issues nothing for failed settles, before-handler settles, missing bodies or streams", async () => {
    const ext = createDeliveryReceiptExtension(config());
    expect(
      await ext.enrichSettlementResponse!(
        {},
        settleContext({ result: { ...settle, success: false } }),
      ),
    ).toBeUndefined();
    expect(
      await ext.enrichSettlementResponse!({}, settleContext({ phase: "before-handler" })),
    ).toBeUndefined();
    expect(
      await ext.enrichSettlementResponse!(
        {},
        settleContext({ transportContext: { request: transport().request } }),
      ),
    ).toBeUndefined();
    const streamExt = createDeliveryReceiptExtension(config({ deliveryMode: "stream" }));
    expect(await streamExt.enrichSettlementResponse!({}, settleContext())).toBeUndefined();
  });

  it("records the resolved log index and tolerates resolver failure", async () => {
    expect(
      (await issue(settleContext(), { resolveLogIndex: async () => 312 })).payload.logIndex,
    ).toBe(312);
    const bad = await issue(settleContext(), {
      resolveLogIndex: async () => {
        throw new Error("rpc down");
      },
    });
    expect(bad.payload.logIndex).toBeNull();
  });

  it("supports delivery by reference with digest and id checks on resolution", async () => {
    const store = createMemoryReceiptStore(ISSUER);
    const ext = createDeliveryReceiptExtension(
      config({ receiptTransport: "reference", receiptStore: store }),
    );
    const out = (await ext.enrichSettlementResponse!({}, settleContext())) as {
      info: { receiptId: string; receiptUrl: string; digest: string };
    };
    const info = extractDeliveryReceipt({
      ...settle,
      extensions: { [DELIVERY_RECEIPT]: out },
    } as SettleResponse)!;
    const fakeFetch = (async (url: string) => store.handle(url)!) as unknown as typeof fetch;
    const receipt = await resolveDeliveryReceipt(info, fakeFetch);
    expect(await computeReceiptId(receipt.payload)).toBe(out.info.receiptId);
    expect(await computeReceiptDigest(receipt)).toBe(out.info.digest);

    // A store that substitutes another genuine receipt is detected (by the digest first).
    const other = await issue(settleContext({ transportContext: transport(new Uint8Array([1])) }));
    const swapFetch = (async () =>
      new Response(canonicalJson(other), { status: 200 })) as unknown as typeof fetch;
    await expect(resolveDeliveryReceipt(info, swapFetch)).rejects.toThrow(/digest/);
  });
});

describe("delivery-receipt: verification paths", () => {
  const expected = () => ({
    settle,
    requirements,
    resourceUrl: RESOURCE,
    method: "GET",
    responseBody: BODY,
  });

  it("accepts a genuine receipt at every level on both paths and reports the path", async () => {
    const receipt = await issue();
    const archival = await verifyDeliveryReceipt(receipt, {
      directory,
      directoryTrust: pinnedPq(),
      expected: expected(),
      now: NOW,
    });
    expect(archival.reasons).toEqual([]);
    expect(archival).toMatchObject({
      valid: true,
      path: "archival",
      longTermEvidence: true,
      trustBasis: "pinned",
      // The archival path checks every signature of the receipt (no split verdict).
      signaturesVerified: [
        { alg: "ml-dsa-65", kid: keyPq.kid, engine: "noble" },
        { alg: "ed25519", kid: keyEd.kid, engine: "webcrypto" },
      ],
      unverifiedAlgorithms: [],
      levels: { integrity: true, authentic: true, trusted: true, settlement: true, delivery: true },
    });
    expect(archival.receiptId).toBe(await computeReceiptId(receipt.payload));

    const session = await verifyDeliveryReceipt(receipt, {
      directory,
      path: "session",
      expected: expected(),
      now: NOW,
    });
    expect(session.reasons).toEqual([]);
    expect(session).toMatchObject({
      valid: true,
      path: "session",
      longTermEvidence: false,
      trustBasis: "tls",
      signaturesVerified: [{ alg: "ed25519", kid: keyEd.kid, engine: "webcrypto" }],
    });
  });

  it("verifies each path's signature independently", async () => {
    const receipt = await issue();
    const badPq = clone(receipt);
    sigOf(badPq, "ml-dsa-65").signature = flip(sigOf(badPq, "ml-dsa-65").signature);
    expect((await verifyDeliveryReceipt(badPq, { directory, now: NOW })).levels.authentic).toBe(
      false,
    );
    // In session only the Ed25519 signature is checked; the result is not long-term evidence.
    const s = await verifyDeliveryReceipt(badPq, {
      directory,
      path: "session",
      now: NOW,
      offline: true,
    });
    expect(s.valid).toBe(true);
    expect(s.longTermEvidence).toBe(false);
    expect(s.unverifiedAlgorithms).toEqual(["ml-dsa-65"]);

    const badEd = clone(receipt);
    sigOf(badEd, "ed25519").signature = flip(sigOf(badEd, "ed25519").signature);
    expect(
      (await verifyDeliveryReceipt(badEd, { directory, path: "session", now: NOW })).levels
        .authentic,
    ).toBe(false);
    // Archival checks every signature: a broken Ed25519 signature is not ignored there either,
    // so archival-valid implies session-valid.
    const archivalBadEd = await verifyDeliveryReceipt(badEd, {
      directory,
      now: NOW,
      offline: true,
    });
    expect(archivalBadEd.valid).toBe(false);
    expect(archivalBadEd.reasons).toContainEqual({
      level: "authentic",
      code: "SIGNATURE_INVALID",
      detail: "ed25519",
    });
  });

  it("requires the signature pair structurally on every path", async () => {
    const receipt = await issue();
    for (const keep of ["ed25519", "ml-dsa-65"]) {
      const stripped = { ...clone(receipt), signatures: [sigOf(receipt, keep)] };
      for (const path of ["session", "archival"] as const) {
        const v = await verifyDeliveryReceipt(stripped, { directory, path, now: NOW });
        expect(v.levels.integrity).toBe(false);
        expect(codes(v)).toEqual(["SIGNATURES_SHAPE"]);
      }
    }
    const twoEd = {
      ...clone(receipt),
      signatures: [sigOf(receipt, "ed25519"), sigOf(receipt, "ed25519")],
    };
    expect(codes(await verifyDeliveryReceipt(twoEd, { directory, now: NOW }))).toEqual([
      "SIGNATURES_DUPLICATE_ALG",
    ]);
    const ed87 = await generateReceiptKeyPair("ml-dsa-87", seed(6));
    const extra = (
      await signDeliveryReceipt(receipt.payload, [signers[0], createLocalReceiptSigner(ed87)])
    ).receipt;
    expect(codes(await verifyDeliveryReceipt(extra, { directory, now: NOW }))).toEqual([
      "SIGNATURE_PAIR_MISSING",
    ]);
  });

  it("rejects an altered payload on both paths, and unsigned fields", async () => {
    const receipt = await issue();
    const altered = clone(receipt);
    altered.payload.amount = "1";
    for (const path of ["session", "archival"] as const) {
      const v = await verifyDeliveryReceipt(altered, { directory, path, now: NOW });
      expect(v.valid).toBe(false);
      expect(codes(v)).toContain("SIGNATURE_INVALID");
    }
    const extraField = { ...clone(receipt), note: "unsigned" };
    expect(
      (await verifyDeliveryReceipt(extraField, { directory, now: NOW })).levels.integrity,
    ).toBe(false);
    const floatPayload = clone(receipt);
    (floatPayload.payload as unknown as Record<string, unknown>).issuedAt = 1.5;
    expect(
      (await verifyDeliveryReceipt(floatPayload, { directory, now: NOW })).levels.integrity,
    ).toBe(false);
    const badDelivery = clone(receipt);
    (badDelivery.payload.delivery as unknown as Record<string, unknown>).extra = 1;
    expect(codes(await verifyDeliveryReceipt(badDelivery, { directory, now: NOW }))).toEqual([
      "PAYLOAD_FIELD_delivery",
    ]);
  });

  it("rejects receipts signed by an untrusted key", async () => {
    const rogueEd = await generateReceiptKeyPair("ed25519", seed(7));
    const roguePq = await generateReceiptKeyPair("ml-dsa-65", seed(7));
    const receipt = await issue();
    const rogueSigners = [rogueEd, roguePq].map(createLocalReceiptSigner);
    const { receipt: rogueReceipt } = await signDeliveryReceipt(receipt.payload, rogueSigners);
    expect(codes(await verifyDeliveryReceipt(rogueReceipt, { directory, now: NOW }))).toContain(
      "KEY_NOT_LISTED",
    );
    const rogueDir = await buildKeyDirectory({
      issuer: ISSUER,
      publishedAt: NOW - 10,
      governance: [
        await generateReceiptKeyPair("ed25519", seed(8)),
        await generateReceiptKeyPair("ml-dsa-65", seed(8)),
      ],
      keys: [activeKeyEntry(rogueEd, NOW - 10), activeKeyEntry(roguePq, NOW - 10)],
    });
    const { receipt: r2 } = await signDeliveryReceipt(
      { ...receipt.payload, keyDirectoryDigest: rogueDir.root },
      rogueSigners,
    );
    const v2 = await verifyDeliveryReceipt(r2, {
      directory: rogueDir,
      directoryTrust: pinnedPq(),
      now: NOW,
    });
    expect(v2.valid).toBe(false);
    expect(codes(v2)).toContain("DIRECTORY_SIGNER_NOT_PINNED");
  });

  it("rejects a receipt whose settlement does not match what the client observed", async () => {
    const receipt = await issue();
    const cases: [string, Record<string, unknown>][] = [
      ["transaction", { settle: { ...settle, transaction: "0x" + "ab".repeat(32) } }],
      ["payer", { settle: { ...settle, payer: "0x0000000000000000000000000000000000000001" } }],
      ["network", { settle: { ...settle, network: "eip155:1" } }],
      ["amount", { settle: { ...settle, amount: "9999" } }],
      ["payTo", { requirements: { ...requirements, payTo: "0x" + "11".repeat(20) } }],
      ["asset", { requirements: { ...requirements, asset: "0x" + "22".repeat(20) } }],
      ["resourceUrl", { resourceUrl: `${ISSUER}/other` }],
      ["method", { method: "POST" }],
      ["paymentId", { paymentId: "pay_other_identifier_123" }],
    ];
    for (const [field, override] of cases) {
      const v = await verifyDeliveryReceipt(receipt, {
        directory,
        expected: { ...expected(), ...override },
        now: NOW,
      });
      expect(v.valid, field).toBe(false);
      expect(v.levels.settlement, field).toBe(false);
      expect(v.reasons, field).toContainEqual({
        level: "settlement",
        code: "SETTLEMENT_MISMATCH",
        detail: field,
      });
    }
    const v = await verifyDeliveryReceipt(receipt, {
      directory,
      expected: { settle: { ...settle, payer: settle.payer!.toLowerCase() } },
      now: NOW,
    });
    expect(v.levels.settlement).toBe(true);
  });

  it("rejects a body that does not match, and a mode that does not match", async () => {
    const receipt = await issue();
    const v = await verifyDeliveryReceipt(receipt, {
      directory,
      expected: { ...expected(), responseBody: new TextEncoder().encode('{"price":"1"}') },
      now: NOW,
    });
    expect(v.levels.delivery).toBe(false);
    expect(codes(v)).toContain("BODY_DIGEST_MISMATCH");
    const m = await verifyDeliveryReceipt(receipt, {
      directory,
      expected: { frames: ["a"] },
      now: NOW,
    });
    expect(codes(m)).toEqual(["DELIVERY_MODE_MISMATCH"]);
  });

  it("enforces issuer authorization and rejects future-dated receipts", async () => {
    const receipt = await issue(
      settleContext({ transportContext: transport(BODY, "https://shop.example/x") }),
    );
    const v = await verifyDeliveryReceipt(receipt, { directory, now: NOW });
    expect(codes(v)).toContain("ISSUER_NOT_AUTHORIZED");
    expect(
      (
        await verifyDeliveryReceipt(receipt, {
          directory,
          acceptedIssuers: [ISSUER],
          now: NOW,
          offline: true,
        })
      ).valid,
    ).toBe(true);
    const future = await verifyDeliveryReceipt(await issue(), { directory, now: NOW - 3600 });
    expect(codes(future)).toContain("ISSUED_AT_IN_FUTURE");
  });
});

describe("delivery-receipt: composition with offer-receipt", () => {
  /**
   * Settles through x402ResourceServer with both extensions registered and declared.
   *
   * @param includeTxHash - offer-receipt includeTxHash option
   * @returns The settle response
   */
  async function settleBoth(includeTxHash: boolean): Promise<SettleResponse> {
    const { privateKey } = await generateES256KeyPair();
    const kid = "did:web:api.example.com#key-1";
    const facilitator: FacilitatorClient = {
      verify: vi.fn(async () => ({ isValid: true, payer: settle.payer })),
      settle: vi.fn(async () => ({ ...settle })),
      getSupported: vi.fn(async () => ({ kinds: [], extensions: [], signers: {} })),
    };
    const server = new x402ResourceServer(facilitator)
      .registerExtension(
        createOfferReceiptExtension(
          createJWSOfferReceiptIssuer(kid, createES256Signer(privateKey, kid)),
        ),
      )
      .registerExtension(createDeliveryReceiptExtension(config()));
    return server.settlePayment(
      { x402Version: 2, accepted: requirements, payload: {}, resource: { url: RESOURCE } } as never,
      requirements,
      { ...declareOfferReceiptExtension({ includeTxHash }), ...declareDeliveryReceiptExtension() },
      transport(),
    );
  }

  it("accepts two receipts that describe the same payment", async () => {
    for (const includeTxHash of [true, false]) {
      const result = await settleBoth(includeTxHash);
      const facts = offerReceiptFacts(result)!;
      expect(facts.transaction).toBe(includeTxHash ? settle.transaction : null);
      const receipt = (extractDeliveryReceipt(result) as { receipt: DeliveryReceipt }).receipt;
      const v = await verifyDeliveryReceipt(receipt, {
        directory,
        expected: { settle, offerReceipt: facts },
        now: NOW,
      });
      expect(v.reasons, String(includeTxHash)).toEqual([]);
      expect(v.levels.settlement).toBe(true);
    }
  });

  it("rejects when the offer-receipt names another transaction, payer or network", async () => {
    const result = await settleBoth(true);
    const receipt = (extractDeliveryReceipt(result) as { receipt: DeliveryReceipt }).receipt;
    const facts = offerReceiptFacts(result)!;
    for (const [field, override] of [
      ["transaction", { transaction: "0x" + "cd".repeat(32) }],
      ["payer", { payer: "0x0000000000000000000000000000000000000003" }],
      ["network", { network: "eip155:1" }],
    ] as const) {
      const v = await verifyDeliveryReceipt(receipt, {
        directory,
        expected: { offerReceipt: { ...facts, ...override } },
        now: NOW,
      });
      expect(v.valid, field).toBe(false);
      expect(v.reasons, field).toContainEqual({
        level: "settlement",
        code: "OFFER_RECEIPT_MISMATCH",
        detail: `offer-receipt.${field}`,
      });
    }
  });

  it("is applied by the fetch plugin when both receipts are in PAYMENT-RESPONSE", async () => {
    const result = await settleBoth(true);
    const offer = (result.extensions as Record<string, { info: { receipt: unknown } }>)[
      OFFER_RECEIPT
    ];
    const mk = (offerInfo: unknown) =>
      (async (input: RequestInfo | URL) => {
        const req = new Request(input);
        if (req.url === DIR_URL) return new Response(JSON.stringify(directory));
        return new Response(BODY, {
          headers: {
            "PAYMENT-RESPONSE": encodePaymentResponseHeader({
              ...result,
              extensions: { ...result.extensions, [OFFER_RECEIPT]: offerInfo },
            } as SettleResponse),
          },
        });
      }) as typeof fetch;
    const paid = () =>
      new Request(RESOURCE, {
        headers: {
          "PAYMENT-SIGNATURE": encodePaymentSignatureHeader({
            x402Version: 2,
            accepted: requirements,
            payload: {},
            resource: { url: RESOURCE },
          } as unknown as PaymentPayload),
        },
      });
    vi.useFakeTimers({ now: NOW * 1000 });
    try {
      const ok = await withDeliveryReceipts(mk(offer))(paid());
      expect(getDeliveryReceiptResult(ok)!.reasons).toEqual([]);
      const forged = {
        info: {
          receipt: {
            format: "eip712",
            payload: {
              version: 1,
              network: settle.network,
              resourceUrl: RESOURCE,
              payer: settle.payer,
              issuedAt: NOW,
              transaction: "0x" + "ef".repeat(32),
            },
            signature: "0x00",
          },
        },
      };
      const bad = await withDeliveryReceipts(mk(forged))(paid());
      expect(codes(getDeliveryReceiptResult(bad)!)).toContain("OFFER_RECEIPT_MISMATCH");
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("delivery-receipt: stream mode (SSE)", () => {
  const streamContext = {
    resourceUrl: `${ISSUER}/live-feed`,
    method: "GET",
    requirements,
    settle,
    responseStatus: 200,
  };
  const expectedStream = () => ({
    settle,
    requirements,
    resourceUrl: `${ISSUER}/live-feed`,
    method: "GET",
  });

  /**
   * Simulates a 15-minute priced SSE route: one event per second, then the terminal frame.
   *
   * @param n - Number of events
   * @param overrides - Config overrides
   * @returns Full event-stream text, the trailer and the frames sent
   */
  async function runStream(
    n = 900,
    overrides: Partial<DeliveryReceiptServerConfig> = {},
  ): Promise<{ text: string; trailer: StreamTrailer; frames: string[] }> {
    const writer = createSseReceiptWriter(
      config({ deliveryMode: "stream", ...overrides }),
      streamContext,
    );
    const frames: string[] = [];
    let text = "";
    for (let i = 0; i < n; i++) {
      const data = JSON.stringify({ seq: i, t: NOW - 900 + i, price: (64000 + i).toString() });
      frames.push(data);
      text += await writer.frame(data, i % 100 === 0 ? "checkpoint" : undefined);
    }
    // A multi-line event and a comment line: framing follows EventSource semantics.
    frames.push("line one\nline two");
    text += await writer.frame("line one\nline two");
    text += ": keep-alive\n\n";
    const { event, trailer } = await writer.finish();
    return { text: text + event, trailer, frames };
  }

  /**
   * Rebuilds an event-stream from frames plus the original trailer event.
   *
   * @param frames - Frames to send
   * @param trailer - Trailer to append
   * @returns Event-stream text
   */
  const rebuild = (frames: string[], trailer: StreamTrailer) =>
    frames.map(f => formatSseEvent(f)).join("") +
    formatSseEvent(JSON.stringify(trailer), STREAM_TRAILER_EVENT);

  it("binds frameCount and the final digest into the receipt and the trailer", async () => {
    const { text, trailer, frames } = await runStream();
    const receipt = (trailer as { receipt: DeliveryReceipt }).receipt;
    const local = await computeStreamDigest(frames);
    expect(receipt.payload.delivery).toEqual({
      mode: "stream",
      framing: "sse",
      frameCount: 901,
      digest: local.digest,
    });
    expect(trailer.frameCount).toBe(901);
    expect(trailer.digest).toBe(local.digest);
    expect(receipt.payload.responseContentType).toBe("text/event-stream");

    for (const path of ["session", "archival"] as const) {
      const v = await verifySseDelivery(text, {
        directory,
        path,
        expected: expectedStream(),
        now: NOW,
      });
      expect(v.reasons, path).toEqual([]);
      expect(v.valid, path).toBe(true);
      expect(v.levels.delivery, path).toBe(true);
    }
  });

  it("detects alteration, reordering, insertion and truncation of frames", async () => {
    const { trailer, frames } = await runStream(50);
    const verify = (text: string) =>
      verifySseDelivery(text, { directory, expected: expectedStream(), now: NOW });

    const altered = [...frames];
    altered[17] = altered[17].replace('"seq":17', '"seq":71');
    expect(codes(await verify(rebuild(altered, trailer)))).toEqual(["STREAM_DIGEST_MISMATCH"]);

    const reordered = [...frames];
    [reordered[3], reordered[4]] = [reordered[4], reordered[3]];
    expect(codes(await verify(rebuild(reordered, trailer)))).toEqual(["STREAM_DIGEST_MISMATCH"]);

    const inserted = [...frames.slice(0, 10), '{"seq":"injected"}', ...frames.slice(10)];
    expect(codes(await verify(rebuild(inserted, trailer)))).toEqual([
      "STREAM_FRAME_COUNT_MISMATCH",
      "STREAM_DIGEST_MISMATCH",
    ]);

    const truncated = frames.slice(0, -5);
    expect(codes(await verify(rebuild(truncated, trailer)))).toEqual([
      "STREAM_FRAME_COUNT_MISMATCH",
      "STREAM_DIGEST_MISMATCH",
    ]);

    const cut = frames.map(f => formatSseEvent(f)).join("");
    expect(codes(await verify(cut))).toEqual(["STREAM_TRAILER_MISSING"]);

    const lyingTrailer = { ...trailer, frameCount: 10 };
    expect(codes(await verify(rebuild(frames, lyingTrailer)))).toEqual(["STREAM_TRAILER_MISMATCH"]);

    const after = rebuild(frames, trailer) + formatSseEvent('{"late":true}');
    expect(codes(await verify(after))).toEqual(["STREAM_EVENTS_AFTER_TRAILER"]);
  });

  it("rejects a receipt signed over a different stream", async () => {
    const a = await runStream(5);
    const b = await runStream(6);
    const mixed = rebuild(a.frames, {
      ...a.trailer,
      receipt: (b.trailer as { receipt: DeliveryReceipt }).receipt,
    } as StreamTrailer);
    const v = await verifySseDelivery(mixed, { directory, expected: expectedStream(), now: NOW });
    expect(v.valid).toBe(false);
    expect(codes(v)).toContain("STREAM_TRAILER_MISMATCH");
  });

  it("supports the receipt by reference in the terminal event", async () => {
    const store = createMemoryReceiptStore(ISSUER);
    const { text, trailer } = await runStream(20, {
      receiptTransport: "reference",
      receiptStore: store,
    });
    expect(Object.keys(trailer).sort()).toEqual(["digest", "frameCount", "reference"]);
    const f = (async (url: string) => store.handle(url)!) as unknown as typeof fetch;
    const v = await verifySseDelivery(text, { directory, expected: expectedStream(), now: NOW }, f);
    expect(v.reasons).toEqual([]);
    expect(v.valid).toBe(true);
  });

  it("refuses frames after finish and empty frames", async () => {
    const w = createSseReceiptWriter(config({ deliveryMode: "stream" }), streamContext);
    await expect(w.frame("")).rejects.toThrow(/empty/);
    await w.finish();
    await expect(w.frame("x")).rejects.toThrow(/finished/);
    const failed = createSseReceiptWriter(config(), {
      ...streamContext,
      settle: { ...settle, success: false },
    });
    await expect(failed.finish()).rejects.toThrow(/did not succeed/);
  });

  it("builds stream payloads through the shared payload builder", () => {
    const p = createReceiptPayload({
      issuer: ISSUER,
      resourceUrl: `${ISSUER}/live-feed`,
      method: "get",
      requirements,
      settle,
      responseStatus: 200,
      responseContentType: "text/event-stream",
      delivery: { mode: "stream", framing: "sse", frameCount: 0, digest: "00".repeat(32) },
      directory,
      issuedAt: NOW,
    });
    expect(p?.method).toBe("GET");
    expect(p?.keyDirectoryDigest).toBe(directory.root);
  });
});

describe("delivery-receipt: x402ResourceServer integration", () => {
  it("adds a verifiable receipt to the real settle response", async () => {
    const facilitator: FacilitatorClient = {
      verify: vi.fn(async () => ({ isValid: true, payer: settle.payer })),
      // Return a copy: the server merges extensions into the object it receives.
      settle: vi.fn(async () => ({ ...settle })),
      getSupported: vi.fn(async () => ({ kinds: [], extensions: [], signers: {} })),
    };
    const server = new x402ResourceServer(facilitator).registerExtension(
      createDeliveryReceiptExtension(config()),
    );
    const paymentPayload = {
      x402Version: 2,
      accepted: requirements,
      payload: {},
      resource: { url: RESOURCE },
    } as unknown as PaymentPayload;
    const result = await server.settlePayment(
      paymentPayload,
      requirements,
      declareDeliveryReceiptExtension(),
      transport(),
    );
    expect(result.transaction).toBe(settle.transaction);
    const header = encodePaymentResponseHeader(result);
    expect(header.length).toBeLessThan(12_000);
    const info = extractDeliveryReceipt(result);
    expect(info && "receipt" in info).toBe(true);
    const v = await verifyDeliveryReceipt((info as { receipt: DeliveryReceipt }).receipt, {
      directory,
      directoryTrust: pinnedPq(),
      expected: { settle, requirements, resourceUrl: RESOURCE, method: "GET", responseBody: BODY },
      now: NOW,
    });
    expect(v.valid).toBe(true);
  });
});

describe("delivery-receipt: fetch plugin", () => {
  /**
   * Fake network: serves the paid resource with a receipt, and the key directory.
   *
   * @param receipt - Receipt to attach (undefined = declared but not delivered)
   * @param body - Body to serve
   * @param dirs - Directory documents by URL
   * @param contentType - Content-Type of the paid response
   * @returns fetch-compatible function
   */
  const network = (
    receipt: DeliveryReceipt | undefined,
    body: Uint8Array = BODY,
    dirs: Record<string, unknown> = { [DIR_URL]: directory },
    contentType = "application/json",
  ) =>
    (async (input: RequestInfo | URL) => {
      const req = new Request(input);
      if (req.url in dirs) {
        return new Response(JSON.stringify(dirs[req.url]), {
          headers: { "content-type": "application/json" },
        });
      }
      const s: SettleResponse = {
        ...settle,
        ...(receipt ? { extensions: { [DELIVERY_RECEIPT]: { info: { receipt } } } } : {}),
      };
      return new Response(body, {
        status: 200,
        headers: {
          "content-type": contentType,
          "PAYMENT-RESPONSE": encodePaymentResponseHeader(s),
        },
      });
    }) as typeof fetch;

  const paidRequest = (deliveryMode = "body") =>
    new Request(RESOURCE, {
      headers: {
        "PAYMENT-SIGNATURE": encodePaymentSignatureHeader({
          x402Version: 2,
          accepted: requirements,
          payload: {},
          resource: { url: RESOURCE },
          extensions: {
            [DELIVERY_RECEIPT]: {
              info: {
                version: 1,
                issuer: ISSUER,
                keyDirectory: DIR_URL,
                algorithms: ["ed25519", "ml-dsa-65"],
                deliveryMode,
              },
            },
          },
        } as unknown as PaymentPayload),
      },
    });

  it("verifies the receipt in session (Ed25519) against the payment sent and the body received", async () => {
    const receipt = await issue();
    const onResult = vi.fn();
    const f = withDeliveryReceipts(network(receipt), {
      pinnedGovernanceKeys: [govEd.publicKeyB64],
      onResult,
    });
    vi.useFakeTimers({ now: NOW * 1000 });
    try {
      const res = await f(paidRequest());
      expect(await res.text()).toBe(new TextDecoder().decode(BODY)); // body still readable
      const v = getDeliveryReceiptResult(res)!;
      expect(v.reasons).toEqual([]);
      expect(v).toMatchObject({ valid: true, path: "session", longTermEvidence: false });
      expect(onResult).toHaveBeenCalledOnce();
      const archival = await withDeliveryReceipts(network(receipt), {
        pinnedGovernanceKeys: [govPq.publicKeyB64],
        path: "archival",
      })(paidRequest());
      expect(getDeliveryReceiptResult(archival)).toMatchObject({
        valid: true,
        longTermEvidence: true,
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("resolves the issuance epoch through the per-epoch archive", async () => {
    const receipt = await issue();
    const e2 = await buildKeyDirectory({
      issuer: ISSUER,
      epoch: 2,
      prevRoot: directory.root,
      publishedAt: NOW + 100,
      governance: [govEd, govPq],
      keys: directory.keys,
    });
    const dirs = { [DIR_URL]: e2, [`${DIR_URL}/epoch/1`]: directory };
    vi.useFakeTimers({ now: (NOW + 200) * 1000 });
    try {
      const res = await withDeliveryReceipts(network(receipt, BODY, dirs))(paidRequest());
      expect(getDeliveryReceiptResult(res)).toMatchObject({
        valid: true,
        directoryEpoch: 1,
        latestDirectoryEpoch: 2,
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("flags a substituted body, a missing receipt, and can fail hard", async () => {
    const receipt = await issue();
    vi.useFakeTimers({ now: NOW * 1000 });
    try {
      const tampered = await withDeliveryReceipts(network(receipt, new Uint8Array([123, 125])))(
        paidRequest(),
      );
      expect(codes(getDeliveryReceiptResult(tampered)!)).toContain("BODY_DIGEST_MISMATCH");
      const missing = await withDeliveryReceipts(network(undefined))(paidRequest());
      expect(getDeliveryReceiptResult(missing)!.reasons[0].code).toBe("RECEIPT_MISSING");
      await expect(
        withDeliveryReceipts(network(undefined), { requireValidReceipt: true })(paidRequest()),
      ).rejects.toThrow(/settled in 0x5c6e/);
      // Unpaid requests and streamed routes pass through untouched.
      const plain = await withDeliveryReceipts(network(receipt))(RESOURCE);
      expect(getDeliveryReceiptResult(plain)).toBeUndefined();
      const streamed = await withDeliveryReceipts(
        network(undefined, BODY, undefined, "text/event-stream"),
      )(paidRequest("stream"));
      expect(getDeliveryReceiptResult(streamed)).toBeUndefined();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("delivery-receipt: receipt by reference (default since v0.2.1, §5.5)", () => {
  const refConfig = (o: Partial<DeliveryReceiptServerConfig> = {}) =>
    config({ receiptTransport: undefined, receiptStore: createMemoryReceiptStore(ISSUER), ...o });

  const issueRef = async (o: Partial<DeliveryReceiptServerConfig> = {}) => {
    const store =
      (o.receiptStore as ReturnType<typeof createMemoryReceiptStore>) ??
      createMemoryReceiptStore(ISSUER);
    const ext = createDeliveryReceiptExtension(refConfig({ receiptStore: store, ...o }));
    const member = (await ext.enrichSettlementResponse!({}, settleContext())) as {
      info: { receiptId: string; receiptUrl: string; digest: string };
    };
    return { member, store };
  };

  it("is the default and needs a store; inline is an explicit choice", async () => {
    expect(() => createDeliveryReceiptExtension(config({ receiptTransport: undefined }))).toThrow(
      /by reference by default/,
    );
    const ext = createDeliveryReceiptExtension(refConfig());
    const declared = (await ext.enrichPaymentRequiredResponse!(
      {},
      {} as PaymentRequiredContext,
    )) as {
      info: { receiptTransport: string };
    };
    expect(declared.info.receiptTransport).toBe("reference");
    const inline = createDeliveryReceiptExtension(config({ receiptTransport: "inline" }));
    const d2 = (await inline.enrichPaymentRequiredResponse!({}, {} as PaymentRequiredContext)) as {
      info: { receiptTransport: string };
    };
    expect(d2.info.receiptTransport).toBe("inline");
  });

  it("puts only { receiptId, receiptUrl, digest } in PAYMENT-RESPONSE, within 1 KB", async () => {
    const { member, store } = await issueRef();
    expect(Object.keys(member)).toEqual(["info"]); // no schema, no receipt
    expect(Object.keys(member.info).sort()).toEqual(["digest", "receiptId", "receiptUrl"]);
    expect(member.info.receiptUrl).toBe(`${ISSUER}/x402/receipts/${member.info.receiptId}`);
    const bytes = new TextEncoder().encode(JSON.stringify(member)).length;
    expect(bytes).toBeLessThanOrEqual(MAX_REFERENCE_EXTENSION_BYTES);
    // The whole header stays small; the same receipt inline is ~8 KB of base64.
    const header = encodePaymentResponseHeader({
      ...settle,
      extensions: { [DELIVERY_RECEIPT]: member },
    });
    expect(header.length).toBeLessThan(1024);
    const inline = encodePaymentResponseHeader({
      ...settle,
      extensions: { [DELIVERY_RECEIPT]: { info: { receipt: await issue() } } },
    });
    expect(inline.length).toBeGreaterThan(7000);
    // The store serves exactly JCS(receipt), immutable, and its SHA-256 is the digest.
    const res = store.handle(member.info.receiptUrl)!;
    expect(res.headers.get("cache-control")).toMatch(/immutable/);
    const doc = await res.text();
    expect(await sha256Hex(doc)).toBe(member.info.digest);
    expect(canonicalJson(JSON.parse(doc))).toBe(doc);
  });

  it("refuses store URLs that are cross-origin, not https, not addressed by id, or over budget", async () => {
    const bad = (url: (id: string) => string) => ({ put: (id: string) => url(id) });
    for (const [store, re] of [
      [bad(id => `https://cdn.example.net/x402/receipts/${id}`), /same-origin/],
      [bad(id => `https://api.example.com/x402/receipts/${id}?v=1`), /receiptId/],
      [bad(() => `https://api.example.com/x402/receipts/latest`), /receiptId/],
      [bad(id => `https://api.example.com/${"p/".repeat(400)}${id}`), /budget/],
    ] as const) {
      await expect(issueRef({ receiptStore: store })).rejects.toThrow(re);
    }
  });

  it("keeps stored documents immutable", () => {
    const store = createMemoryReceiptStore(ISSUER);
    store.put("a".repeat(64), {} as DeliveryReceipt, "{}");
    expect(() => store.put("a".repeat(64), {} as DeliveryReceipt, '{"x":1}')).toThrow(
      /never changes/,
    );
  });

  it("checks the digest before parsing, then JCS, then the id", async () => {
    const { member, store } = await issueRef();
    const info = member.info;
    const doc = store.get(info.receiptId)!;
    const serve = (text: string) =>
      (async () => new Response(text, { status: 200 })) as unknown as typeof fetch;
    expect(await computeReceiptId((await resolveDeliveryReceipt(info, serve(doc))).payload)).toBe(
      info.receiptId,
    );
    // Same receipt, other bytes (pretty-printed): the digest no longer matches.
    const pretty = JSON.stringify(JSON.parse(doc), null, 2);
    await expect(resolveDeliveryReceipt(info, serve(pretty))).rejects.toThrow(/digest/);
    // Even with a digest computed over those bytes, a non-canonical document is refused.
    await expect(
      resolveDeliveryReceipt({ ...info, digest: await sha256Hex(pretty) }, serve(pretty)),
    ).rejects.toThrow(/JCS/);
    // A signature swapped by the store changes the digest although receiptId still matches.
    const swapped = JSON.parse(doc) as DeliveryReceipt;
    swapped.signatures.reverse();
    await expect(resolveDeliveryReceipt(info, serve(canonicalJson(swapped)))).rejects.toThrow(
      /digest/,
    );
    // Malformed references fail before any fetch.
    const seen: string[] = [];
    const spy = (async (u: string) => {
      seen.push(u);
      return new Response(doc);
    }) as unknown as typeof fetch;
    await expect(resolveDeliveryReceipt({ ...info, digest: "" }, spy)).rejects.toThrow(/digest/);
    await expect(
      resolveDeliveryReceipt({ ...info, receiptUrl: `${ISSUER}/x402/receipts/latest` }, spy),
    ).rejects.toThrow(/addressed/);
    expect(seen).toEqual([]);
  });

  it("verifies end to end through the fetch plugin, and fails closed without a digest", async () => {
    const store = createMemoryReceiptStore(ISSUER);
    const { member } = await issueRef({ receiptStore: store });
    const net = (m: unknown) =>
      (async (input: RequestInfo | URL) => {
        const req = new Request(input);
        if (req.url === DIR_URL) return new Response(JSON.stringify(directory));
        const served = store.handle(req);
        if (served) return served;
        return new Response(BODY, {
          headers: {
            "content-type": "application/json",
            "PAYMENT-RESPONSE": encodePaymentResponseHeader({
              ...settle,
              extensions: { [DELIVERY_RECEIPT]: m },
            } as SettleResponse),
          },
        });
      }) as typeof fetch;
    const paid = () =>
      new Request(RESOURCE, {
        headers: {
          "PAYMENT-SIGNATURE": encodePaymentSignatureHeader({
            x402Version: 2,
            accepted: requirements,
            payload: {},
            resource: { url: RESOURCE },
            extensions: { [DELIVERY_RECEIPT]: { info: { keyDirectory: DIR_URL } } },
          } as unknown as PaymentPayload),
        },
      });
    vi.useFakeTimers({ now: NOW * 1000 });
    try {
      const res = await withDeliveryReceipts(net(member), {
        pinnedGovernanceKeys: [govEd.publicKeyB64],
      })(paid());
      expect(new Uint8Array(await res.arrayBuffer())).toEqual(BODY); // body untouched
      expect(getDeliveryReceiptResult(res)).toMatchObject({ valid: true, path: "session" });
      const noDigest = {
        info: { receiptId: member.info.receiptId, receiptUrl: member.info.receiptUrl },
      };
      const r2 = await withDeliveryReceipts(net(noDigest))(paid());
      expect(getDeliveryReceiptResult(r2)!.valid).toBe(false);
      expect(getDeliveryReceiptResult(r2)!.reasons[0].code).toBe("RECEIPT_UNAVAILABLE");
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("delivery-receipt: constants", () => {
  it("uses the registered key use", () => {
    expect(RECEIPT_KEY_USE).toBe("x402-delivery-receipt");
  });
});
