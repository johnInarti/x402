import { describe, it, expect, beforeAll, vi } from "vitest";
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
  activeKeyEntry,
  buildKeyDirectory,
  canonicalJson,
  computeReceiptId,
  createDeliveryReceiptExtension,
  createLocalReceiptSigner,
  declareDeliveryReceiptExtension,
  extractDeliveryReceipt,
  fromCanonicalBase64,
  generateReceiptKeyPair,
  getDeliveryReceiptResult,
  keyAuthorizationError,
  resolveDeliveryReceipt,
  sha256Hex,
  signDeliveryReceipt,
  verifyDeliveryReceipt,
  verifyKeyDirectory,
  withDeliveryReceipts,
  type DeliveryReceipt,
  type KeyDirectory,
  type ReceiptKeyPair,
} from "../src/delivery-receipt";

const ISSUER = "https://api.example.com";
const RESOURCE = `${ISSUER}/premium-data`;
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

let governance: ReceiptKeyPair;
let receiptKey: ReceiptKeyPair;
let directory: KeyDirectory;

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
 * Issues a receipt through the extension hook.
 *
 * @param ctx - Settle context
 * @returns The receipt
 */
async function issue(ctx: SettleResultContext = settleContext()): Promise<DeliveryReceipt> {
  const ext = createDeliveryReceiptExtension({
    issuer: ISSUER,
    signer: createLocalReceiptSigner(receiptKey),
    now: () => NOW,
  });
  const out = (await ext.enrichSettlementResponse!({}, ctx)) as {
    info: { receipt: DeliveryReceipt };
  };
  return out.info.receipt;
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

beforeAll(async () => {
  governance = await generateReceiptKeyPair("ml-dsa-65", seed(1));
  receiptKey = await generateReceiptKeyPair("ml-dsa-65", seed(2));
  directory = await buildKeyDirectory({
    issuer: ISSUER,
    governance,
    keys: [activeKeyEntry(receiptKey, NOW - 86_400)],
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
});

describe("delivery-receipt: key directory", () => {
  it("verifies a freshly built directory (tls and pinned)", async () => {
    const tls = await verifyKeyDirectory(directory, { expectedIssuer: ISSUER });
    expect(tls).toMatchObject({ ok: true, trustBasis: "tls" });
    const pinned = await verifyKeyDirectory(directory, {
      expectedIssuer: ISSUER,
      pinnedGovernanceKeys: [governance.publicKeyB64],
    });
    expect(pinned).toMatchObject({ ok: true, trustBasis: "pinned" });
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
    const other = await generateReceiptKeyPair("ml-dsa-65", seed(9));
    const forged = await buildKeyDirectory({
      issuer: ISSUER,
      governance: other,
      keys: [activeKeyEntry(receiptKey, NOW - 10)],
    });
    expect(
      (
        await verifyKeyDirectory(forged, {
          expectedIssuer: ISSUER,
          pinnedGovernanceKeys: [governance.publicKeyB64],
        })
      ).code,
    ).toBe("DIRECTORY_SIGNER_NOT_PINNED");
    expect(
      (await verifyKeyDirectory(forged, { expectedIssuer: ISSUER, requirePinned: true })).code,
    ).toBe("DIRECTORY_SIGNER_NOT_PINNED");
    const badSig = clone(directory);
    badSig.signature = forged.signature;
    expect((await verifyKeyDirectory(badSig, { expectedIssuer: ISSUER })).code).toBe(
      "DIRECTORY_SIGNATURE_INVALID",
    );
  });

  it("detects rollback and equivocation, and malformed input", async () => {
    expect(
      (
        await verifyKeyDirectory(directory, {
          expectedIssuer: ISSUER,
          previous: { epoch: 2, root: "a".repeat(64) },
        })
      ).code,
    ).toBe("DIRECTORY_ROLLBACK");
    expect(
      (
        await verifyKeyDirectory(directory, {
          expectedIssuer: ISSUER,
          previous: { epoch: 1, root: "a".repeat(64) },
        })
      ).code,
    ).toBe("DIRECTORY_EQUIVOCATION");
    expect((await verifyKeyDirectory(null, { expectedIssuer: ISSUER })).ok).toBe(false);
    const listedGov = clone(directory);
    listedGov.keys.push({ ...activeKeyEntry(governance, 0) });
    expect((await verifyKeyDirectory(listedGov, { expectedIssuer: ISSUER })).detail).toBe(
      "governance key listed",
    );
  });

  it("applies the key lifecycle at issuedAt", () => {
    const e = activeKeyEntry(receiptKey, 100);
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

describe("delivery-receipt: server extension", () => {
  it("declares itself in the 402 response", async () => {
    const ext = createDeliveryReceiptExtension({
      issuer: ISSUER,
      signer: createLocalReceiptSigner(receiptKey),
    });
    const out = (await ext.enrichPaymentRequiredResponse!({}, {} as PaymentRequiredContext)) as {
      info: Record<string, unknown>;
    };
    expect(out.info).toEqual({
      version: 1,
      issuer: ISSUER,
      keyDirectory: `${ISSUER}/.well-known/x402-receipt-keys`,
      algorithms: ["ml-dsa-65"],
      delivery: "inline",
    });
    expect(declareDeliveryReceiptExtension()).toEqual({ [DELIVERY_RECEIPT]: {} });
    expect(() =>
      createDeliveryReceiptExtension({
        issuer: ISSUER,
        keyDirectory: "https://other.example/keys",
        signer: createLocalReceiptSigner(receiptKey),
      }),
    ).toThrow(/same-origin/);
  });

  it("binds settlement, resource and body digest into the signed payload", async () => {
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
    expect(receipt.alg).toBe("ml-dsa-65");
    expect(receipt.kid).toBe(receiptKey.kid);
    expect(fromCanonicalBase64(receipt.signature)!.length).toBe(3309);
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
      responseSha256: await sha256Hex(BODY),
      responseContentType: "application/json",
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

  it("issues nothing for failed settles, before-handler settles or missing bodies", async () => {
    expect(
      await createDeliveryReceiptExtension({
        issuer: ISSUER,
        signer: createLocalReceiptSigner(receiptKey),
      }).enrichSettlementResponse!({}, settleContext({ result: { ...settle, success: false } })),
    ).toBeUndefined();
    const ext = createDeliveryReceiptExtension({
      issuer: ISSUER,
      signer: createLocalReceiptSigner(receiptKey),
    });
    expect(
      await ext.enrichSettlementResponse!({}, settleContext({ phase: "before-handler" })),
    ).toBe(undefined);
    expect(
      await ext.enrichSettlementResponse!(
        {},
        settleContext({ transportContext: { request: transport().request } }),
      ),
    ).toBeUndefined();
  });

  it("records the resolved log index and tolerates resolver failure", async () => {
    const mk = (resolveLogIndex: () => Promise<number | null>) =>
      createDeliveryReceiptExtension({
        issuer: ISSUER,
        signer: createLocalReceiptSigner(receiptKey),
        resolveLogIndex,
        now: () => NOW,
      });
    const ok = (await mk(async () => 312).enrichSettlementResponse!({}, settleContext())) as {
      info: { receipt: DeliveryReceipt };
    };
    expect(ok.info.receipt.payload.logIndex).toBe(312);
    const bad = (await mk(async () => {
      throw new Error("rpc down");
    }).enrichSettlementResponse!({}, settleContext())) as { info: { receipt: DeliveryReceipt } };
    expect(bad.info.receipt.payload.logIndex).toBeNull();
  });

  it("supports delivery by reference with id check on resolution", async () => {
    const store = new Map<string, DeliveryReceipt>();
    const ext = createDeliveryReceiptExtension({
      issuer: ISSUER,
      signer: createLocalReceiptSigner(receiptKey),
      now: () => NOW,
      receiptStore: {
        put: async (id, r) => {
          store.set(id, r);
          return `${ISSUER}/x402/receipts/${id}`;
        },
      },
    });
    const out = (await ext.enrichSettlementResponse!({}, settleContext())) as {
      info: { receiptId: string; receiptUrl: string };
    };
    const info = extractDeliveryReceipt({
      ...settle,
      extensions: { [DELIVERY_RECEIPT]: out },
    } as SettleResponse)!;
    const fakeFetch = (async (url: string) =>
      new Response(JSON.stringify(store.get(url.split("/").pop()!)), {
        status: 200,
      })) as unknown as typeof fetch;
    const receipt = await resolveDeliveryReceipt(info, fakeFetch);
    expect(await computeReceiptId(receipt.payload)).toBe(out.info.receiptId);

    // A store that substitutes another genuine receipt is detected.
    const other = await issue(settleContext({ transportContext: transport(new Uint8Array([1])) }));
    const swapFetch = (async () =>
      new Response(JSON.stringify(other), { status: 200 })) as unknown as typeof fetch;
    await expect(resolveDeliveryReceipt(info, swapFetch)).rejects.toThrow(/does not match/);
  });
});

describe("delivery-receipt: verification", () => {
  const expected = () => ({
    settle,
    requirements,
    resourceUrl: RESOURCE,
    method: "GET",
    responseBody: BODY,
  });

  it("accepts a genuine receipt at every level", async () => {
    const receipt = await issue();
    const v = await verifyDeliveryReceipt(receipt, {
      directory,
      directoryTrust: { pinnedGovernanceKeys: [governance.publicKeyB64] },
      expected: expected(),
      now: NOW,
    });
    expect(v.reasons).toEqual([]);
    expect(v).toMatchObject({
      valid: true,
      trustBasis: "pinned",
      levels: { integrity: true, authentic: true, trusted: true, settlement: true, delivery: true },
    });
    expect(v.receiptId).toBe(await computeReceiptId(receipt.payload));
  });

  it("rejects an altered receipt (payload and signature)", async () => {
    const receipt = await issue();
    const altered = clone(receipt);
    altered.payload.amount = "1";
    const v1 = await verifyDeliveryReceipt(altered, { directory, now: NOW });
    expect(v1.valid).toBe(false);
    expect(v1.levels.authentic).toBe(false);
    expect(v1.reasons.map(r => r.code)).toContain("SIGNATURE_INVALID");

    const badSig = clone(receipt);
    const bytes = fromCanonicalBase64(badSig.signature)!;
    bytes[10] ^= 0xff;
    badSig.signature = Buffer.from(bytes).toString("base64");
    expect((await verifyDeliveryReceipt(badSig, { directory, now: NOW })).levels.authentic).toBe(
      false,
    );

    const extraField = { ...clone(receipt), note: "unsigned" };
    expect(
      (await verifyDeliveryReceipt(extraField, { directory, now: NOW })).levels.integrity,
    ).toBe(false);
    const floatPayload = clone(receipt);
    (floatPayload.payload as unknown as Record<string, unknown>).issuedAt = 1.5;
    expect(
      (await verifyDeliveryReceipt(floatPayload, { directory, now: NOW })).levels.integrity,
    ).toBe(false);
  });

  it("rejects receipts signed by an untrusted key", async () => {
    const rogue = await generateReceiptKeyPair("ml-dsa-65", seed(7));
    const receipt = await issue();
    const { receipt: rogueReceipt } = await signDeliveryReceipt(
      receipt.payload,
      createLocalReceiptSigner(rogue),
    );
    const v = await verifyDeliveryReceipt(rogueReceipt, { directory, now: NOW });
    expect(v.valid).toBe(false);
    expect(v.reasons.map(r => r.code)).toContain("KEY_NOT_LISTED");

    // Rogue key listed in a directory signed by a governance key the client did not pin.
    const rogueGov = await generateReceiptKeyPair("ml-dsa-65", seed(8));
    const rogueDir = await buildKeyDirectory({
      issuer: ISSUER,
      governance: rogueGov,
      keys: [activeKeyEntry(rogue, NOW - 10)],
    });
    const v2 = await verifyDeliveryReceipt(rogueReceipt, {
      directory: rogueDir,
      directoryTrust: { pinnedGovernanceKeys: [governance.publicKeyB64] },
      now: NOW,
    });
    expect(v2.valid).toBe(false);
    expect(v2.reasons.map(r => r.code)).toContain("DIRECTORY_SIGNER_NOT_PINNED");

    // Same key, now revoked in the genuine directory.
    const revokedDir = await buildKeyDirectory({
      issuer: ISSUER,
      governance,
      epoch: 2,
      prevRoot: directory.root,
      keys: [{ ...activeKeyEntry(receiptKey, NOW - 86_400), status: "revoked", revokedAt: NOW }],
    });
    const v3 = await verifyDeliveryReceipt(receipt, { directory: revokedDir, now: NOW });
    expect(v3.levels.authentic).toBe(true);
    expect(v3.levels.trusted).toBe(false);
    expect(v3.reasons.map(r => r.code)).toContain("KEY_REVOKED");
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
    // Address comparison is case-insensitive for EVM addresses.
    const v = await verifyDeliveryReceipt(receipt, {
      directory,
      expected: { settle: { ...settle, payer: settle.payer!.toLowerCase() } },
      now: NOW,
    });
    expect(v.levels.settlement).toBe(true);
  });

  it("rejects a receipt whose body digest does not match the served bytes", async () => {
    const receipt = await issue();
    const v = await verifyDeliveryReceipt(receipt, {
      directory,
      expected: { ...expected(), responseBody: new TextEncoder().encode('{"price":"1"}') },
      now: NOW,
    });
    expect(v.valid).toBe(false);
    expect(v.levels.delivery).toBe(false);
    expect(v.reasons.map(r => r.code)).toContain("BODY_DIGEST_MISMATCH");
  });

  it("enforces issuer authorization for the resource origin", async () => {
    const receipt = await issue(
      settleContext({ transportContext: transport(BODY, "https://shop.example/x") }),
    );
    const v = await verifyDeliveryReceipt(receipt, { directory, now: NOW });
    expect(v.levels.trusted).toBe(false);
    expect(v.reasons.map(r => r.code)).toContain("ISSUER_NOT_AUTHORIZED");
    const v2 = await verifyDeliveryReceipt(receipt, {
      directory,
      acceptedIssuers: [ISSUER],
      now: NOW,
    });
    expect(v2.valid).toBe(true);
  });

  it("rejects future-dated receipts and supports ed25519 as a declared algorithm", async () => {
    const receipt = await issue();
    const v = await verifyDeliveryReceipt(receipt, { directory, now: NOW - 3600 });
    expect(v.reasons.map(r => r.code)).toContain("ISSUED_AT_IN_FUTURE");

    const edKey = await generateReceiptKeyPair("ed25519", seed(3));
    const edDir = await buildKeyDirectory({
      issuer: ISSUER,
      governance,
      keys: [activeKeyEntry(edKey, NOW - 10)],
    });
    const { receipt: edReceipt } = await signDeliveryReceipt(
      receipt.payload,
      createLocalReceiptSigner(edKey),
    );
    expect((await verifyDeliveryReceipt(edReceipt, { directory: edDir, now: NOW })).valid).toBe(
      true,
    );
    // An ML-DSA signature presented as ed25519 fails on length before any crypto runs.
    expect(
      (
        await verifyDeliveryReceipt(
          { ...receipt, alg: "ed25519", kid: edKey.kid },
          { directory: edDir, now: NOW },
        )
      ).levels.integrity,
    ).toBe(false);
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
      createDeliveryReceiptExtension({
        issuer: ISSUER,
        signer: createLocalReceiptSigner(receiptKey),
        now: () => NOW,
      }),
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
      directoryTrust: { pinnedGovernanceKeys: [governance.publicKeyB64] },
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
   * @returns fetch-compatible function
   */
  const network = (receipt: DeliveryReceipt | undefined, body: Uint8Array = BODY) =>
    (async (input: RequestInfo | URL) => {
      const req = new Request(input);
      if (req.url.endsWith("/.well-known/x402-receipt-keys")) {
        return new Response(JSON.stringify(directory), {
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
          "content-type": "application/json",
          "PAYMENT-RESPONSE": encodePaymentResponseHeader(s),
        },
      });
    }) as typeof fetch;

  const paidRequest = () =>
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
                keyDirectory: `${ISSUER}/.well-known/x402-receipt-keys`,
                algorithms: ["ml-dsa-65"],
              },
            },
          },
        } as unknown as PaymentPayload),
      },
    });

  it("verifies the receipt against the payment that was sent and the body received", async () => {
    const receipt = await issue();
    const onResult = vi.fn();
    const f = withDeliveryReceipts(network(receipt), {
      pinnedGovernanceKeys: [governance.publicKeyB64],
      onResult,
    });
    vi.useFakeTimers({ now: NOW * 1000 });
    try {
      const res = await f(paidRequest());
      expect(await res.text()).toBe(new TextDecoder().decode(BODY)); // body still readable
      const v = getDeliveryReceiptResult(res)!;
      expect(v.reasons).toEqual([]);
      expect(v.valid).toBe(true);
      expect(onResult).toHaveBeenCalledOnce();
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
      expect(getDeliveryReceiptResult(tampered)!.reasons.map(r => r.code)).toContain(
        "BODY_DIGEST_MISMATCH",
      );
      const missing = await withDeliveryReceipts(network(undefined))(paidRequest());
      expect(getDeliveryReceiptResult(missing)!.reasons[0].code).toBe("RECEIPT_MISSING");
      await expect(
        withDeliveryReceipts(network(undefined), { requireValidReceipt: true })(paidRequest()),
      ).rejects.toThrow(/settled in 0x5c6e/);
      // Unpaid requests pass through untouched.
      const plain = await withDeliveryReceipts(network(receipt))(RESOURCE);
      expect(getDeliveryReceiptResult(plain)).toBeUndefined();
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
