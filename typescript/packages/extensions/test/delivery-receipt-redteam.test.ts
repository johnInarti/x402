// Red-team regression tests for delivery-receipt v0.2 (independent adversarial review).
// Each test is the PoC of one finding; against the unpatched reference they fail.
import { describe, it, expect, beforeAll, vi } from "vitest";
import { encodePaymentResponseHeader, encodePaymentSignatureHeader } from "@x402/core/http";
import type { PaymentRequirements, SettleResponse } from "@x402/core/types";
import {
  activeKeyEntry,
  buildKeyDirectory,
  canonicalJson,
  createLocalReceiptSigner,
  createReceiptPayload,
  createSseReceiptWriter,
  fetchKeyDirectory,
  generateReceiptKeyPair,
  getDeliveryReceiptResult,
  resolveDeliveryReceipt,
  sha256Hex,
  signDeliveryReceipt,
  verifyDeliveryReceipt,
  verifySignature,
  verifySignatureWithEngine,
  verifySseDelivery,
  parseSse,
  withDeliveryReceipts,
  type DeliveryReceipt,
  type KeyDirectory,
  type ReceiptKeyPair,
  type ReceiptSigner,
} from "../src/delivery-receipt";

const ISSUER = "https://api.example.com";
const RESOURCE = `${ISSUER}/premium-data`;
const DIR_URL = `${ISSUER}/.well-known/x402-receipt-keys`;
const NOW = 1_790_473_960;
const BODY = new TextEncoder().encode('{"good":"content"}');
const requirements = {
  scheme: "exact",
  network: "eip155:8453",
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
  amount: "10000",
  maxTimeoutSeconds: 60,
  extra: {},
} as PaymentRequirements;
const settle: SettleResponse = {
  success: true,
  transaction: "0x5c6e0000000000000000000000000000000000000000000000000000000000a1",
  network: "eip155:8453",
  payer: "0x857b06519E91e3A54538791bDbb0E22373e36b66",
};
const seed = (n: number) => new Uint8Array(32).fill(n);
const codes = (v: { reasons: { code: string }[] }) => v.reasons.map(r => r.code);
let govEd: ReceiptKeyPair, govPq: ReceiptKeyPair, keyEd: ReceiptKeyPair, keyPq: ReceiptKeyPair;
let dir1: KeyDirectory;
let signers: ReceiptSigner[];

/**
 * Genuine receipt from the issuer's real keys.
 *
 * @param over - Fact overrides
 * @returns Receipt
 */
async function receiptFor(over: Record<string, unknown> = {}): Promise<DeliveryReceipt> {
  const payload = createReceiptPayload({
    issuer: ISSUER,
    resourceUrl: RESOURCE,
    method: "GET",
    requirements,
    settle,
    responseStatus: null,
    responseContentType: "application/json",
    delivery: {
      mode: "body",
      sha256: Buffer.from(await crypto.subtle.digest("SHA-256", BODY)).toString("hex"),
    },
    directory: dir1,
    issuedAt: NOW,
    ...over,
  })!;
  return (await signDeliveryReceipt(payload, signers)).receipt;
}

const paymentSignature = (info: Record<string, unknown>) =>
  encodePaymentSignatureHeader({
    x402Version: 2,
    accepted: requirements,
    payload: {},
    resource: { url: RESOURCE },
    extensions: { "delivery-receipt": { info } },
  } as never);

beforeAll(async () => {
  govEd = await generateReceiptKeyPair("ed25519", seed(1));
  govPq = await generateReceiptKeyPair("ml-dsa-65", seed(1));
  keyEd = await generateReceiptKeyPair("ed25519", seed(2));
  keyPq = await generateReceiptKeyPair("ml-dsa-65", seed(2));
  signers = [createLocalReceiptSigner(keyEd), createLocalReceiptSigner(keyPq)];
  dir1 = await buildKeyDirectory({
    issuer: ISSUER,
    publishedAt: NOW - 86_400,
    governance: [govEd, govPq],
    keys: [activeKeyEntry(keyEd, NOW - 86_400), activeKeyEntry(keyPq, NOW - 86_400)],
  });
});

describe("RT-1 a verifier exception never yields valid", () => {
  it("a non-string SettleResponse.payer does not skip settlement and delivery", async () => {
    // A genuine receipt for an OLD payment and other content, stapled to a new one.
    const old = await receiptFor({ settle: { ...settle, transaction: "0x01d" } });
    const v = await verifyDeliveryReceipt(old, {
      directory: dir1,
      now: NOW,
      path: "session",
      expected: {
        settle: { ...settle, transaction: "0x0e1", payer: 1 as unknown as string },
        requirements,
        resourceUrl: RESOURCE,
        method: "GET",
        responseBody: new TextEncoder().encode("GARBAGE"),
      },
    });
    expect(v.valid).toBe(false);
    expect(v.levels.settlement).toBe(false);
  });

  it("end to end: the fetch plugin flags it and requireValidReceipt throws", async () => {
    const old = await receiptFor({ settle: { ...settle, transaction: "0x01d" } });
    const header = {
      ...settle,
      transaction: "0x0e1",
      payer: 1,
      extensions: { "delivery-receipt": { info: { receipt: old } } },
    };
    const baseFetch = (async (req: Request | string) => {
      const u = typeof req === "string" ? req : req.url;
      if (u === DIR_URL) return new Response(JSON.stringify(dir1));
      return new Response("GARBAGE", {
        headers: { "PAYMENT-RESPONSE": encodePaymentResponseHeader(header as never) },
      });
    }) as typeof fetch;
    vi.useFakeTimers({ now: NOW * 1000 });
    try {
      const res = await withDeliveryReceipts(baseFetch)(RESOURCE, {
        headers: { "PAYMENT-SIGNATURE": paymentSignature({ keyDirectory: DIR_URL }) },
      });
      expect(getDeliveryReceiptResult(res)!.valid).toBe(false);
      await expect(
        withDeliveryReceipts(baseFetch, { requireValidReceipt: true })(RESOURCE, {
          headers: { "PAYMENT-SIGNATURE": paymentSignature({ keyDirectory: DIR_URL }) },
        }),
      ).rejects.toThrow(/invalid receipt/);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("RT-2 pinned trust honours a remembered newer epoch", () => {
  it("rejects a chain that stops before the epoch the verifier already accepted", async () => {
    const dir2 = await buildKeyDirectory({
      issuer: ISSUER,
      epoch: 2,
      prevRoot: dir1.root,
      publishedAt: NOW - 3600,
      governance: [govEd, govPq],
      keys: dir1.keys.map(k => ({ ...k, status: "revoked" as const, revokedAt: NOW - 3600 })),
    });
    // The holder of the (now revoked) receipt keys signs a fresh receipt naming epoch 1 and
    // serves only epoch 1.
    const forged = await receiptFor();
    const v = await verifyDeliveryReceipt(forged, {
      directories: [dir1],
      directoryTrust: {
        pinnedGovernanceKeys: [govEd.publicKeyB64, govPq.publicKeyB64],
        previous: { epoch: 2, root: dir2.root },
      },
      now: NOW,
      offline: true,
    });
    expect(v.valid).toBe(false);
    expect(codes(v)).toContain("DIRECTORY_ROLLBACK");
  });
});

describe("RT-3 no split verdict between paths", () => {
  it("archival rejects a receipt whose Ed25519 signature is broken; session reports ML-DSA unchecked", async () => {
    const r = await receiptFor();
    const badEd = structuredClone(r);
    badEd.signatures.find(s => s.alg === "ed25519")!.signature = Buffer.alloc(64, 7).toString(
      "base64",
    );
    const a = await verifyDeliveryReceipt(badEd, { directory: dir1, now: NOW, offline: true });
    expect(a.valid).toBe(false);
    const badPq = structuredClone(r);
    badPq.signatures.find(s => s.alg === "ml-dsa-65")!.signature = Buffer.alloc(3309, 7).toString(
      "base64",
    );
    const s = await verifyDeliveryReceipt(badPq, {
      directory: dir1,
      now: NOW,
      path: "session",
      offline: true,
    });
    expect(s.unverifiedAlgorithms).toEqual(["ml-dsa-65"]);
    expect(s.longTermEvidence).toBe(false);
  });
});

describe("RT-4 Ed25519 small-order keys (regression; both engines already reject)", () => {
  it("does not accept R = identity, S = 0 under a small-order public key", async () => {
    const msg = new TextEncoder().encode("any message");
    const identity = new Uint8Array(32);
    identity[0] = 1;
    const sig = new Uint8Array(64);
    sig.set(identity, 0);
    const ord2 = new Uint8Array(32).fill(0xff);
    ord2[0] = 0xec;
    ord2[31] = 0x7f;
    for (const pk of [identity, ord2]) {
      expect(verifySignature("ed25519", pk, msg, sig)).toBe(false);
      expect((await verifySignatureWithEngine("ed25519", pk, msg, sig)).ok).toBe(false);
    }
  });
});

describe("RT-5 SSE writer hashes what EventSource dispatches", () => {
  const ctx = { resourceUrl: RESOURCE, method: "GET", requirements, settle };
  it("verifies frames that contain CR or CRLF", async () => {
    const w = createSseReceiptWriter(
      { issuer: ISSUER, signers, directory: dir1, now: () => NOW, receiptTransport: "inline" },
      ctx,
    );
    const text = (await w.frame("a\r\nb")) + (await w.frame("x\ry")) + (await w.finish()).event;
    const v = await verifySseDelivery(text, { directory: dir1, now: NOW, offline: true });
    expect(v.reasons).toEqual([]);
    expect(v.valid).toBe(true);
  });
  it("refuses event names that inject lines or impersonate the terminal event", async () => {
    const w = createSseReceiptWriter(
      { issuer: ISSUER, signers, directory: dir1, now: () => NOW, receiptTransport: "inline" },
      ctx,
    );
    await expect(w.frame("ok", "tick\n\ndata: injected")).rejects.toThrow(/event name/);
    await expect(w.frame("ok", "x402-delivery-receipt")).rejects.toThrow(/event name/);
  });
});

describe("RT-6 valid means all five levels (§8.1)", () => {
  it("is not valid when settlement and delivery were never evaluated", async () => {
    const v = await verifyDeliveryReceipt(await receiptFor(), { directory: dir1, now: NOW });
    expect(v.valid).toBe(false);
    expect(v.levels).toMatchObject({ integrity: true, authentic: true, trusted: true });
  });
  it("a stream receipt for another payment is not valid without settlement facts", async () => {
    const w = createSseReceiptWriter(
      { issuer: ISSUER, signers, directory: dir1, now: () => NOW, receiptTransport: "inline" },
      {
        resourceUrl: RESOURCE,
        method: "GET",
        requirements,
        settle: { ...settle, transaction: "0x0ther" },
      },
    );
    const text = (await w.frame("a")) + (await w.finish()).event;
    expect((await verifySseDelivery(text, { directory: dir1, now: NOW })).valid).toBe(false);
    const bound = await verifySseDelivery(text, {
      directory: dir1,
      now: NOW,
      expected: { settle, requirements, resourceUrl: RESOURCE, method: "GET" },
    });
    expect(bound.valid).toBe(false);
    expect(bound.levels.settlement).toBe(false);
  });
});

describe("RT-7 canonicalization subset", () => {
  it("rejects lone surrogates in values and keys (no portable UTF-8)", () => {
    expect(() => canonicalJson({ a: "\ud800" })).toThrow(/surrogate/);
    expect(() => canonicalJson({ a: "x\udc00" })).toThrow(/surrogate/);
    expect(() => canonicalJson({ ["\ud800"]: 1 })).toThrow(/surrogate/);
    expect(canonicalJson({ a: "😀" })).toBe('{"a":"😀"}');
    expect(() => canonicalJson({ a: -0 })).toThrow();
  });
});

describe("RT-8 a stream declaration does not switch verification off", () => {
  it("verifies (and fails) a non-SSE response when the 402 declared stream mode", async () => {
    const baseFetch = (async () =>
      new Response("GARBAGE", {
        headers: {
          "content-type": "application/json",
          "PAYMENT-RESPONSE": encodePaymentResponseHeader(settle),
        },
      })) as unknown as typeof fetch;
    await expect(
      withDeliveryReceipts(baseFetch, { requireValidReceipt: true })(RESOURCE, {
        headers: { "PAYMENT-SIGNATURE": paymentSignature({ deliveryMode: "stream" }) },
      }),
    ).rejects.toThrow(/RECEIPT_MISSING/);
  });
});

describe("RT-9 receipts by reference are not fetched from arbitrary URLs", () => {
  it("checks scheme and origin before fetching", async () => {
    const seen: string[] = [];
    const f = (async (u: string) => {
      seen.push(String(u));
      return new Response("{}");
    }) as unknown as typeof fetch;
    const id = "a".repeat(64);
    const digest = "c".repeat(64);
    await expect(
      resolveDeliveryReceipt(
        { receiptId: id, receiptUrl: "http://169.254.169.254/latest", digest },
        f,
      ),
    ).rejects.toThrow(/https/);
    await expect(
      resolveDeliveryReceipt({ receiptId: id, receiptUrl: "https://intranet.corp/r", digest }, f, [
        ISSUER,
      ]),
    ).rejects.toThrow(/same-origin/);
    expect(seen).toEqual([]);
  });
});

describe("RT-10 a long document list is refused, not truncated", () => {
  it("fails instead of silently dropping the current epoch", async () => {
    const docs = Array.from({ length: 66 }, () => dir1);
    const v = await verifyDeliveryReceipt(await receiptFor(), {
      directories: docs,
      now: NOW,
      offline: true,
    });
    expect(codes(v)).toContain("DIRECTORY_CHAIN_TOO_LONG");
  });
});

describe("RT-11 duplicate JSON members are refused in fetched documents", () => {
  it("rejects a directory and a referenced receipt with duplicate keys", async () => {
    const text = JSON.stringify(dir1).replace('"epoch":1', '"epoch":1,"epoch":1');
    const f = (async () => new Response(text)) as unknown as typeof fetch;
    await expect(fetchKeyDirectory(DIR_URL, f)).rejects.toThrow(/duplicate/);
    const r = await receiptFor();
    const rt = JSON.stringify(r).replace('"amount":"10000"', '"amount":"1","amount":"10000"');
    const g = (async () => new Response(rt)) as unknown as typeof fetch;
    await expect(
      resolveDeliveryReceipt(
        {
          receiptId: "b".repeat(64),
          receiptUrl: `${ISSUER}/x402/receipts/${"b".repeat(64)}`,
          digest: await sha256Hex(rt),
        },
        g,
        [ISSUER],
      ),
    ).rejects.toThrow(/duplicate/);
  });
});

describe("RT-12 verdicts do not depend on WebCrypto being present", () => {
  it("noble fallback gives the same verdict as WebCrypto Ed25519", async () => {
    const r = await receiptFor();
    const tampered = structuredClone(r);
    tampered.payload.amount = "1";
    const opts = { directory: dir1, now: NOW, path: "session" as const, offline: true };
    const withWc = [
      await verifyDeliveryReceipt(r, opts),
      await verifyDeliveryReceipt(tampered, opts),
    ];
    vi.resetModules();
    const spy = vi.spyOn(crypto.subtle, "importKey").mockImplementation(async () => {
      throw new Error("Ed25519 not supported");
    });
    try {
      const fresh = await import("../src/delivery-receipt");
      const noWc = [
        await fresh.verifyDeliveryReceipt(r, opts),
        await fresh.verifyDeliveryReceipt(tampered, opts),
      ];
      expect(noWc[0].signaturesVerified[0].engine).toBe("noble");
      expect(withWc[0].signaturesVerified[0].engine).toBe("webcrypto");
      expect(noWc.map(v => [v.valid, v.levels])).toEqual(withWc.map(v => [v.valid, v.levels]));
    } finally {
      spy.mockRestore();
    }
  });
});

describe("RT-13 unregistered stream framing", () => {
  it("rejects a stream receipt whose framing is not registered", async () => {
    const r = await receiptFor({
      delivery: { mode: "stream", framing: "ndjson", frameCount: 0, digest: "0".repeat(64) },
    });
    expect(
      codes(await verifyDeliveryReceipt(r, { directory: dir1, now: NOW, offline: true })),
    ).toContain("PAYLOAD_FIELD_delivery");
  });
});

describe("RT-14 SSE end of stream", () => {
  it("does not dispatch an event that was never terminated by a blank line", async () => {
    expect(parseSse("data: a\n\ndata: b\n")).toEqual([
      { event: "message", data: "a", id: undefined },
    ]);
    expect(parseSse("data: a")).toEqual([]);
    const w = createSseReceiptWriter(
      { issuer: ISSUER, signers, directory: dir1, now: () => NOW, receiptTransport: "inline" },
      { resourceUrl: RESOURCE, method: "GET", requirements, settle },
    );
    const text = (await w.frame("a")) + (await w.finish()).event;
    const cut = text.slice(0, -1); // the terminal event lost its blank line
    expect(
      codes(await verifySseDelivery(cut, { directory: dir1, now: NOW, offline: true })),
    ).toContain("STREAM_TRAILER_MISSING");
  });
});
