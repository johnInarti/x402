/**
 * Reads the test vectors published in specs/extensions/delivery-receipt.md (Appendix A) and
 * delivery-receipt.vectors.json (Appendix B) and checks them against this implementation.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import {
  activeKeyEntry,
  buildKeyDirectory,
  canonicalJson,
  computeReceiptId,
  computeStreamDigest,
  createDeliveryReceiptExtension,
  createLocalReceiptSigner,
  fromCanonicalBase64,
  generateReceiptKeyPair,
  receiptSignedMessage,
  sha256Hex,
  verifyDeliveryReceipt,
  verifySignature,
  verifySignatureWithEngine,
  verifySseDelivery,
  type DeliveryReceipt,
  type ReceiptAlgorithm,
} from "../src/delivery-receipt";

const SPEC = fileURLToPath(
  new URL("../../../../specs/extensions/delivery-receipt.md", import.meta.url),
);
const VECTORS = fileURLToPath(
  new URL("../../../../specs/extensions/delivery-receipt.vectors.json", import.meta.url),
);

/**
 * Extracts the `<!-- test-vector: name -->` JSON blocks of the spec.
 *
 * @param markdown - Spec text
 * @returns Vectors by name
 */
function appendixVectors(markdown: string): Map<string, Record<string, unknown>> {
  const out = new Map<string, Record<string, unknown>>();
  const re = /<!-- test-vector: ([\w/.-]+) -->\n```json\n([\s\S]*?)\n```/g;
  for (const m of markdown.matchAll(re)) out.set(m[1], JSON.parse(m[2]));
  return out;
}

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const unhex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));

const vectors = appendixVectors(readFileSync(SPEC, "utf8"));
const file = JSON.parse(readFileSync(VECTORS, "utf8"));

describe("delivery-receipt: spec Appendix A vectors", () => {
  it("contains the message vector, one vector per registered algorithm and the stream vector", () => {
    expect([...vectors.keys()].sort()).toEqual([
      "receipt-message",
      "signature/ed25519",
      "signature/ml-dsa-65",
      "signature/ml-dsa-87",
      "stream",
    ]);
  });

  it("reproduces the JCS octets, the receipt id and the 88 signed octets", async () => {
    const v = vectors.get("receipt-message")!;
    expect(canonicalJson(v.payload)).toBe(v.jcs);
    expect(await sha256Hex(v.jcs as string)).toBe(v.receiptId);
    expect(await computeReceiptId(v.payload as never)).toBe(v.receiptId);
    const msg = receiptSignedMessage(v.receiptId as string);
    expect(msg.length).toBe(88);
    expect(hex(msg)).toBe(v.messageHex);
    expect(new TextDecoder().decode(msg)).toBe(v.message);
  });

  for (const alg of ["ed25519", "ml-dsa-65", "ml-dsa-87"] as ReceiptAlgorithm[]) {
    it(`verifies and re-derives the ${alg} vector`, async () => {
      const v = vectors.get(`signature/${alg}`)!;
      const msg = vectors.get("receipt-message")!;
      expect(v.receiptId).toBe(msg.receiptId);
      const kp = await generateReceiptKeyPair(alg, unhex(v.seed as string));
      expect(kp.publicKeyB64).toBe(v.publicKey);
      expect(kp.kid).toBe(v.kid);
      const message = unhex(msg.messageHex as string);
      const sig = fromCanonicalBase64(v.signature)!;
      expect(verifySignature(alg, kp.publicKey, message, sig)).toBe(true);
      expect((await verifySignatureWithEngine(alg, kp.publicKey, message, sig)).ok).toBe(true);
      // Deterministic signing reproduces the published signature byte for byte.
      expect(Buffer.from(await createLocalReceiptSigner(kp).sign(message)).toString("base64")).toBe(
        v.signature,
      );
      const other = new Uint8Array(message);
      other[other.length - 1] ^= 1;
      expect(verifySignature(alg, kp.publicKey, other, sig)).toBe(false);
    });
  }

  it("reproduces every step of the stream digest", async () => {
    const v = vectors.get("stream")!;
    const frames = v.frames as string[];
    const steps = v.steps as string[];
    expect(steps[0]).toBe(await sha256Hex("x402-delivery-stream/1"));
    for (let i = 1; i <= frames.length; i++) {
      const f = new TextEncoder().encode(frames[i - 1]);
      const buf = new Uint8Array(40 + f.length);
      buf.set(unhex(steps[i - 1]), 0);
      new DataView(buf.buffer).setBigUint64(32, BigInt(f.length), false);
      buf.set(f, 40);
      expect(await sha256Hex(buf)).toBe(steps[i]);
    }
    expect(await computeStreamDigest(frames)).toEqual({
      frameCount: v.frameCount,
      digest: v.digest,
    });
  });
});

describe("delivery-receipt: Appendix B end-to-end vector", () => {
  const e = file.endToEnd;
  const pinned = {
    pinnedGovernanceKeys: [e.governanceKeys.ed25519, e.governanceKeys["ml-dsa-65"]],
  };

  it("agrees with the appendix", () => {
    for (const s of file.signatures) {
      const a = vectors.get(`signature/${s.alg}`)!;
      expect(s.publicKey).toBe(a.publicKey);
      expect(s.signature).toBe(a.signature);
    }
    expect(file.stream).toEqual(vectors.get("stream"));
  });

  it("verifies on both paths with every level passing", async () => {
    for (const path of ["session", "archival"] as const) {
      const v = await verifyDeliveryReceipt(e.receipt, {
        directory: e.directory,
        directoryTrust: pinned,
        path,
        expected: {
          settle: e.settle,
          requirements: e.requirements,
          resourceUrl: e.resourceUrl,
          method: "GET",
          responseBody: new TextEncoder().encode(e.body),
        },
        now: e.now,
      });
      expect(v.reasons, path).toEqual([]);
      expect(v.valid, path).toBe(true);
      expect(v.longTermEvidence, path).toBe(path === "archival");
    }
  });

  it("is reproduced byte for byte from the seeds", async () => {
    const kp = (alg: ReceiptAlgorithm, s: string) => generateReceiptKeyPair(alg, unhex(s));
    const gov = [
      await kp("ed25519", e.seeds.governance.ed25519),
      await kp("ml-dsa-65", e.seeds.governance["ml-dsa-65"]),
    ];
    const keys = [
      await kp("ed25519", e.seeds.receiptKeys.ed25519),
      await kp("ml-dsa-65", e.seeds.receiptKeys["ml-dsa-65"]),
    ];
    const directory = await buildKeyDirectory({
      issuer: e.directory.issuer,
      publishedAt: e.directory.publishedAt,
      governance: gov,
      keys: keys.map(k => activeKeyEntry(k, e.directory.keys[0].notBefore)),
    });
    expect(directory).toEqual(e.directory);
    const ext = createDeliveryReceiptExtension({
      issuer: e.directory.issuer,
      signers: keys.map(createLocalReceiptSigner),
      directory,
      now: () => e.now,
      resolveLogIndex: async () => e.receipt.payload.logIndex,
    });
    const out = (await ext.enrichSettlementResponse!({}, {
      paymentPayload: { x402Version: 2, accepted: e.requirements, payload: {} },
      requirements: e.requirements,
      declaredExtensions: { "delivery-receipt": {} },
      phase: "after-handler",
      transportContext: {
        request: {
          adapter: { getUrl: () => e.resourceUrl, getMethod: () => "GET" },
          method: "GET",
          path: new URL(e.resourceUrl).pathname,
        },
        responseBody: Buffer.from(e.body),
        responseHeaders: { "content-type": "application/json" },
      },
      result: e.settle,
    } as never)) as { info: { receipt: DeliveryReceipt } };
    expect(out.info.receipt).toEqual(e.receipt);
  });

  it("verifies the published SSE event stream and its terminal frame", async () => {
    const v = await verifySseDelivery(e.stream.eventStream, {
      directory: e.directory,
      directoryTrust: pinned,
      expected: { settle: e.settle, resourceUrl: e.stream.resourceUrl, method: "GET" },
      now: e.now,
    });
    expect(v.reasons).toEqual([]);
    expect(v.valid).toBe(true);
    expect(e.stream.trailer.digest).toBe(file.stream.digest);
  });
});
