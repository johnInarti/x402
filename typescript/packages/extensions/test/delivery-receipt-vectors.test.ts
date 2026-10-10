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
  createMemoryReceiptStore,
  createSseReceiptWriter,
  fromCanonicalBase64,
  parseSse,
  resolveDeliveryReceipt,
  splitSseStream,
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
      receiptTransport: "inline",
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

describe("delivery-receipt: receipt by reference vector (§5.5)", () => {
  const e = file.endToEnd;
  const r = e.reference;

  it("is the endToEnd receipt, within the 1 KB header budget, and its digest is SHA-256(JCS)", async () => {
    expect(Object.keys(r.settleExtension)).toEqual(["info"]);
    expect(r.settleExtensionBytes).toBe(Buffer.byteLength(JSON.stringify(r.settleExtension)));
    expect(r.settleExtensionBytes).toBeLessThanOrEqual(1024);
    expect(r.document).toBe(canonicalJson(e.receipt));
    expect(await sha256Hex(r.document)).toBe(r.settleExtension.info.digest);
    expect(r.settleExtension.info.receiptId).toBe(await computeReceiptId(e.receipt.payload));
    const f = (async () => new Response(r.document)) as unknown as typeof fetch;
    expect(await resolveDeliveryReceipt(r.settleExtension.info, f, [e.directory.issuer])).toEqual(
      e.receipt,
    );
  });
});

describe("delivery-receipt: 15-minute SSE session fixture (§5.6)", () => {
  const e = file.endToEnd;
  const s = file.streamSession;
  const pinned = {
    pinnedGovernanceKeys: [e.governanceKeys.ed25519, e.governanceKeys["ml-dsa-65"]],
  };
  const serve = (async (url: string) =>
    url === s.terminal.reference.receiptUrl
      ? new Response(s.receiptDocument)
      : new Response("not found", { status: 404 })) as unknown as typeof fetch;

  it("frames are exactly what EventSource dispatches as MessageEvent.data", async () => {
    const events = parseSse(s.eventStream);
    expect(events).toEqual(s.dispatched);
    expect(events.map(ev => ev.event).filter((v, i, a) => a.indexOf(v) === i)).toEqual([
      "hello",
      "pool",
      "expired",
      "x402-delivery-receipt",
    ]);
    const { frames, trailer, eventsAfterTrailer } = splitSseStream(events);
    expect(frames).toEqual(s.frames);
    expect(eventsAfterTrailer).toBe(0);
    expect(trailer).toEqual(s.terminal);
    expect(frames.some(f => f.includes("\r"))).toBe(false); // CRLF in the source is hashed as LF
    expect(await computeStreamDigest(frames)).toEqual({
      frameCount: s.frameCount,
      digest: s.digest,
    });
  });

  it("binds frameCount and digest in the terminal event and in the receipt; no trailer", async () => {
    expect(Object.keys(s.terminal).sort()).toEqual(["digest", "frameCount", "reference"]);
    expect(await sha256Hex(s.receiptDocument)).toBe(s.terminal.reference.digest);
    const receipt = JSON.parse(s.receiptDocument) as DeliveryReceipt;
    expect(receipt.payload.delivery).toEqual({
      mode: "stream",
      framing: "sse",
      frameCount: s.frameCount,
      digest: s.digest,
    });
    expect(receipt.payload.resourceUrl).toBe(s.resourceUrl);
    expect(receipt.payload.issuedAt - s.settledAt).toBe(s.windowSeconds);
  });

  it("verifies at every level on both paths", async () => {
    for (const path of ["session", "archival"] as const) {
      const v = await verifySseDelivery(
        s.eventStream,
        {
          directory: e.directory,
          directoryTrust: pinned,
          path,
          expected: {
            settle: s.settle,
            requirements: s.requirements,
            resourceUrl: s.resourceUrl,
            method: s.method,
            responseStatus: 200,
          },
          now: s.now,
        },
        serve,
      );
      expect(v.reasons, path).toEqual([]);
      expect(v.valid, path).toBe(true);
      expect(v.longTermEvidence, path).toBe(path === "archival");
    }
  });

  it("detects a dropped, altered or replayed pool event", async () => {
    const opts = {
      directory: e.directory,
      directoryTrust: pinned,
      expected: { settle: s.settle, resourceUrl: s.resourceUrl, method: s.method },
      now: s.now,
    };
    const poolLine = s.eventStream.indexOf("id: 3\n");
    const nextBlank = s.eventStream.indexOf("\n\n", poolLine) + 2;
    const dropped = s.eventStream.slice(0, poolLine) + s.eventStream.slice(nextBlank);
    const altered = s.eventStream.replace('"atRisk":true', '"atRisk":false');
    const replayed =
      s.eventStream.slice(0, nextBlank) +
      s.eventStream.slice(poolLine, nextBlank) +
      s.eventStream.slice(nextBlank);
    for (const text of [dropped, altered, replayed]) {
      expect(text).not.toBe(s.eventStream);
      const v = await verifySseDelivery(text, opts, serve);
      expect(v.valid).toBe(false);
      expect(v.levels.delivery).toBe(false);
    }
  });

  it("is reproduced byte for byte by replaying the recipe through the writer", async () => {
    const kp = (alg: ReceiptAlgorithm, sd: string) => generateReceiptKeyPair(alg, unhex(sd));
    const keys = [
      await kp("ed25519", e.seeds.receiptKeys.ed25519),
      await kp("ml-dsa-65", e.seeds.receiptKeys["ml-dsa-65"]),
    ];
    const store = createMemoryReceiptStore(e.directory.issuer);
    const w = createSseReceiptWriter(
      {
        issuer: e.directory.issuer,
        signers: keys.map(createLocalReceiptSigner),
        directory: e.directory,
        now: () => s.now,
        resolveLogIndex: async () => 312,
        receiptStore: store,
      },
      {
        resourceUrl: s.resourceUrl,
        method: s.method,
        requirements: s.requirements,
        settle: s.settle,
        responseStatus: 200,
      },
    );
    let text = "";
    for (const st of s.recipe as (
      | { raw: string }
      | { frame: string; event?: string; id?: string }
    )[]) {
      if ("raw" in st) text += st.raw;
      else text += (st.id ? `id: ${st.id}\n` : "") + (await w.frame(st.frame, st.event));
    }
    const fin = await w.finish();
    expect(text + fin.event).toBe(s.eventStream);
    expect(store.get(fin.receiptId)).toBe(s.receiptDocument);
  });
});
