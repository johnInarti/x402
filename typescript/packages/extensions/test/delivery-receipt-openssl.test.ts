/**
 * Independent check of the Appendix A signature vectors with node:crypto only (OpenSSL), sharing no code with
 * the reference implementation or its noble backend. ML-DSA needs OpenSSL >= 3.5 (Node >= 24); on older
 * runtimes those rows are skipped, never reported as passing.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

interface Row {
  alg: "ed25519" | "ml-dsa-65" | "ml-dsa-87";
  seed: string;
  publicKey: string;
  payload: unknown;
  receiptId: string;
  message: string;
  messageHex: string;
  signature: string;
}

const vectors = JSON.parse(
  readFileSync(
    join(__dirname, "../../../../specs/extensions/delivery-receipt.vectors.json"),
    "utf8",
  ),
) as { signatures: Row[] };

// DER building blocks (RFC 8410 for Ed25519, RFC 9881 / FIPS 204 OIDs 2.16.840.1.101.3.4.3.{18,19} for ML-DSA).
const OID: Record<Row["alg"], string> = {
  ed25519: "06032b6570",
  "ml-dsa-65": "0609608648016503040312",
  "ml-dsa-87": "0609608648016503040313",
};
const RAW_PUB: Record<Row["alg"], number> = { ed25519: 32, "ml-dsa-65": 1952, "ml-dsa-87": 2592 };
const derLen = (n: number) =>
  n < 128
    ? Buffer.from([n])
    : n < 256
      ? Buffer.from([0x81, n])
      : Buffer.from([0x82, n >> 8, n & 255]);
const tlv = (tag: number, body: Buffer) =>
  Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
const algId = (alg: Row["alg"]) => tlv(0x30, Buffer.from(OID[alg], "hex"));

const publicKey = (alg: Row["alg"], raw: Buffer): KeyObject =>
  createPublicKey({
    key: tlv(0x30, Buffer.concat([algId(alg), tlv(0x03, Buffer.concat([Buffer.from([0]), raw]))])),
    format: "der",
    type: "spki",
  });
// PKCS#8 from the 32-octet seed: Ed25519 CurvePrivateKey (RFC 8410), ML-DSA seed CHOICE [0] (RFC 9881).
const privateKeyFromSeed = (alg: Row["alg"], seed: Buffer): KeyObject =>
  createPrivateKey({
    key: tlv(
      0x30,
      Buffer.concat([
        Buffer.from("020100", "hex"),
        algId(alg),
        tlv(0x04, alg === "ed25519" ? tlv(0x04, seed) : tlv(0x80, seed)),
      ]),
    ),
    format: "der",
    type: "pkcs8",
  });

const decode = (s: string) =>
  Buffer.from(s, /^[0-9a-f]+$/i.test(s) && s.length % 2 === 0 ? "hex" : "base64");
const jcs = (x: unknown): string =>
  x === null || typeof x !== "object"
    ? JSON.stringify(x)
    : Array.isArray(x)
      ? `[${x.map(jcs).join(",")}]`
      : `{${Object.keys(x as object)
          .sort()
          .map(k => `${JSON.stringify(k)}:${jcs((x as Record<string, unknown>)[k])}`)
          .join(",")}}`;

const supported = (alg: Row["alg"]) => {
  try {
    publicKey(alg, Buffer.alloc(RAW_PUB[alg], 1));
    return true;
  } catch {
    return false;
  }
};

describe("delivery-receipt vectors, independent OpenSSL check (node:crypto only)", () => {
  for (const row of vectors.signatures) {
    it.skipIf(!supported(row.alg))(`${row.alg}: id, message, key-from-seed, signature`, () => {
      const pub = decode(row.publicKey);
      const sig = decode(row.signature);
      const msg = Buffer.from(row.messageHex, "hex");

      expect(createHash("sha256").update(jcs(row.payload)).digest("hex")).toBe(row.receiptId);
      expect(msg.equals(Buffer.from(`x402-delivery-receipt/1\n${row.receiptId}`))).toBe(true);
      expect(msg.toString("utf8")).toBe(row.message);

      const derived = createPublicKey(privateKeyFromSeed(row.alg, decode(row.seed)))
        .export({ format: "der", type: "spki" })
        .subarray(-RAW_PUB[row.alg]);
      expect(derived.equals(pub)).toBe(true);

      expect(verify(null, msg, publicKey(row.alg, pub), sig)).toBe(true);
      const tampered = Buffer.from(msg);
      tampered[tampered.length - 1] ^= 1;
      expect(verify(null, tampered, publicKey(row.alg, pub), sig)).toBe(false);
    });
  }

  it.skipIf(!supported("ed25519"))(
    "ed25519: OpenSSL re-signs the published signature byte for byte",
    () => {
      const row = vectors.signatures.find(r => r.alg === "ed25519")!;
      const resigned = sign(
        null,
        Buffer.from(row.messageHex, "hex"),
        privateKeyFromSeed("ed25519", decode(row.seed)),
      );
      expect(resigned.equals(decode(row.signature))).toBe(true);
    },
  );
});
