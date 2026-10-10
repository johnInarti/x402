/**
 * Encoding helpers for the delivery-receipt extension: strict JCS subset (§3),
 * SHA-256 and canonical base64 (§6).
 */

import { base64 } from "@scure/base";
import { RECEIPT_DOMAIN, type DeliveryReceipt, type DeliveryReceiptPayload } from "./types";

const MAX_DEPTH = 16;

/**
 * RFC 8785 canonical JSON restricted to the subset every runtime serializes identically:
 * strings, booleans, null, arrays, objects and safe integers. Floats, -0, NaN, undefined,
 * bigint and functions are rejected instead of being coerced.
 *
 * @param value - The value to canonicalize
 * @param depth - Current nesting depth (internal)
 * @returns The canonical JSON text
 */
export function canonicalJson(value: unknown, depth = 0): string {
  if (depth > MAX_DEPTH) throw new Error("canonicalJson: nesting too deep");
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      // I-JSON (RFC 7493 §2.1): strings MUST be valid Unicode. A lone surrogate has no UTF-8
      // encoding, so runtimes disagree on it (escaped vs. replaced vs. rejected) (§3).
      if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)) {
        throw new Error("canonicalJson: lone surrogate in signed string");
      }
      return JSON.stringify(value);
    case "number":
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
        throw new Error("canonicalJson: only safe integers are allowed in signed JSON");
      }
      return String(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map(v => canonicalJson(v, depth + 1)).join(",")}]`;
      }
      const obj = value as Record<string, unknown>;
      // RFC 8785 sorts by UTF-16 code units, which is what Array.prototype.sort does by default.
      const keys = Object.keys(obj).sort();
      for (const k of keys) canonicalJson(k, depth + 1); // keys obey the same string rule
      return `{${keys
        .map(k => {
          if (obj[k] === undefined) throw new Error(`canonicalJson: undefined value at "${k}"`);
          return `${JSON.stringify(k)}:${canonicalJson(obj[k], depth + 1)}`;
        })
        .join(",")}}`;
    }
    default:
      throw new Error(`canonicalJson: unsupported type ${typeof value}`);
  }
}

/**
 * Lowercase hex SHA-256 (WebCrypto; available in browsers and Node >= 18).
 *
 * @param data - Bytes or UTF-8 text to hash
 * @returns Lowercase hex digest
 */
export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Lowercase hex encoding.
 *
 * @param bytes - Bytes to encode
 * @returns Hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Canonical base64 encoding (RFC 4648 §4, padded).
 *
 * @param bytes - Bytes to encode
 * @returns Base64 text
 */
export function toBase64(bytes: Uint8Array): string {
  return base64.encode(bytes);
}

/**
 * Strict base64 decoding: the input must re-encode to itself (no whitespace, no
 * non-zero pad bits, padding present). Returns null on any deviation.
 *
 * @param text - Base64 text
 * @returns Decoded bytes or null
 */
export function fromCanonicalBase64(text: unknown): Uint8Array | null {
  if (typeof text !== "string" || text.length === 0 || text.length % 4 !== 0) return null;
  try {
    const bytes = base64.decode(text);
    return base64.encode(bytes) === text ? bytes : null;
  } catch {
    return null;
  }
}

/**
 * Receipt id: lowercase hex SHA-256 of JCS(payload) (§3).
 *
 * @param payload - The receipt payload
 * @returns The receipt id
 */
export async function computeReceiptId(payload: DeliveryReceiptPayload): Promise<string> {
  return sha256Hex(canonicalJson(payload));
}

/**
 * The document served at `receiptUrl` (§5.5): the JCS text of the whole wire object
 * (payload and signatures). It is the only representation a server may serve there.
 *
 * @param receipt - The wire receipt
 * @returns Canonical JSON text
 */
export function receiptDocument(receipt: DeliveryReceipt): string {
  return canonicalJson(receipt);
}

/**
 * The `digest` of a receipt reference (§5.5): lowercase hex SHA-256 of {@link receiptDocument}.
 *
 * @param receipt - The wire receipt
 * @returns The reference digest
 */
export async function computeReceiptDigest(receipt: DeliveryReceipt): Promise<string> {
  return sha256Hex(receiptDocument(receipt));
}

/**
 * Exact bytes signed for a receipt (§5.3).
 *
 * @param receiptId - Receipt id from {@link computeReceiptId}
 * @returns UTF-8 bytes of `x402-delivery-receipt/1\n<receiptId>`
 */
export function receiptSignedMessage(receiptId: string): Uint8Array {
  return new TextEncoder().encode(`${RECEIPT_DOMAIN}\n${receiptId}`);
}

/**
 * Strict JSON parse for receipts and directories received as text (§12): refuses a BOM, oversized
 * input and duplicate member names (JSON.parse silently keeps the last one, other parsers keep the
 * first, so a duplicate makes two verifiers read two different payloads).
 *
 * @param text - JSON text
 * @param maxBytes - Maximum UTF-16 length accepted
 * @returns Parsed value
 */
export function parseJsonStrict(text: string, maxBytes = 1024 * 1024): unknown {
  if (typeof text !== "string") throw new Error("expected JSON text");
  if (text.length > maxBytes) throw new Error("JSON too large");
  if (text.charCodeAt(0) === 0xfeff) throw new Error("JSON starts with a BOM");
  const value = JSON.parse(text);
  const stack: (Set<string> | null)[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const raw = text.slice(i, j + 1);
      let k = j + 1;
      while (k < text.length && /\s/.test(text[k])) k++;
      const scope = stack[stack.length - 1];
      if (text[k] === ":" && scope) {
        const key = JSON.parse(raw) as string;
        if (scope.has(key))
          throw new Error(`duplicate JSON member ${JSON.stringify(key.slice(0, 64))}`);
        scope.add(key);
      }
      i = j;
    } else if (c === "{") stack.push(new Set());
    else if (c === "[") stack.push(null);
    else if (c === "}" || c === "]") stack.pop();
  }
  return value;
}
