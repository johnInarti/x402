/**
 * Encoding helpers for the delivery-receipt extension: strict JCS subset (§3),
 * SHA-256 and canonical base64 (§6).
 */

import { base64 } from "@scure/base";
import { RECEIPT_DOMAIN, type DeliveryReceiptPayload } from "./types";

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
 * Exact bytes signed for a receipt (§5.3).
 *
 * @param receiptId - Receipt id from {@link computeReceiptId}
 * @returns UTF-8 bytes of `x402-delivery-receipt/1\n<receiptId>`
 */
export function receiptSignedMessage(receiptId: string): Uint8Array {
  return new TextEncoder().encode(`${RECEIPT_DOMAIN}\n${receiptId}`);
}
