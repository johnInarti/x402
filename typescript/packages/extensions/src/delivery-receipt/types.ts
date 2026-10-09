/**
 * Types for the x402 delivery-receipt extension.
 *
 * Spec: specs/extensions/delivery-receipt.md
 */

/** Extension identifier (key under `extensions`). */
export const DELIVERY_RECEIPT = "delivery-receipt";

/** First line of every signed receipt message (domain separation, §5.3). */
export const RECEIPT_DOMAIN = "x402-delivery-receipt/1";

/** Key directory format identifier and signed-message prefix (§7.2). */
export const KEY_DIRECTORY_SPEC = "x402-receipt-key-directory/1";

/** Required `use` of a receipt-signing key in the directory (§7.2). */
export const RECEIPT_KEY_USE = "x402-delivery-receipt";

/** Conventional well-known path of the key directory (§7.1). */
export const KEY_DIRECTORY_WELL_KNOWN_PATH = "/.well-known/x402-receipt-keys";

/** Algorithms registered in §6. */
export type ReceiptAlgorithm = "ml-dsa-65" | "ml-dsa-87" | "ed25519";

/** `PaymentRequired.extensions["delivery-receipt"].info` (§4). */
export interface DeliveryReceiptDeclarationInfo {
  version: 1;
  issuer: string;
  keyDirectory: string;
  algorithms: ReceiptAlgorithm[];
  delivery?: "inline" | "reference";
}

/** Receipt payload, version 1 (§5.2). Every field is always present. */
export interface DeliveryReceiptPayload {
  version: 1;
  issuer: string;
  resourceUrl: string;
  method: string;
  scheme: string;
  network: string;
  asset: string;
  payTo: string;
  amount: string;
  payer: string;
  transaction: string;
  logIndex: number | null;
  paymentId: string | null;
  responseStatus: number | null;
  responseSha256: string;
  responseContentType: string | null;
  issuedAt: number;
}

/** Wire object (§5.3). */
export interface DeliveryReceipt {
  alg: ReceiptAlgorithm;
  kid: string;
  payload: DeliveryReceiptPayload;
  /** Canonical base64 signature over `RECEIPT_DOMAIN + "\n" + receiptId`. */
  signature: string;
}

/** Settle-response `info` (§5.1 / §5.5). */
export type DeliveryReceiptSettleInfo =
  | { receipt: DeliveryReceipt }
  | { receiptId: string; receiptUrl: string };

export type KeyStatus = "reserved" | "active" | "retiring" | "retired" | "revoked";

/** One entry of `keys[]` in the key directory (§7.2). */
export interface KeyDirectoryEntry {
  kid: string;
  alg: ReceiptAlgorithm;
  publicKey: string;
  use: string;
  status: KeyStatus;
  notBefore: number | null;
  notAfter: number | null;
  revokedAt: number | null;
}

/** Signed key directory (§7.2). */
export interface KeyDirectory {
  spec: typeof KEY_DIRECTORY_SPEC;
  issuer: string;
  epoch: number;
  prevRoot: string;
  governanceKey: { alg: ReceiptAlgorithm; publicKey: string };
  keys: KeyDirectoryEntry[];
  root: string;
  signature: string;
}

/**
 * Something that can sign receipt messages. Implementations may wrap a local key, an HSM
 * or a remote signing service; the extension only hands it the exact message bytes.
 */
export interface ReceiptSigner {
  alg: ReceiptAlgorithm;
  kid: string;
  sign(message: Uint8Array): Promise<Uint8Array> | Uint8Array;
}

/** Verification levels (§8.1). `null` = not evaluated. */
export interface ReceiptVerificationLevels {
  integrity: boolean;
  authentic: boolean | null;
  trusted: boolean | null;
  settlement: boolean | null;
  delivery: boolean | null;
}

export interface ReceiptVerificationResult {
  /** True only when every level that was requested passed. */
  valid: boolean;
  levels: ReceiptVerificationLevels;
  receiptId: string | null;
  /** How the directory's governance key was trusted. */
  trustBasis: "pinned" | "tls" | "none";
  reasons: { level: keyof ReceiptVerificationLevels; code: string; detail?: string }[];
}
