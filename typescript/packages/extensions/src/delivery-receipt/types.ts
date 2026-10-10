/**
 * Types for the x402 delivery-receipt extension.
 *
 * Spec: specs/extensions/delivery-receipt.md (draft v0.2.1)
 */

/** Extension identifier (key under `extensions`). */
export const DELIVERY_RECEIPT = "delivery-receipt";

/** First line of every signed receipt message (domain separation, §5.3). */
export const RECEIPT_DOMAIN = "x402-delivery-receipt/1";

/** Key directory format identifier and signed-message prefix (§7.2). */
export const KEY_DIRECTORY_SPEC = "x402-receipt-key-directory/1";

/** Domain string that seeds the running digest of a stream (§5.6). */
export const STREAM_DOMAIN = "x402-delivery-stream/1";

/** SSE event type of the terminal event that carries `frameCount`, the digest and the receipt (§5.6). */
export const STREAM_TRAILER_EVENT = "x402-delivery-receipt";

/**
 * Header budget of a receipt delivered by reference (§5.5): the UTF-8 JSON text of
 * `SettleResponse.extensions["delivery-receipt"]` MUST NOT exceed this many octets.
 */
export const MAX_REFERENCE_EXTENSION_BYTES = 1024;

/** Required `use` of a receipt-signing key in the directory (§7.2). */
export const RECEIPT_KEY_USE = "x402-delivery-receipt";

/** Conventional well-known path of the key directory (§7.1). */
export const KEY_DIRECTORY_WELL_KNOWN_PATH = "/.well-known/x402-receipt-keys";

/** Algorithms registered in §6. */
export type ReceiptAlgorithm = "ml-dsa-65" | "ml-dsa-87" | "ed25519";

/** Algorithm of the in-session verification path (§6.1). */
export const SESSION_ALGORITHM = "ed25519" as const;

/** Algorithm of the archival / offline verification path (§6.1). */
export const ARCHIVAL_ALGORITHM = "ml-dsa-65" as const;

/**
 * Verification path (§8.1): `session` checks the Ed25519 signature (WebCrypto-friendly);
 * `archival` checks the ML-DSA-65 signature and is the only path that yields long-term evidence.
 */
export type VerificationPath = "session" | "archival";

/** `PaymentRequired.extensions["delivery-receipt"].info` (§4). */
export interface DeliveryReceiptDeclarationInfo {
  version: 1;
  issuer: string;
  /** Stable directory URL; per-epoch archives live at `${keyDirectory}/epoch/<n>` (§7.1). */
  keyDirectory: string;
  /** MUST include `ed25519` and `ml-dsa-65`. */
  algorithms: ReceiptAlgorithm[];
  /** What the receipt commits to (§5.4, §5.6). Default `body`. */
  deliveryMode?: "body" | "stream";
  /** Where the receipt travels (§5.5). Default `reference`. */
  receiptTransport?: "inline" | "reference";
}

/** Delivery commitment for a buffered response body (§5.4). */
export interface BodyDelivery {
  mode: "body";
  /** Lowercase hex SHA-256 of the identity-coded body octets. */
  sha256: string;
}

/** Delivery commitment for a stream of frames (§5.6). */
export interface StreamDelivery {
  mode: "stream";
  /** How the response was cut into frames. Registered: `sse`. */
  framing: string;
  /** Number of frames hashed (the terminal frame is not counted). */
  frameCount: number;
  /** Lowercase hex running digest after the last frame. */
  digest: string;
}

export type DeliveryCommitment = BodyDelivery | StreamDelivery;

/** Receipt payload, version 1 as defined by draft v0.2 (§5.2). Every field is always present. */
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
  responseContentType: string | null;
  delivery: DeliveryCommitment;
  /** Epoch of the key directory in force at `issuedAt`. */
  keyDirectoryEpoch: number;
  /** `root` of that directory epoch: SHA-256 of its canonical content (§7.2). */
  keyDirectoryDigest: string;
  issuedAt: number;
}

/** One signature over the receipt message (§5.3). */
export interface ReceiptSignature {
  alg: ReceiptAlgorithm;
  kid: string;
  /** Canonical base64 signature over `RECEIPT_DOMAIN + "\n" + receiptId`. */
  signature: string;
}

/** Wire object (§5.3). */
export interface DeliveryReceipt {
  payload: DeliveryReceiptPayload;
  /** 2–4 entries, distinct `alg`, MUST include `ed25519` and `ml-dsa-65`. */
  signatures: ReceiptSignature[];
}

/**
 * Compact reference to a receipt served at `receiptUrl` (§5.5), the default transport.
 * `digest` is the lowercase hex SHA-256 of the octets served there, which are exactly
 * `JCS(receipt)`; the client checks it before parsing or trusting the document.
 */
export interface DeliveryReceiptReference {
  receiptId: string;
  receiptUrl: string;
  digest: string;
}

/** Settle-response `info` (§5.1 / §5.5): a reference (default) or the receipt inline. */
export type DeliveryReceiptSettleInfo = DeliveryReceiptReference | { receipt: DeliveryReceipt };

/**
 * Data of the terminal `x402-delivery-receipt` event of a stream (§5.6). `digest` here is the
 * stream digest; a receipt delivered by reference is nested under `reference`.
 */
export type StreamTrailer = { frameCount: number; digest: string } & (
  | { receipt: DeliveryReceipt }
  | { reference: DeliveryReceiptReference }
);

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

/** Governance key of a directory (§7.2). */
export interface GovernanceKey {
  alg: ReceiptAlgorithm;
  publicKey: string;
}

/** Signature of a directory by one of its governance keys (§7.2). */
export interface DirectorySignature {
  alg: ReceiptAlgorithm;
  signature: string;
}

/** Signed key directory, one epoch (§7.2). */
export interface KeyDirectory {
  spec: typeof KEY_DIRECTORY_SPEC;
  issuer: string;
  epoch: number;
  prevRoot: string;
  /** Unix seconds from which this epoch is in force. */
  publishedAt: number;
  governanceKeys: GovernanceKey[];
  keys: KeyDirectoryEntry[];
  root: string;
  signatures: DirectorySignature[];
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
  /**
   * True only when all five levels passed (§8.1 "valid for the client"); with `offline: true`,
   * `settlement` may be unevaluated. Never true after a verifier error.
   */
  valid: boolean;
  /** Which signature path was verified (§8.1). */
  path: VerificationPath;
  /**
   * True only for the archival path with `authentic` and `trusted` passing: the result can be
   * kept as long-term evidence. Always false on the session path.
   */
  longTermEvidence: boolean;
  /** Algorithms whose signatures were verified, with the engine used. */
  signaturesVerified: { alg: ReceiptAlgorithm; kid: string; engine: string }[];
  /**
   * Algorithms present in `signatures` whose signature was NOT checked (on the session path, at
   * least `ml-dsa-65`). A client that keeps the receipt as evidence must still run the archival
   * path before relying on it (§6.1).
   */
  unverifiedAlgorithms: ReceiptAlgorithm[];
  levels: ReceiptVerificationLevels;
  receiptId: string | null;
  /** How the directory's governance key was trusted. */
  trustBasis: "pinned" | "tls" | "none";
  /** Directory epoch the receipt was issued under, and the latest epoch it was chained to. */
  directoryEpoch: number | null;
  latestDirectoryEpoch: number | null;
  reasons: { level: keyof ReceiptVerificationLevels; code: string; detail?: string }[];
}
