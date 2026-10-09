/**
 * x402 Delivery-Receipt Extension
 *
 * Signed receipts that bind an x402 settlement to the exact response that was served,
 * with a declared signature algorithm (ml-dsa-65 baseline) and a signed key directory.
 *
 * Spec: specs/extensions/delivery-receipt.md
 */

export * from "./types";
export {
  canonicalJson,
  sha256Hex,
  toBase64,
  fromCanonicalBase64,
  computeReceiptId,
  receiptSignedMessage,
} from "./encoding";
export {
  SUPPORTED_ALGORITHMS,
  verifySignature,
  deriveKid,
  generateReceiptKeyPair,
  createLocalReceiptSigner,
  type ReceiptKeyPair,
} from "./algorithms";
export {
  DEFAULT_CLOCK_SKEW_SECONDS,
  computeDirectoryRoot,
  directorySignedMessage,
  buildKeyDirectory,
  activeKeyEntry,
  verifyKeyDirectory,
  keyAuthorizationError,
  fetchKeyDirectory,
  type DirectoryVerificationOptions,
  type DirectoryVerificationResult,
} from "./directory";
export {
  DECLARATION_SCHEMA,
  SETTLE_INFO_SCHEMA,
  buildDeclarationInfo,
  buildReceiptPayload,
  signDeliveryReceipt,
  createDeliveryReceiptExtension,
  declareDeliveryReceiptExtension,
  type DeliveryReceiptServerConfig,
  type SettlementLocator,
} from "./server";
export {
  extractDeliveryReceipt,
  resolveDeliveryReceipt,
  verifyDeliveryReceipt,
  withDeliveryReceipts,
  getDeliveryReceiptResult,
  type ReceiptExpectations,
  type VerifyDeliveryReceiptOptions,
  type DeliveryReceiptFetchOptions,
} from "./client";
