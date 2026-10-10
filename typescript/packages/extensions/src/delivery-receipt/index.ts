/**
 * x402 Delivery-Receipt Extension
 *
 * Signed receipts that bind an x402 settlement to the exact response (or stream of frames) that
 * was served. Every receipt carries an Ed25519 signature for in-session verification and an
 * ML-DSA-65 signature over the same message for archival verification, and names the key
 * directory epoch it was issued under.
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
  computeReceiptDigest,
  receiptDocument,
  receiptSignedMessage,
} from "./encoding";
export {
  SUPPORTED_ALGORITHMS,
  verifySignature,
  verifySignatureWithEngine,
  hasWebCryptoEd25519,
  type VerifyEngine,
  deriveKid,
  generateReceiptKeyPair,
  createLocalReceiptSigner,
  type ReceiptKeyPair,
} from "./algorithms";
export {
  DEFAULT_CLOCK_SKEW_SECONDS,
  MAX_CHAIN_EPOCHS,
  computeDirectoryRoot,
  keyDirectoryEpochUrl,
  verifyKeyDirectoryChain,
  fetchKeyDirectoryChain,
  pathAlgorithm,
  type DirectoryChainResult,
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
  createReceiptPayload,
  createSseReceiptWriter,
  createMemoryReceiptStore,
  type ReceiptStore,
  type MemoryReceiptStore,
  type DirectorySource,
  type ReceiptFacts,
  type SseReceiptContext,
  type SseReceiptWriter,
  publicResourceUrl,
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
  verifySseDelivery,
  offerReceiptFacts,
  withDeliveryReceipts,
  type OfferReceiptFacts,
  getDeliveryReceiptResult,
  type ReceiptExpectations,
  type VerifyDeliveryReceiptOptions,
  type DeliveryReceiptFetchOptions,
} from "./client";
export {
  StreamDigest,
  computeStreamDigest,
  formatSseEvent,
  formatSseTrailer,
  parseSse,
  splitSseStream,
  type SseEvent,
} from "./stream";
