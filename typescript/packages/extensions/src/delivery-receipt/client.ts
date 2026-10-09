/**
 * Client-side extraction and verification of delivery receipts (§8).
 */

import { decodePaymentResponseHeader, decodePaymentSignatureHeader } from "@x402/core/http";
import type { PaymentPayload, PaymentRequirements, SettleResponse } from "@x402/core/types";
import { OFFER_RECEIPT, type SignedReceipt } from "../offer-receipt/types";
import { extractReceiptPayload } from "../offer-receipt/signing";
import { getAlgorithm, verifySignatureWithEngine } from "./algorithms";
import {
  DEFAULT_CLOCK_SKEW_SECONDS,
  fetchKeyDirectoryChain,
  keyAuthorizationError,
  pathAlgorithm,
  verifyKeyDirectoryChain,
  type DirectoryVerificationOptions,
} from "./directory";
import { computeReceiptId, fromCanonicalBase64, receiptSignedMessage, sha256Hex } from "./encoding";
import { computeStreamDigest, parseSse, splitSseStream } from "./stream";
import {
  ARCHIVAL_ALGORITHM,
  DELIVERY_RECEIPT,
  KEY_DIRECTORY_WELL_KNOWN_PATH,
  SESSION_ALGORITHM,
  type DeliveryReceipt,
  type DeliveryReceiptDeclarationInfo,
  type DeliveryReceiptPayload,
  type DeliveryReceiptSettleInfo,
  type ReceiptVerificationLevels,
  type ReceiptVerificationResult,
  type StreamTrailer,
  type VerificationPath,
} from "./types";

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Extracts the delivery-receipt info from a SettleResponse, if present and well-shaped.
 *
 * @param settle - Decoded SettleResponse (PAYMENT-RESPONSE)
 * @returns Inline receipt or reference, or null
 */
export function extractDeliveryReceipt(
  settle: SettleResponse | undefined | null,
): DeliveryReceiptSettleInfo | null {
  const info = (settle?.extensions as Record<string, { info?: unknown }> | undefined)?.[
    DELIVERY_RECEIPT
  ]?.info as Record<string, unknown> | undefined;
  if (!info || typeof info !== "object") return null;
  if (info.receipt && typeof info.receipt === "object") {
    return { receipt: info.receipt as DeliveryReceipt };
  }
  if (typeof info.receiptId === "string" && typeof info.receiptUrl === "string") {
    return { receiptId: info.receiptId, receiptUrl: info.receiptUrl };
  }
  return null;
}

/**
 * Resolves a receipt delivered by reference (§5.5) and checks it is the one announced.
 *
 * @param info - Settle info
 * @param fetchImpl - fetch implementation
 * @returns The receipt
 */
export async function resolveDeliveryReceipt(
  info: DeliveryReceiptSettleInfo,
  fetchImpl: typeof fetch = fetch,
): Promise<DeliveryReceipt> {
  if ("receipt" in info) return info.receipt;
  if (!HEX64.test(info.receiptId)) throw new Error("invalid receiptId");
  const res = await fetchImpl(info.receiptUrl, { redirect: "error" });
  if (!res.ok) throw new Error(`receipt fetch failed: HTTP ${res.status}`);
  const receipt = (await res.json()) as DeliveryReceipt;
  if (
    !receipt?.payload ||
    new URL(info.receiptUrl).origin !== receipt.payload.issuer ||
    (await computeReceiptId(receipt.payload)) !== info.receiptId
  ) {
    throw new Error("referenced receipt does not match receiptId");
  }
  return receipt;
}

/** What the client observed, for the settlement and delivery levels (§8.3). */
export interface ReceiptExpectations {
  settle?: SettleResponse;
  requirements?: PaymentRequirements;
  resourceUrl?: string;
  method?: string;
  paymentId?: string | null;
  /** Body octets received (body mode). */
  responseBody?: Uint8Array;
  responseStatus?: number;
  /** Frames received before the terminal frame, in order (stream mode). */
  frames?: (Uint8Array | string)[];
  /** `frameCount`/`digest` read from the terminal frame (stream mode). */
  trailer?: { frameCount: unknown; digest: unknown };
  /** `offer-receipt` receipt found in the same SettleResponse (§2.1 composition rule). */
  offerReceipt?: OfferReceiptFacts;
}

/** Fields of an `offer-receipt` receipt payload that the composition rule compares (§2.1). */
export interface OfferReceiptFacts {
  network: string;
  payer: string;
  /** `null` when the offer-receipt omitted the optional transaction. */
  transaction: string | null;
}

export interface VerifyDeliveryReceiptOptions {
  /** Key directory documents: the current one and/or archives / saved copies of any epochs. */
  directories?: unknown[];
  /** Single directory document (shorthand for `directories: [directory]`). */
  directory?: unknown;
  /** Directory trust options (pinned governance keys, rollback state). */
  directoryTrust?: Omit<DirectoryVerificationOptions, "expectedIssuer" | "path">;
  /**
   * `session` verifies the Ed25519 signature (in-session, WebCrypto where available);
   * `archival` (default) verifies the ML-DSA-65 signature and is required for long-term evidence.
   */
  path?: VerificationPath;
  /**
   * Issuers accepted in addition to the resource origin (e.g. an independent notary).
   * Never inferred from the receipt (§8.2).
   */
  acceptedIssuers?: string[];
  expected?: ReceiptExpectations;
  /** Verifier clock (unix seconds). */
  now?: number;
  skewSeconds?: number;
}

type FieldType = "string" | "int" | "nstring" | "nint" | "hex64" | "object" | "pint";

const PAYLOAD_FIELDS: Record<keyof DeliveryReceiptPayload, FieldType> = {
  version: "int",
  issuer: "string",
  resourceUrl: "string",
  method: "string",
  scheme: "string",
  network: "string",
  asset: "string",
  payTo: "string",
  amount: "string",
  payer: "string",
  transaction: "string",
  logIndex: "nint",
  paymentId: "nstring",
  responseStatus: "nint",
  responseContentType: "nstring",
  delivery: "object",
  keyDirectoryEpoch: "pint",
  keyDirectoryDigest: "hex64",
  issuedAt: "int",
};

/**
 * Type check of one payload field.
 *
 * @param v - Value
 * @param t - Declared type
 * @returns Whether the value has the type
 */
function hasType(v: unknown, t: FieldType): boolean {
  const isInt = Number.isSafeInteger(v) && (v as number) >= 0;
  switch (t) {
    case "string":
      return typeof v === "string";
    case "int":
      return isInt;
    case "pint":
      return isInt && (v as number) >= 1;
    case "nstring":
      return v === null || typeof v === "string";
    case "nint":
      return v === null || isInt;
    case "hex64":
      return typeof v === "string" && HEX64.test(v);
    case "object":
      return !!v && typeof v === "object" && !Array.isArray(v);
  }
}

/**
 * Structural check of the delivery commitment (§5.4, §5.6).
 *
 * @param d - Candidate commitment
 * @returns Whether it is well-formed
 */
function deliveryOk(d: Record<string, unknown>): boolean {
  const keys = Object.keys(d).sort().join(",");
  if (d.mode === "body") return keys === "mode,sha256" && hasType(d.sha256, "hex64");
  if (d.mode === "stream") {
    return (
      keys === "digest,frameCount,framing,mode" &&
      hasType(d.digest, "hex64") &&
      hasType(d.frameCount, "int") &&
      typeof d.framing === "string" &&
      d.framing.length > 0
    );
  }
  return false;
}

/**
 * Structural check of the payload (§5.2): exactly the v1 fields, with the declared types.
 *
 * @param p - Candidate payload
 * @returns Reason code or null
 */
function payloadError(p: unknown): string | null {
  if (!p || typeof p !== "object" || Array.isArray(p)) return "PAYLOAD_INVALID";
  const obj = p as Record<string, unknown>;
  if (Object.keys(obj).length !== Object.keys(PAYLOAD_FIELDS).length) return "PAYLOAD_FIELDS";
  for (const [k, t] of Object.entries(PAYLOAD_FIELDS)) {
    if (!hasType(obj[k], t)) return `PAYLOAD_FIELD_${k}`;
  }
  if (obj.version !== 1) return "PAYLOAD_VERSION";
  if (!deliveryOk(obj.delivery as Record<string, unknown>)) return "PAYLOAD_FIELD_delivery";
  if ((obj.transaction as string).length === 0) return "PAYLOAD_FIELD_transaction";
  try {
    if (new URL(obj.issuer as string).origin !== obj.issuer) return "PAYLOAD_FIELD_issuer";
    new URL(obj.resourceUrl as string);
  } catch {
    return "PAYLOAD_URL";
  }
  return null;
}

/**
 * Structural check of `signatures[]` (§5.3): 2–4 entries, distinct registered algs, both
 * baseline algorithms present, canonical base64 of the right length.
 *
 * @param list - Candidate list
 * @returns Reason code or null
 */
function signaturesError(list: unknown): string | null {
  if (!Array.isArray(list) || list.length < 2 || list.length > 4) return "SIGNATURES_SHAPE";
  const seen = new Set<string>();
  for (const s of list) {
    if (!s || typeof s !== "object" || Object.keys(s).length !== 3) return "SIGNATURES_SHAPE";
    const e = s as Record<string, unknown>;
    const suite = getAlgorithm(e.alg);
    if (!suite) return "ALG_UNSUPPORTED";
    if (seen.has(e.alg as string)) return "SIGNATURES_DUPLICATE_ALG";
    seen.add(e.alg as string);
    if (typeof e.kid !== "string" || e.kid.length === 0) return "KID_INVALID";
    const sig = fromCanonicalBase64(e.signature);
    if (!sig || sig.length !== suite.signatureBytes) return "SIGNATURE_ENCODING";
  }
  if (!seen.has(SESSION_ALGORITHM) || !seen.has(ARCHIVAL_ALGORITHM))
    return "SIGNATURE_PAIR_MISSING";
  return null;
}

const sameAddress = (a: string, b: string): boolean =>
  a === b || (/^0x[0-9a-fA-F]{40}$/.test(a) && a.toLowerCase() === b.toLowerCase());

/**
 * Settlement binding (§8.3). Returns null when nothing was expected, else the mismatching fields.
 *
 * @param payload - Receipt payload
 * @param e - What the client observed
 * @returns Mismatching field names, or null if not evaluated
 */
function settlementMismatches(
  payload: DeliveryReceiptPayload,
  e: ReceiptExpectations,
): string[] | null {
  if (
    !e.settle &&
    !e.requirements &&
    !e.resourceUrl &&
    !e.method &&
    e.paymentId === undefined &&
    !e.offerReceipt
  ) {
    return null;
  }
  const checks: [string, boolean][] = [];
  if (e.offerReceipt) {
    // Composition with offer-receipt (§2.1): both receipts describe the same payment.
    checks.push(
      ["offer-receipt.network", payload.network === e.offerReceipt.network],
      ["offer-receipt.payer", sameAddress(payload.payer, e.offerReceipt.payer)],
      [
        "offer-receipt.transaction",
        e.offerReceipt.transaction === null || payload.transaction === e.offerReceipt.transaction,
      ],
    );
  }
  if (e.settle) {
    checks.push(
      ["transaction", payload.transaction === e.settle.transaction],
      ["network", payload.network === e.settle.network],
      ["payer", !!e.settle.payer && sameAddress(payload.payer, e.settle.payer)],
      ["amount", e.settle.amount === undefined || payload.amount === e.settle.amount],
    );
  }
  if (e.requirements) {
    checks.push(
      ["scheme", payload.scheme === e.requirements.scheme],
      ["asset", sameAddress(payload.asset, e.requirements.asset)],
      ["payTo", sameAddress(payload.payTo, e.requirements.payTo)],
      ["amount", e.settle?.amount !== undefined || payload.amount === e.requirements.amount],
    );
  }
  if (e.resourceUrl !== undefined)
    checks.push(["resourceUrl", payload.resourceUrl === e.resourceUrl]);
  if (e.method !== undefined) checks.push(["method", payload.method === e.method.toUpperCase()]);
  if (e.paymentId !== undefined)
    checks.push(["paymentId", payload.paymentId === (e.paymentId ?? null)]);
  return [...new Set(checks.filter(([, ok]) => !ok).map(([field]) => field))];
}

/**
 * Delivery binding: body digest or stream digest, and (when signed) status. Returns null when
 * nothing was observed.
 *
 * @param payload - Receipt payload
 * @param e - What the client observed
 * @returns Reason codes (empty when delivery matches), or null if not evaluated
 */
async function deliveryMismatches(
  payload: DeliveryReceiptPayload,
  e: ReceiptExpectations,
): Promise<string[] | null> {
  const d = payload.delivery;
  const codes: string[] = [];
  if (e.responseBody) {
    if (d.mode !== "body") codes.push("DELIVERY_MODE_MISMATCH");
    else if ((await sha256Hex(e.responseBody)) !== d.sha256) codes.push("BODY_DIGEST_MISMATCH");
  } else if (e.frames || e.trailer) {
    if (d.mode !== "stream") {
      codes.push("DELIVERY_MODE_MISMATCH");
    } else {
      if (e.trailer && (e.trailer.frameCount !== d.frameCount || e.trailer.digest !== d.digest)) {
        codes.push("STREAM_TRAILER_MISMATCH");
      }
      if (e.frames) {
        const got = await computeStreamDigest(e.frames);
        if (got.frameCount !== d.frameCount) codes.push("STREAM_FRAME_COUNT_MISMATCH");
        if (got.digest !== d.digest) codes.push("STREAM_DIGEST_MISMATCH");
      }
    }
  } else {
    return null;
  }
  if (
    payload.responseStatus !== null &&
    e.responseStatus !== undefined &&
    payload.responseStatus !== e.responseStatus
  ) {
    codes.push("STATUS_MISMATCH");
  }
  return codes;
}

/**
 * Evaluates the settlement and delivery levels into `levels`/`reasons`.
 *
 * @param payload - Receipt payload
 * @param e - What the client observed
 * @param levels - Levels to update
 * @param reasons - Reasons to append to
 * @param done - Builds the verdict
 * @returns The verdict
 */
async function evaluateBindings(
  payload: DeliveryReceiptPayload,
  e: ReceiptExpectations,
  levels: ReceiptVerificationLevels,
  reasons: ReceiptVerificationResult["reasons"],
  done: () => ReceiptVerificationResult,
): Promise<ReceiptVerificationResult> {
  const mism = settlementMismatches(payload, e);
  if (mism) {
    levels.settlement = mism.length === 0;
    for (const m of mism) {
      reasons.push({
        level: "settlement",
        code: m.startsWith("offer-receipt.") ? "OFFER_RECEIPT_MISMATCH" : "SETTLEMENT_MISMATCH",
        detail: m,
      });
    }
  }
  const codes = await deliveryMismatches(payload, e);
  if (codes) {
    levels.delivery = codes.length === 0;
    for (const code of codes) reasons.push({ level: "delivery", code });
  }
  return done();
}

/**
 * Verifies a delivery receipt (§8). Never throws.
 *
 * Levels `integrity`, `authentic` and `trusted` are always evaluated, on the requested path.
 * `settlement` is evaluated when settlement facts are given; `delivery` when a body, frames or a
 * trailer are given. `valid` requires every evaluated level to pass. `longTermEvidence` is true
 * only on the archival path.
 *
 * @param input - Receipt wire object (parsed JSON)
 * @param options - Verification options
 * @returns Verdict with per-level results and reason codes
 */
export async function verifyDeliveryReceipt(
  input: unknown,
  options: VerifyDeliveryReceiptOptions,
): Promise<ReceiptVerificationResult> {
  const path: VerificationPath = options.path ?? "archival";
  const levels: ReceiptVerificationLevels = {
    integrity: false,
    authentic: null,
    trusted: null,
    settlement: null,
    delivery: null,
  };
  const reasons: ReceiptVerificationResult["reasons"] = [];
  const signaturesVerified: ReceiptVerificationResult["signaturesVerified"] = [];
  let receiptId: string | null = null;
  let trustBasis: ReceiptVerificationResult["trustBasis"] = "none";
  let directoryEpoch: number | null = null;
  let latestDirectoryEpoch: number | null = null;
  const done = (): ReceiptVerificationResult => {
    const valid =
      levels.integrity === true &&
      levels.authentic === true &&
      levels.trusted === true &&
      levels.settlement !== false &&
      levels.delivery !== false;
    return {
      valid,
      path,
      longTermEvidence: path === "archival" && levels.authentic === true && levels.trusted === true,
      signaturesVerified,
      levels,
      receiptId,
      trustBasis,
      directoryEpoch,
      latestDirectoryEpoch,
      reasons,
    };
  };

  try {
    // ── integrity ──
    const r = input as Partial<DeliveryReceipt> | null;
    if (!r || typeof r !== "object" || Object.keys(r).length !== 2) {
      reasons.push({ level: "integrity", code: "RECEIPT_SHAPE" });
      return done();
    }
    const sErr = signaturesError(r.signatures);
    const pErr = payloadError(r.payload);
    if (sErr) reasons.push({ level: "integrity", code: sErr });
    if (pErr) reasons.push({ level: "integrity", code: pErr });
    if (reasons.length) return done();
    const payload = r.payload as DeliveryReceiptPayload;
    receiptId = await computeReceiptId(payload);
    levels.integrity = true;
    directoryEpoch = payload.keyDirectoryEpoch;

    // ── directory chain (§7.5) ──
    const alg = pathAlgorithm(path);
    const sigEntry = r.signatures!.find(s => s.alg === alg)!;
    const docs = options.directories ?? (options.directory ? [options.directory] : []);
    const chain = await verifyKeyDirectoryChain(docs, payload.keyDirectoryEpoch, {
      ...options.directoryTrust,
      expectedIssuer: payload.issuer,
      path,
    });
    const skew = options.skewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
    const entry = chain.directory?.keys.find(k => k.kid === sigEntry.kid);

    if (!chain.ok || !chain.directory || !entry) {
      levels.authentic = false;
      levels.trusted = false;
      reasons.push(
        chain.ok
          ? { level: "authentic", code: "KEY_NOT_LISTED", detail: sigEntry.kid }
          : { level: "trusted", code: chain.code ?? "DIRECTORY_INVALID", detail: chain.detail },
      );
      return await evaluateBindings(payload, options.expected ?? {}, levels, reasons, done);
    }

    // ── authentic ──
    const verified =
      entry.alg === alg
        ? await verifySignatureWithEngine(
            alg,
            fromCanonicalBase64(entry.publicKey)!,
            receiptSignedMessage(receiptId),
            fromCanonicalBase64(sigEntry.signature)!,
          )
        : { ok: false, engine: "none" };
    levels.authentic = verified.ok;
    if (verified.ok) signaturesVerified.push({ alg, kid: sigEntry.kid, engine: verified.engine });
    else reasons.push({ level: "authentic", code: "SIGNATURE_INVALID", detail: alg });

    // ── trusted ──
    trustBasis = chain.trustBasis;
    latestDirectoryEpoch = chain.latest!.epoch;
    const now = options.now ?? Math.floor(Date.now() / 1000);
    const trustCodes: string[] = [];
    if (chain.directory.root !== payload.keyDirectoryDigest) {
      trustCodes.push("KEY_DIRECTORY_DIGEST_MISMATCH");
    }
    if (chain.directory.publishedAt > payload.issuedAt + skew) {
      trustCodes.push("KEY_DIRECTORY_NOT_IN_FORCE");
    }
    if (chain.successor && chain.successor.publishedAt + skew < payload.issuedAt) {
      trustCodes.push("KEY_DIRECTORY_SUPERSEDED");
    }
    const latestEntry = chain.latest!.keys.find(k => k.kid === sigEntry.kid)!;
    for (const e of latestEntry === entry ? [entry] : [entry, latestEntry]) {
      const keyErr = keyAuthorizationError(e, alg, payload.issuedAt, now, skew);
      if (keyErr && !trustCodes.includes(keyErr)) trustCodes.push(keyErr);
    }
    const resourceOrigin = new URL(payload.resourceUrl).origin;
    const issuerOk =
      payload.issuer === resourceOrigin ||
      (options.acceptedIssuers ?? []).some(i => new URL(i).origin === payload.issuer);
    if (!issuerOk) trustCodes.push("ISSUER_NOT_AUTHORIZED");
    for (const code of trustCodes) {
      reasons.push({
        level: "trusted",
        code,
        ...(code === "ISSUER_NOT_AUTHORIZED" ? { detail: payload.issuer } : {}),
      });
    }
    levels.trusted = levels.authentic && trustCodes.length === 0;
    return await evaluateBindings(payload, options.expected ?? {}, levels, reasons, done);
  } catch (error) {
    reasons.push({
      level: "integrity",
      code: "VERIFIER_ERROR",
      detail: error instanceof Error ? error.message : String(error),
    });
    return done();
  }
}

/**
 * Verifies a paid SSE stream end to end: splits the event-stream text into content frames and the
 * terminal frame, resolves the receipt, and checks the running digest, the frame count and the
 * receipt (§5.6). Alteration, reordering, insertion and truncation of frames are all detected.
 *
 * @param text - The full event-stream text received
 * @param options - Verification options (as {@link verifyDeliveryReceipt}); `expected.frames` and
 *   `expected.trailer` are filled in from the stream
 * @param fetchImpl - fetch implementation, used only for receipts delivered by reference
 * @returns Verdict
 */
export async function verifySseDelivery(
  text: string,
  options: VerifyDeliveryReceiptOptions,
  fetchImpl: typeof fetch = fetch,
): Promise<ReceiptVerificationResult> {
  const { frames, trailer, eventsAfterTrailer } = splitSseStream(parseSse(text));
  const base = await verifyDeliveryReceiptOrMissing(trailer, options, frames, fetchImpl);
  if (eventsAfterTrailer > 0) {
    base.reasons.push({ level: "delivery", code: "STREAM_EVENTS_AFTER_TRAILER" });
    base.levels.delivery = false;
    base.valid = false;
  }
  return base;
}

/**
 * Resolves the receipt from a trailer (inline or by reference) and verifies it with the frames.
 *
 * @param trailer - Parsed trailer, or null if the stream ended without one
 * @param options - Verification options
 * @param frames - Content frames received
 * @param fetchImpl - fetch implementation
 * @returns Verdict
 */
async function verifyDeliveryReceiptOrMissing(
  trailer: StreamTrailer | null,
  options: VerifyDeliveryReceiptOptions,
  frames: string[],
  fetchImpl: typeof fetch,
): Promise<ReceiptVerificationResult> {
  if (!trailer || typeof trailer !== "object") {
    return failedResult(options.path ?? "archival", "STREAM_TRAILER_MISSING");
  }
  let receipt: DeliveryReceipt;
  try {
    receipt = await resolveDeliveryReceipt(trailer as DeliveryReceiptSettleInfo, fetchImpl);
  } catch (error) {
    return failedResult(
      options.path ?? "archival",
      "RECEIPT_UNAVAILABLE",
      error instanceof Error ? error.message : String(error),
    );
  }
  return verifyDeliveryReceipt(receipt, {
    ...options,
    expected: {
      ...options.expected,
      frames,
      trailer: { frameCount: trailer.frameCount, digest: trailer.digest },
    },
  });
}

/**
 * A verdict for a receipt that could not be obtained.
 *
 * @param path - Verification path
 * @param code - Reason code
 * @param detail - Optional detail
 * @returns Failed verdict
 */
function failedResult(
  path: VerificationPath,
  code: string,
  detail?: string,
): ReceiptVerificationResult {
  return {
    valid: false,
    path,
    longTermEvidence: false,
    signaturesVerified: [],
    levels: { integrity: false, authentic: null, trusted: null, settlement: null, delivery: null },
    receiptId: null,
    trustBasis: "none",
    directoryEpoch: null,
    latestDirectoryEpoch: null,
    reasons: [{ level: "integrity", code, ...(detail ? { detail } : {}) }],
  };
}

export interface DeliveryReceiptFetchOptions {
  /** Base64 governance keys trusted out of band (recommended). Without them trust is "tls". */
  pinnedGovernanceKeys?: string[];
  /** Extra accepted issuers (e.g. a notary origin). */
  acceptedIssuers?: string[];
  /**
   * Signature path checked in session. Default `session` (Ed25519, WebCrypto where available).
   * Use `archival` to verify the ML-DSA-65 signature as well when the runtime allows it.
   */
  path?: VerificationPath;
  /** Called with the verdict of every paid response that declared or carried a receipt. */
  onResult?: (
    result: ReceiptVerificationResult,
    context: { request: Request; response: Response },
  ) => void;
  /** Fail with an error if the server declared receipts but none verifies. Default false. */
  requireValidReceipt?: boolean;
  /** Overrides the directory URL per issuer origin. */
  keyDirectoryUrls?: Record<string, string>;
}

const results = new WeakMap<Response, ReceiptVerificationResult>();

/**
 * Returns the receipt verdict attached to a response by {@link withDeliveryReceipts}.
 *
 * @param response - The response returned by the wrapped fetch
 * @returns The verdict, if any
 */
export function getDeliveryReceiptResult(
  response: Response,
): ReceiptVerificationResult | undefined {
  return results.get(response);
}

/**
 * Reads the `offer-receipt` receipt payload from a SettleResponse, when present (§2.1). Only the
 * fields needed for the composition rule are returned; verifying the offer-receipt signature is
 * the job of the offer-receipt verifier.
 *
 * @param settle - Decoded SettleResponse
 * @returns `{ network, payer, transaction }` or null when no readable offer-receipt is present
 */
export function offerReceiptFacts(
  settle: SettleResponse | undefined | null,
): OfferReceiptFacts | null {
  const receipt = (
    settle?.extensions as Record<string, { info?: { receipt?: unknown } }> | undefined
  )?.[OFFER_RECEIPT]?.info?.receipt;
  if (!receipt || typeof receipt !== "object") return null;
  try {
    const p = extractReceiptPayload(receipt as SignedReceipt);
    if (typeof p?.network !== "string" || typeof p?.payer !== "string") return null;
    return {
      network: p.network,
      payer: p.payer,
      transaction: typeof p.transaction === "string" && p.transaction !== "" ? p.transaction : null,
    };
  } catch {
    return null;
  }
}

/**
 * Wraps the BASE fetch passed to `wrapFetchWithPayment` so that every paid response is checked
 * against the payment the client actually sent:
 *
 * ```ts
 * const fetchWithPay = wrapFetchWithPayment(withDeliveryReceipts(fetch, { pinnedGovernanceKeys }), client);
 * const res = await fetchWithPay(url);
 * getDeliveryReceiptResult(res); // { valid, path, levels, reasons, ... }
 * ```
 *
 * Sitting under the payment wrapper gives access to the PAYMENT-SIGNATURE request header (the
 * accepted requirements and the echoed declaration) and to the PAYMENT-RESPONSE header and body.
 * Streamed routes (`deliveryMode: "stream"`) are passed through untouched: their receipt arrives in
 * the terminal frame, so verify them with {@link verifySseDelivery} once the stream is consumed.
 *
 * @param baseFetch - The fetch that performs network I/O
 * @param options - Verification options
 * @returns A fetch-compatible function
 */
export function withDeliveryReceipts(
  baseFetch: typeof fetch,
  options: DeliveryReceiptFetchOptions = {},
): typeof fetch {
  const directoryCache = new Map<string, Promise<unknown[]>>();
  const path = options.path ?? "session";

  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    const response = await baseFetch(request.clone());

    const sigHeader = request.headers.get("PAYMENT-SIGNATURE");
    const respHeader =
      response.headers.get("PAYMENT-RESPONSE") ?? response.headers.get("X-PAYMENT-RESPONSE");
    if (!sigHeader || !respHeader) return response;

    let paymentPayload: PaymentPayload;
    let settle: SettleResponse;
    try {
      paymentPayload = decodePaymentSignatureHeader(sigHeader);
      settle = decodePaymentResponseHeader(respHeader);
    } catch {
      return response;
    }
    const declared = (
      paymentPayload.extensions as
        | Record<string, { info?: Partial<DeliveryReceiptDeclarationInfo> }>
        | undefined
    )?.[DELIVERY_RECEIPT];
    if (declared?.info?.deliveryMode === "stream") return response;
    const info = extractDeliveryReceipt(settle);
    if (!declared && !info) return response;

    let result: ReceiptVerificationResult;
    if (!info || !settle.success) {
      result = failedResult(path, "RECEIPT_MISSING");
    } else {
      try {
        const receipt = await resolveDeliveryReceipt(info, baseFetch);
        const issuer = receipt.payload.issuer;
        const dirUrl =
          options.keyDirectoryUrls?.[issuer] ??
          (declared?.info?.keyDirectory && new URL(declared.info.keyDirectory).origin === issuer
            ? declared.info.keyDirectory
            : new URL(KEY_DIRECTORY_WELL_KNOWN_PATH, issuer).toString());
        const cacheKey = `${dirUrl}#${receipt.payload.keyDirectoryEpoch}`;
        if (!directoryCache.has(cacheKey)) {
          const p = fetchKeyDirectoryChain(dirUrl, receipt.payload.keyDirectoryEpoch, baseFetch);
          p.catch(() => directoryCache.delete(cacheKey));
          directoryCache.set(cacheKey, p);
        }
        const body = new Uint8Array(await response.clone().arrayBuffer());
        const paymentId = (
          paymentPayload.extensions as Record<string, { info?: { id?: unknown } }> | undefined
        )?.["payment-identifier"]?.info?.id;
        result = await verifyDeliveryReceipt(receipt, {
          directories: await directoryCache.get(cacheKey),
          directoryTrust: options.pinnedGovernanceKeys
            ? { pinnedGovernanceKeys: options.pinnedGovernanceKeys }
            : undefined,
          path,
          acceptedIssuers: options.acceptedIssuers,
          expected: {
            settle,
            requirements: paymentPayload.accepted,
            resourceUrl: request.url,
            method: request.method,
            paymentId: typeof paymentId === "string" ? paymentId : null,
            responseBody: body,
            responseStatus: response.status,
            offerReceipt: offerReceiptFacts(settle) ?? undefined,
          },
        });
      } catch (error) {
        result = failedResult(
          path,
          "RECEIPT_UNAVAILABLE",
          error instanceof Error ? error.message : String(error),
        );
      }
    }
    results.set(response, result);
    options.onResult?.(result, { request, response });
    if (options.requireValidReceipt && !result.valid) {
      throw new Error(
        `delivery-receipt: invalid receipt (${result.reasons.map(r => r.code).join(", ")}); ` +
          `the payment was settled in ${settle.transaction}`,
      );
    }
    return response;
  }) as typeof fetch;
}
