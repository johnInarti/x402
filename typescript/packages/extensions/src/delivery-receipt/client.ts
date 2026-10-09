/**
 * Client-side extraction and verification of delivery receipts (§8).
 */

import { decodePaymentResponseHeader, decodePaymentSignatureHeader } from "@x402/core/http";
import type { PaymentPayload, PaymentRequirements, SettleResponse } from "@x402/core/types";
import { getAlgorithm, verifySignature } from "./algorithms";
import {
  DEFAULT_CLOCK_SKEW_SECONDS,
  fetchKeyDirectory,
  keyAuthorizationError,
  verifyKeyDirectory,
  type DirectoryVerificationOptions,
} from "./directory";
import { computeReceiptId, fromCanonicalBase64, receiptSignedMessage, sha256Hex } from "./encoding";
import {
  DELIVERY_RECEIPT,
  KEY_DIRECTORY_WELL_KNOWN_PATH,
  type DeliveryReceipt,
  type DeliveryReceiptPayload,
  type DeliveryReceiptSettleInfo,
  type ReceiptAlgorithm,
  type ReceiptVerificationLevels,
  type ReceiptVerificationResult,
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
  responseBody?: Uint8Array;
  responseStatus?: number;
}

export interface VerifyDeliveryReceiptOptions {
  /** Parsed key directory of the issuer. */
  directory: unknown;
  /** Directory trust options (pinned governance keys, rollback state). */
  directoryTrust?: Omit<DirectoryVerificationOptions, "expectedIssuer">;
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

const PAYLOAD_FIELDS: Record<keyof DeliveryReceiptPayload, "string" | "int" | "nstring" | "nint"> =
  {
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
    responseSha256: "string",
    responseContentType: "nstring",
    issuedAt: "int",
  };

/**
 * Structural check of the payload (§5.2): exactly the v1 fields, with the declared types.
 *
 * @param p - Candidate payload
 * @returns Reason code or null
 */
function payloadError(p: unknown): string | null {
  if (!p || typeof p !== "object" || Array.isArray(p)) return "PAYLOAD_INVALID";
  const obj = p as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length !== Object.keys(PAYLOAD_FIELDS).length) return "PAYLOAD_FIELDS";
  for (const [k, t] of Object.entries(PAYLOAD_FIELDS)) {
    const v = obj[k];
    const isInt = Number.isSafeInteger(v) && (v as number) >= 0;
    const ok =
      (t === "string" && typeof v === "string") ||
      (t === "int" && isInt) ||
      (t === "nstring" && (v === null || typeof v === "string")) ||
      (t === "nint" && (v === null || isInt));
    if (!ok) return `PAYLOAD_FIELD_${k}`;
  }
  if (obj.version !== 1) return "PAYLOAD_VERSION";
  if (!HEX64.test(obj.responseSha256 as string)) return "PAYLOAD_FIELD_responseSha256";
  if ((obj.transaction as string).length === 0) return "PAYLOAD_FIELD_transaction";
  try {
    if (new URL(obj.issuer as string).origin !== obj.issuer) return "PAYLOAD_FIELD_issuer";
    new URL(obj.resourceUrl as string);
  } catch {
    return "PAYLOAD_URL";
  }
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
  if (!e.settle && !e.requirements && !e.resourceUrl && !e.method && e.paymentId === undefined) {
    return null;
  }
  const checks: [string, boolean][] = [];
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
  return checks.filter(([, ok]) => !ok).map(([field]) => field);
}

/**
 * Delivery binding: body digest and (when signed) status.
 *
 * @param payload - Receipt payload
 * @param body - Body bytes received
 * @param status - Observed HTTP status
 * @returns Reason codes (empty when delivery matches)
 */
async function deliveryMismatches(
  payload: DeliveryReceiptPayload,
  body: Uint8Array,
  status: number | undefined,
): Promise<string[]> {
  const codes: string[] = [];
  if ((await sha256Hex(body)) !== payload.responseSha256) codes.push("BODY_DIGEST_MISMATCH");
  if (
    payload.responseStatus !== null &&
    status !== undefined &&
    payload.responseStatus !== status
  ) {
    codes.push("STATUS_MISMATCH");
  }
  return codes;
}

/**
 * Verifies a delivery receipt (§8). Never throws.
 *
 * Levels `integrity`, `authentic` and `trusted` are always evaluated. `settlement` is evaluated
 * when `expected.settle` or `expected.requirements` is given; `delivery` when
 * `expected.responseBody` is given. `valid` requires every evaluated level to pass.
 *
 * @param input - Receipt wire object (parsed JSON)
 * @param options - Verification options
 * @returns Verdict with per-level results and reason codes
 */
export async function verifyDeliveryReceipt(
  input: unknown,
  options: VerifyDeliveryReceiptOptions,
): Promise<ReceiptVerificationResult> {
  const levels: ReceiptVerificationLevels = {
    integrity: false,
    authentic: null,
    trusted: null,
    settlement: null,
    delivery: null,
  };
  const reasons: ReceiptVerificationResult["reasons"] = [];
  let receiptId: string | null = null;
  let trustBasis: ReceiptVerificationResult["trustBasis"] = "none";
  const done = (): ReceiptVerificationResult => ({
    valid:
      levels.integrity === true &&
      levels.authentic === true &&
      levels.trusted === true &&
      levels.settlement !== false &&
      levels.delivery !== false,
    levels,
    receiptId,
    trustBasis,
    reasons,
  });

  try {
    // ── integrity ──
    const r = input as Partial<DeliveryReceipt> | null;
    if (!r || typeof r !== "object" || Object.keys(r).length !== 4) {
      reasons.push({ level: "integrity", code: "RECEIPT_SHAPE" });
      return done();
    }
    const suite = getAlgorithm(r.alg);
    const sig = fromCanonicalBase64(r.signature);
    const pErr = payloadError(r.payload);
    if (!suite)
      reasons.push({ level: "integrity", code: "ALG_UNSUPPORTED", detail: String(r.alg) });
    if (typeof r.kid !== "string") reasons.push({ level: "integrity", code: "KID_INVALID" });
    if (!sig || (suite && sig.length !== suite.signatureBytes)) {
      reasons.push({ level: "integrity", code: "SIGNATURE_ENCODING" });
    }
    if (pErr) reasons.push({ level: "integrity", code: pErr });
    if (reasons.length) return done();
    const payload = r.payload as DeliveryReceiptPayload;
    receiptId = await computeReceiptId(payload);
    levels.integrity = true;

    // ── directory + key lookup ──
    const dirRes = await verifyKeyDirectory(options.directory, {
      ...options.directoryTrust,
      expectedIssuer: payload.issuer,
    });
    const entry = dirRes.directory?.keys.find(k => k.kid === r.kid);

    // ── authentic ──
    if (!dirRes.ok || !entry) {
      levels.authentic = false;
      levels.trusted = false;
      reasons.push(
        dirRes.ok
          ? { level: "authentic", code: "KEY_NOT_LISTED", detail: r.kid }
          : { level: "trusted", code: dirRes.code ?? "DIRECTORY_INVALID", detail: dirRes.detail },
      );
    } else {
      const pk = fromCanonicalBase64(entry.publicKey)!;
      levels.authentic =
        entry.alg === r.alg &&
        verifySignature(r.alg as ReceiptAlgorithm, pk, receiptSignedMessage(receiptId), sig!);
      if (!levels.authentic) reasons.push({ level: "authentic", code: "SIGNATURE_INVALID" });

      // ── trusted ──
      trustBasis = dirRes.trustBasis;
      const now = options.now ?? Math.floor(Date.now() / 1000);
      const keyErr = keyAuthorizationError(
        entry,
        r.alg as string,
        payload.issuedAt,
        now,
        options.skewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS,
      );
      const resourceOrigin = new URL(payload.resourceUrl).origin;
      const issuerOk =
        payload.issuer === resourceOrigin ||
        (options.acceptedIssuers ?? []).some(i => new URL(i).origin === payload.issuer);
      if (keyErr) reasons.push({ level: "trusted", code: keyErr });
      if (!issuerOk) {
        reasons.push({ level: "trusted", code: "ISSUER_NOT_AUTHORIZED", detail: payload.issuer });
      }
      levels.trusted = levels.authentic && !keyErr && issuerOk;
    }

    // ── settlement / delivery ──
    const e = options.expected ?? {};
    const mism = settlementMismatches(payload, e);
    if (mism) {
      levels.settlement = mism.length === 0;
      for (const m of mism) {
        reasons.push({ level: "settlement", code: "SETTLEMENT_MISMATCH", detail: m });
      }
    }
    if (e.responseBody) {
      const codes = await deliveryMismatches(payload, e.responseBody, e.responseStatus);
      levels.delivery = codes.length === 0;
      for (const code of codes) reasons.push({ level: "delivery", code });
    }
    return done();
  } catch (error) {
    reasons.push({
      level: "integrity",
      code: "VERIFIER_ERROR",
      detail: error instanceof Error ? error.message : String(error),
    });
    return done();
  }
}

export interface DeliveryReceiptFetchOptions {
  /** Base64 governance keys trusted out of band (recommended). Without them trust is "tls". */
  pinnedGovernanceKeys?: string[];
  /** Extra accepted issuers (e.g. a notary origin). */
  acceptedIssuers?: string[];
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
 * Wraps the BASE fetch passed to `wrapFetchWithPayment` so that every paid response is checked
 * against the payment the client actually sent:
 *
 * ```ts
 * const fetchWithPay = wrapFetchWithPayment(withDeliveryReceipts(fetch, { pinnedGovernanceKeys }), client);
 * const res = await fetchWithPay(url);
 * getDeliveryReceiptResult(res); // { valid, levels, reasons, ... }
 * ```
 *
 * Sitting under the payment wrapper gives access to the PAYMENT-SIGNATURE request header (the
 * accepted requirements and the echoed declaration) and to the PAYMENT-RESPONSE header and body.
 *
 * @param baseFetch - The fetch that performs network I/O
 * @param options - Verification options
 * @returns A fetch-compatible function
 */
export function withDeliveryReceipts(
  baseFetch: typeof fetch,
  options: DeliveryReceiptFetchOptions = {},
): typeof fetch {
  const directoryCache = new Map<string, Promise<unknown>>();

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
      paymentPayload.extensions as Record<string, { info?: { keyDirectory?: string } }>
    )?.[DELIVERY_RECEIPT];
    const info = extractDeliveryReceipt(settle);
    if (!declared && !info) return response;

    let result: ReceiptVerificationResult;
    if (!info || !settle.success) {
      result = {
        valid: false,
        levels: {
          integrity: false,
          authentic: null,
          trusted: null,
          settlement: null,
          delivery: null,
        },
        receiptId: null,
        trustBasis: "none",
        reasons: [{ level: "integrity", code: "RECEIPT_MISSING" }],
      };
    } else {
      try {
        const receipt = await resolveDeliveryReceipt(info, baseFetch);
        const issuer = receipt.payload.issuer;
        const dirUrl =
          options.keyDirectoryUrls?.[issuer] ??
          (declared?.info?.keyDirectory && new URL(declared.info.keyDirectory).origin === issuer
            ? declared.info.keyDirectory
            : new URL(KEY_DIRECTORY_WELL_KNOWN_PATH, issuer).toString());
        if (!directoryCache.has(dirUrl)) {
          const p = fetchKeyDirectory(dirUrl, baseFetch);
          p.catch(() => directoryCache.delete(dirUrl));
          directoryCache.set(dirUrl, p);
        }
        const body = new Uint8Array(await response.clone().arrayBuffer());
        const paymentId = (
          paymentPayload.extensions as Record<string, { info?: { id?: unknown } }> | undefined
        )?.["payment-identifier"]?.info?.id;
        result = await verifyDeliveryReceipt(receipt, {
          directory: await directoryCache.get(dirUrl),
          directoryTrust: options.pinnedGovernanceKeys
            ? { pinnedGovernanceKeys: options.pinnedGovernanceKeys }
            : undefined,
          acceptedIssuers: options.acceptedIssuers,
          expected: {
            settle,
            requirements: paymentPayload.accepted,
            resourceUrl: request.url,
            method: request.method,
            paymentId: typeof paymentId === "string" ? paymentId : null,
            responseBody: body,
            responseStatus: response.status,
          },
        });
      } catch (error) {
        result = {
          valid: false,
          levels: {
            integrity: false,
            authentic: null,
            trusted: null,
            settlement: null,
            delivery: null,
          },
          receiptId: null,
          trustBasis: "none",
          reasons: [
            {
              level: "integrity",
              code: "RECEIPT_UNAVAILABLE",
              detail: error instanceof Error ? error.message : String(error),
            },
          ],
        };
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
