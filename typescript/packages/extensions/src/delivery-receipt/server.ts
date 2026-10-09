/**
 * Delivery-receipt extension for x402ResourceServer.
 *
 * Uses the extension hooks to (1) declare the extension in 402 responses and (2) sign a
 * receipt after a successful settle, binding the settlement to the SHA-256 of the response
 * body that the HTTP middleware buffered for settlement.
 *
 * Spec: specs/extensions/delivery-receipt.md
 */

import type { ResourceServerExtension, SettleResultContext } from "@x402/core/types";
import type { HTTPTransportContext } from "@x402/core/http";
import { computeReceiptId, receiptSignedMessage, sha256Hex, toBase64 } from "./encoding";
import {
  DELIVERY_RECEIPT,
  type DeliveryReceipt,
  type DeliveryReceiptDeclarationInfo,
  type DeliveryReceiptPayload,
  type ReceiptAlgorithm,
  type ReceiptSigner,
} from "./types";

/** JSON Schema for the declaration `info` (§4). */
export const DECLARATION_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    version: { type: "integer", const: 1 },
    issuer: { type: "string" },
    keyDirectory: { type: "string", format: "uri" },
    algorithms: { type: "array", items: { type: "string" }, minItems: 1 },
    delivery: { type: "string", enum: ["inline", "reference"] },
  },
  required: ["version", "issuer", "keyDirectory", "algorithms"],
} as const;

/** JSON Schema for the settle-response `info` (§10). */
export const SETTLE_INFO_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    receipt: {
      type: "object",
      properties: {
        alg: { type: "string" },
        kid: { type: "string" },
        payload: { type: "object" },
        signature: { type: "string" },
      },
      required: ["alg", "kid", "payload", "signature"],
    },
    receiptId: { type: "string", pattern: "^[0-9a-f]{64}$" },
    receiptUrl: { type: "string", format: "uri" },
  },
  oneOf: [{ required: ["receipt"] }, { required: ["receiptId", "receiptUrl"] }],
} as const;

/** Settlement facts handed to an optional log-index resolver. */
export interface SettlementLocator {
  network: string;
  transaction: string;
  asset: string;
  payTo: string;
  amount: string;
}

export interface DeliveryReceiptServerConfig {
  /** Origin of the signer, e.g. "https://api.example.com". */
  issuer: string;
  /** Key directory URL; defaults to `${issuer}/.well-known/x402-receipt-keys`. */
  keyDirectory?: string;
  /** Receipt signer (local key, HSM, remote service). */
  signer: ReceiptSigner;
  /**
   * Resolves the block-level log index of the transfer that paid `payTo` (e.g. by reading the
   * transaction receipt). Returning null or throwing leaves `logIndex: null` in the receipt.
   */
  resolveLogIndex?: (locator: SettlementLocator) => Promise<number | null>;
  /**
   * When set, receipts are delivered by reference (§5.5): the store persists the receipt and
   * returns its same-origin URL.
   */
  receiptStore?: { put(receiptId: string, receipt: DeliveryReceipt): Promise<string> };
  /** Clock override (unix seconds), for tests. */
  now?: () => number;
}

/**
 * Builds the declaration `info` for a configuration.
 *
 * @param config - Server configuration
 * @returns Declaration info
 */
export function buildDeclarationInfo(
  config: DeliveryReceiptServerConfig,
): DeliveryReceiptDeclarationInfo {
  const issuer = new URL(config.issuer).origin;
  const keyDirectory =
    config.keyDirectory ?? new URL("/.well-known/x402-receipt-keys", issuer).toString();
  if (new URL(keyDirectory).origin !== issuer) {
    throw new Error("delivery-receipt: keyDirectory must be same-origin with issuer");
  }
  return {
    version: 1,
    issuer,
    keyDirectory,
    algorithms: [config.signer.alg as ReceiptAlgorithm],
    delivery: config.receiptStore ? "reference" : "inline",
  };
}

/**
 * Reads the payment-identifier id the client sent, if any.
 *
 * @param extensions - PaymentPayload.extensions
 * @returns The id or null
 */
function readPaymentId(extensions: unknown): string | null {
  const ext = (extensions as Record<string, { info?: { id?: unknown } }> | undefined)?.[
    "payment-identifier"
  ];
  const id = ext?.info?.id;
  return typeof id === "string" && id.length >= 16 && id.length <= 128 ? id : null;
}

/**
 * Rebases a request URL on the issuer origin when both name the same host, so a server behind a
 * TLS-terminating proxy (which sees http://) still signs the URL the client requested (§5.2).
 *
 * @param url - URL reported by the HTTP adapter
 * @param issuer - Issuer origin
 * @returns The URL as seen by the client
 */
export function publicResourceUrl(url: string, issuer: string): string {
  const u = new URL(url);
  const i = new URL(issuer);
  return u.hostname === i.hostname ? `${i.origin}${u.pathname}${u.search}` : u.toString();
}

/**
 * Builds the unsigned receipt payload from a settle context. Returns null when a receipt must
 * not be issued (failed settle, no body, missing facts).
 *
 * @param context - Settle result context from x402ResourceServer
 * @param issuer - Issuer origin
 * @param issuedAt - Issuance time (unix seconds)
 * @returns Payload without logIndex resolution, or null
 */
export async function buildReceiptPayload(
  context: SettleResultContext,
  issuer: string,
  issuedAt: number,
): Promise<DeliveryReceiptPayload | null> {
  const { result, requirements, paymentPayload } = context;
  if (!result.success || !result.transaction || !result.payer || !result.network) return null;
  if (context.phase !== "after-handler") return null; // body not observable (§5.4)
  const transport = context.transportContext as HTTPTransportContext | undefined;
  const body = transport?.responseBody;
  const request = transport?.request;
  if (!body || !request?.adapter) return null;

  const headers = transport.responseHeaders ?? {};
  const contentTypeKey = Object.keys(headers).find(k => k.toLowerCase() === "content-type");

  return {
    version: 1,
    issuer,
    resourceUrl: publicResourceUrl(request.adapter.getUrl(), issuer),
    method: (request.method || request.adapter.getMethod()).toUpperCase(),
    scheme: requirements.scheme,
    network: result.network,
    asset: requirements.asset,
    payTo: requirements.payTo,
    amount: result.amount ?? requirements.amount,
    payer: result.payer,
    transaction: result.transaction,
    logIndex: null,
    paymentId: readPaymentId(paymentPayload.extensions),
    responseStatus: null,
    responseSha256: await sha256Hex(new Uint8Array(body)),
    responseContentType: contentTypeKey ? headers[contentTypeKey] : null,
    issuedAt,
  };
}

/**
 * Signs a payload into a wire receipt (§5.3).
 *
 * @param payload - Receipt payload
 * @param signer - Receipt signer
 * @returns Receipt and its id
 */
export async function signDeliveryReceipt(
  payload: DeliveryReceiptPayload,
  signer: ReceiptSigner,
): Promise<{ receipt: DeliveryReceipt; receiptId: string }> {
  const receiptId = await computeReceiptId(payload);
  const signature = await signer.sign(receiptSignedMessage(receiptId));
  return {
    receipt: { alg: signer.alg, kid: signer.kid, payload, signature: toBase64(signature) },
    receiptId,
  };
}

/**
 * Creates the delivery-receipt ResourceServerExtension.
 *
 * @param config - Server configuration
 * @returns Extension to register with x402ResourceServer.registerExtension()
 */
export function createDeliveryReceiptExtension(
  config: DeliveryReceiptServerConfig,
): ResourceServerExtension {
  const info = buildDeclarationInfo(config);
  const now = config.now ?? (() => Math.floor(Date.now() / 1000));

  return {
    key: DELIVERY_RECEIPT,

    enrichPaymentRequiredResponse: async (): Promise<unknown> => ({
      info,
      schema: DECLARATION_SCHEMA,
    }),

    enrichSettlementResponse: async (
      _: unknown,
      context: SettleResultContext,
    ): Promise<unknown> => {
      const payload = await buildReceiptPayload(context, info.issuer, now());
      if (!payload) return undefined;

      if (config.resolveLogIndex) {
        try {
          const idx = await config.resolveLogIndex({
            network: payload.network,
            transaction: payload.transaction,
            asset: payload.asset,
            payTo: payload.payTo,
            amount: payload.amount,
          });
          payload.logIndex = Number.isSafeInteger(idx) && (idx as number) >= 0 ? idx : null;
        } catch {
          payload.logIndex = null;
        }
      }

      const { receipt, receiptId } = await signDeliveryReceipt(payload, config.signer);
      if (config.receiptStore) {
        const receiptUrl = await config.receiptStore.put(receiptId, receipt);
        if (new URL(receiptUrl).origin !== info.issuer) {
          throw new Error("delivery-receipt: receiptUrl must be same-origin with issuer");
        }
        return { info: { receiptId, receiptUrl }, schema: SETTLE_INFO_SCHEMA };
      }
      return { info: { receipt }, schema: SETTLE_INFO_SCHEMA };
    },
  };
}

/**
 * Route-config declaration helper.
 *
 * @returns Extension declaration to spread into a route's `extensions`
 */
export function declareDeliveryReceiptExtension(): Record<string, Record<string, never>> {
  return { [DELIVERY_RECEIPT]: {} };
}
