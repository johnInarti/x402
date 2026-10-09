/**
 * Delivery-receipt extension for x402ResourceServer.
 *
 * Uses the extension hooks to (1) declare the extension in 402 responses and (2) sign a
 * receipt after a successful settle, binding the settlement to the SHA-256 of the response
 * body that the HTTP middleware buffered for settlement. Streamed routes use
 * {@link createSseReceiptWriter}, which hashes frames as they are sent and emits the receipt in a
 * terminal frame (§5.6).
 *
 * Spec: specs/extensions/delivery-receipt.md
 */

import type {
  PaymentPayload,
  PaymentRequirements,
  ResourceServerExtension,
  SettleResponse,
  SettleResultContext,
} from "@x402/core/types";
import type { HTTPTransportContext } from "@x402/core/http";
import { computeReceiptId, receiptSignedMessage, sha256Hex, toBase64 } from "./encoding";
import { StreamDigest, formatSseEvent, formatSseTrailer } from "./stream";
import {
  ARCHIVAL_ALGORITHM,
  DELIVERY_RECEIPT,
  KEY_DIRECTORY_WELL_KNOWN_PATH,
  SESSION_ALGORITHM,
  type DeliveryCommitment,
  type DeliveryReceipt,
  type DeliveryReceiptDeclarationInfo,
  type DeliveryReceiptPayload,
  type KeyDirectory,
  type ReceiptSigner,
  type StreamTrailer,
} from "./types";

/** JSON Schema for the declaration `info` (§4). */
export const DECLARATION_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    version: { type: "integer", const: 1 },
    issuer: { type: "string" },
    keyDirectory: { type: "string", format: "uri" },
    algorithms: {
      type: "array",
      items: { type: "string" },
      allOf: [{ contains: { const: "ed25519" } }, { contains: { const: "ml-dsa-65" } }],
    },
    deliveryMode: { type: "string", enum: ["body", "stream"] },
    receiptTransport: { type: "string", enum: ["inline", "reference"] },
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
        payload: { type: "object" },
        signatures: {
          type: "array",
          minItems: 2,
          maxItems: 4,
          items: {
            type: "object",
            properties: {
              alg: { type: "string" },
              kid: { type: "string" },
              signature: { type: "string" },
            },
            required: ["alg", "kid", "signature"],
          },
        },
      },
      required: ["payload", "signatures"],
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

/** Current directory, or a function returning it (called once per receipt). */
export type DirectorySource = KeyDirectory | (() => KeyDirectory | Promise<KeyDirectory>);

export interface DeliveryReceiptServerConfig {
  /** Origin of the signer, e.g. "https://api.example.com". */
  issuer: string;
  /** Stable key directory URL; defaults to `${issuer}/.well-known/x402-receipt-keys`. */
  keyDirectory?: string;
  /** Receipt signers: MUST include `ed25519` and `ml-dsa-65` (§6.1). */
  signers: ReceiptSigner[];
  /** The directory epoch in force; its epoch and root are bound into every receipt (§5.2). */
  directory: DirectorySource;
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
  /** Routes declared with this extension are streamed (§5.6). Default `body`. */
  deliveryMode?: "body" | "stream";
  /** Clock override (unix seconds), for tests. */
  now?: () => number;
}

/**
 * Checks that a signer set carries the v0.2 baseline pair.
 *
 * @param signers - Receipt signers
 */
function assertSignerPair(signers: ReceiptSigner[]): void {
  const algs = signers.map(s => s.alg);
  if (
    !algs.includes(SESSION_ALGORITHM) ||
    !algs.includes(ARCHIVAL_ALGORITHM) ||
    new Set(algs).size !== algs.length ||
    algs.length > 4
  ) {
    throw new Error("delivery-receipt: signers must include ed25519 and ml-dsa-65, once each");
  }
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
  assertSignerPair(config.signers);
  const issuer = new URL(config.issuer).origin;
  const keyDirectory =
    config.keyDirectory ?? new URL(KEY_DIRECTORY_WELL_KNOWN_PATH, issuer).toString();
  if (new URL(keyDirectory).origin !== issuer) {
    throw new Error("delivery-receipt: keyDirectory must be same-origin with issuer");
  }
  return {
    version: 1,
    issuer,
    keyDirectory,
    algorithms: config.signers.map(s => s.alg),
    deliveryMode: config.deliveryMode ?? "body",
    receiptTransport: config.receiptStore ? "reference" : "inline",
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
 * Resolves a directory source.
 *
 * @param source - Directory or function returning it
 * @returns The current directory
 */
async function currentDirectory(source: DirectorySource): Promise<KeyDirectory> {
  return typeof source === "function" ? await source() : source;
}

/** Facts a receipt is built from (§5.2). Everything is server-side data held at settle time. */
export interface ReceiptFacts {
  issuer: string;
  resourceUrl: string;
  method: string;
  requirements: Pick<PaymentRequirements, "scheme" | "asset" | "payTo" | "amount">;
  settle: SettleResponse;
  paymentPayload?: Pick<PaymentPayload, "extensions">;
  responseStatus: number | null;
  responseContentType: string | null;
  delivery: DeliveryCommitment;
  directory: Pick<KeyDirectory, "epoch" | "root">;
  issuedAt: number;
  logIndex?: number | null;
}

/**
 * Builds an unsigned receipt payload from server-side facts.
 *
 * @param f - Receipt facts
 * @returns The payload, or null when the settle did not succeed
 */
export function createReceiptPayload(f: ReceiptFacts): DeliveryReceiptPayload | null {
  const { settle } = f;
  if (!settle.success || !settle.transaction || !settle.payer || !settle.network) return null;
  return {
    version: 1,
    issuer: f.issuer,
    resourceUrl: f.resourceUrl,
    method: f.method.toUpperCase(),
    scheme: f.requirements.scheme,
    network: settle.network,
    asset: f.requirements.asset,
    payTo: f.requirements.payTo,
    amount: settle.amount ?? f.requirements.amount,
    payer: settle.payer,
    transaction: settle.transaction,
    logIndex: f.logIndex ?? null,
    paymentId: readPaymentId(f.paymentPayload?.extensions),
    responseStatus: f.responseStatus,
    responseContentType: f.responseContentType,
    delivery: f.delivery,
    keyDirectoryEpoch: f.directory.epoch,
    keyDirectoryDigest: f.directory.root,
    issuedAt: f.issuedAt,
  };
}

/**
 * Builds the unsigned body-mode payload from a settle context. Returns null when a receipt must
 * not be issued (failed settle, no body, missing facts).
 *
 * @param context - Settle result context from x402ResourceServer
 * @param issuer - Issuer origin
 * @param issuedAt - Issuance time (unix seconds)
 * @param directory - Directory epoch in force
 * @returns Payload without logIndex resolution, or null
 */
export async function buildReceiptPayload(
  context: SettleResultContext,
  issuer: string,
  issuedAt: number,
  directory: Pick<KeyDirectory, "epoch" | "root">,
): Promise<DeliveryReceiptPayload | null> {
  if (context.phase !== "after-handler") return null; // body not observable (§5.4)
  const transport = context.transportContext as HTTPTransportContext | undefined;
  const body = transport?.responseBody;
  const request = transport?.request;
  if (!body || !request?.adapter) return null;
  const headers = transport.responseHeaders ?? {};
  const contentTypeKey = Object.keys(headers).find(k => k.toLowerCase() === "content-type");
  return createReceiptPayload({
    issuer,
    resourceUrl: publicResourceUrl(request.adapter.getUrl(), issuer),
    method: request.method || request.adapter.getMethod(),
    requirements: context.requirements,
    settle: context.result,
    paymentPayload: context.paymentPayload,
    responseStatus: null,
    responseContentType: contentTypeKey ? headers[contentTypeKey] : null,
    delivery: { mode: "body", sha256: await sha256Hex(new Uint8Array(body)) },
    directory,
    issuedAt,
  });
}

/**
 * Signs a payload into a wire receipt (§5.3): every signer signs the same message.
 *
 * @param payload - Receipt payload
 * @param signers - Receipt signers (the baseline pair, optionally more)
 * @returns Receipt and its id
 */
export async function signDeliveryReceipt(
  payload: DeliveryReceiptPayload,
  signers: ReceiptSigner[],
): Promise<{ receipt: DeliveryReceipt; receiptId: string }> {
  const receiptId = await computeReceiptId(payload);
  const message = receiptSignedMessage(receiptId);
  const signatures = [];
  for (const s of signers) {
    signatures.push({ alg: s.alg, kid: s.kid, signature: toBase64(await s.sign(message)) });
  }
  return { receipt: { payload, signatures }, receiptId };
}

/**
 * Shared issuance path: resolves the log index, checks the signers against the directory, signs,
 * and stores the receipt when delivering by reference.
 *
 * @param config - Server configuration
 * @param issuer - Issuer origin
 * @param payload - Unsigned payload
 * @param directory - Directory the payload names
 * @returns Inline receipt or reference
 */
async function issue(
  config: DeliveryReceiptServerConfig,
  issuer: string,
  payload: DeliveryReceiptPayload,
  directory: KeyDirectory,
): Promise<{ receipt: DeliveryReceipt } | { receiptId: string; receiptUrl: string }> {
  for (const s of config.signers) {
    const entry = directory.keys.find(k => k.kid === s.kid);
    if (!entry || entry.alg !== s.alg) {
      throw new Error(`delivery-receipt: signer ${s.kid} (${s.alg}) is not in directory epoch`);
    }
  }
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
  const { receipt, receiptId } = await signDeliveryReceipt(payload, config.signers);
  if (config.receiptStore) {
    const receiptUrl = await config.receiptStore.put(receiptId, receipt);
    if (new URL(receiptUrl).origin !== issuer) {
      throw new Error("delivery-receipt: receiptUrl must be same-origin with issuer");
    }
    return { receiptId, receiptUrl };
  }
  return { receipt };
}

/**
 * Creates the delivery-receipt ResourceServerExtension (body mode). For streamed routes, declare
 * with `deliveryMode: "stream"` and issue receipts with {@link createSseReceiptWriter}; the settle
 * hook then adds nothing.
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
      if (info.deliveryMode === "stream") return undefined; // receipt goes in the trailer
      const directory = await currentDirectory(config.directory);
      const payload = await buildReceiptPayload(context, info.issuer, now(), directory);
      if (!payload) return undefined;
      return {
        info: await issue(config, info.issuer, payload, directory),
        schema: SETTLE_INFO_SCHEMA,
      };
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

/** Context of one paid stream, known once settlement has succeeded. */
export interface SseReceiptContext {
  resourceUrl: string;
  method: string;
  requirements: Pick<PaymentRequirements, "scheme" | "asset" | "payTo" | "amount">;
  settle: SettleResponse;
  paymentPayload?: Pick<PaymentPayload, "extensions">;
  responseStatus?: number | null;
  responseContentType?: string | null;
}

/** Writer that turns frames into SSE events and seals the stream with a receipt (§5.6). */
export interface SseReceiptWriter {
  /** Hashes `data` as the next frame and returns the SSE event text to send. */
  frame(data: string, event?: string): Promise<string>;
  /** Signs the receipt over everything framed so far and returns the terminal event text. */
  finish(): Promise<{ event: string; trailer: StreamTrailer; receiptId: string }>;
}

/**
 * Creates an SSE writer for a paid stream. Frames are the UTF-8 octets of each event's `data`
 * (what `EventSource` exposes as `MessageEvent.data`); the terminal `x402-delivery-receipt` event
 * carries `frameCount`, the final digest and the receipt, whose payload binds the same two values.
 *
 * @param config - Server configuration (same as the extension)
 * @param context - Settlement context of this request
 * @returns The writer
 */
export function createSseReceiptWriter(
  config: DeliveryReceiptServerConfig,
  context: SseReceiptContext,
): SseReceiptWriter {
  const info = buildDeclarationInfo(config);
  const now = config.now ?? (() => Math.floor(Date.now() / 1000));
  const digest = new StreamDigest();
  let finished = false;
  return {
    async frame(data: string, event?: string): Promise<string> {
      if (finished) throw new Error("delivery-receipt: stream already finished");
      if (data === "") throw new Error("delivery-receipt: empty frames are not dispatched by SSE");
      await digest.update(data);
      return formatSseEvent(data, event);
    },
    async finish() {
      if (finished) throw new Error("delivery-receipt: stream already finished");
      finished = true;
      const directory = await currentDirectory(config.directory);
      const frameCount = digest.frameCount;
      const final = await digest.digest();
      const payload = createReceiptPayload({
        issuer: info.issuer,
        resourceUrl: publicResourceUrl(context.resourceUrl, info.issuer),
        method: context.method,
        requirements: context.requirements,
        settle: context.settle,
        paymentPayload: context.paymentPayload,
        responseStatus: context.responseStatus ?? null,
        responseContentType: context.responseContentType ?? "text/event-stream",
        delivery: { mode: "stream", framing: "sse", frameCount, digest: final },
        directory,
        issuedAt: now(),
      });
      if (!payload) throw new Error("delivery-receipt: settlement did not succeed");
      const out = await issue(config, info.issuer, payload, directory);
      const receiptId = "receipt" in out ? await computeReceiptId(payload) : out.receiptId;
      const trailer = { frameCount, digest: final, ...out } as StreamTrailer;
      return { event: formatSseTrailer(trailer), trailer, receiptId };
    },
  };
}
