/**
 * Delivery-receipt extension for x402ResourceServer.
 *
 * Uses the extension hooks to (1) declare the extension in 402 responses and (2) sign a
 * receipt after a successful settle, binding the settlement to the SHA-256 of the response
 * body that the HTTP middleware buffered for settlement. By default `PAYMENT-RESPONSE` carries only
 * a compact reference `{ receiptId, receiptUrl, digest }` and the receipt is served, immutable, at
 * `receiptUrl` (§5.5). Streamed routes use {@link createSseReceiptWriter}, which hashes frames as
 * they are sent and ends the stream with a terminal `x402-delivery-receipt` event (§5.6).
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
import {
  computeReceiptId,
  receiptDocument,
  receiptSignedMessage,
  sha256Hex,
  toBase64,
} from "./encoding";
import { StreamDigest, formatSseEvent, formatSseTrailer } from "./stream";
import {
  ARCHIVAL_ALGORITHM,
  DELIVERY_RECEIPT,
  KEY_DIRECTORY_WELL_KNOWN_PATH,
  MAX_REFERENCE_EXTENSION_BYTES,
  SESSION_ALGORITHM,
  STREAM_TRAILER_EVENT,
  type DeliveryCommitment,
  type DeliveryReceipt,
  type DeliveryReceiptDeclarationInfo,
  type DeliveryReceiptPayload,
  type DeliveryReceiptReference,
  type DeliveryReceiptSettleInfo,
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
    digest: { type: "string", pattern: "^[0-9a-f]{64}$" },
  },
  oneOf: [{ required: ["receipt"] }, { required: ["receiptId", "receiptUrl", "digest"] }],
} as const;

/**
 * Persists receipts delivered by reference and serves them at their `receiptUrl` (§5.5).
 * `put` receives the exact document to serve (`JCS(receipt)`) and returns its URL, which MUST be
 * https, same-origin with the issuer and end with `/<receiptId>`. The document at that URL MUST
 * never change.
 */
export interface ReceiptStore {
  put(receiptId: string, receipt: DeliveryReceipt, document: string): Promise<string> | string;
}

/** A {@link ReceiptStore} kept in memory, with a handler that serves it (for tests and examples). */
export interface MemoryReceiptStore extends ReceiptStore {
  /** The stored document for an id, if any. */
  get(receiptId: string): string | undefined;
  /** Serves `GET <prefix><receiptId>`; returns undefined for any other request. */
  handle(request: Request | string): Response | undefined;
}

/**
 * Creates an in-memory receipt store serving `${issuer}${prefix}<receiptId>`. Production
 * deployments persist the documents (they are immutable and content-addressed, so any blob store or
 * CDN works) and keep them retrievable for at least 30 days.
 *
 * @param issuer - Issuer origin
 * @param prefix - Path prefix, default `/x402/receipts/`
 * @returns The store
 */
export function createMemoryReceiptStore(
  issuer: string,
  prefix = "/x402/receipts/",
): MemoryReceiptStore {
  const origin = new URL(issuer).origin;
  const docs = new Map<string, string>();
  return {
    put(receiptId, _receipt, document) {
      const prior = docs.get(receiptId);
      if (prior !== undefined && prior !== document) {
        throw new Error("delivery-receipt: a stored receipt document never changes");
      }
      docs.set(receiptId, document);
      return `${origin}${prefix}${receiptId}`;
    },
    get: receiptId => docs.get(receiptId),
    handle(request) {
      const u = new URL(typeof request === "string" ? request : request.url);
      if (u.origin !== origin || !u.pathname.startsWith(prefix)) return undefined;
      const doc = docs.get(u.pathname.slice(prefix.length));
      if (doc === undefined) return new Response("not found", { status: 404 });
      return new Response(doc, {
        status: 200,
        headers: {
          "content-type": "application/json",
          "cache-control": "public, max-age=31536000, immutable",
        },
      });
    },
  };
}

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
   * Where the receipt travels (§5.5). Default `reference`: `PAYMENT-RESPONSE` (or the terminal
   * stream event) carries only `{ receiptId, receiptUrl, digest }` and `receiptStore` serves the
   * receipt. Use `inline` only when you know every hop accepts a `PAYMENT-RESPONSE` of about 8 KB.
   */
  receiptTransport?: "reference" | "inline";
  /** Persists and serves receipts delivered by reference. Required for `reference`. */
  receiptStore?: ReceiptStore;
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
    receiptTransport: receiptTransportOf(config),
  };
}

/**
 * Resolves the transport of a configuration (§5.5): `reference` unless `inline` is chosen.
 *
 * @param config - Server configuration
 * @returns The transport
 */
function receiptTransportOf(config: DeliveryReceiptServerConfig): "reference" | "inline" {
  const transport = config.receiptTransport ?? "reference";
  if (transport !== "reference" && transport !== "inline") {
    throw new Error("delivery-receipt: receiptTransport must be reference or inline");
  }
  if (transport === "reference" && !config.receiptStore) {
    throw new Error(
      'delivery-receipt: receipts are delivered by reference by default; configure a receiptStore, or set receiptTransport: "inline" only if your response headers fit an ~8 KB PAYMENT-RESPONSE',
    );
  }
  return transport;
}

/**
 * Checks a receipt URL returned by a store (§5.5): https, same-origin with the issuer, and
 * content-addressed (last path segment = receipt id).
 *
 * @param receiptUrl - URL returned by the store
 * @param issuer - Issuer origin
 * @param receiptId - Receipt id
 */
function assertReceiptUrl(receiptUrl: string, issuer: string, receiptId: string): void {
  const u = new URL(receiptUrl);
  if (u.origin !== issuer) {
    throw new Error("delivery-receipt: receiptUrl must be same-origin with issuer");
  }
  if (u.protocol !== "https:" && !(u.hostname === "localhost" || u.hostname === "127.0.0.1")) {
    throw new Error("delivery-receipt: receiptUrl must be https");
  }
  if (u.search || u.hash || u.pathname.split("/").pop() !== receiptId) {
    throw new Error("delivery-receipt: receiptUrl must end with /<receiptId>");
  }
}

/**
 * The settle-response member for a receipt (§5.1, §5.5). The schema of §10 is not repeated on
 * the wire, so a reference stays within the header budget.
 *
 * @param info - Inline receipt or reference
 * @returns `{ info }`, checked against the budget when it is a reference
 */
function settleMember(info: DeliveryReceiptSettleInfo): { info: DeliveryReceiptSettleInfo } {
  const member = { info };
  if (!("receipt" in info)) {
    const bytes = new TextEncoder().encode(JSON.stringify(member)).length;
    if (bytes > MAX_REFERENCE_EXTENSION_BYTES) {
      throw new Error(
        `delivery-receipt: reference is ${bytes} octets, over the ${MAX_REFERENCE_EXTENSION_BYTES}-octet budget`,
      );
    }
  }
  return member;
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
 * and, by default, stores the receipt and returns its reference (§5.5).
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
): Promise<{ receipt: DeliveryReceipt; reference: DeliveryReceiptReference | null }> {
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
  if (receiptTransportOf(config) === "inline") return { receipt, reference: null };
  const document = receiptDocument(receipt);
  const receiptUrl = await config.receiptStore!.put(receiptId, receipt, document);
  assertReceiptUrl(receiptUrl, issuer, receiptId);
  return { receipt, reference: { receiptId, receiptUrl, digest: await sha256Hex(document) } };
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
      if (info.deliveryMode === "stream") return undefined; // receipt goes in the terminal event
      const directory = await currentDirectory(config.directory);
      const payload = await buildReceiptPayload(context, info.issuer, now(), directory);
      if (!payload) return undefined;
      const { receipt, reference } = await issue(config, info.issuer, payload, directory);
      // Never in the response body: the body stays byte-identical to what delivery.sha256 covers.
      return settleMember(reference ?? { receipt });
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
 * carries `frameCount`, the final digest and the receipt (by reference unless `inline`), whose
 * payload binds the same two values. Nothing travels in HTTP trailers.
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
      if (event !== undefined && (/[\r\n]/.test(event) || event === STREAM_TRAILER_EVENT)) {
        throw new Error("delivery-receipt: invalid SSE event name for a content frame");
      }
      // Hash what EventSource will expose as MessageEvent.data: CR and CRLF become LF (§5.6).
      await digest.update(data.replace(/\r\n|\r/g, "\n"));
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
      const { receipt, reference } = await issue(config, info.issuer, payload, directory);
      const receiptId = reference?.receiptId ?? (await computeReceiptId(receipt.payload));
      const trailer: StreamTrailer = reference
        ? { frameCount, digest: final, reference }
        : { frameCount, digest: final, receipt };
      return { event: formatSseTrailer(trailer), trailer, receiptId };
    },
  };
}
