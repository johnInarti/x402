/**
 * Stream delivery (§5.6): frames are hashed in order into a running digest, and the frame
 * count plus the final digest are delivered in a terminal frame and bound into the receipt.
 *
 *   d_0 = SHA-256(UTF-8("x402-delivery-stream/1"))
 *   d_i = SHA-256(d_{i-1} || uint64be(len(f_i)) || f_i)
 *
 * Each step is a one-shot SHA-256, so the digest can be maintained with WebCrypto alone (which
 * has no incremental hashing API).
 */

import { bytesToHex } from "./encoding";
import { STREAM_DOMAIN, STREAM_TRAILER_EVENT, type StreamTrailer } from "./types";

const MAX_FRAME_BYTES = 2 ** 32;

/**
 * One-shot SHA-256 to raw bytes.
 *
 * @param data - Bytes to hash
 * @returns Digest bytes
 */
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

/**
 * Running digest of a stream of frames (§5.6).
 */
export class StreamDigest {
  #state: Promise<Uint8Array>;
  #count = 0;

  /**
   * Starts a new running digest at d_0.
   */
  constructor() {
    this.#state = sha256(new TextEncoder().encode(STREAM_DOMAIN));
  }

  /**
   * Number of frames absorbed so far.
   *
   * @returns The frame count
   */
  get frameCount(): number {
    return this.#count;
  }

  /**
   * Appends one frame. Calls are applied in call order even if not awaited.
   *
   * @param frame - Frame octets, or text (hashed as UTF-8)
   * @returns Resolves once the frame is absorbed
   */
  update(frame: Uint8Array | string): Promise<void> {
    const bytes = typeof frame === "string" ? new TextEncoder().encode(frame) : frame;
    if (bytes.length >= MAX_FRAME_BYTES) throw new Error("stream frame too large");
    this.#count += 1;
    const prev = this.#state;
    this.#state = prev.then(d => {
      const buf = new Uint8Array(32 + 8 + bytes.length);
      buf.set(d, 0);
      new DataView(buf.buffer).setBigUint64(32, BigInt(bytes.length), false);
      buf.set(bytes, 40);
      return sha256(buf);
    });
    return this.#state.then(() => undefined);
  }

  /**
   * Current running digest.
   *
   * @returns Lowercase hex digest after the frames absorbed so far
   */
  async digest(): Promise<string> {
    return bytesToHex(await this.#state);
  }
}

/**
 * Computes `{ frameCount, digest }` for a list of frames.
 *
 * @param frames - Frames in delivery order
 * @returns Frame count and final running digest
 */
export async function computeStreamDigest(
  frames: Iterable<Uint8Array | string>,
): Promise<{ frameCount: number; digest: string }> {
  const d = new StreamDigest();
  for (const f of frames) await d.update(f);
  return { frameCount: d.frameCount, digest: await d.digest() };
}

/**
 * Serializes one SSE event whose `data` is the given text (one `data:` line per line of text).
 *
 * @param data - Event data (the frame, for content events)
 * @param event - Optional event type
 * @returns SSE event text including the terminating blank line
 */
export function formatSseEvent(data: string, event?: string): string {
  const lines = data.split(/\r\n|\r|\n/).map(l => `data: ${l}\n`);
  return `${event ? `event: ${event}\n` : ""}${lines.join("")}\n`;
}

/**
 * Serializes the terminal frame (§5.6).
 *
 * @param trailer - Frame count, digest and the receipt (inline or by reference)
 * @returns SSE event text
 */
export function formatSseTrailer(trailer: StreamTrailer): string {
  return formatSseEvent(JSON.stringify(trailer), STREAM_TRAILER_EVENT);
}

/** One dispatched SSE event. */
export interface SseEvent {
  event: string;
  data: string;
  id?: string;
}

/**
 * Minimal SSE parser following the HTML event-stream interpretation rules: returns the events an
 * EventSource would dispatch (events with an empty data buffer are not dispatched).
 *
 * @param text - Full event-stream text
 * @returns Dispatched events in order
 */
export function parseSse(text: string): SseEvent[] {
  const events: SseEvent[] = [];
  let data: string[] = [];
  let event = "";
  let id: string | undefined;
  const body = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const lines = body.split(/\r\n|\r|\n/);
  // The last element is an unterminated line (or ""): EventSource never processes it, and an event
  // still pending at end of stream is discarded, not dispatched.
  lines.pop();
  for (const line of lines) {
    if (line === "") {
      if (data.length) events.push({ event: event || "message", data: data.join("\n"), id });
      data = [];
      event = "";
      continue;
    }
    if (line.startsWith(":")) continue;
    const i = line.indexOf(":");
    const field = i === -1 ? line : line.slice(0, i);
    let value = i === -1 ? "" : line.slice(i + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "data") data.push(value);
    else if (field === "event") event = value;
    else if (field === "id" && !value.includes("\0")) id = value;
  }
  return events;
}

/**
 * Splits parsed SSE events into content frames and the terminal trailer (§5.6). Anything after the
 * trailer is ignored and reported.
 *
 * @param events - Dispatched events
 * @returns Frames (event data), the parsed trailer if present, and the number of events after it
 */
export function splitSseStream(events: SseEvent[]): {
  frames: string[];
  trailer: StreamTrailer | null;
  eventsAfterTrailer: number;
} {
  const frames: string[] = [];
  for (let i = 0; i < events.length; i++) {
    if (events[i].event === STREAM_TRAILER_EVENT) {
      let trailer: StreamTrailer | null = null;
      try {
        trailer = JSON.parse(events[i].data) as StreamTrailer;
      } catch {
        trailer = null;
      }
      return { frames, trailer, eventsAfterTrailer: events.length - i - 1 };
    }
    frames.push(events[i].data);
  }
  return { frames, trailer: null, eventsAfterTrailer: 0 };
}
