/**
 * Signature algorithm registry for the delivery-receipt extension (§6).
 */

import { ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { ed25519 } from "@noble/curves/ed25519";
import { toBase64 } from "./encoding";
import type { ReceiptAlgorithm, ReceiptSigner } from "./types";

interface AlgorithmSuite {
  publicKeyBytes: number;
  signatureBytes: number;
  seedBytes: number;
  keygen(seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
}

const SUITES: Record<ReceiptAlgorithm, AlgorithmSuite> = {
  // FIPS 204 pure ML-DSA with an empty context string. Deterministic signing is used so a
  // receipt can be re-derived byte-for-byte in tests; FIPS 204 allows both variants.
  "ml-dsa-65": {
    publicKeyBytes: 1952,
    signatureBytes: 3309,
    seedBytes: 32,
    keygen: seed => ml_dsa65.keygen(seed),
    sign: (m, sk) => ml_dsa65.sign(m, sk, { extraEntropy: false }),
    verify: (s, m, pk) => ml_dsa65.verify(s, m, pk),
  },
  "ml-dsa-87": {
    publicKeyBytes: 2592,
    signatureBytes: 4627,
    seedBytes: 32,
    keygen: seed => ml_dsa87.keygen(seed),
    sign: (m, sk) => ml_dsa87.sign(m, sk, { extraEntropy: false }),
    verify: (s, m, pk) => ml_dsa87.verify(s, m, pk),
  },
  ed25519: {
    publicKeyBytes: 32,
    signatureBytes: 64,
    seedBytes: 32,
    keygen: seed => ({ secretKey: seed, publicKey: ed25519.getPublicKey(seed) }),
    sign: (m, sk) => ed25519.sign(m, sk),
    // Strict RFC 8032 verification (no ZIP-215 leniency) so all verifiers agree.
    verify: (s, m, pk) => ed25519.verify(s, m, pk, { zip215: false }),
  },
};

/** Algorithms this implementation can verify. */
export const SUPPORTED_ALGORITHMS = Object.keys(SUITES) as ReceiptAlgorithm[];

/**
 * Returns the suite for a registered algorithm, or undefined.
 *
 * @param alg - Algorithm identifier
 * @returns The suite or undefined
 */
export function getAlgorithm(alg: unknown): AlgorithmSuite | undefined {
  return typeof alg === "string" && Object.prototype.hasOwnProperty.call(SUITES, alg)
    ? SUITES[alg as ReceiptAlgorithm]
    : undefined;
}

/**
 * Verifies a signature, returning false (never throwing) on malformed input or a length
 * that does not match the algorithm table.
 *
 * @param alg - Algorithm identifier
 * @param publicKey - Raw public key bytes
 * @param message - Signed message bytes
 * @param signature - Raw signature bytes
 * @returns Whether the signature is valid
 */
export function verifySignature(
  alg: ReceiptAlgorithm,
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  const suite = getAlgorithm(alg);
  if (!suite) return false;
  if (publicKey.length !== suite.publicKeyBytes || signature.length !== suite.signatureBytes) {
    return false;
  }
  try {
    return suite.verify(signature, message, publicKey) === true;
  } catch {
    return false;
  }
}

/** Engine that verified a signature. */
export type VerifyEngine = "webcrypto" | "noble";

let webCryptoEd25519: Promise<boolean> | undefined;

/**
 * Whether this runtime's WebCrypto implements Ed25519 (Workers, Deno, Node >= 20, recent
 * browsers). Probed once by importing a fixed valid public key.
 *
 * @returns True when `crypto.subtle` can import Ed25519 keys
 */
export function hasWebCryptoEd25519(): Promise<boolean> {
  webCryptoEd25519 ??= (async () => {
    try {
      if (!globalThis.crypto?.subtle) return false;
      await crypto.subtle.importKey(
        "raw",
        ed25519.getPublicKey(new Uint8Array(32)) as BufferSource,
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      return true;
    } catch {
      return false;
    }
  })();
  return webCryptoEd25519;
}

/**
 * Verifies a signature, using WebCrypto for Ed25519 where the runtime provides it (the
 * in-session path of §8.1) and the bundled implementation otherwise. Never throws.
 *
 * @param alg - Algorithm identifier
 * @param publicKey - Raw public key bytes
 * @param message - Signed message bytes
 * @param signature - Raw signature bytes
 * @returns Whether the signature is valid and which engine checked it
 */
export async function verifySignatureWithEngine(
  alg: ReceiptAlgorithm,
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<{ ok: boolean; engine: VerifyEngine }> {
  const suite = getAlgorithm(alg);
  if (
    alg === "ed25519" &&
    suite &&
    publicKey.length === suite.publicKeyBytes &&
    signature.length === suite.signatureBytes &&
    (await hasWebCryptoEd25519())
  ) {
    try {
      const key = await crypto.subtle.importKey(
        "raw",
        publicKey as BufferSource,
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      const ok = await crypto.subtle.verify(
        { name: "Ed25519" },
        key,
        signature as BufferSource,
        message as BufferSource,
      );
      // WebCrypto Ed25519 is not uniformly strict across runtimes (Node 20 accepts a
      // small-order public key with R = identity, S = 0). Require the strict RFC 8032
      // check as well, so the verdict never depends on the engine (§6.1).
      return { ok: ok && verifySignature(alg, publicKey, message, signature), engine: "webcrypto" };
    } catch {
      return { ok: false, engine: "webcrypto" };
    }
  }
  return { ok: verifySignature(alg, publicKey, message, signature), engine: "noble" };
}

/**
 * Recommended key id derivation (§7.2): first 16 hex chars of SHA-256 over the base64 key text.
 *
 * @param publicKeyB64 - Canonical base64 public key
 * @returns Key id
 */
export async function deriveKid(publicKeyB64: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(publicKeyB64) as BufferSource,
  );
  return Array.from(new Uint8Array(digest).slice(0, 8), b => b.toString(16).padStart(2, "0")).join(
    "",
  );
}

export interface ReceiptKeyPair {
  alg: ReceiptAlgorithm;
  kid: string;
  publicKey: Uint8Array;
  publicKeyB64: string;
  secretKey: Uint8Array;
}

/**
 * Generates (or deterministically derives from a 32-byte seed) a receipt key pair.
 *
 * @param alg - Algorithm identifier
 * @param seed - Optional 32-byte seed; random when omitted
 * @returns The key pair with its derived kid
 */
export async function generateReceiptKeyPair(
  alg: ReceiptAlgorithm,
  seed?: Uint8Array,
): Promise<ReceiptKeyPair> {
  const suite = getAlgorithm(alg);
  if (!suite) throw new Error(`Unsupported receipt algorithm: ${alg}`);
  const s = seed ?? crypto.getRandomValues(new Uint8Array(suite.seedBytes));
  if (s.length !== suite.seedBytes) throw new Error(`Seed must be ${suite.seedBytes} bytes`);
  const { publicKey, secretKey } = suite.keygen(s);
  const publicKeyB64 = toBase64(publicKey);
  return { alg, kid: await deriveKid(publicKeyB64), publicKey, publicKeyB64, secretKey };
}

/**
 * Wraps a local secret key as a {@link ReceiptSigner}.
 *
 * @param keyPair - Key pair from {@link generateReceiptKeyPair}
 * @returns A signer
 */
export function createLocalReceiptSigner(keyPair: ReceiptKeyPair): ReceiptSigner {
  const suite = getAlgorithm(keyPair.alg);
  if (!suite) throw new Error(`Unsupported receipt algorithm: ${keyPair.alg}`);
  return {
    alg: keyPair.alg,
    kid: keyPair.kid,
    sign: (message: Uint8Array) => suite.sign(message, keyPair.secretKey),
  };
}

/**
 * Signs arbitrary bytes with a key pair (used for directories).
 *
 * @param keyPair - Key pair
 * @param message - Message bytes
 * @returns Signature bytes
 */
export function signWithKeyPair(keyPair: ReceiptKeyPair, message: Uint8Array): Uint8Array {
  const suite = getAlgorithm(keyPair.alg);
  if (!suite) throw new Error(`Unsupported receipt algorithm: ${keyPair.alg}`);
  return suite.sign(message, keyPair.secretKey);
}
