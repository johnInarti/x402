/**
 * Signed key directory for delivery receipts (§7).
 */

import { getAlgorithm, signWithKeyPair, verifySignature, type ReceiptKeyPair } from "./algorithms";
import { canonicalJson, fromCanonicalBase64, sha256Hex, toBase64 } from "./encoding";
import {
  KEY_DIRECTORY_SPEC,
  RECEIPT_KEY_USE,
  type KeyDirectory,
  type KeyDirectoryEntry,
  type KeyStatus,
  type ReceiptAlgorithm,
} from "./types";

const ZERO_ROOT = "0".repeat(64);
const HEX64 = /^[0-9a-f]{64}$/;
const KID = /^[A-Za-z0-9._-]{1,64}$/;
const STATUSES: KeyStatus[] = ["reserved", "active", "retiring", "retired", "revoked"];
const MAX_KEYS = 256;

/** Default allowance for `issuedAt` in the future (§7.4). */
export const DEFAULT_CLOCK_SKEW_SECONDS = 300;

/**
 * Directory root (§7.2): SHA-256 over JCS of the directory content with keys sorted by kid.
 *
 * @param dir - Directory fields (signature and root are ignored)
 * @returns Lowercase hex root
 */
export async function computeDirectoryRoot(
  dir: Pick<KeyDirectory, "spec" | "issuer" | "epoch" | "prevRoot" | "governanceKey" | "keys">,
): Promise<string> {
  const keys = [...dir.keys].sort((a, b) => (a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0));
  return sha256Hex(
    canonicalJson({
      spec: dir.spec,
      issuer: dir.issuer,
      epoch: dir.epoch,
      prevRoot: dir.prevRoot,
      governanceKey: dir.governanceKey,
      keys,
    }),
  );
}

/**
 * Message signed by the governance key.
 *
 * @param root - Directory root
 * @returns UTF-8 bytes of `x402-receipt-key-directory/1\n<root>`
 */
export function directorySignedMessage(root: string): Uint8Array {
  return new TextEncoder().encode(`${KEY_DIRECTORY_SPEC}\n${root}`);
}

/**
 * Builds and signs a key directory.
 *
 * @param params - Directory parameters
 * @param params.issuer - Origin that owns the directory
 * @param params.epoch - Epoch number (1 for the first directory)
 * @param params.prevRoot - Root of the previous epoch (defaults to 64 zeros)
 * @param params.governance - Governance key pair (signs the directory, never listed in keys)
 * @param params.keys - Receipt keys
 * @returns The signed directory
 */
export async function buildKeyDirectory(params: {
  issuer: string;
  epoch?: number;
  prevRoot?: string;
  governance: ReceiptKeyPair;
  keys: KeyDirectoryEntry[];
}): Promise<KeyDirectory> {
  const body = {
    spec: KEY_DIRECTORY_SPEC,
    issuer: params.issuer,
    epoch: params.epoch ?? 1,
    prevRoot: params.prevRoot ?? ZERO_ROOT,
    governanceKey: { alg: params.governance.alg, publicKey: params.governance.publicKeyB64 },
    keys: params.keys,
  } as const;
  const root = await computeDirectoryRoot(body);
  const signature = toBase64(signWithKeyPair(params.governance, directorySignedMessage(root)));
  return { ...body, keys: [...params.keys], root, signature };
}

/**
 * Convenience: directory entry for an active receipt key.
 *
 * @param keyPair - Receipt key pair
 * @param notBefore - Activation time (unix seconds)
 * @returns Directory entry
 */
export function activeKeyEntry(keyPair: ReceiptKeyPair, notBefore: number): KeyDirectoryEntry {
  return {
    kid: keyPair.kid,
    alg: keyPair.alg,
    publicKey: keyPair.publicKeyB64,
    use: RECEIPT_KEY_USE,
    status: "active",
    notBefore,
    notAfter: null,
    revokedAt: null,
  };
}

export interface DirectoryVerificationOptions {
  /** Origin the directory must belong to (fetch origin, or the receipt issuer offline). */
  expectedIssuer: string;
  /** Base64 governance keys trusted out of band. When set, trustBasis is "pinned". */
  pinnedGovernanceKeys?: string[];
  /** Refuse TLS-only trust (requires pinnedGovernanceKeys). */
  requirePinned?: boolean;
  /** Highest (epoch, root) previously accepted, for rollback/equivocation checks. */
  previous?: { epoch: number; root: string };
}

export interface DirectoryVerificationResult {
  ok: boolean;
  trustBasis: "pinned" | "tls" | "none";
  directory?: KeyDirectory;
  code?: string;
  detail?: string;
}

const isNullableTime = (v: unknown): v is number | null =>
  v === null || (Number.isSafeInteger(v) && (v as number) >= 0);

/**
 * Structural validation of a directory entry.
 *
 * @param e - Candidate entry
 * @returns Whether the entry is well-formed
 */
function isEntry(e: unknown): e is KeyDirectoryEntry {
  if (!e || typeof e !== "object") return false;
  const k = e as Record<string, unknown>;
  const suite = getAlgorithm(k.alg);
  const pk = fromCanonicalBase64(k.publicKey);
  return (
    typeof k.kid === "string" &&
    KID.test(k.kid) &&
    !!suite &&
    !!pk &&
    pk.length === suite.publicKeyBytes &&
    typeof k.use === "string" &&
    STATUSES.includes(k.status as KeyStatus) &&
    isNullableTime(k.notBefore) &&
    isNullableTime(k.notAfter) &&
    isNullableTime(k.revokedAt)
  );
}

/**
 * Verifies a key directory (§7.3). Never throws.
 *
 * @param input - Parsed directory JSON
 * @param options - Verification options
 * @returns Result with the typed directory when ok
 */
export async function verifyKeyDirectory(
  input: unknown,
  options: DirectoryVerificationOptions,
): Promise<DirectoryVerificationResult> {
  const fail = (code: string, detail?: string): DirectoryVerificationResult => ({
    ok: false,
    trustBasis: "none",
    code,
    detail,
  });
  try {
    if (!input || typeof input !== "object") return fail("DIRECTORY_INVALID", "not an object");
    const d = input as Record<string, unknown>;
    if (d.spec !== KEY_DIRECTORY_SPEC) return fail("DIRECTORY_INVALID", "spec");
    if (typeof d.issuer !== "string" || d.issuer !== options.expectedIssuer) {
      return fail("DIRECTORY_ISSUER_MISMATCH", String(d.issuer));
    }
    if (!Number.isSafeInteger(d.epoch) || (d.epoch as number) < 1) {
      return fail("DIRECTORY_INVALID", "epoch");
    }
    if (typeof d.prevRoot !== "string" || !HEX64.test(d.prevRoot)) {
      return fail("DIRECTORY_INVALID", "prevRoot");
    }
    if (d.epoch === 1 && d.prevRoot !== ZERO_ROOT) return fail("DIRECTORY_INVALID", "prevRoot");
    const gov = d.governanceKey as Record<string, unknown> | undefined;
    const govSuite = gov && getAlgorithm(gov.alg);
    const govKey = gov && fromCanonicalBase64(gov.publicKey);
    if (!gov || !govSuite || !govKey || govKey.length !== govSuite.publicKeyBytes) {
      return fail("DIRECTORY_INVALID", "governanceKey");
    }
    if (Object.keys(gov).length !== 2) return fail("DIRECTORY_INVALID", "governanceKey fields");
    if (!Array.isArray(d.keys) || d.keys.length === 0 || d.keys.length > MAX_KEYS) {
      return fail("DIRECTORY_INVALID", "keys");
    }
    const kids = new Set<string>();
    const pubs = new Set<string>();
    for (const e of d.keys) {
      if (!isEntry(e)) return fail("DIRECTORY_INVALID", "key entry");
      if (Object.keys(e).length !== 8) return fail("DIRECTORY_INVALID", "key entry fields");
      if (kids.has(e.kid) || pubs.has(e.publicKey)) return fail("DIRECTORY_INVALID", "duplicate");
      if (e.publicKey === gov.publicKey) return fail("DIRECTORY_INVALID", "governance key listed");
      kids.add(e.kid);
      pubs.add(e.publicKey);
    }
    const dir = d as unknown as KeyDirectory;
    const root = await computeDirectoryRoot(dir);
    if (dir.root !== root) return fail("DIRECTORY_ROOT_MISMATCH");
    const sig = fromCanonicalBase64(dir.signature);
    if (
      !sig ||
      !verifySignature(
        dir.governanceKey.alg as ReceiptAlgorithm,
        govKey,
        directorySignedMessage(root),
        sig,
      )
    ) {
      return fail("DIRECTORY_SIGNATURE_INVALID");
    }
    if (options.previous) {
      if (dir.epoch < options.previous.epoch) return fail("DIRECTORY_ROLLBACK");
      if (dir.epoch === options.previous.epoch && dir.root !== options.previous.root) {
        return fail("DIRECTORY_EQUIVOCATION");
      }
    }
    if (options.pinnedGovernanceKeys) {
      if (!options.pinnedGovernanceKeys.includes(dir.governanceKey.publicKey)) {
        return fail("DIRECTORY_SIGNER_NOT_PINNED");
      }
      return { ok: true, trustBasis: "pinned", directory: dir };
    }
    if (options.requirePinned) return fail("DIRECTORY_SIGNER_NOT_PINNED", "no pinned key given");
    return { ok: true, trustBasis: "tls", directory: dir };
  } catch (error) {
    return fail("DIRECTORY_INVALID", error instanceof Error ? error.message : String(error));
  }
}

/**
 * Key lifecycle check at the receipt's signed time (§7.4).
 *
 * @param entry - Directory entry of the signing key
 * @param alg - Receipt algorithm
 * @param issuedAt - Signed issuance time (unix seconds)
 * @param now - Verifier clock (unix seconds)
 * @param skewSeconds - Allowed future skew
 * @returns null when authorized, otherwise a reason code
 */
export function keyAuthorizationError(
  entry: KeyDirectoryEntry,
  alg: string,
  issuedAt: number,
  now: number,
  skewSeconds = DEFAULT_CLOCK_SKEW_SECONDS,
): string | null {
  if (entry.use !== RECEIPT_KEY_USE) return "KEY_USE_MISMATCH";
  if (entry.alg !== alg) return "KEY_ALG_MISMATCH";
  if (issuedAt > now + skewSeconds) return "ISSUED_AT_IN_FUTURE";
  switch (entry.status) {
    case "active":
      if (entry.notBefore === null || issuedAt < entry.notBefore) return "KEY_NOT_YET_VALID";
      if (entry.notAfter !== null && issuedAt > entry.notAfter) return "KEY_EXPIRED";
      return null;
    case "retiring":
    case "retired":
      if (entry.notBefore === null || entry.notAfter === null) return "KEY_WINDOW_UNDEFINED";
      if (issuedAt < entry.notBefore || issuedAt > entry.notAfter) return "KEY_EXPIRED";
      return null;
    case "revoked":
      return "KEY_REVOKED";
    default:
      return "KEY_NOT_ACTIVE";
  }
}

/**
 * Fetches a key directory over HTTPS without following redirects and with a size cap.
 * The result still has to go through {@link verifyKeyDirectory}.
 *
 * @param url - Directory URL
 * @param fetchImpl - fetch implementation (defaults to global fetch)
 * @param maxBytes - Maximum body size
 * @returns Parsed JSON
 */
export async function fetchKeyDirectory(
  url: string,
  fetchImpl: typeof fetch = fetch,
  maxBytes = 1024 * 1024,
): Promise<unknown> {
  const u = new URL(url);
  const loopback = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) {
    throw new Error("key directory must be fetched over https");
  }
  const res = await fetchImpl(url, { redirect: "error", headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`key directory fetch failed: HTTP ${res.status}`);
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.length > maxBytes) throw new Error("key directory too large");
  return JSON.parse(new TextDecoder().decode(buf));
}
