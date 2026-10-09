/**
 * Signed key directory for delivery receipts (§7): one document per epoch, a stable current URL,
 * immutable per-epoch archives and a prevRoot hash chain.
 */

import {
  getAlgorithm,
  signWithKeyPair,
  verifySignatureWithEngine,
  type ReceiptKeyPair,
} from "./algorithms";
import { canonicalJson, fromCanonicalBase64, sha256Hex, toBase64 } from "./encoding";
import {
  ARCHIVAL_ALGORITHM,
  KEY_DIRECTORY_SPEC,
  RECEIPT_KEY_USE,
  SESSION_ALGORITHM,
  type GovernanceKey,
  type KeyDirectory,
  type KeyDirectoryEntry,
  type KeyStatus,
  type ReceiptAlgorithm,
  type VerificationPath,
} from "./types";

const ZERO_ROOT = "0".repeat(64);
const HEX64 = /^[0-9a-f]{64}$/;
const KID = /^[A-Za-z0-9._-]{1,64}$/;
const STATUSES: KeyStatus[] = ["reserved", "active", "retiring", "retired", "revoked"];
const MAX_KEYS = 256;
const MAX_GOVERNANCE_KEYS = 4;
/** Upper bound on archives fetched to chain one receipt (§7.5). */
export const MAX_CHAIN_EPOCHS = 64;

/** Default allowance for `issuedAt` in the future and for directory hand-over (§7.4). */
export const DEFAULT_CLOCK_SKEW_SECONDS = 300;

/**
 * Signature algorithm checked on each verification path (§8.1).
 *
 * @param path - Verification path
 * @returns The algorithm that path relies on
 */
export function pathAlgorithm(path: VerificationPath): ReceiptAlgorithm {
  return path === "session" ? SESSION_ALGORITHM : ARCHIVAL_ALGORITHM;
}

const byString =
  <T>(key: (v: T) => string) =>
  (a: T, b: T): number =>
    key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0;

type DirectoryContent = Pick<
  KeyDirectory,
  "spec" | "issuer" | "epoch" | "prevRoot" | "publishedAt" | "governanceKeys" | "keys"
>;

/**
 * Directory root (§7.2): SHA-256 over JCS of the directory content, with `governanceKeys`
 * sorted by `alg` and `keys` sorted by `kid`. This is also the receipt's `keyDirectoryDigest`.
 *
 * @param dir - Directory fields (`root` and `signatures` are ignored)
 * @returns Lowercase hex root
 */
export async function computeDirectoryRoot(dir: DirectoryContent): Promise<string> {
  return sha256Hex(
    canonicalJson({
      spec: dir.spec,
      issuer: dir.issuer,
      epoch: dir.epoch,
      prevRoot: dir.prevRoot,
      publishedAt: dir.publishedAt,
      governanceKeys: [...dir.governanceKeys].sort(byString(g => g.alg)),
      keys: [...dir.keys].sort(byString(k => k.kid)),
    }),
  );
}

/**
 * Message signed by every governance key.
 *
 * @param root - Directory root
 * @returns UTF-8 bytes of `x402-receipt-key-directory/1\n<root>`
 */
export function directorySignedMessage(root: string): Uint8Array {
  return new TextEncoder().encode(`${KEY_DIRECTORY_SPEC}\n${root}`);
}

/**
 * URL of the immutable archive of one epoch (§7.1).
 *
 * @param keyDirectory - Stable directory URL from the declaration
 * @param epoch - Epoch number
 * @returns `${keyDirectory}/epoch/${epoch}`
 */
export function keyDirectoryEpochUrl(keyDirectory: string, epoch: number): string {
  return `${keyDirectory.replace(/\/+$/, "")}/epoch/${epoch}`;
}

/**
 * Builds and signs one directory epoch.
 *
 * @param params - Directory parameters
 * @param params.issuer - Origin that owns the directory
 * @param params.epoch - Epoch number (1 for the first directory)
 * @param params.prevRoot - Root of the previous epoch (64 zeros for epoch 1)
 * @param params.publishedAt - Unix seconds from which this epoch is in force
 * @param params.governance - Governance key pairs; MUST include ed25519 and ml-dsa-65
 * @param params.keys - Receipt keys
 * @returns The signed directory
 */
export async function buildKeyDirectory(params: {
  issuer: string;
  epoch?: number;
  prevRoot?: string;
  publishedAt: number;
  governance: ReceiptKeyPair[];
  keys: KeyDirectoryEntry[];
}): Promise<KeyDirectory> {
  const governanceKeys: GovernanceKey[] = params.governance
    .map(g => ({ alg: g.alg, publicKey: g.publicKeyB64 }))
    .sort(byString(g => g.alg));
  const body: DirectoryContent = {
    spec: KEY_DIRECTORY_SPEC,
    issuer: params.issuer,
    epoch: params.epoch ?? 1,
    prevRoot: params.prevRoot ?? ZERO_ROOT,
    publishedAt: params.publishedAt,
    governanceKeys,
    keys: [...params.keys],
  };
  const root = await computeDirectoryRoot(body);
  const message = directorySignedMessage(root);
  const signatures = [...params.governance]
    .sort(byString(g => g.alg))
    .map(g => ({ alg: g.alg, signature: toBase64(signWithKeyPair(g, message)) }));
  return { ...body, root, signatures };
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
  /** Which governance signature to verify. Default `archival`. */
  path?: VerificationPath;
  /**
   * Base64 governance keys trusted out of band. When set, trustBasis is "pinned" only if the
   * governance key whose signature was verified on this path is in the list.
   */
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
  if (!e || typeof e !== "object" || Object.keys(e).length !== 8) return false;
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
 * Structural validation of a list of `{ alg, <field> }` objects with distinct registered algs.
 *
 * @param list - Candidate list
 * @param field - Name of the base64 field
 * @param bytes - Expected decoded length per algorithm
 * @returns Whether the list is well-formed
 */
function isAlgList(
  list: unknown,
  field: "publicKey" | "signature",
  bytes: (alg: ReceiptAlgorithm) => number,
): boolean {
  if (!Array.isArray(list) || list.length === 0 || list.length > MAX_GOVERNANCE_KEYS) return false;
  const seen = new Set<string>();
  for (const item of list) {
    if (!item || typeof item !== "object" || Object.keys(item).length !== 2) return false;
    const g = item as Record<string, unknown>;
    if (!getAlgorithm(g.alg) || seen.has(g.alg as string)) return false;
    const raw = fromCanonicalBase64(g[field]);
    if (!raw || raw.length !== bytes(g.alg as ReceiptAlgorithm)) return false;
    seen.add(g.alg as string);
  }
  return seen.has(SESSION_ALGORITHM) && seen.has(ARCHIVAL_ALGORITHM);
}

/**
 * Verifies one directory epoch (§7.3). Never throws.
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
    if (Object.keys(d).length !== 9) return fail("DIRECTORY_INVALID", "fields");
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
    if ((d.epoch === 1) !== (d.prevRoot === ZERO_ROOT))
      return fail("DIRECTORY_INVALID", "prevRoot");
    if (!Number.isSafeInteger(d.publishedAt) || (d.publishedAt as number) < 0) {
      return fail("DIRECTORY_INVALID", "publishedAt");
    }
    if (!isAlgList(d.governanceKeys, "publicKey", a => getAlgorithm(a)!.publicKeyBytes)) {
      return fail("DIRECTORY_INVALID", "governanceKeys");
    }
    if (!isAlgList(d.signatures, "signature", a => getAlgorithm(a)!.signatureBytes)) {
      return fail("DIRECTORY_INVALID", "signatures");
    }
    if (!Array.isArray(d.keys) || d.keys.length === 0 || d.keys.length > MAX_KEYS) {
      return fail("DIRECTORY_INVALID", "keys");
    }
    const govKeys = d.governanceKeys as GovernanceKey[];
    const govPubs = new Set(govKeys.map(g => g.publicKey));
    const kids = new Set<string>();
    const pubs = new Set<string>();
    for (const e of d.keys) {
      if (!isEntry(e)) return fail("DIRECTORY_INVALID", "key entry");
      if (kids.has(e.kid) || pubs.has(e.publicKey)) return fail("DIRECTORY_INVALID", "duplicate");
      if (govPubs.has(e.publicKey)) return fail("DIRECTORY_INVALID", "governance key listed");
      kids.add(e.kid);
      pubs.add(e.publicKey);
    }
    const dir = d as unknown as KeyDirectory;
    const root = await computeDirectoryRoot(dir);
    if (dir.root !== root) return fail("DIRECTORY_ROOT_MISMATCH");

    const alg = pathAlgorithm(options.path ?? "archival");
    const gov = govKeys.find(g => g.alg === alg)!;
    const sig = dir.signatures.find(s => s.alg === alg)!;
    const { ok } = await verifySignatureWithEngine(
      alg,
      fromCanonicalBase64(gov.publicKey)!,
      directorySignedMessage(root),
      fromCanonicalBase64(sig.signature)!,
    );
    if (!ok) return fail("DIRECTORY_SIGNATURE_INVALID", alg);

    if (options.previous) {
      if (dir.epoch < options.previous.epoch) return fail("DIRECTORY_ROLLBACK");
      if (dir.epoch === options.previous.epoch && dir.root !== options.previous.root) {
        return fail("DIRECTORY_EQUIVOCATION");
      }
    }
    if (options.pinnedGovernanceKeys) {
      if (!options.pinnedGovernanceKeys.includes(gov.publicKey)) {
        return fail("DIRECTORY_SIGNER_NOT_PINNED", alg);
      }
      return { ok: true, trustBasis: "pinned", directory: dir };
    }
    if (options.requirePinned) return fail("DIRECTORY_SIGNER_NOT_PINNED", "no pinned key given");
    return { ok: true, trustBasis: "tls", directory: dir };
  } catch (error) {
    return fail("DIRECTORY_INVALID", error instanceof Error ? error.message : String(error));
  }
}

const STATUS_RANK: Record<KeyStatus, number> = {
  reserved: 0,
  active: 1,
  retiring: 2,
  retired: 3,
  revoked: 4,
};

/**
 * Append-only rule between consecutive epochs (§7.4): every key of `prev` stays listed in `next`
 * with the same identity, and its status only moves forward.
 *
 * @param prev - Epoch n
 * @param next - Epoch n+1
 * @returns null when the transition is allowed, otherwise a reason code
 */
function transitionError(prev: KeyDirectory, next: KeyDirectory): string | null {
  const sameGov =
    prev.governanceKeys.length === next.governanceKeys.length &&
    prev.governanceKeys.every(g =>
      next.governanceKeys.some(h => h.alg === g.alg && h.publicKey === g.publicKey),
    );
  if (!sameGov) return "DIRECTORY_CHAIN_GOVERNANCE_CHANGED";
  if (next.prevRoot !== prev.root) return "DIRECTORY_CHAIN_BROKEN";
  if (next.publishedAt < prev.publishedAt) return "DIRECTORY_CHAIN_TIME";
  for (const k of prev.keys) {
    const n = next.keys.find(e => e.kid === k.kid);
    if (!n) return "DIRECTORY_CHAIN_KEY_DROPPED";
    if (n.alg !== k.alg || n.publicKey !== k.publicKey || n.use !== k.use) {
      return "DIRECTORY_CHAIN_KEY_CHANGED";
    }
    if (STATUS_RANK[n.status] < STATUS_RANK[k.status]) return "DIRECTORY_CHAIN_STATUS_REGRESSED";
  }
  return null;
}

export interface DirectoryChainResult {
  ok: boolean;
  trustBasis: "pinned" | "tls" | "none";
  /** Directory of the requested epoch. */
  directory?: KeyDirectory;
  /** Highest epoch chained from the requested one (statuses are read from here). */
  latest?: KeyDirectory;
  /** Next epoch after the requested one, when available (bounds the "in force" window). */
  successor?: KeyDirectory;
  code?: string;
  detail?: string;
}

/**
 * Verifies the epoch a receipt was issued under and chains it forward through the epochs
 * provided (§7.5). With pinned governance keys any epoch signed by a pinned key is trusted; without
 * them (TLS trust) the requested epoch must chain to the highest epoch provided, which is taken to
 * be the current directory fetched from the stable URL. Never throws.
 *
 * @param documents - Directory documents of any epochs (current, archives, saved copies)
 * @param epoch - Epoch to resolve
 * @param options - Verification options
 * @returns Chain result
 */
export async function verifyKeyDirectoryChain(
  documents: unknown[],
  epoch: number,
  options: DirectoryVerificationOptions,
): Promise<DirectoryChainResult> {
  const fail = (code: string, detail?: string): DirectoryChainResult => ({
    ok: false,
    trustBasis: "none",
    code,
    detail,
  });
  const byEpoch = new Map<number, KeyDirectory>();
  let trustBasis: "pinned" | "tls" = "tls";
  for (const doc of documents.slice(0, MAX_CHAIN_EPOCHS + 1)) {
    const r = await verifyKeyDirectory(doc, { ...options, previous: undefined });
    if (!r.ok || !r.directory) return fail(r.code ?? "DIRECTORY_INVALID", r.detail);
    const existing = byEpoch.get(r.directory.epoch);
    if (existing && existing.root !== r.directory.root) return fail("DIRECTORY_EQUIVOCATION");
    byEpoch.set(r.directory.epoch, r.directory);
    if (r.directory.epoch === epoch) trustBasis = r.trustBasis as "pinned" | "tls";
  }
  const directory = byEpoch.get(epoch);
  if (!directory) return fail("DIRECTORY_EPOCH_UNAVAILABLE", String(epoch));

  let latest = directory;
  while (byEpoch.has(latest.epoch + 1)) {
    const next = byEpoch.get(latest.epoch + 1)!;
    const err = transitionError(latest, next);
    if (err) return fail(err, `${latest.epoch} -> ${next.epoch}`);
    latest = next;
  }
  const highest = Math.max(...byEpoch.keys());
  if (trustBasis === "tls" && latest.epoch !== highest) {
    return fail("DIRECTORY_CHAIN_BROKEN", `epoch ${epoch} does not chain to ${highest}`);
  }
  if (options.previous) {
    if (latest.epoch < options.previous.epoch) {
      // A saved copy that predates the remembered state is fine offline only if pinned.
      if (trustBasis !== "pinned") return fail("DIRECTORY_ROLLBACK");
    } else if (
      byEpoch.has(options.previous.epoch) &&
      byEpoch.get(options.previous.epoch)!.root !== options.previous.root
    ) {
      return fail("DIRECTORY_EQUIVOCATION");
    }
  }
  return {
    ok: true,
    trustBasis,
    directory,
    latest,
    successor: byEpoch.get(epoch + 1),
  };
}

/**
 * Key lifecycle check at the receipt's signed time (§7.4).
 *
 * @param entry - Directory entry of the signing key
 * @param alg - Signature algorithm
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

/**
 * Fetches what is needed to verify a receipt issued under `epoch`: the current directory from the
 * stable URL and, when it is newer, the archives `epoch .. current-1` (§7.5).
 *
 * @param keyDirectory - Stable directory URL
 * @param epoch - Epoch named by the receipt
 * @param fetchImpl - fetch implementation
 * @returns Directory documents, current last
 */
export async function fetchKeyDirectoryChain(
  keyDirectory: string,
  epoch: number,
  fetchImpl: typeof fetch = fetch,
): Promise<unknown[]> {
  const current = (await fetchKeyDirectory(keyDirectory, fetchImpl)) as { epoch?: unknown };
  const top = Number.isSafeInteger(current?.epoch) ? (current.epoch as number) : 0;
  if (!Number.isSafeInteger(epoch) || epoch < 1 || top <= epoch) return [current];
  if (top - epoch > MAX_CHAIN_EPOCHS) throw new Error("key directory chain too long");
  const archives: unknown[] = [];
  for (let n = epoch; n < top; n++) {
    archives.push(await fetchKeyDirectory(keyDirectoryEpochUrl(keyDirectory, n), fetchImpl));
  }
  return [...archives, current];
}
