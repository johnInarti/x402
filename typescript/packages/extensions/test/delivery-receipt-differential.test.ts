/* eslint-disable -- red-team fuzzing harness, not library code */
// RED-TEAM differential fuzzer: reference (@x402/extensions/delivery-receipt) vs the second
// implementation (@fractalai/x402-receipts, a port; path in RT_PKG). Same inputs, compare the
// verdict per level. Seeded and reproducible: RT_DIFF=1 + RT_PKG enable it; RT_SEED, RT_CASES, RT_MUT tune it.
import { it, expect } from "vitest";
import { writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as ref from "../src/delivery-receipt";
import type { PaymentRequirements, SettleResponse } from "@x402/core/types";

// RT_PKG: path to the second implementation's src/delivery-receipt.mjs (@fractalai/x402-receipts).
const PKG = process.env.RT_PKG ?? "";
const OUT = process.env.RT_OUT ?? join(tmpdir(), "rt-dr-diff-cases.json");
const N = Number(process.env.RT_CASES ?? 3200);
const M = Number(process.env.RT_MUT ?? 1);
let rngState = Number(process.env.RT_SEED ?? 402);
const rnd = () => {
  // mulberry32
  rngState |= 0;
  rngState = (rngState + 0x6d2b79f5) | 0;
  let t = Math.imul(rngState ^ (rngState >>> 15), 1 | rngState);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = <T>(a: readonly T[]): T => a[Math.floor(rnd() * a.length)];
const chance = (p: number) => rnd() < p;

const ISSUER = "https://api.example.com";
const RESOURCE = `${ISSUER}/premium-data`;
const NOW = 1_790_473_960;
const BODY = new TextEncoder().encode('{"price":"64012.55"}');
const requirements = {
  scheme: "exact",
  network: "eip155:8453",
  asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
  amount: "10000",
  maxTimeoutSeconds: 60,
  extra: {},
} as PaymentRequirements;
const settle: SettleResponse = {
  success: true,
  transaction: "0x5c6e0000000000000000000000000000000000000000000000000000000000a1",
  network: "eip155:8453",
  payer: "0x857b06519E91e3A54538791bDbb0E22373e36b66",
};
const seed = (n: number) => new Uint8Array(32).fill(n);

const WEIRD_VALUES: unknown[] = [
  "",
  "x",
  "GET",
  "get",
  -0,
  0,
  1,
  -1,
  1.5,
  2 ** 53,
  2 ** 53 - 1,
  Number.MAX_VALUE,
  null,
  true,
  false,
  [],
  {},
  ["a"],
  { a: 1 },
  "\ud800",
  "\udc00x",
  "é",
  "é",
  "\u0000",
  "a".repeat(5000),
  "0x857B06519E91E3A54538791BDBB0E22373E36B66",
  "https://evil.example/x",
  "http://api.example.com/premium-data",
  "https://api.example.com",
  "https://api.example.com/",
  "eip155:84532",
  "base",
  "9".repeat(80),
];

it.skipIf(!process.env.RT_DIFF || !process.env.RT_PKG)(
  `differential: ${N} cases`,
  async () => {
    const pkg = await import(PKG);
    const govEd = await ref.generateReceiptKeyPair("ed25519", seed(1));
    const govPq = await ref.generateReceiptKeyPair("ml-dsa-65", seed(1));
    const keyEd = await ref.generateReceiptKeyPair("ed25519", seed(2));
    const keyPq = await ref.generateReceiptKeyPair("ml-dsa-65", seed(2));
    const keyEd2 = await ref.generateReceiptKeyPair("ed25519", seed(3));
    const keyPq2 = await ref.generateReceiptKeyPair("ml-dsa-65", seed(3));
    const key87 = await ref.generateReceiptKeyPair("ml-dsa-87", seed(4));
    const evilGovEd = await ref.generateReceiptKeyPair("ed25519", seed(9));
    const evilGovPq = await ref.generateReceiptKeyPair("ml-dsa-65", seed(9));
    const allKeys = [keyEd, keyPq, keyEd2, keyPq2, key87];
    const entry = (k: ref.ReceiptKeyPair, over: Partial<ref.KeyDirectoryEntry> = {}) => ({
      ...ref.activeKeyEntry(k, NOW - 86_400),
      ...over,
    });

    const dir1 = await ref.buildKeyDirectory({
      issuer: ISSUER,
      publishedAt: NOW - 86_400,
      governance: [govEd, govPq],
      keys: [
        entry(keyEd),
        entry(keyPq),
        entry(key87),
        entry(keyEd2, { status: "reserved", notBefore: null }),
      ],
    });
    const mk2 = (
      keys: ref.KeyDirectoryEntry[],
      publishedAt = NOW - 3600,
      prev = dir1.root,
      gov = [govEd, govPq],
      epoch = 2,
    ) =>
      ref.buildKeyDirectory({
        issuer: ISSUER,
        epoch,
        prevRoot: prev,
        publishedAt,
        governance: gov,
        keys,
      });
    const dir2ok = await mk2([
      entry(keyEd),
      entry(keyPq),
      entry(key87),
      entry(keyEd2, { status: "reserved", notBefore: null }),
      entry(keyPq2),
    ]);
    const dir2revoked = await mk2([
      entry(keyEd, { status: "revoked", revokedAt: NOW - 3600 }),
      entry(keyPq, { status: "revoked", revokedAt: NOW - 3600 }),
      entry(key87),
      entry(keyEd2, { status: "active" }),
    ]);
    const dir2retired = await mk2([
      entry(keyEd, { status: "retired", notAfter: NOW - 7200 }),
      entry(keyPq, { status: "retiring", notAfter: NOW + 10 }),
      entry(key87),
      entry(keyEd2, { status: "active" }),
    ]);
    const dir2dropped = await mk2([entry(keyEd), entry(keyPq)]);
    const dir2regress = await mk2(
      [
        entry(keyEd),
        entry(keyPq),
        entry(key87),
        entry(keyEd2, { status: "reserved", notBefore: null }),
        entry(keyPq2),
      ],
      NOW - 3600,
    );
    const dir2gov = await mk2(
      [
        entry(keyEd),
        entry(keyPq),
        entry(key87),
        entry(keyEd2, { status: "reserved", notBefore: null }),
      ],
      NOW - 3600,
      dir1.root,
      [evilGovEd, govPq],
    );
    const dir2fork = await mk2(
      [entry(keyEd), entry(keyPq), entry(key87), entry(keyEd2, { status: "active" })],
      NOW - 3000,
    );
    const dir2future = await mk2(
      [
        entry(keyEd),
        entry(keyPq),
        entry(key87),
        entry(keyEd2, { status: "reserved", notBefore: null }),
      ],
      NOW + 100_000,
    );
    const dir2early = await mk2(
      [
        entry(keyEd),
        entry(keyPq),
        entry(key87),
        entry(keyEd2, { status: "reserved", notBefore: null }),
      ],
      NOW - 90_000,
    );
    const dir3 = await ref.buildKeyDirectory({
      issuer: ISSUER,
      epoch: 3,
      prevRoot: dir2ok.root,
      publishedAt: NOW - 60,
      governance: [govEd, govPq],
      keys: [
        entry(keyEd),
        entry(keyPq),
        entry(key87),
        entry(keyEd2, { status: "reserved", notBefore: null }),
        entry(keyPq2),
      ],
    });
    const evilDir = await ref.buildKeyDirectory({
      issuer: ISSUER,
      publishedAt: NOW - 86_400,
      governance: [evilGovEd, evilGovPq],
      keys: [entry(keyEd), entry(keyPq)],
    });
    const foreignDir = await ref.buildKeyDirectory({
      issuer: "https://evil.example",
      publishedAt: NOW - 86_400,
      governance: [govEd, govPq],
      keys: [entry(keyEd), entry(keyPq)],
    });
    const DIRSETS: Record<string, unknown[]> = {
      d1: [dir1],
      d12: [dir1, dir2ok],
      d123: [dir1, dir2ok, dir3],
      d13: [dir1, dir3],
      d12rev: [dir1, dir2revoked],
      d12ret: [dir1, dir2retired],
      d12drop: [dir1, dir2dropped],
      d12reg: [dir1, dir2regress],
      d12gov: [dir1, dir2gov],
      d12fork: [dir1, dir2ok, dir2fork],
      d12fut: [dir1, dir2future],
      d12early: [dir1, dir2early],
      evil: [evilDir],
      foreign: [foreignDir],
      none: [],
      d2only: [dir2ok],
      d21: [dir2ok, dir1],
      dup: [dir1, dir1],
    };
    const sha = async (b: Uint8Array) => ref.sha256Hex(b);

    const basePayload = async (over: Record<string, unknown> = {}, dir = dir1) => ({
      version: 1,
      issuer: ISSUER,
      resourceUrl: RESOURCE,
      method: "GET",
      scheme: "exact",
      network: settle.network,
      asset: requirements.asset,
      payTo: requirements.payTo,
      amount: "10000",
      payer: settle.payer,
      transaction: settle.transaction,
      logIndex: 312,
      paymentId: null,
      responseStatus: null,
      responseContentType: "application/json",
      delivery: { mode: "body", sha256: await sha(BODY) },
      keyDirectoryEpoch: dir.epoch,
      keyDirectoryDigest: dir.root,
      issuedAt: NOW,
      ...over,
    });
    const signerFor = (k: ref.ReceiptKeyPair) => ref.createLocalReceiptSigner(k);
    // Resign: message from whichever implementation can canonicalize the payload.
    const resign = async (payload: any, keys: ref.ReceiptKeyPair[]) => {
      let id: string | null = null;
      try {
        id = await ref.computeReceiptId(payload);
      } catch {
        try {
          id = pkg.receiptId(payload);
        } catch {
          id = null;
        }
      }
      if (!id) return null;
      const msg = ref.receiptSignedMessage(id);
      return keys.map(k => ({
        alg: k.alg,
        kid: k.kid,
        signature: ref.toBase64(signerFor(k).sign(msg) as Uint8Array),
      }));
    };

    const PAYLOAD_KEYS = Object.keys(await basePayload());
    const sigCache = new Map<string, any>();
    const summary: Record<string, number> = {};
    const diffs: any[] = [];
    let streamCases = 0;

    for (let i = 0; i < N; i++) {
      const tags: string[] = [];
      const isStream = chance(0.2);
      let payload: any;
      let frames: string[] = [];
      let sseText: string | null = null;
      const dirKey = chance(1 - 0.4 * M) ? pick(["d1", "d12", "d123"]) : pick(Object.keys(DIRSETS));
      const docs = DIRSETS[dirKey].map(d => structuredClone(d));
      tags.push(`dirs:${dirKey}`);
      const namedDir = chance(0.85) ? dir1 : pick([dir2ok, dir3, dir2revoked, dir2fork]);
      if (namedDir !== dir1) tags.push(`names-epoch:${namedDir.epoch}`);

      if (isStream) {
        streamCases++;
        tags.push("stream");
        frames = Array.from({ length: Math.floor(rnd() * 5) }, (_, j) =>
          pick(["tick", `frame-${j}`, "a\nb", "é", '{"x":1}', "line"]),
        );
        const d = await ref.computeStreamDigest(frames);
        payload = await basePayload(
          {
            responseContentType: "text/event-stream",
            delivery: { mode: "stream", framing: "sse", ...d },
          },
          namedDir,
        );
      } else {
        payload = await basePayload({}, namedDir);
      }

      // ── payload mutations ──
      let resignNeeded = false;
      const nPayloadMut = chance(0.55 * M) ? 1 + Math.floor(rnd() * 2) : 0;
      for (let m = 0; m < nPayloadMut; m++) {
        const kind = pick(["set", "set", "set", "delete", "extra", "delivery", "issuedAt", "case"]);
        const k = pick(PAYLOAD_KEYS);
        if (kind === "set") {
          payload[k] = structuredClone(pick(WEIRD_VALUES));
          tags.push(`p.set:${k}`);
        } else if (kind === "delete") {
          delete payload[k];
          tags.push(`p.del:${k}`);
        } else if (kind === "extra") {
          payload[pick(["extra", "__proto__x", "Version", "issuer "])] = 1;
          tags.push("p.extra");
        } else if (kind === "delivery") {
          const dm = pick(["mode", "extra", "frameCount", "framing", "sha", "swap"]);
          tags.push(`p.delivery:${dm}`);
          if (
            !payload.delivery ||
            typeof payload.delivery !== "object" ||
            Array.isArray(payload.delivery)
          )
            payload.delivery = { mode: "body", sha256: await sha(BODY) };
          if (dm === "mode") payload.delivery.mode = pick(["body", "stream", "BODY", ""]);
          if (dm === "extra") payload.delivery.x = 1;
          if (dm === "frameCount")
            payload.delivery.frameCount = pick([-1, 2 ** 53, 0, 1, 1.5, "1", -0]);
          if (dm === "framing") payload.delivery.framing = pick(["", "ndjson", "SSE"]);
          if (dm === "sha")
            payload.delivery.sha256 = pick(["A".repeat(64), "0".repeat(63), "0".repeat(64)]);
          if (dm === "swap")
            payload.delivery = {
              mode: "stream",
              framing: "sse",
              frameCount: 0,
              digest: await ref.sha256Hex("x402-delivery-stream/1"),
            };
        } else if (kind === "issuedAt") {
          payload.issuedAt = pick([
            NOW + 299,
            NOW + 301,
            NOW + 10_000,
            NOW - 86_400 - 1,
            NOW - 4000,
            0,
          ]);
          tags.push("p.issuedAt");
        } else if (kind === "case") {
          payload.payer =
            typeof payload.payer === "string" ? payload.payer.toUpperCase() : payload.payer;
          tags.push("p.payerCase");
        }
        resignNeeded = true;
      }

      // ── signatures ──
      const keySet = chance(0.9)
        ? [keyEd, keyPq]
        : pick([
            [keyEd, keyPq, key87],
            [keyEd2, keyPq],
            [keyEd, keyPq2],
            [keyPq, keyEd],
          ]);
      if (keySet[0] !== keyEd || keySet.length !== 2)
        tags.push(`keys:${keySet.map(k => k.kid.slice(0, 4)).join("+")}`);
      let signatures: any = null;
      const resignNow = !resignNeeded || chance(0.7);
      if (resignNow) {
        const cacheKey = JSON.stringify([payload, keySet.map(k => k.kid)]);
        // structuredClone-safe key: -0 and lone surrogates matter, so only cache when JSON round-trips
        signatures = sigCache.get(cacheKey) ?? (await resign(payload, keySet));
        if (
          signatures &&
          JSON.stringify(payload) === JSON.stringify(JSON.parse(JSON.stringify(payload))) &&
          !Object.is(payload.logIndex, -0)
        )
          sigCache.set(cacheKey, signatures);
        if (resignNeeded) tags.push("resigned");
      }
      if (!signatures) {
        const basePl = isStream ? payload : await basePayload({}, namedDir);
        signatures = (await resign(basePl, keySet)) ?? [];
        if (resignNeeded) tags.push("stale-sig");
      }
      signatures = structuredClone(signatures);
      if (chance(0.3 * M)) {
        const sm = pick([
          "drop-ed",
          "drop-pq",
          "dup",
          "swapAlg",
          "swapKid",
          "garbage-ed",
          "garbage-pq",
          "b64pad",
          "b64ws",
          "short",
          "extraField",
          "unknownAlg",
          "kidUnknown",
          "five",
          "reorder",
          "kidEmpty",
          "edFromOtherPayload",
        ]);
        tags.push(`s:${sm}`);
        const ed = signatures.find((s: any) => s.alg === "ed25519");
        const pq = signatures.find((s: any) => s.alg === "ml-dsa-65");
        if (sm === "drop-ed") signatures = signatures.filter((s: any) => s !== ed);
        if (sm === "drop-pq") signatures = signatures.filter((s: any) => s !== pq);
        if (sm === "dup" && ed) signatures.push({ ...ed });
        if (sm === "swapAlg" && ed && pq) {
          const t = ed.alg;
          ed.alg = pq.alg;
          pq.alg = t;
        }
        if (sm === "swapKid" && ed && pq) {
          const t = ed.kid;
          ed.kid = pq.kid;
          pq.kid = t;
        }
        if (sm === "garbage-ed" && ed) ed.signature = Buffer.alloc(64, 3).toString("base64");
        if (sm === "garbage-pq" && pq) pq.signature = Buffer.alloc(3309, 3).toString("base64");
        if (sm === "b64pad" && ed) ed.signature = ed.signature.replace(/=+$/, "");
        if (sm === "b64ws" && ed)
          ed.signature = ed.signature.slice(0, 10) + "\n" + ed.signature.slice(10);
        if (sm === "short" && ed) ed.signature = Buffer.alloc(63, 1).toString("base64");
        if (sm === "extraField" && ed) ed.extra = 1;
        if (sm === "unknownAlg" && ed) ed.alg = "ed448";
        if (sm === "kidUnknown" && ed) ed.kid = "deadbeefdeadbeef";
        if (sm === "kidEmpty" && pq) pq.kid = "";
        if (sm === "five") signatures = [...signatures, ...signatures, ...signatures].slice(0, 5);
        if (sm === "reorder") signatures.reverse();
        if (sm === "edFromOtherPayload" && ed) {
          const other = await resign(await basePayload({ amount: "1" }, namedDir), [keyEd]);
          ed.signature = other![0].signature;
        }
      }
      let receipt: any = { payload, signatures };
      if (chance(0.03)) {
        receipt.extra = 1;
        tags.push("r.extra");
      }
      if (chance(0.02)) {
        receipt = pick([null, [], "x", { payload }, 7]);
        tags.push("r.shape");
      }

      // ── directory mutations ──
      if (chance(0.12 * M) && docs.length) {
        const dm = pick([
          "tamper",
          "root",
          "issuer",
          "sigflip-ed",
          "sigflip-pq",
          "extra",
          "epochStr",
          "keysEmpty",
          "govDup",
        ]);
        tags.push(`d:${dm}`);
        const d: any = docs[0];
        if (dm === "tamper") d.keys[0].status = "retired";
        if (dm === "root") d.root = "0".repeat(64);
        if (dm === "issuer") d.issuer = ISSUER + "/";
        if (dm === "sigflip-ed")
          d.signatures.find((s: any) => s.alg === "ed25519").signature = Buffer.alloc(
            64,
            9,
          ).toString("base64");
        if (dm === "sigflip-pq")
          d.signatures.find((s: any) => s.alg === "ml-dsa-65").signature = Buffer.alloc(
            3309,
            9,
          ).toString("base64");
        if (dm === "extra") d.extra = 1;
        if (dm === "epochStr") d.epoch = String(d.epoch);
        if (dm === "keysEmpty") d.keys = [];
        if (dm === "govDup") d.governanceKeys.push({ ...d.governanceKeys[0] });
      }

      // ── options ──
      const path = pick(["session", "archival"] as const);
      const trustMode =
        M < 1 && chance(0.6)
          ? pick(["tls", "pinBoth"])
          : pick([
              "tls",
              "tls",
              "pinBoth",
              "pinEd",
              "pinPq",
              "pinEvil",
              "requirePinned",
              "prev2",
              "prev1bad",
            ]);
      tags.push(`path:${path}`, `trust:${trustMode}`);
      const directoryTrust: any = {
        tls: undefined,
        pinBoth: { pinnedGovernanceKeys: [govEd.publicKeyB64, govPq.publicKeyB64] },
        pinEd: { pinnedGovernanceKeys: [govEd.publicKeyB64] },
        pinPq: { pinnedGovernanceKeys: [govPq.publicKeyB64] },
        pinEvil: { pinnedGovernanceKeys: [evilGovEd.publicKeyB64, evilGovPq.publicKeyB64] },
        requirePinned: { requirePinned: true },
        prev2: {
          pinnedGovernanceKeys: [govEd.publicKeyB64, govPq.publicKeyB64],
          previous: { epoch: 2, root: dir2ok.root },
        },
        prev1bad: { previous: { epoch: 1, root: "f".repeat(64) } },
      }[trustMode];
      const now = chance(0.9) ? NOW : pick([NOW - 1000, NOW + 100_000, NOW - 86_400 * 2]);
      const skewSeconds = chance(0.9) ? undefined : pick([0, 10, 100_000]);
      const acceptedIssuers = chance(0.9)
        ? undefined
        : pick([["https://evil.example"], [ISSUER], ["not a url"]]);

      // ── expectations ──
      let expected: any = undefined;
      if (chance(0.8)) {
        expected = {
          settle: { ...settle },
          requirements: { ...requirements },
          resourceUrl: RESOURCE,
          method: "GET",
          paymentId: null,
        };
        if (!isStream) {
          expected.responseBody = BODY;
          expected.responseStatus = 200;
        }
        if (chance(0.35 * M)) {
          const em = pick([
            "tx",
            "txCase",
            "network",
            "payerCase",
            "payerOther",
            "payerNum",
            "payerMissing",
            "amount",
            "amountSettle",
            "asset",
            "assetCase",
            "payTo",
            "scheme",
            "url",
            "urlSlash",
            "method",
            "methodLower",
            "paymentId",
            "body",
            "bodyEmpty",
            "status",
            "offerOk",
            "offerPayer",
            "offerNet",
            "offerTxNull",
            "offerTx",
            "noSettle",
            "onlyUrl",
          ]);
          tags.push(`e:${em}`);
          const s = expected.settle,
            rq = expected.requirements;
          if (em === "tx") s.transaction = "0x" + "1".repeat(64);
          if (em === "txCase") s.transaction = s.transaction.toUpperCase().replace("0X", "0x");
          if (em === "network") s.network = "eip155:84532";
          if (em === "payerCase") s.payer = s.payer.toLowerCase();
          if (em === "payerOther") s.payer = "0x000000000000000000000000000000000000dEaD";
          if (em === "payerNum") s.payer = 1;
          if (em === "payerMissing") delete s.payer;
          if (em === "amount") rq.amount = "9999";
          if (em === "amountSettle") s.amount = "9999";
          if (em === "asset") rq.asset = "0x0000000000000000000000000000000000000001";
          if (em === "assetCase") rq.asset = rq.asset.toLowerCase();
          if (em === "payTo") rq.payTo = "0x0000000000000000000000000000000000000002";
          if (em === "scheme") rq.scheme = "upto";
          if (em === "url") expected.resourceUrl = `${ISSUER}/other`;
          if (em === "urlSlash") expected.resourceUrl = `${RESOURCE}/`;
          if (em === "method") expected.method = "POST";
          if (em === "methodLower") expected.method = "get";
          if (em === "paymentId") expected.paymentId = "pay_0123456789abcdef";
          if (em === "body" && !isStream)
            expected.responseBody = new TextEncoder().encode("tampered");
          if (em === "bodyEmpty" && !isStream) expected.responseBody = new Uint8Array(0);
          if (em === "status") {
            expected.responseStatus = 500;
            payload.responseStatus = payload.responseStatus ?? null;
          }
          if (em === "offerOk")
            expected.offerReceipt = {
              network: settle.network,
              payer: settle.payer.toLowerCase(),
              transaction: settle.transaction,
            };
          if (em === "offerPayer")
            expected.offerReceipt = {
              network: settle.network,
              payer: "0x000000000000000000000000000000000000dEaD",
              transaction: null,
            };
          if (em === "offerNet")
            expected.offerReceipt = { network: "eip155:1", payer: settle.payer, transaction: null };
          if (em === "offerTxNull")
            expected.offerReceipt = {
              network: settle.network,
              payer: settle.payer,
              transaction: null,
            };
          if (em === "offerTx")
            expected.offerReceipt = {
              network: settle.network,
              payer: settle.payer,
              transaction: "0xabc",
            };
          if (em === "noSettle") delete expected.settle;
          if (em === "onlyUrl") expected = { resourceUrl: RESOURCE };
        }
      }

      // ── stream wire ──
      if (isStream) {
        let fr = [...frames];
        let trailerObj: any = {
          frameCount: (payload?.delivery as any)?.frameCount,
          digest: payload?.delivery?.digest,
          receipt,
        };
        let after = "";
        let bom = "";
        if (chance(0.5 * M)) {
          const sm = pick([
            "reorder",
            "insert",
            "drop",
            "dup",
            "crlf",
            "trailerCount",
            "trailerDigest",
            "after",
            "afterComment",
            "noTrailer",
            "bom",
            "bom2",
            "trailerBadJson",
            "trailerRef",
            "emptyData",
            "multiTrailer",
            "idField",
            "trailerNoBlank",
          ]);
          tags.push(`sse:${sm}`);
          if (sm === "reorder" && fr.length > 1) fr.reverse();
          if (sm === "insert") fr.splice(Math.floor(rnd() * (fr.length + 1)), 0, "injected");
          if (sm === "drop" && fr.length) fr.pop();
          if (sm === "dup" && fr.length) fr.push(fr[0]);
          if (sm === "crlf") fr = fr.map(f => f.replace(/\n/g, "\r\n"));
          if (sm === "trailerCount") trailerObj.frameCount = (trailerObj.frameCount ?? 0) + 1;
          if (sm === "trailerDigest") trailerObj.digest = "0".repeat(64);
          if (sm === "after") after = "data: late\n\n";
          if (sm === "afterComment") after = ": just a comment\n\n";
          if (sm === "multiTrailer") after = null as any;
          if (sm === "noTrailer") trailerObj = null;
          if (sm === "bom") bom = "﻿";
          if (sm === "bom2") bom = "﻿﻿";
          if (sm === "trailerBadJson") trailerObj = "{bad";
          if (sm === "trailerRef")
            trailerObj = {
              frameCount: trailerObj.frameCount,
              digest: trailerObj.digest,
              reference: {
                receiptId: "a".repeat(64),
                receiptUrl: `https://api.example.com/x402/receipts/${"a".repeat(64)}`,
                digest: "b".repeat(64),
              },
            };
          if (sm === "emptyData") fr.push("");
          if (sm === "idField") tags.push("id");
          if (sm === "trailerNoBlank") tags.push("noblank");
          if (
            ["reorder", "insert", "drop", "dup", "crlf"].includes(sm) &&
            JSON.stringify(fr) === JSON.stringify(frames)
          )
            tags[tags.length - 1] = `sse:${sm}:noop`;
        }
        const frameText = fr
          .map(f =>
            f === ""
              ? "data:\n\n"
              : ref.formatSseEvent(f, tags.includes("id") ? undefined : undefined),
          )
          .join("");
        let trailerText = "";
        if (trailerObj !== null) {
          const data = typeof trailerObj === "string" ? trailerObj : JSON.stringify(trailerObj);
          trailerText =
            `event: x402-delivery-receipt\ndata: ${data}\n` +
            (tags.includes("noblank") ? "" : "\n");
        }
        if (after === null) {
          after = trailerText;
        }
        sseText = bom + frameText + trailerText + after;
      }

      const offline = chance(0.3);
      if (offline) tags.push("offline");
      const opts: any = {
        directories: docs,
        directoryTrust,
        path,
        now,
        offline,
        ...(skewSeconds !== undefined ? { skewSeconds } : {}),
        ...(acceptedIssuers ? { acceptedIssuers } : {}),
        ...(expected ? { expected } : {}),
      };
      const noFetch = (async () => new Response("{}", { status: 404 })) as unknown as typeof fetch;
      let a: any, b: any;
      try {
        a =
          sseText !== null
            ? await ref.verifySseDelivery(sseText, structuredClone(opts), noFetch)
            : await ref.verifyDeliveryReceipt(structuredClone(receipt), structuredClone(opts));
      } catch (e) {
        a = { threw: String(e) };
      }
      try {
        b =
          sseText !== null
            ? await pkg.verifySseDelivery(sseText, structuredClone(opts), noFetch)
            : pkg.verifyDeliveryReceipt(structuredClone(receipt), structuredClone(opts));
      } catch (e) {
        b = { threw: String(e) };
      }
      const va = JSON.stringify({
        valid: a.valid,
        levels: a.levels,
        lte: a.longTermEvidence,
        threw: a.threw,
      });
      const vb = JSON.stringify({
        valid: b.valid,
        levels: b.levels,
        lte: b.longTermEvidence,
        threw: b.threw,
      });
      const outcome = a.valid ? "valid" : "invalid";
      summary[outcome] = (summary[outcome] ?? 0) + 1;
      if (va !== vb) {
        diffs.push({
          case: i,
          tags,
          ref: {
            valid: a.valid,
            levels: a.levels,
            codes: a.reasons?.map((r: any) => r.code),
            threw: a.threw,
          },
          pkg: {
            valid: b.valid,
            levels: b.levels,
            codes: b.reasons?.map((r: any) => r.code),
            threw: b.threw,
          },
        });
      }
      // Red flags independent of the differential: valid verdicts with a mutation that should never pass.
      const forbidden = tags.some(t =>
        /^(e:(tx|network|payerOther|payerNum|amount|amountSettle|asset|payTo|scheme|url|method|paymentId|body|offerPayer|offerNet|offerTx)$|sse:(reorder|insert|drop|dup|trailerCount|trailerDigest|after|noTrailer|multiTrailer)$|stale-sig|d:(tamper|root|issuer)|s:(drop-ed|drop-pq|dup|unknownAlg|five|kidEmpty))/.test(
          t,
        ),
      );
      if ((a.valid || b.valid) && forbidden) {
        // Some sse mutations are no-ops (e.g. reorder of identical frames); record for triage.
        (summary as any).redFlags = ((summary as any).redFlags ?? 0) + 1;
        diffs.push({
          case: i,
          redFlag: true,
          tags,
          ref: { valid: a.valid, levels: a.levels, codes: a.reasons?.map((r: any) => r.code) },
          pkg: { valid: b.valid, levels: b.levels, codes: b.reasons?.map((r: any) => r.code) },
        });
      }
    }
    writeFileSync(
      OUT,
      JSON.stringify(
        {
          seed: process.env.RT_SEED ?? 402,
          cases: N,
          streamCases,
          summary,
          differential: diffs.filter(d => !d.redFlag).length,
          redFlags: diffs.filter(d => d.redFlag).length,
          diffs,
        },
        null,
        1,
      ),
    );
    console.log(
      `### cases=${N} stream=${streamCases} summary=${JSON.stringify(summary)} differential=${diffs.filter(d => !d.redFlag).length} redFlags=${diffs.filter(d => d.redFlag).length}`,
    );
    expect(N).toBeGreaterThan(0);
  },
  1_800_000,
);
