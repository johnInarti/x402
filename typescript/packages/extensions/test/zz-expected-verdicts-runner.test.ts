/**
 * Runs the A.7 `expectedVerdicts` convention against the TypeScript reference:
 * first the 14 runs published in the vectors file (control), then a proposed file overlaid on it.
 * Reports, never asserts: the output JSON is the result.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { it } from "vitest";
import {
  resolveDeliveryReceipt,
  verifyDeliveryReceipt,
  verifySseDelivery,
} from "../src/delivery-receipt";

const UPSTREAM = process.env.DR_VECTORS!;
const PROPOSED = process.env.DR_PROPOSED!;
const OUT = process.env.DR_OUT!;

const LEVELS = ["integrity", "authentic", "trusted", "settlement", "delivery"] as const;
type Lv = "pass" | "fail" | "not-evaluated";

function pointer(doc: unknown, ptr: string): unknown {
  let cur: any = doc;
  for (const raw of ptr.split("/").slice(1)) {
    const k = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (cur === null || typeof cur !== "object" || !(k in cur)) {
      throw new Error(`unresolved pointer ${ptr} at ${k}`);
    }
    cur = cur[k];
  }
  return cur;
}

function deref(doc: unknown, v: unknown): unknown {
  if (v && typeof v === "object" && !Array.isArray(v)) {
    const keys = Object.keys(v as object);
    if (keys.length === 1 && keys[0] === "$ref") return pointer(doc, (v as any).$ref);
  }
  return v;
}

const lv = (x: boolean | null | undefined): Lv =>
  x === true ? "pass" : x === false ? "fail" : "not-evaluated";

async function runOne(doc: any, run: any) {
  const inp: Record<string, any> = {};
  for (const [k, v] of Object.entries(run.inputs)) inp[k] = deref(doc, v);
  const gk = inp.pinnedGovernanceKeys;
  const expected: any = {
    settle: inp.settle,
    requirements: inp.requirements,
    resourceUrl: inp.resourceUrl,
    method: inp.method,
  };
  if (typeof inp.responseBody === "string") {
    expected.responseBody = new TextEncoder().encode(inp.responseBody);
  }
  if (typeof inp.responseStatus === "number") expected.responseStatus = inp.responseStatus;
  const opts: any = {
    directory: inp.directory,
    directoryTrust: gk ? { pinnedGovernanceKeys: [gk.ed25519, gk["ml-dsa-65"]] } : undefined,
    path: run.path,
    now: inp.now,
    offline: run.offline === true,
    expected,
  };
  const serve = (async () =>
    typeof inp.receiptDocument === "string"
      ? new Response(inp.receiptDocument)
      : new Response("", { status: 404 })) as unknown as typeof fetch;

  let res: any;
  let threw: string | null = null;
  try {
    if (typeof inp.eventStream === "string") {
      res = await verifySseDelivery(inp.eventStream, opts, serve);
    } else if (inp.reference) {
      let receipt: unknown;
      try {
        receipt = await resolveDeliveryReceipt(inp.reference, serve, [
          new URL(inp.resourceUrl).origin,
        ]);
      } catch (e) {
        threw = `resolve: ${(e as Error).message}`;
      }
      if (!threw) res = await verifyDeliveryReceipt(receipt, opts);
    } else {
      res = await verifyDeliveryReceipt(inp.receipt, opts);
    }
  } catch (e) {
    threw = `verify: ${(e as Error).message}`;
  }

  const got: any = threw
    ? {
        path: run.path,
        levels: {
          integrity: "fail",
          authentic: "not-evaluated",
          trusted: "not-evaluated",
          settlement: "not-evaluated",
          delivery: "not-evaluated",
        },
        valid: false,
        longTermEvidence: false,
        reasons: [{ level: "integrity", code: threw }],
        unverifiedAlgorithms: [],
      }
    : {
        path: res.path,
        levels: Object.fromEntries(LEVELS.map(l => [l, lv(res.levels[l])])),
        valid: res.valid,
        longTermEvidence: res.longTermEvidence,
        reasons: res.reasons,
        unverifiedAlgorithms: res.unverifiedAlgorithms,
      };
  const firstBad = LEVELS.find(l => got.levels[l] !== "pass") ?? null;
  const expFirstBad = run.reason ? run.reason.level : null;
  const levelDiff = LEVELS.filter(l => got.levels[l] !== run.levels[l]).map(
    l => `${l}: expected ${run.levels[l]}, got ${got.levels[l]}`,
  );
  const codes = (got.reasons ?? []).map((r: any) => `${r.level}:${r.code}`);
  const codeCompared =
    run.reason &&
    ["KEY_DIRECTORY_DIGEST_MISMATCH", "DELIVERY_UNCONFIRMED"].includes(run.reason.code);
  const codeOk = !codeCompared || codes.includes(`${run.reason.level}:${run.reason.code}`);
  const decisive =
    got.path === run.path &&
    got.valid === run.valid &&
    got.longTermEvidence === run.longTermEvidence &&
    firstBad === expFirstBad &&
    codeOk;
  return {
    id: run.id,
    path: run.path,
    strict: decisive && levelDiff.length === 0,
    decisive,
    expected: {
      valid: run.valid,
      longTermEvidence: run.longTermEvidence,
      reason: run.reason,
      levels: run.levels,
    },
    got: {
      valid: got.valid,
      longTermEvidence: got.longTermEvidence,
      firstNonPassingLevel: firstBad,
      levels: got.levels,
      reasons: codes,
      unverifiedAlgorithms: got.unverifiedAlgorithms,
    },
    levelDiff,
    codeCompared: !!codeCompared,
    codeOk,
  };
}

it("runs expectedVerdicts (control + proposed) through the reference", async () => {
  const upstream = JSON.parse(readFileSync(UPSTREAM, "utf8"));
  const proposed = JSON.parse(readFileSync(PROPOSED, "utf8"));
  const control = [];
  for (const run of upstream.expectedVerdicts) control.push(await runOne(upstream, run));
  const merged = { ...upstream, fixtures: proposed.fixtures };
  const prop = [];
  for (const run of proposed.expectedVerdicts) prop.push(await runOne(merged, run));
  const tally = (a: any[]) => ({
    runs: a.length,
    strict: a.filter(x => x.strict).length,
    decisive: a.filter(x => x.decisive).length,
  });
  const out = { control: tally(control), proposed: tally(prop), controlRuns: control, proposedRuns: prop };
  writeFileSync(OUT, JSON.stringify(out, null, 2));
  console.log(JSON.stringify({ control: out.control, proposed: out.proposed }));
}, 120000);
