/**
 * Runs every entry of `expectedVerdicts` in delivery-receipt.vectors.json through this
 * implementation and checks it under the conformance rule of the spec's Appendix A.7:
 *
 * - the same `path`, `valid` and `longTermEvidence`;
 * - the same value for every level listed in `levels`, which lists the levels up to and including
 *   the first one that did not pass (a later level is informative and is not compared);
 * - the same `reason.level`, and `reason.code` for the codes the spec defines.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import {
  resolveDeliveryReceipt,
  verifyDeliveryReceipt,
  verifySseDelivery,
  type ReceiptVerificationResult,
} from "../src/delivery-receipt";

const VECTORS = fileURLToPath(
  new URL("../../../../specs/extensions/delivery-receipt.vectors.json", import.meta.url),
);

const LEVELS = ["integrity", "authentic", "trusted", "settlement", "delivery"] as const;
type Level = (typeof LEVELS)[number];
type LevelResult = "pass" | "fail" | "not-evaluated";

/** Codes whose value A.7 compares; every other code in the file is a diagnostic. */
const SPEC_CODES = new Set(["KEY_DIRECTORY_DIGEST_MISMATCH", "DELIVERY_UNCONFIRMED"]);

interface Run {
  id: string;
  path: "session" | "archival";
  offline?: boolean;
  inputs: Record<string, unknown>;
  levels: Partial<Record<Level, LevelResult>>;
  valid: boolean;
  longTermEvidence: boolean;
  reason: { level: Level; code: string } | null;
}

/** A run's inputs after `$ref` resolution, by the roles A.7 names. */
interface RunInputs {
  receipt?: unknown;
  reference?: Parameters<typeof resolveDeliveryReceipt>[0];
  receiptDocument?: string;
  eventStream?: string;
  directory?: unknown;
  pinnedGovernanceKeys?: Record<string, string>;
  now?: number;
  settle?: unknown;
  requirements?: unknown;
  resourceUrl: string;
  method?: string;
  responseBody?: string;
  responseStatus?: number;
}

const file = JSON.parse(readFileSync(VECTORS, "utf8"));

/**
 * Resolves an RFC 6901 JSON Pointer against the vectors file.
 *
 * @param ptr - Pointer
 * @returns The value it names
 */
function pointer(ptr: string): unknown {
  let cur: unknown = file;
  for (const raw of ptr.split("/").slice(1)) {
    const key = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (cur === null || typeof cur !== "object" || !(key in cur)) {
      throw new Error(`unresolved pointer ${ptr}`);
    }
    cur = (cur as Record<string, unknown>)[key];
  }
  return cur;
}

/**
 * Replaces a `{ "$ref": ... }` value by what it points to; any other value is literal.
 *
 * @param v - Input value
 * @returns The resolved value
 */
function deref(v: unknown): unknown {
  if (v && typeof v === "object" && !Array.isArray(v)) {
    const keys = Object.keys(v);
    if (keys.length === 1 && keys[0] === "$ref") return pointer((v as { $ref: string }).$ref);
  }
  return v;
}

const asLevel = (x: boolean | null | undefined): LevelResult =>
  x === true ? "pass" : x === false ? "fail" : "not-evaluated";

/**
 * Gives the run's inputs to the verifier, by role, exactly as A.7 describes them.
 *
 * @param run - One entry of `expectedVerdicts`
 * @returns The verifier's result
 */
async function verify(run: Run): Promise<ReceiptVerificationResult> {
  const inp = Object.fromEntries(
    Object.entries(run.inputs).map(([k, v]) => [k, deref(v)]),
  ) as RunInputs;
  const expected: Record<string, unknown> = {
    settle: inp.settle,
    requirements: inp.requirements,
    resourceUrl: inp.resourceUrl,
    method: inp.method,
  };
  if (typeof inp.responseBody === "string") {
    expected.responseBody = new TextEncoder().encode(inp.responseBody);
  }
  if (typeof inp.responseStatus === "number") expected.responseStatus = inp.responseStatus;
  const gk = inp.pinnedGovernanceKeys;
  const options = {
    directory: inp.directory,
    directoryTrust: gk ? { pinnedGovernanceKeys: [gk.ed25519, gk["ml-dsa-65"]] } : undefined,
    path: run.path,
    now: inp.now,
    offline: run.offline === true,
    expected,
  } as Parameters<typeof verifyDeliveryReceipt>[1];
  // The only octets the verifier can fetch are the ones the run says were served at receiptUrl.
  const serve = (async () =>
    typeof inp.receiptDocument === "string"
      ? new Response(inp.receiptDocument)
      : new Response("", { status: 404 })) as unknown as typeof fetch;

  if (typeof inp.eventStream === "string")
    return verifySseDelivery(inp.eventStream, options, serve);
  if (inp.reference) {
    const receipt = await resolveDeliveryReceipt(inp.reference, serve, [
      new URL(inp.resourceUrl).origin,
    ]);
    return verifyDeliveryReceipt(receipt, options);
  }
  return verifyDeliveryReceipt(inp.receipt, options);
}

const runs: Run[] = file.expectedVerdicts;

describe("delivery-receipt: expectedVerdicts (Appendix A.7)", () => {
  it("lists every level up to and including the first that did not pass, and no later one", () => {
    for (const run of runs) {
      const listed = LEVELS.filter(l => l in run.levels);
      const first = LEVELS.find(l => run.levels[l] !== "pass");
      const want = first ? LEVELS.slice(0, LEVELS.indexOf(first) + 1) : [...LEVELS];
      expect(listed, run.id).toEqual(want);
      expect(run.reason?.level ?? null, run.id).toBe(first ?? null);
      expect(run.valid, run.id).toBe(run.reason === null);
    }
  });

  it("session path over a broken ml-dsa-65 entry: valid, and ml-dsa-65 reported as not checked (§6.1)", async () => {
    const run = runs.find(r => r.id === "splitVerdict/session");
    expect(run).toBeDefined();
    const res = await verify(run!);
    expect(res.valid).toBe(true);
    expect(res.longTermEvidence).toBe(false);
    expect(res.unverifiedAlgorithms).toContain("ml-dsa-65");
  });

  it.each(runs.map(r => [r.id, r] as const))("%s", async (_id, run) => {
    const res = await verify(run);
    expect(res.path).toBe(run.path);
    expect(res.valid).toBe(run.valid);
    expect(res.longTermEvidence).toBe(run.longTermEvidence);
    for (const level of Object.keys(run.levels) as Level[]) {
      expect([level, asLevel(res.levels[level])]).toEqual([level, run.levels[level]]);
    }
    if (run.reason) {
      expect(res.reasons.map(r => r.level)).toContain(run.reason.level);
      if (SPEC_CODES.has(run.reason.code)) {
        expect(res.reasons).toContainEqual(
          expect.objectContaining({ level: run.reason.level, code: run.reason.code }),
        );
      }
    }
  });
});
