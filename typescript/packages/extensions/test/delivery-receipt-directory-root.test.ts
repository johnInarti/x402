/**
 * Appendix A.6: the §7.2 root of the Appendix B directory, and the digests of the common wrong projections
 * (each must differ from the root, so a verifier can diagnose its own mismatch).
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { computeDirectoryRoot } from "../src/delivery-receipt";

type Dir = Record<string, unknown> & {
  governanceKeys: Array<{ alg: string }>;
  keys: Array<{ kid: string }>;
};
const vectors = JSON.parse(
  readFileSync(
    join(__dirname, "../../../../specs/extensions/delivery-receipt.vectors.json"),
    "utf8",
  ),
) as { endToEnd: { directory: Dir } };
const dir = vectors.endToEnd.directory;

const jcs = (x: unknown): string =>
  x === null || typeof x !== "object"
    ? JSON.stringify(x)
    : Array.isArray(x)
      ? `[${x.map(jcs).join(",")}]`
      : `{${Object.keys(x as object)
          .sort()
          .map(k => `${JSON.stringify(k)}:${jcs((x as Record<string, unknown>)[k])}`)
          .join(",")}}`;
const sha = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

const ROOT = "40b0560cd3637678eef1ff13743dfbac97ed6f153dcabebc536e3bc5e1e9e4a6";
const seven = {
  spec: dir.spec,
  issuer: dir.issuer,
  epoch: dir.epoch,
  prevRoot: dir.prevRoot,
  publishedAt: dir.publishedAt,
  governanceKeys: [...dir.governanceKeys].sort((a, b) => (a.alg < b.alg ? -1 : 1)),
  keys: [...dir.keys].sort((a, b) => (a.kid < b.kid ? -1 : 1)),
};

describe("Appendix A.6 — key directory root worked example", () => {
  it("normative seven-member preimage: 5905 octets, root as published, reference implementation agrees", async () => {
    const pre = jcs(seven);
    expect(Buffer.byteLength(pre, "utf8")).toBe(5905);
    expect(sha(pre)).toBe(ROOT);
    expect(dir.root).toBe(ROOT);
    expect(await computeDirectoryRoot(dir as never)).toBe(ROOT);
  });

  it("each common wrong projection yields the digest listed in A.6, never the root", () => {
    const noSig = Object.fromEntries(Object.entries(dir).filter(([k]) => k !== "signatures"));
    const noRoot = Object.fromEntries(Object.entries(noSig).filter(([k]) => k !== "root"));
    const wrong: Record<string, string> = {
      d2b584052f3b4eba60f9623067c6fa899441121ad867985693462750bd231bc1: jcs(noSig),
      b781c6532561bae7fe3c855a33203c4c9b882cca53bde9b3fbb6aa2903aeb0c6: jcs(dir),
      d7b1a34dc2bc97c4f931023713137c381974d522bad7f5053de67f6ec7d9f412: jcs({
        ...noRoot,
        governanceKeys: [...seven.governanceKeys].reverse(),
        keys: [...seven.keys].reverse(),
      }),
      "0c5c80bc9a971aeb6b619e9e33e53c176b3bffd56a6b904864a117e5b9a54d89": jcs(
        Object.fromEntries(Object.entries(seven).filter(([k]) => k !== "publishedAt")),
      ),
      "23d5a755a17f2b9e1eda158a8c5de73168a11530a16106d0713579157278fbd1": JSON.stringify(seven),
    };
    for (const [digest, preimage] of Object.entries(wrong)) {
      expect(sha(preimage)).toBe(digest);
      expect(digest).not.toBe(ROOT);
    }
  });
});
