# `expectedVerdicts` cross-run (Appendix A.7)

`../zz-expected-verdicts-runner.test.ts` runs the A.7 `expectedVerdicts` convention through the TypeScript
reference in this branch (`3cce288`, unmodified): first the 14 runs published in the vectors file (control), then a
proposed file overlaid on it. It reports and never asserts; `run-out.json` is the result.

Inputs used for `run-out.json`:

- vectors file from x402-foundation/x402#3783 at `e82f684`, sha256 `ad195d4c…`
- proposed negative vectors by Tetsurohhori, `aos-standard/catalog` at `036e9ab`, sha256 `e376c64b…` (7 fixtures, 11 runs)

Run:

```
cd typescript/packages/extensions
DR_VECTORS=<vectors.json> DR_PROPOSED=<proposed.json> DR_OUT=<out.json> \
  npx vitest run test/zz-expected-verdicts-runner.test.ts
```

Each run is reported twice:

- `decisive`: `path`, `valid`, `longTermEvidence`, the first non-passing level, and the reason code where the
  expected code is one the reference names (`KEY_DIRECTORY_DIGEST_MISMATCH`, `DELIVERY_UNCONFIRMED`).
- `strict`: `decisive` and the same value on all five levels.

Result: control 14 runs, all levels / `valid` / `reason.level` agree, but the reference does not emit
`DELIVERY_UNCONFIRMED` in the 4 runs that expect it. Proposed 11 runs: 11/11 decisive, 5/11 strict; the 6 differ only
on levels after the first non-passing one (the reference keeps evaluating).
