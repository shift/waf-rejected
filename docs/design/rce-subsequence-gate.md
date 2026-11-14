# Ordered-subsequence gates for the RCE regex families

**Branch:** `perf/rce-gate` (base `02497de`)
**Status:** implemented behind the existing (default) `rust-engine` feature; no
configuration default, rule, or public contract changed.

## Problem

The literal prefilter (`rules/crs/prefilter.json`) proves a mandatory ≥2-byte
literal for 137 regex evaluations on a 4 KiB body. The RCE command families
`932125`, `932230`, `932235`, `932250`, `932260`, `932370` and `932380` have no
such literal: every letter of a command word may be separated by shell filler
(`c'1'a'2't`), so the regex has `c…a…t` as an **ordered subsequence**, not as a
substring. Those rules were therefore always evaluated and dominated the
residual regex time.

## Model

For one regex, `subsequence::extract` derives a prerequisite in
`OR(AND(OR(sequence)))` form:

* an **alternative** is one way the regex can match (one alternation branch);
* every **clause** of that alternative is mandatory (a concatenation);
* a **clause** is satisfied when one of its **sequences** occurs;
* a **sequence** is an ordered list of **steps**; a step is a 256-bit byte set
  plus an optional maximum gap.

This is exact for concatenation and alternation:

| regex construct | prerequisite |
|---|---|
| literal / class | one step |
| concatenation `AB` | concatenate clause lists (cross-product alternatives) |
| alternation `A\|B` | union of alternatives |
| `?`, `*`, `{0,n}` | nothing (a match may skip it) |
| `+`, `{m,n}` with `m ≥ 1` | one occurrence's requirement |
| `.`, anchors, `\b`, back-references, unknown atoms | nothing |

Two soundness-preserving reductions keep the structure small:

* if an alternative is a superset of another (more clauses), it is removed
  because the smaller one is easier to satisfy;
* if combining alternatives would exceed `MAX_ALTS` (8 192), one conjunct is
  dropped. Dropping a conjunct, truncating an OR, or ignoring an atom can only
  make the prerequisite weaker, never wrong. A rule with no remaining
  non-trivial requirement stays ungated.

The extractor refuses patterns that are not pure ASCII, contain `\x{...}`,
`\p{...}`/`\P{...}` or scoped inline flags, because Unicode case folding could
match bytes the ASCII fold does not. Spans whose character class is only partly
understood (POSIX classes, unknown escapes, ambiguous ranges) become opaque
atoms rather than guessed steps.

### Matching

`Sequence::matches` is a greedy ordered scan. A one-byte step uses `memchr`; a
class step uses the byte-set mask. `Step::max_gap` bounds the distance from the
previous match; the CRS filler uses unbounded `*` quantifiers, so the extracted
steps carry the unlimited gap, but the matcher enforces a finite bound when one
is present (unit-tested). Greedy leftmost matching is exact for subsequence
existence, including bounded gaps.

The engine builds one 256-bit **presence bitmap** per candidate value and shares
it across every subsequence rule. Values shorter than 256 bytes are not
subsequence-gated: their regexes are cheaper than walking the alternatives, and
leaving them ungated is sound.

## Integration

* `gate::attach` assigns subsequence gates to positive `@rx` rules in the RCE
  family (`932xxx`) that use no transforms and that the literal artifact did
  not already gate. Gate ids stay dense and rule order is untouched.
* `GateSet` keeps the literal Aho-Corasick groups and adds one
  `SubsequenceGroup` for the identity pipeline. Both feed the same cached
  `GateMask`, so `GateSet::allows`, the serial path and the
  `parallel-args` path are unchanged.
* A missing bit still means "the prerequisite was absent, skip the regex"; a
  candidate without a cache id still returns `None`, which means "run the
  regex". Values below the 256-byte threshold set **every** subsequence bit
  instead of leaving the mask empty: an empty mask means "absent" and would
  turn the size optimisation into a false negative (caught by the corpus and
  the filler-separated regression test).
* The Vectorscan candidate pass previously skipped every rule that had any
  gate. `GateSet::is_literal` now distinguishes literal gates, so the RCE rules
  keep the candidate pass as an independent second check.

## Soundness

The contract is one-sided: a gate may only skip when the regex provably cannot
match. Tests:

* exhaustive no-false-negative property over five representative patterns and
  every string up to length 4 from a 15-byte attack alphabet: whenever the real
  `regex` matches, the extracted requirement is satisfied;
* a filler-separated command (`ti''me sh -c whoami`) still blocks through the
  engine, while a benign value containing the same subsequence still allows;
* optional atoms are not required, alternation is a disjunction, and patterns
  without a provable requirement (`.*`, `\p{L}`, lookahead, optional-only) stay
  ungated;
* the 2,112-case corpus decision parity gate is unchanged.

## Measurements

Measured with the release `rust-engine-parity` binary (`--bench --reps 300`,
`taskset -c 2-5`) on the shared reference host while other agents were building,
so absolute values are directional. The baseline row is the same worktree with
this change stashed and rebuilt; both runs used the same load conditions.

| Body | Before p50 | After p50 | Before p99 | After p99 |
|---|---:|---:|---:|---:|
| bodyless | 135.2 µs | 135.5 µs | 180.3 µs | 178.0 µs |
| 1 KiB | 298.7 µs | 294.2 µs | 360.0 µs | 356.1 µs |
| 4 KiB | 603.7 µs | **573.5 µs** | 652.6 µs | 671.6 µs |
| 8 KiB | 1 006.9 µs | **943.2 µs** | 1 164.7 µs | 1 003.3 µs |

Targets: 4 KiB < 480 µs (missed, 573.5 µs) and 8 KiB < 850 µs (missed,
943.2 µs). The reduction is real but smaller than the target: the gate removes
~52 µs of 4 KiB regex time and adds ~16 µs of gate time, for a net ~30 µs
(5 %). The remaining gate cost is the existing literal pipeline (transforms
plus Aho-Corasick for the other gated rules), not the subsequence scan.

Regex evaluations at 4 KiB: **151 skipped / 131 evaluated**, versus **137
skipped / 145 evaluated** before (the corpus has 282 regex evaluations in
total). Per-category profile at 4 KiB:

| category | before | after |
|---|---:|---:|
| gate | 128.1 µs | 144.0 µs |
| regex/operator | 273.9 µs | 222.6 µs |
| transform | 92.9 µs | 94.4 µs |
| candidates | 23.7 µs | 23.6 µs |

The 4 KiB target would need roughly 90 µs of additional savings; the RCE
families only account for ~75 µs of regex time in total, so even a free gate
would not reach it on this host. The 8 KiB target needs ~87 µs and is similarly
out of reach with this workload.


## Limitations

* The cap-driven reduction chooses the cheaper conjunct, so e.g. `932230`
  gates on its command *prefix* alternatives rather than carrying the full
  prefix × command cross-product. That is sound but weaker than an exact
  candidate pass; the Vectorscan candidate pass covers the gap when enabled.
* Only the `932` family and only identity transform chains are analysed. Other
  families would need transform-aware extraction (a transformed literal is not
  a byte subsequence of the input).
* The model ignores case folding outside ASCII, as the engine compiles ASCII
  patterns with `(?-u)`.
