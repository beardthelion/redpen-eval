# RedPen Eval — SPEC

## One-liner
An open-source eval harness that grades AI code reviewers against real, known vulnerabilities. Feed a reviewer vulnerable code, check whether it catches the bug, score it. Ground truth comes from verified CVE variant-sweep rules, not human labels.

## Why this one
Job postings keep asking for eval harnesses because every team shipping LLM features needs to measure them. Most candidates demo generic chat evals. This is security-grounded, has proprietary ground truth (the sweep corpus, growing daily), and demos live in an interview in under five minutes. It also compounds: every sweep run grows the dataset.

## How it works
1. **Dataset builder** (`redpen build-dataset`): reads `rules/verified/*.yaml` + `evidence/<ghsa>/` from the cve-variant-sweep repo. Each case = {case_id, ecosystem, guard_class, cve, vuln_code, fixed_code, rule_path}. `vuln_code` is the sink file at the vulnerable ref (trimmed to the relevant function/file window); `fixed_code` is the same window at the fixed ref. Dataset is versioned (`dataset/v1/`, manifest.json with rule SHAs) so scores stay comparable as the corpus grows.
2. **Runner** (`redpen run --reviewer <name> --cases <all|guard-class|ids>`): presents `vuln_code` to the reviewer behind a fixed review prompt ("Review this code for security vulnerabilities. List each finding with file, line, and vulnerability class."). Collects the raw review text. Reviewer adapters are a small interface (`review(code) -> str`); ship with an OpenAI-compatible API adapter and a mock adapter for tests. Any model plugs in.
3. **Scorer**: two layers.
   - *Ground-truth sanity*: the case's semgrep rule must fire on `vuln_code` and stay silent on `fixed_code` (re-verified at dataset build time).
   - *LLM-as-judge*: a fixed judge prompt scores the review — did it name the right vulnerability class at the right location? Verdicts: HIT (right class, right spot), PARTIAL (right class, wrong spot / vague), MISS. Then the same reviewer is run against `fixed_code`: any finding there = FALSE POSITIVE.
4. **Reporter** (`redpen report`): terminal table + static HTML leaderboard. Metrics per reviewer: detection rate (recall) overall and per guard class (auth-check, input-validation, allowlist-denylist, escaping-encoding, type-range-check, ...), false-positive rate, and a blended score. Leaderboard ranks reviewers; per-case drill-down shows the review text vs. the judge verdict.

## MVP scope (v1)
- CLI with `build-dataset`, `run`, `report`.
- Dataset builder over the existing 25-rule corpus (go + pip ecosystems).
- Two reviewer adapters: OpenAI-compatible endpoint (configurable base URL/key) and mock.
- LLM-as-judge scorer with HIT/PARTIAL/MISS + false-positive check on fixed code.
- Terminal table + single-file HTML leaderboard.
- README with a 5-minute demo script (see below) and a results table from at least 2 reviewers.

## Non-goals for v1
- Not a SAST tool and not a fuzzer; semgrep is ground truth, not the product.
- No auto-fix, no IDE plugin, no hosted service.
- No training/fine-tuning of reviewers.

## Repo layout
```
redpen-eval/
  redpen/
    dataset.py     # build-dataset: sweep rules -> versioned cases
    reviewers/     # adapter interface + openai_compat.py + mock.py
    prompts.py     # fixed review prompt + fixed judge prompt (versioned)
    scorer.py      # HIT/PARTIAL/MISS + false-positive check
    report.py      # terminal table + HTML leaderboard
    cli.py
  dataset/v1/      # built cases + manifest.json (committed)
  results/         # per-run JSON (gitignored except a sample)
  tests/
```

## Interview demo script (5 min)
1. "Every company is letting AI review code. Nobody measures whether the reviewer catches real bugs." (30s)
2. `redpen run --reviewer gpt-x --cases all` — show it reviewing 25 real CVE-derived cases. (1 min)
3. `redpen report` — leaderboard: detection rate per vulnerability class, false positives on fixed code. (2 min)
4. "The dataset grows daily from my CVE variant-sweep pipeline — 25 cases today, versioned, so scores stay comparable." (1 min)
5. Close: "I built the eval because I kept seeing 'eval harness' in postings and wanted to show, not tell." (30s)

## Resume bullets this enables
- "Built RedPen Eval, an open-source harness scoring AI code reviewers against 25+ CVE-derived vulnerability cases; measures detection rate per bug class and false-positive rate on patched code."
- "Curated a versioned security eval dataset from a daily CVE variant-sweep pipeline (Semgrep rules verified against vulnerable/fixed refs)."
- "Implemented LLM-as-judge scoring with fixed rubrics (HIT/PARTIAL/MISS) and deterministic ground-truth checks."

## Build order for the coding agent
1. `dataset.py` + manifest; verify all 25 cases build (rule fires on vuln, silent on fixed).
2. Reviewer interface + mock adapter; `run` end-to-end on mock.
3. Judge prompt + `scorer.py`; hand-verify 5 cases before trusting it.
4. `report.py` terminal table, then HTML.
5. OpenAI-compatible adapter; run 2 real reviewers; commit sample results + README.
