# seed-cases.json

48 verified CVE-variant-sweep cases, one per verified semgrep rule. Regenerated 2026-10-22
from the local sweep workspace (`~/workspace/bounty/cve-variant-sweep`); the original 25-case
seed was generated 2026-10-19 (backup: `seed-cases.json.bak-2026-10-19`). The regen script is
`regen_seed.py` in this directory, and it validates by reproducing the original 25 cases exactly
before writing. Rule SHAs from `rules/verified/*.yaml`, vuln/fixed refs from
`evidence/<ghsa>/vuln-run.json` and `fixed-run.json`, repo URL from the intake advisory records,
sink file path recovered from the verification checkout paths.

Fields per case:
- `case_id` — GHSA id, matches `rules/verified/<case_id>.yaml`
- `ecosystem` — go, npm, or pip
- `cve` — CVE id
- `repo_url` — upstream repo to clone
- `vuln_ref` / `fixed_ref` — commit SHAs; check out each, extract `sink_file` for the case code
- `sink_file` — path relative to repo root where the rule fired (the vulnerable window)

`guard_class` lives in the rule YAML metadata (`metadata.guard_class`). The dataset builder
(`redpen build-dataset` per SPEC.md) joins this seed with the rules to produce `dataset/v1/`
cases with extracted `vuln_code` / `fixed_code` windows.
