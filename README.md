# RedPen Eval

RedPen Eval measures how well an AI code reviewer finds real security bugs. It shows a reviewer the vulnerable version of a code window taken from a published CVE fix, then the patched version of the same window, and has a judge grade both free-text reviews. A reviewer earns credit when it names the right vulnerability class at the right lines on the vulnerable code and does not report that same vulnerability again on the patched code. The ground truth comes from the cve-variant-sweep corpus, where every case is a semgrep rule verified to fire on the vulnerable commit and stay silent on its fix, so no human labeling is involved. I built it because teams ship LLM reviewers without checking whether they catch anything, and generic evals use synthetic bugs or hand labels.

The CLI is `redpen`, with three commands: `build-dataset` builds a versioned dataset from the corpus, `run` sends cases to a reviewer and a judge, and `report` prints a leaderboard and can write an HTML version with per-case drill-down. A mock reviewer and a mock judge let the whole pipeline run offline.

## Install

Python 3.10 or newer.

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
```

This installs semgrep 1.177.x as a dependency. The tests run offline with `pytest`.

## Offline quickstart

```sh
redpen run --reviewer mock --judge mock --cases all --results-dir /tmp/redpen-demo
redpen report --results-dir /tmp/redpen-demo --html /tmp/redpen-demo/report.html
```

The first command runs all 25 cases against the mock reviewer and mock judge defined in `reviewers.yaml` and writes a run directory under `/tmp/redpen-demo`. The second prints the terminal leaderboard and writes a single-file HTML leaderboard you can open in a browser. Click a case to see the review text next to the judge verdict.

`--cases` takes `all`, a guard class such as `auth-check`, or a comma-separated list of case ids. Short ids work too, so `--cases j3hg,23vg` runs two cases.

## Real reviewers and the judge

Reviewers and judges are configured in `reviewers.yaml`. The `openai_compat` adapter talks to any OpenAI-compatible chat completions endpoint and takes `base_url`, `model`, and `api_key_env`, the name of the environment variable that holds the key. Keys are read from the environment and never written to disk. The checked-in file runs everything through [aimlapi.com](https://aimlapi.com): Grok 4.7 as `reviewer-a`, Gemini 3.1 Pro as `reviewer-b`, and Claude Sonnet 5.5 as the `llm` judge, all on one key. aimlapi rejects a `seed` below 1, and its proxy sometimes drops a response that takes several minutes; `--resume` retries those cases. Export the key, then:

```sh
export AIMLAPI_API_KEY=...
redpen run --reviewer reviewer-a --judge llm --cases all
redpen run --reviewer reviewer-b --judge llm --cases all
redpen report
```

Results go to `results/` by default. A run that stops partway can be continued with `--resume RUN_ID`, which also retries cases that ended in a reviewer error. `report --markdown PATH` writes the leaderboard as a Markdown table, and `report --runs ID[,ID...]` restricts it to specific runs.

## Dataset

`dataset/v1` holds 25 cases built from cve-variant-sweep at commit `c5bd9ad`. By ecosystem there are 15 Go cases, 6 npm cases (5 TypeScript, 1 JavaScript), and 4 pip cases. By guard class:

| Guard class | Cases |
| --- | --- |
| input-validation | 6 |
| auth-check | 5 |
| allowlist-denylist | 4 |
| escaping-encoding | 4 |
| type-range-check | 3 |
| size-cap | 2 |
| symlink-toctou-check | 1 |

Each case has a vulnerable window and a fixed window of the sink file. The expected spans, which define "the right spot", are the semgrep match spans plus the lines the fix changed. When a target line sits inside a function or class, the window is exactly that construct with no added context lines; context lines tended to cut into neighboring declarations and break parsing. A target outside any construct gets 3 lines of context on each side. The fixed window is cut the same way from the corresponding lines of the patched file.

Every case then has to pass a ground-truth sanity check on the committed window files: the rule fires on the vulnerable window, stays silent on the fixed window, and semgrep reports no errors on either. A parse error never counts as silent. If a trimmed window fails the check, both sides fall back to the whole sink file and the case is marked `whole_file`; if the whole file also fails, the build fails. In v1, 16 cases are trimmed and 9 are whole-file (23vg, c42q, g8cf, qfxx, v75v, w5f2, x34j, x586, xv7q). One case, pw5q, has an accepted semgrep parse warning caused by Go 1.26 syntax. It is the only entry in an explicit per-case allowlist in `redpen/dataset.py` and the warning is recorded in its `case.json`; any other parse warning fails the build.

`dataset/v1/manifest.json` records the corpus commit, each rule's sha256, the semgrep version, refs, window bounds, license, and a hash of the case set. Each case also records the CVE publish date and the fix commit date.

To rebuild, you need a local clone of cve-variant-sweep with no uncommitted changes under `rules/verified` or `evidence`, network access, and an authenticated `gh` CLI (it reads advisory and license metadata from the GitHub API, and upstream commits are fetched with git into a cache directory):

```sh
redpen build-dataset --sweep-dir /path/to/cve-variant-sweep --out dataset/v1 --force
```

The build is all or nothing. It attempts every case, lists each failure with its reason, and writes nothing if any case fails. It refuses to overwrite an existing directory without `--force`.

## Licensing

The window files are excerpts of upstream open-source projects and stay under those projects' licenses. Each window file starts with an attribution header naming the source repository, ref, and path, the date it was excerpted and modified, the SPDX license, and a copyright line. Each case records its license in `case.json`, and the upstream license texts are copied verbatim under `dataset/v1/licenses/`. Two cases, j3hg (nginx-ui) and xv7q (vikunja), are excerpts of AGPL-3.0 projects, and their window headers carry a notice that the excerpt is released under the GNU Affero General Public License v3.0. RedPen's own code is a separate work from the dataset excerpts.

## Metrics

Each case is scored on both sides. On the vulnerable side, the judge reads the review and reports whether it named the right vulnerability class and which lines it cited; code then decides the verdict. HIT means the class matches and a cited line or narrow range falls within 5 lines of an expected span. A range wider than 11 lines never counts as located, so citing a whole function earns no location credit. PARTIAL means the class matches without a located citation. Anything else is a MISS. On the fixed side, the question is only whether the review reported the patched vulnerability again. Other findings on the fixed code do not count against the reviewer, because nearly every reviewer lists something and counting all of them would put every reviewer near a 100% false-positive rate.

The headline number is the pair score (formula `pair-v1`). Per case, the vulnerable side earns 1 for a HIT, 0.5 for a PARTIAL, and 0 for a MISS, and that credit is kept only if the fixed side is clean. The pair score is the average over cases where both sides were scored, with a case-level bootstrap 95% interval. Recall (HIT count over vulnerable-side cases) and false-positive rate (re-reported count over scored fixed sides) are shown separately with Wilson 95% intervals. Per-guard-class recall is shown as k/n.

Empty output and refusals count against the reviewer: a MISS on the vulnerable side, never a clean fixed side, and zero pair credit. Infrastructure failures are kept out of the metrics. A transport or configuration failure is a reviewer error and malformed judge output (after one repair retry) is a judge error; both are excluded and shown as counts beside each metric's n. A run with any reviewer error is listed below the ranked rows as `UNRANKED`.

`report` refuses to put runs on the same leaderboard when they differ in dataset version, case set, review prompt, judge prompt, judge configuration, or scoring settings. It exits 2 and names the field that differs, so every row on one leaderboard was measured the same way.

## Caveats

The judge is an LLM grading free text, and a reviewer can address text to the grader to push its verdict. The judge prompts delimit the review and tell the judge to ignore instructions inside it, but the backstop is a human hand-check of a sample of verdicts (`redpen report --worksheet PATH`), and results are not published until that is signed off.

The reviewer never sees the harness's ground truth: no rule text, advisory or CVE id, vulnerability description, repository name, or attribution header goes into a reviewer request. The upstream source is not redacted, though, so project names, import paths, and other identifiers in the code itself can hint at which project and which advisory a window came from.

Windows are cut around the known vulnerability. A reviewer looking at one function that contains the bug has a much easier job than one reviewing a whole repository, so recall here is an upper bound on what the same reviewer would find in a full-file or full-repo review.

On some cases the expected spans cover most of the window, so nearly any cited line is "located" and a HIT is effectively a class match. Cases where 80% or more of the vulnerable window's code lines would count as located: 2cvf, 47c3, 637c, 685w, 74vm, cv23, fmxq, p7v4, pw5q. Each case's `location_selectivity` is in its `case.json`.

These are public CVEs. Each case records the CVE publish date and the fix commit date, and a model whose training cutoff falls after them may have seen the advisory or the fix. Treat results for such models as upper bounds.

Some cases share a sink file. kin-openapi's `req_resp_decoder.go` serves 74vm, g8cf, and vrcc, and tinacms has three cases (c42q, pwhx, x34j), so results on those cases are correlated and the effective number of independent cases is smaller than 25.

Per-class n is small: one guard class has a single case and two have two or three. Read per-class recall as a rough signal, not a ranking.

## 5-minute demo script

1. "Every company is letting AI review code. Nobody measures whether the reviewer catches real bugs." (30s)
2. Run a live reviewer on two cases. A full run is 50 reviewer calls plus 50 judge calls and does not fit in a minute, so the live step uses a short subset: `redpen run --reviewer reviewer-a --judge llm --cases j3hg,23vg`. While it runs, explain that the reviewer sees only the numbered code and a fixed prompt, never the rule, the advisory, or the project name from case metadata. (1 min)
3. `redpen report --results-dir results/sample` shows the full leaderboard from the committed sample runs: pair score, recall and false-positive rate with intervals, recall per guard class, and the HTML drill-down from a HIT to the review text. (2 min)
4. "The dataset comes from my CVE variant-sweep pipeline, 25 cases today, versioned, so scores stay comparable as it grows." (1 min)
5. Close: "I built the eval because I kept seeing 'eval harness' in job postings and wanted to show, not tell." (30s)

## Results

Results pending judge hand-check sign-off.
