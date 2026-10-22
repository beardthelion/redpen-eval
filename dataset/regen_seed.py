#!/usr/bin/env python3
"""Regenerate redpen-eval seed-cases.json from the verified sweep rule corpus.
Derivation (AGENTS.md 2026-10-19):
- case_id/cve/ecosystem from rules/verified/<ghsa>.yaml metadata
- vuln_ref/fixed_ref from evidence/<ghsa>/{vuln,fixed}-run.json
- repo_url from intake/advisories-*.json records
- sink_file: strip /tmp/sweep-checkouts-<rand>/ or /tmp/sweep-co/ + <GHSA>-vuln/
  from evidence vuln-run sink_matched_paths (lowercase GHSA suffixes allowed)
"""
import json, glob, re, sys, yaml

SWEEP = "/home/hatch/workspace/bounty/cve-variant-sweep"

def load_intake_repos():
    repos = {}
    for fn in sorted(glob.glob(f"{SWEEP}/intake/advisories-*.json")):
        try:
            data = json.load(open(fn))
        except Exception:
            continue
        for rec in data.get("records", []) or []:
            gid = rec.get("ghsa_id")
            if gid and rec.get("repo_url"):
                repos[gid] = rec["repo_url"]
    return repos

def sink_file_from(ghsa):
    v = json.load(open(f"{SWEEP}/evidence/{ghsa}/vuln-run.json"))
    paths = v.get("sink_matched_paths", [])
    if not paths:
        raise ValueError(f"{ghsa}: no sink_matched_paths in vuln-run.json")
    p = paths[0]
    m = re.match(r"^/tmp/(?:sweep-checkouts-[A-Za-z0-9_]+|sweep-co)/GHSA-[A-Za-z0-9-]+-vuln/(.+)$", p)
    if not m:
        raise ValueError(f"{ghsa}: unparseable sink path: {p}")
    return m.group(1)

def build_case(ghsa, repos):
    rule = yaml.safe_load(open(f"{SWEEP}/rules/verified/{ghsa}.yaml"))
    md = rule["rules"][0]["metadata"]
    vuln = json.load(open(f"{SWEEP}/evidence/{ghsa}/vuln-run.json"))
    fixed = json.load(open(f"{SWEEP}/evidence/{ghsa}/fixed-run.json"))
    if ghsa not in repos:
        raise ValueError(f"{ghsa}: repo_url not found in intake records")
    return {
        "case_id": ghsa,
        "ecosystem": md["ecosystem"],
        "cve": md["cve"],
        "repo_url": repos[ghsa],
        "vuln_ref": vuln["ref"],
        "fixed_ref": fixed["ref"],
        "sink_file": sink_file_from(ghsa),
    }

def main():
    repos = load_intake_repos()
    rule_files = sorted(glob.glob(f"{SWEEP}/rules/verified/*.yaml"))
    cases, errors = [], []
    for fn in rule_files:
        ghsa = fn.split("/")[-1].replace(".yaml", "")
        try:
            cases.append(build_case(ghsa, repos))
        except Exception as e:
            errors.append(str(e))
    # validate against existing seed: originals must reproduce exactly
    old = {c["case_id"]: c for c in json.load(open(f"{sys.argv[1]}/seed-cases.json"))} if len(sys.argv) > 1 else {}
    new = {c["case_id"]: c for c in cases}
    mismatches = [gid for gid in old if old[gid] != new.get(gid)]
    print(f"rules: {len(rule_files)}, cases built: {len(cases)}, errors: {len(errors)}")
    for e in errors: print("ERROR:", e)
    print(f"old seed cases: {len(old)}, reproduced exactly: {len(old) - len(mismatches)}, mismatches: {mismatches}")
    added = sorted(set(new) - set(old))
    print(f"new cases added: {len(added)}: {added}")
    if mismatches or errors:
        print("ABORT: mismatches or errors, not writing")
        sys.exit(1)
    out = sorted(cases, key=lambda c: c["case_id"])
    if "--write" in sys.argv:
        import shutil, datetime
        ds = sys.argv[1]
        shutil.copy(f"{ds}/seed-cases.json", f"{ds}/seed-cases.json.bak-2026-10-19")
        json.dump(out, open(f"{ds}/seed-cases.json", "w"), indent=1)
        open(f"{ds}/seed-cases.json", "a").write("\n")
        print(f"WROTE {len(out)} cases to {ds}/seed-cases.json (backup: seed-cases.json.bak-2026-10-19)")

main()
