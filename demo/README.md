# Demo target picking

Goal: a small Node repo with (a) a real test suite that runs in <60s, (b) at least one vulnerable dependency where the fix requires a major version bump and produces real call-site changes.

## Picking a repo

Look for these traits:

- `package.json` has `"scripts": { "test": "..." }` that actually runs.
- `npm install && npm test` is green at HEAD.
- `npm audit` reports at least one vuln with `fixAvailable.isSemVerMajor: true`.
- Few enough call sites of the vulnerable package that the diff is reviewable (~1–10 files).

## Quick check script

```
git clone <url> /tmp/probe && cd /tmp/probe \
  && npm install --no-audit --no-fund \
  && npm test \
  && npm audit --json | jq '.vulnerabilities | to_entries[] | select(.value.fixAvailable.isSemVerMajor==true) | .key'
```

If that prints at least one package name, you have a candidate.

## Best demo: stoda's own repo

If the team brings their own repo with known CVEs, use that — real stakes make a much better demo. They will need to grant `gh` push access (or you fork and point at the fork).

## Fallback

Pre-stage a fork of a small Express + Jest app pinned to old `body-parser` / `lodash` / `minimist`. Commit the fork URL here on Friday morning before the team arrives.
