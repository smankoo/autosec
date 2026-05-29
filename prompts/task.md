# Task

Bump **{{package}}** from `{{current}}` to `{{fixed}}` in this repository, and fix any breaking-change fallout so that the test suite passes.

## Vulnerability

- Severity: {{severity}}
- Title: {{title}}
- Advisory: {{advisoryUrl}}
- Major version bump: {{isMajorBump}}

## Test command

```
{{testCommand}}
```

If this is empty, stop immediately and emit `status: failed` with note `no test command — refusing to operate without a test suite to verify the change`.

## Call sites in this repo

These are the files that import `{{package}}`. Focus your edits here.

```
{{callSites}}
```

## Upstream changelog ({{changelogSource}}, {{changelogNotes}})

{{changelogText}}

## Procedure

1. Update `package.json` to require `{{fixed}}` (or `^{{fixed}}` matching existing style).
2. Run `npm install` to refresh the lockfile.
3. Run the test command. If green, you're done — emit the summary block.
4. If red, read the failure output, consult the changelog, edit the offending call sites, and run tests again.
5. Repeat at most {{maxIters}} times.

Begin.
