import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { autosecBranchName } from './triage.js';

const exec = promisify(execFile);

/**
 * Branch, commit, push, and open a PR. Returns { url, branch, draft }.
 */
export async function openPR({ repoDir, vuln, targets, ctx, contexts, summary, testResult, baselineResult, branchBase, draft, push = true, verdict }) {
  // Back-compat: single-vuln callers may pass {vuln} instead of {targets}.
  if (!targets) targets = vuln ? [vuln] : [];
  const isMulti = targets.length > 1;
  const branch = isMulti
    ? `autosec/multi-${targets.length}-${shortHash(targets.map((t) => t.package).join(','))}`
    : autosecBranchName(targets[0]);
  const title = isMulti
    ? `autosec: bump ${targets.length} dependencies (${highestSeverity(targets)})`
    : `autosec: bump ${targets[0].package} to ${targets[0].fixed} (${targets[0].severity})`;
  const body = renderBody({ targets, ctx, contexts, summary, testResult, baselineResult, verdict });

  await git(repoDir, ['checkout', '-B', branch]);
  await git(repoDir, ['add', '-A']);
  // No-op commit guard
  try {
    await git(repoDir, ['diff', '--cached', '--quiet']);
    return { url: null, branch, draft, note: 'no changes to commit' };
  } catch {
    // there are staged changes — proceed
  }
  await git(repoDir, ['commit', '-m', title]);

  if (!push) {
    const { stdout: diff } = await git(repoDir, ['diff', '--stat', `${branchBase}..HEAD`]);
    return {
      url: null,
      branch,
      draft,
      pushed: false,
      title,
      body,
      diffstat: diff.trim(),
      workspace: repoDir,
      note: 'push skipped (--no-push); branch committed locally',
    };
  }

  try {
    await git(repoDir, ['push', '-u', 'origin', branch, '--force-with-lease']);
  } catch (e) {
    const msg = `${e.message}\nstderr: ${e.stderr || ''}\nstdout: ${e.stdout || ''}`;
    throw new Error(`git push failed: ${msg}`);
  }

  const args = [
    'pr', 'create',
    '--title', title,
    '--body', body,
    '--base', branchBase,
    '--head', branch,
  ];
  if (draft) args.push('--draft');

  const { stdout } = await exec('gh', args, { cwd: repoDir });
  const url = (stdout.match(/https:\/\/\S+/) || [])[0] || null;

  if (draft) {
    try {
      await exec('gh', ['pr', 'edit', branch, '--add-label', 'autosec,needs-human'], { cwd: repoDir });
    } catch {}
  } else {
    try {
      await exec('gh', ['pr', 'edit', branch, '--add-label', 'autosec'], { cwd: repoDir });
    } catch {}
  }

  return { url, branch, draft };
}

async function git(cwd, args) {
  return exec('git', args, { cwd });
}

function highestSeverity(targets) {
  const order = ['critical', 'high', 'moderate', 'low', 'info'];
  for (const s of order) if (targets.some((t) => t.severity === s)) return s;
  return targets[0]?.severity || 'unknown';
}

function shortHash(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h) + s.charCodeAt(i) | 0;
  return Math.abs(h).toString(36).slice(0, 6);
}

function renderBody({ targets, ctx, contexts, summary, testResult, baselineResult, verdict }) {
  const tail = (testResult?.output || '').split('\n').slice(-60).join('\n');
  const baselinePassed = baselineResult?.pass ?? true;
  const verdictLabel = verdict?.label || (testResult?.pass ? 'pass' : (baselinePassed ? 'regression' : 'pre-existing-failure'));
  const verdictNote = {
    pass:                   'PASSED',
    regression:             'FAILED (regression introduced by these bumps)',
    'pre-existing-failure': 'FAILED (pre-existing failures — baseline also failing)',
    'environment-broken':   'FAILED (test environment broken — not caused by these bumps)',
  }[verdictLabel] || 'FAILED';
  const testNote = verdictNote;
  const meta = ctx?.repoMeta;
  const repoLink = meta ? `https://github.com/${meta.owner}/${meta.repo}` : null;
  const isMulti = targets.length > 1;
  const bumpHeader = isMulti
    ? [
        `## AutoSec dependency bumps (${targets.length})`,
        ``,
        ...targets.map((t) =>
          `- \`${t.package}\` \`${t.current || '?'}\` → \`${t.fixed}\` (${t.severity}${t.isMajorBump ? ', major' : ''})${t.advisoryUrl ? ` — [advisory](${t.advisoryUrl})` : ''}`
        ),
      ]
    : [
        `## AutoSec dependency bump`,
        ``,
        `- **Package:** \`${targets[0].package}\``,
        `- **Bump:** \`${targets[0].current || '?'}\` → \`${targets[0].fixed}\``,
        `- **Severity:** ${targets[0].severity}`,
        `- **Major version bump:** ${targets[0].isMajorBump ? 'yes' : 'no'}`,
        targets[0].advisoryUrl ? `- **Advisory:** ${targets[0].advisoryUrl}` : null,
      ];
  return [
    ...bumpHeader,
    repoLink ? `- **Upstream:** ${repoLink}` : null,
    ``,
    `### Migration notes (from agent)`,
    ``,
    summary?.migration_notes || '(none)',
    ``,
    `### Files touched`,
    ``,
    (summary?.files_touched || []).map((f) => `- \`${f}\``).join('\n') || '(see diff)',
    ``,
    `### Changelog sources`,
    ``,
    (contexts || [ctx]).filter(Boolean).map((c, i) =>
      `- \`${targets[i]?.package || '?'}\`: ${c.changelog.source} — ${c.changelog.notes}`
    ).join('\n'),
    ``,
    `### Test results`,
    ``,
    `- **Baseline (pre-fix):** ${baselinePassed ? 'PASSED' : 'FAILED'}`,
    `- **Post-fix:** ${testNote}`,
    verdict?.reason ? `- **Verdict reason:** ${verdict.reason}` : null,
    verdict?.hint ? `- **Hint:** ${verdict.hint}` : null,
    ``,
    `### Test output (tail)`,
    ``,
    '```',
    tail || '(no output captured)',
    '```',
    ``,
    `---`,
    `_Generated by AutoSec. Status: **${summary?.status || 'unknown'}**_`,
  ]
    .filter((x) => x !== null)
    .join('\n');
}
