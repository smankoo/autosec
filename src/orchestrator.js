import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

import { scan } from './scan.js';
import { triage } from './triage.js';
import { gatherContext } from './context.js';
import { runAgent } from './agent.js';
import { verify } from './verify.js';
import { openPR } from './pr.js';

const exec = promisify(execFile);

export async function run({ repoUrl, dryRun, maxIters, branchBase, target: targetPkg, push = true }) {
  const runId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const root = path.join(os.tmpdir(), 'autosec-runs', runId);
  await mkdir(root, { recursive: true });
  const repoDir = path.join(root, 'repo');

  log('clone', { repoUrl, repoDir });
  await exec('git', ['clone', '--depth', '50', repoUrl, repoDir]);
  await configurePushAuth(repoDir);
  await exec('git', ['config', 'user.name', process.env.GIT_AUTHOR_NAME || 'AutoSec Bot'], { cwd: repoDir });
  await exec('git', ['config', 'user.email', process.env.GIT_AUTHOR_EMAIL || 'autosec@example.invalid'], { cwd: repoDir });

  log('npm-install');
  const npmArgs = ['install', '--no-audit', '--no-fund'];
  if (process.env.AUTOSEC_NPM_REGISTRY) npmArgs.push(`--registry=${process.env.AUTOSEC_NPM_REGISTRY}`);
  await exec('npm', npmArgs, { cwd: repoDir, maxBuffer: 50 * 1024 * 1024 });

  log('scan');
  const vulns = await scan(repoDir);
  log('scan.result', { count: vulns.length });

  let target;
  if (targetPkg) {
    target = vulns.find((v) => v.package === targetPkg);
    if (!target) {
      return { runId, status: 'no-op', reason: `target ${targetPkg} not in scan results`, vulnsFound: vulns.length };
    }
  } else {
    target = await triage(vulns, { repoDir });
  }
  if (!target) {
    return { runId, status: 'no-op', reason: 'no actionable vuln', vulnsFound: vulns.length };
  }
  log('target', target);

  log('context');
  const ctx = await gatherContext(target, repoDir);
  log('context.result', {
    callSites: ctx.callSites.length,
    changelogSource: ctx.changelog.source,
    changelogChars: ctx.changelog.text.length,
    testCommand: ctx.testCommand,
  });

  if (!ctx.testCommand) {
    return { runId, status: 'failed', reason: 'no test command in repo', target };
  }

  if (dryRun) {
    return { runId, status: 'dry-run', target, ctxSummary: summarizeCtx(ctx) };
  }

  log('agent.start');
  const { transcript, summary } = await runAgent({ repoDir, vuln: target, ctx, maxIters });
  log('agent.done', { status: summary.status });

  log('verify');
  const testResult = await verify(repoDir);
  log('verify.result', { pass: testResult.pass });

  const draft = !testResult.pass || summary.status !== 'success';
  log('pr.open', { draft, push });
  const pr = await openPR({
    repoDir,
    vuln: target,
    ctx,
    summary,
    testResult,
    branchBase,
    draft,
    push,
  });

  return {
    runId,
    status: push ? (testResult.pass ? 'pr-opened' : 'pr-opened-draft') : 'committed-local',
    target,
    pr,
    summary,
    workspace: repoDir,
  };
}

async function configurePushAuth(repoDir) {
  // If a GitHub token is available (env or `gh auth token`), embed it in the remote URL
  // so `git push` works headlessly without relying on the user's keychain helper.
  let token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  if (!token) {
    try {
      const { stdout } = await exec('gh', ['auth', 'token']);
      token = stdout.trim();
    } catch {}
  }
  if (!token) return;
  try {
    const { stdout } = await exec('git', ['remote', 'get-url', 'origin'], { cwd: repoDir });
    const url = stdout.trim();
    const m = url.match(/^https:\/\/(?:[^@]+@)?(github\.com\/.+?)(?:\.git)?$/);
    if (!m) return;
    const newUrl = `https://x-access-token:${token}@${m[1]}.git`;
    await exec('git', ['remote', 'set-url', 'origin', newUrl], { cwd: repoDir });
  } catch {}
}

function summarizeCtx(ctx) {
  return {
    callSites: ctx.callSites,
    testCommand: ctx.testCommand,
    changelog: { source: ctx.changelog.source, notes: ctx.changelog.notes, chars: ctx.changelog.text.length },
    repoMeta: ctx.repoMeta,
  };
}

function log(stage, data) {
  const ts = new Date().toISOString();
  if (data === undefined) console.error(`[autosec ${ts}] ${stage}`);
  else console.error(`[autosec ${ts}] ${stage} ${JSON.stringify(data)}`);
}
