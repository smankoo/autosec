import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, rm, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import { scan } from './scan.js';
import { triage } from './triage.js';
import { gatherContext } from './context.js';
import { runAgent } from './agent.js';
import { verify } from './verify.js';
import { openPR } from './pr.js';

const exec = promisify(execFile);

export async function run({ repoUrl, dryRun, maxIters, branchBase, target: targetPkg, push = true, onLog }) {
  const runId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const root = path.join(os.tmpdir(), 'autosec-runs', runId);
  await mkdir(root, { recursive: true });
  const repoDir = path.join(root, 'repo');
  const log = makeLogger(onLog);

  const sshUrl = repoUrl.replace(/^https:\/\/github\.com\/(.+?)(?:\.git)?$/, 'git@github.com:$1.git');
  log('clone', { repoUrl: sshUrl, repoDir });
  await exec('git', ['clone', '--depth', '50', sshUrl, repoDir]);
  await configurePushAuth(repoDir);
  await exec('git', ['config', 'user.name', process.env.GIT_AUTHOR_NAME || 'AutoSec Bot'], { cwd: repoDir });
  await exec('git', ['config', 'user.email', process.env.GIT_AUTHOR_EMAIL || 'autosec@example.invalid'], { cwd: repoDir });

  log('npm-install');
  const npmArgs = ['install', '--no-audit', '--no-fund', `--cache=${path.join(root, 'npm-cache')}`];
  if (process.env.AUTOSEC_NPM_REGISTRY) npmArgs.push(`--registry=${process.env.AUTOSEC_NPM_REGISTRY}`);
  await exec('npm', npmArgs, { cwd: repoDir, maxBuffer: 50 * 1024 * 1024 });

  // Detect the required node version from installed node_modules, then reinstall
  // with the correct node if it differs from the current one so native bindings match.
  const nodeEnv = await resolveNodeEnv(repoDir, log);
  if (nodeEnv !== process.env) {
    const { rm: rmDir } = await import('node:fs/promises');
    await rmDir(path.join(repoDir, 'node_modules'), { recursive: true, force: true });
    await exec('npm', npmArgs, { cwd: repoDir, env: nodeEnv, maxBuffer: 50 * 1024 * 1024 });
  }

  log('scan');
  const vulns = await scan(repoDir);
  log('scan.result', {
    count: vulns.length,
    vulns: vulns.map((v) => ({
      package: v.package,
      severity: v.severity,
      current: v.current,
      fixed: v.fixed,
      isMajorBump: v.isMajorBump,
      title: v.title,
      advisoryUrl: v.advisoryUrl,
    })),
  });

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

  log('baseline');
  const baselineResult = await verify(repoDir, { env: nodeEnv });
  log('baseline.result', { pass: baselineResult.pass, output: baselineResult.output });

  if (dryRun) {
    return { runId, status: 'dry-run', target, ctxSummary: summarizeCtx(ctx), baseline: baselineResult };
  }

  log('agent.start');
  const { transcript, summary } = await runAgent({
    repoDir,
    vuln: target,
    ctx,
    maxIters,
    onChunk: onLog
      ? ({ stream, text }) => onLog({ ts: new Date().toISOString(), stage: 'agent.chunk', data: { stream, text } })
      : undefined,
  });
  log('agent.done', { status: summary.status });

  log('verify');
  const testResult = await verify(repoDir, { env: nodeEnv });
  log('verify.result', { pass: testResult.pass, baselinePass: baselineResult.pass, output: testResult.output });

  // Only treat test failure as a regression if baseline was passing.
  const testsRegressed = !testResult.pass && baselineResult.pass;
  const draft = testsRegressed || summary.status !== 'success';
  log('pr.open', { draft, push });
  const pr = await openPR({
    repoDir,
    vuln: target,
    ctx,
    summary,
    testResult,
    baselineResult,
    branchBase,
    draft,
    push,
  });

  return {
    runId,
    status: push ? (draft ? 'pr-opened-draft' : 'pr-opened') : 'committed-local',
    target,
    pr,
    summary,
    workspace: repoDir,
  };
}

async function resolveNodeEnv(repoDir, log) {
  const NVM_SH = path.join(os.homedir(), '.nvm', 'nvm.sh');
  if (!existsSync(NVM_SH)) return process.env;

  let version;

  // 1. .nvmrc / .node-version
  for (const f of ['.nvmrc', '.node-version']) {
    try {
      const v = (await readFile(path.join(repoDir, f), 'utf8')).trim();
      if (v) { version = v; break; }
    } catch {}
  }

  // 2. engines.node in package.json
  if (!version) {
    try {
      const pkg = JSON.parse(await readFile(path.join(repoDir, 'package.json'), 'utf8'));
      const eng = pkg.engines?.node;
      if (eng) version = minVersionFromRange(eng);
    } catch {}
  }

  // 3. Scan all installed node_modules for the highest minimum engine requirement
  if (!version) {
    try {
      const { readdir } = await import('node:fs/promises');
      const pkgDirs = await readdir(path.join(repoDir, 'node_modules'));
      let maxMin = [0, 0, 0];
      for (const dir of pkgDirs) {
        if (dir.startsWith('.')) continue;
        const pkgJsonPath = dir.startsWith('@')
          ? null // skip scoped for now — handled below
          : path.join(repoDir, 'node_modules', dir, 'package.json');
        if (!pkgJsonPath) continue;
        try {
          const depPkg = JSON.parse(await readFile(pkgJsonPath, 'utf8'));
          const eng = depPkg.engines?.node;
          if (!eng) continue;
          const v = minVersionFromRange(eng);
          if (!v) continue;
          const parts = v.split('.').map(Number);
          if (cmpVersion(parts, maxMin) > 0) maxMin = parts;
        } catch {}
      }
      if (maxMin[0] > 0) version = maxMin.join('.');
    } catch {}
  }

  if (!version) return process.env;

  try {
    const { stdout } = await exec('/bin/bash', ['-c',
      `source "${NVM_SH}" --no-use && nvm install "${version}" --no-progress > /dev/null 2>&1 && nvm which "${version}"`,
    ]);
    const nodePath = stdout.trim().split('\n').pop().trim();
    const nodeBin = path.dirname(nodePath);
    if (nodeBin && nodeBin !== '.') {
      log('node-version', { requested: version, bin: nodeBin });
      return { ...process.env, PATH: `${nodeBin}:${process.env.PATH}` };
    }
  } catch {}

  return process.env;
}

function minVersionFromRange(range) {
  // Extract the first concrete x.y.z from a semver range like "^20.19.0 || >=22.12.0"
  const m = range.match(/(\d+\.\d+\.\d+)/);
  return m ? m[1] : null;
}

function cmpVersion(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
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

function makeLogger(onLog) {
  return function log(stage, data) {
    const ts = new Date().toISOString();
    if (data === undefined) console.error(`[autosec ${ts}] ${stage}`);
    else console.error(`[autosec ${ts}] ${stage} ${JSON.stringify(data)}`);
    if (onLog) {
      try {
        onLog({ ts, stage, data: data ?? null });
      } catch {}
    }
  };
}
