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
import { snapshotNatives, restoreMissingNatives } from './nativeSnapshot.js';
import { classifyVerify } from './classify.js';
import {
  NPM_CACHE_DIR, nodeModulesCacheKey, restoreNodeModules,
  snapshotNodeModules, hasLockfile, preferredInstallCmd,
} from './installCache.js';

const exec = promisify(execFile);

export async function run({ repoUrl, dryRun, maxIters, branchBase, target: targetPkg, push = true, onLog, selectTargets }) {
  const runId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const root = path.join(os.tmpdir(), 'autosec-runs', runId);
  await mkdir(root, { recursive: true });
  const repoDir = path.join(root, 'repo');
  const log = makeLogger(onLog);

  const { httpsUrl, sshUrl } = normalizeRepoUrls(repoUrl);
  const cloneUrl = await cloneWithFallback({ httpsUrl, sshUrl, repoDir, log });
  await configurePushAuth(repoDir);
  await exec('git', ['config', 'user.name', process.env.GIT_AUTHOR_NAME || 'AutoSec Bot'], { cwd: repoDir });
  await exec('git', ['config', 'user.email', process.env.GIT_AUTHOR_EMAIL || 'autosec@example.invalid'], { cwd: repoDir });

  // Resolve the target Node BEFORE any install — otherwise the first install
  // compiles native bindings against the host's V8 ABI, and we either ship
  // mismatched binaries or have to wipe and reinstall (slow). The pre-install
  // resolve only consults files in a fresh clone: .nvmrc, .node-version,
  // package.json#engines.node.
  const nodeEnv = await resolveNodeEnv(repoDir, log);
  const nodeBinHint = nodeEnv === process.env
    ? process.execPath
    : (nodeEnv.PATH || '').split(':')[0];

  log('npm-install');
  const npmCacheArg = `--cache=${NPM_CACHE_DIR}`;
  const lockfile = await hasLockfile(repoDir);
  const installCmd = preferredInstallCmd(lockfile);
  const npmArgs = [installCmd, '--no-audit', '--no-fund', npmCacheArg];
  if (process.env.AUTOSEC_NPM_REGISTRY) npmArgs.push(`--registry=${process.env.AUTOSEC_NPM_REGISTRY}`);

  const cacheKey = await nodeModulesCacheKey(repoDir, nodeBinHint);
  let cacheHit = cacheKey ? await restoreNodeModules(cacheKey, repoDir) : false;
  if (cacheHit) {
    log('npm-install.cache-hit', { key: cacheKey });
  } else {
    await runInstall(npmArgs, { cwd: repoDir, env: nodeEnv }, log);
    if (cacheKey) {
      const cached = await snapshotNodeModules(cacheKey, repoDir);
      if (cached) log('npm-install.cache-store', { key: cacheKey });
    }
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

  // Decide which vulns to remediate. Priority: explicit targetPkg (single, CLI),
  // then UI-supplied selectTargets callback (multi), then triage's best pick.
  let targets;
  if (targetPkg) {
    const t = vulns.find((v) => v.package === targetPkg);
    if (!t) return { runId, status: 'no-op', reason: `target ${targetPkg} not in scan results`, vulnsFound: vulns.length };
    targets = [t];
  } else if (selectTargets && vulns.length > 0) {
    const picks = await selectTargets(vulns);
    if (!picks || picks.length === 0) {
      return { runId, status: 'no-op', reason: 'user selected no vulnerabilities', vulnsFound: vulns.length };
    }
    targets = picks;
  } else {
    const best = await triage(vulns, { repoDir });
    targets = best ? [best] : [];
  }
  if (targets.length === 0) {
    return { runId, status: 'no-op', reason: 'no actionable vuln', vulnsFound: vulns.length };
  }
  log('targets', { count: targets.length, packages: targets.map((t) => t.package), targets });

  log('context');
  const contexts = [];
  for (const t of targets) {
    const c = await gatherContext(t, repoDir);
    contexts.push(c);
  }
  // Use the first target's testCommand and changelog as the run-level summary —
  // testCommand comes from package.json so it's the same for every target.
  const ctx = contexts[0];
  log('context.result', {
    callSites: contexts.reduce((n, c) => n + c.callSites.length, 0),
    changelogSource: ctx.changelog.source,
    changelogChars: contexts.reduce((n, c) => n + c.changelog.text.length, 0),
    testCommand: ctx.testCommand,
    perTarget: contexts.map((c, i) => ({
      package: targets[i].package,
      callSites: c.callSites.length,
      changelogChars: c.changelog.text.length,
    })),
  });

  if (!ctx.testCommand) {
    return { runId, status: 'failed', reason: 'no test command in repo', targets };
  }

  log('baseline');
  const baselineResult = await verify(repoDir, { env: nodeEnv });
  log('baseline.result', { pass: baselineResult.pass, output: baselineResult.output, tests: baselineResult.tests || [] });

  if (dryRun) {
    return { runId, status: 'dry-run', targets, ctxSummary: summarizeCtx(ctx), baseline: baselineResult };
  }

  // Snapshot native bindings (.node files) before the agent runs. Many bumps
  // refresh package-lock and re-extract tarballs, which strips the compiled
  // binary on hosts where it can't be rebuilt (canvas, sharp, etc.). Restoring
  // these afterward keeps the test environment intact so we can actually
  // judge whether the bump caused regressions.
  const snapshotDir = path.join(root, 'native-snapshot');
  const snap = await snapshotNatives(repoDir, snapshotDir);
  log('native.snapshot', { count: snap.count });

  log('agent.start', { targetCount: targets.length });
  const { transcript, summary } = await runAgent({
    repoDir,
    targets,
    contexts,
    maxIters,
    onChunk: onLog
      ? ({ stream, text }) => onLog({ ts: new Date().toISOString(), stage: 'agent.chunk', data: { stream, text } })
      : undefined,
  });
  log('agent.done', { status: summary.status });

  const restored = await restoreMissingNatives(repoDir, snapshotDir);
  if (restored.length) log('native.restore', { restored });

  log('verify');
  const testResult = await verify(repoDir, { env: nodeEnv });
  const verdict = classifyVerify({ baseline: baselineResult, verify: testResult });
  log('verify.result', {
    pass: testResult.pass,
    baselinePass: baselineResult.pass,
    output: testResult.output,
    tests: testResult.tests || [],
    baselineTests: baselineResult.tests || [],
    classification: verdict,
    nativeRestored: restored,
  });

  // Only the "regression" verdict actually blocks: pre-existing or env-broken
  // failures aren't caused by the bump.
  const testsRegressed = verdict.label === 'regression';
  const draft = testsRegressed || summary.status !== 'success';
  log('pr.open', { draft, push });
  const pr = await openPR({
    repoDir,
    targets,
    ctx,
    contexts,
    summary,
    testResult,
    baselineResult,
    branchBase,
    draft,
    push,
    verdict,
  });

  return {
    runId,
    status: push ? (draft ? 'pr-opened-draft' : 'pr-opened') : 'committed-local',
    targets,
    target: targets[0], // back-compat for single-target callers/UI
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

function normalizeRepoUrls(input) {
  // Accept either "https://github.com/owner/repo[.git]" or "git@github.com:owner/repo[.git]".
  let owner, repo;
  let m = input.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?\/?$/);
  if (m) { owner = m[1]; repo = m[2]; }
  else {
    m = input.match(/^git@github\.com:([^/]+)\/([^/]+?)(?:\.git)?$/);
    if (m) { owner = m[1]; repo = m[2]; }
  }
  if (!owner) {
    // Fallback: trust caller, return the input as both — git will pick whichever works.
    return { httpsUrl: input, sshUrl: input };
  }
  return {
    httpsUrl: `https://github.com/${owner}/${repo}.git`,
    sshUrl: `git@github.com:${owner}/${repo}.git`,
  };
}

async function cloneWithFallback({ httpsUrl, sshUrl, repoDir, log }) {
  // Prefer the scheme that has matching credentials configured. If a GitHub
  // token is available, https will work non-interactively; otherwise try ssh
  // first since the user likely has an SSH key. Either way, fall back on
  // failure so it Just Works on machines configured for the other scheme.
  const hasToken = !!(process.env.GH_TOKEN || process.env.GITHUB_TOKEN || (await ghAuthToken()));
  const order = hasToken ? [httpsUrl, sshUrl] : [sshUrl, httpsUrl];
  let firstErr;
  for (const url of order) {
    try {
      log('clone', { repoUrl: url, repoDir });
      // GIT_TERMINAL_PROMPT=0 prevents git from blocking on a username/password
      // prompt when https creds are missing — it just fails fast so we can fall back.
      // GIT_SSH_COMMAND with BatchMode=yes does the same for ssh (no host-key prompt).
      const env = {
        ...process.env,
        GIT_TERMINAL_PROMPT: '0',
        GIT_SSH_COMMAND: 'ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new',
      };
      await exec('git', ['clone', '--depth', '50', url, repoDir], { env });
      return url;
    } catch (e) {
      firstErr = firstErr || e;
      log('clone.retry', { failedUrl: url, error: shortErr(e) });
      // Clean up partial clone before retry
      try { await rm(repoDir, { recursive: true, force: true }); } catch {}
    }
  }
  throw new Error(`clone failed for both https and ssh: ${shortErr(firstErr)}`);
}

async function ghAuthToken() {
  try {
    const { stdout } = await exec('gh', ['auth', 'token']);
    return stdout.trim() || null;
  } catch { return null; }
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

async function runInstall(npmArgs, opts, log) {
  // Try the preferred command (ci or install). Two fallbacks:
  // 1. If `npm ci` fails because the lockfile is out of sync, retry with
  //    `npm install` (which will rewrite the lockfile).
  // 2. If postinstalls fail (native build errors), retry with --ignore-scripts.
  const isCi = npmArgs[0] === 'ci';
  const env = { ...(opts.env || process.env), maxBuffer: 50 * 1024 * 1024 };
  try {
    await exec('npm', npmArgs, { ...opts, env, maxBuffer: 50 * 1024 * 1024 });
    return;
  } catch (err) {
    const msg = String(err.stderr || err.message || '');
    if (isCi && /can only install packages when your package\.json and package-lock\.json/.test(msg)) {
      log('npm-install.retry', { reason: 'lockfile out of sync; falling back to npm install' });
      const fallback = ['install', ...npmArgs.slice(1)];
      try {
        await exec('npm', fallback, { ...opts, env, maxBuffer: 50 * 1024 * 1024 });
        return;
      } catch (err2) {
        log('npm-install.retry', { reason: 'npm install failed, retrying with --ignore-scripts', error: shortErr(err2) });
        await exec('npm', [...fallback, '--ignore-scripts'], { ...opts, env, maxBuffer: 50 * 1024 * 1024 });
        return;
      }
    }
    log('npm-install.retry', { reason: 'install failed, retrying with --ignore-scripts', error: shortErr(err) });
    await exec('npm', [...npmArgs, '--ignore-scripts'], { ...opts, env, maxBuffer: 50 * 1024 * 1024 });
  }
}

function shortErr(err) {
  const m = String(err?.message || err || '');
  return m.length > 400 ? m.slice(0, 400) + '…' : m;
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
