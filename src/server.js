import express from 'express';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { mkdir, writeFile, appendFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { run as runOrchestrator } from './orchestrator.js';
import { runRecovery } from './recovery.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEB_DIR = path.resolve(__dirname, '..', 'web');
const RUNS_DIR = path.join(os.homedir(), '.autosec', 'runs');

// In-memory run registry. For a real product this becomes Redis / DB.
const runs = new Map(); // runId -> { events: [], subscribers: Set, status, result, error }

function newRun() {
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const dir = path.join(RUNS_DIR, id);
  mkdir(dir, { recursive: true }).catch(() => {});
  const r = {
    id,
    dir,
    events: [],
    subscribers: new Set(),
    status: 'pending',
    result: null,
    error: null,
    startedAt: Date.now(),
    chatHistory: [], // [{role: 'user'|'assistant', text, ts}]
    chatAgentTranscript: '', // accumulated claude stdout for this run (cached for chat context)
  };
  runs.set(id, r);
  return r;
}

function pushEvent(run, evt) {
  run.events.push(evt);
  if (evt.stage === 'agent.chunk' && evt.data?.text) {
    run.chatAgentTranscript += evt.data.text;
    appendFile(path.join(run.dir, 'agent.txt'), evt.data.text).catch(() => {});
  } else if (evt.stage === 'baseline.result') {
    if (evt.data?.output != null) {
      writeFile(path.join(run.dir, 'baseline.txt'), evt.data.output).catch(() => {});
    }
  } else if (evt.stage === 'verify.result') {
    if (evt.data?.output != null) {
      writeFile(path.join(run.dir, 'verify.txt'), evt.data.output).catch(() => {});
    }
  } else if (evt.stage === 'scan.result') {
    writeFile(path.join(run.dir, 'scan.json'), JSON.stringify(evt.data, null, 2)).catch(() => {});
  } else if (evt.stage === 'error') {
    appendFile(path.join(run.dir, 'error.txt'), `[${evt.ts}] ${evt.data?.message || 'unknown error'}\n`).catch(() => {});
  }
  for (const sub of run.subscribers) {
    try { sub(evt); } catch {}
  }
}

function writeManifest(run) {
  // Exclude agent.chunk events — content is in agent.txt
  const events = run.events.filter((e) => e.stage !== 'agent.chunk');
  const manifest = {
    id: run.id,
    status: run.status,
    startedAt: run.startedAt,
    finishedAt: Date.now(),
    error: run.error || null,
    result: run.result || null,
    events,
  };
  writeFile(path.join(run.dir, 'manifest.json'), JSON.stringify(manifest, null, 2)).catch(() => {});
  // Write a human-readable summary alongside
  const lines = [`AutoSec run ${run.id}`, `Status: ${run.status}`, `Started: ${new Date(run.startedAt).toISOString()}`, `Finished: ${new Date(manifest.finishedAt).toISOString()}`];
  if (run.error) lines.push(`Error: ${run.error}`);
  const queued = events.find((e) => e.stage === 'queued');
  if (queued?.data) lines.push(`Repo: ${queued.data.repoUrl}`, `Dry run: ${queued.data.dryRun}`);
  const scan = events.find((e) => e.stage === 'scan.result');
  if (scan?.data) lines.push(``, `Vulnerabilities found: ${scan.data.count}`, ...(scan.data.vulns || []).map((v) => `  ${v.package} (${v.severity}) ${v.current || '?'} -> ${v.fixed}${v.isMajorBump ? ' [major]' : ''}`));
  const target = events.find((e) => e.stage === 'target');
  if (target?.data) lines.push(``, `Target: ${target.data.package} ${target.data.current || '?'} -> ${target.data.fixed} (${target.data.severity})`);
  const baseline = events.find((e) => e.stage === 'baseline.result');
  if (baseline?.data) lines.push(`Baseline tests: ${baseline.data.pass ? 'PASSED' : 'FAILED'}`);
  const verify = events.find((e) => e.stage === 'verify.result');
  if (verify?.data) {
    const note = !verify.data.pass ? (verify.data.baselinePass ? 'FAILED (regression)' : 'FAILED (pre-existing)') : 'PASSED';
    lines.push(`Post-fix tests: ${note}`);
  }
  if (run.result?.pr?.branch) lines.push(`Branch: ${run.result.pr.branch}`);
  if (run.result?.pr?.url) lines.push(`PR: ${run.result.pr.url}`);
  if (run.result?.summary?.migration_notes) lines.push(``, `Agent notes:`, run.result.summary.migration_notes);
  lines.push(``, `Artifacts: ${run.dir}`);
  writeFile(path.join(run.dir, 'summary.txt'), lines.join('\n') + '\n').catch(() => {});
}

function buildRunContext(run) {
  // Compact, model-friendly snapshot of everything that happened in this run.
  const target = run.result?.target;
  const summary = run.result?.summary;
  const pr = run.result?.pr;
  const lines = [];
  lines.push(`# AutoSec run ${run.id}`);
  lines.push(`Status: ${run.status}${run.error ? ` (error: ${run.error})` : ''}`);
  lines.push(`Started: ${new Date(run.startedAt).toISOString()}`);
  const queuedEvt = run.events.find((e) => e.stage === 'queued');
  if (queuedEvt?.data) {
    lines.push(`Repo URL: ${queuedEvt.data.repoUrl}`);
    lines.push(`User-supplied target: ${queuedEvt.data.target || '(none — orchestrator picked automatically)'}`);
    lines.push(`Dry run: ${queuedEvt.data.dryRun}`);
    lines.push(`Max iterations: ${queuedEvt.data.maxIters}`);
  }
  if (run.result?.status) lines.push(`Result status: ${run.result.status}`);
  if (run.result?.reason) lines.push(`Reason: ${run.result.reason}`);
  lines.push('');
  lines.push(`Note on selection logic: When no user target is supplied, AutoSec triages by (1) preferring direct dependencies of the repo over transitive ones, then (2) sorting by severity (critical > high > moderate > low), then (3) skipping any vuln that already has an open autosec/* PR. When a user target is supplied, that target is forced regardless of severity.`);
  lines.push('');
  if (target) {
    lines.push(`## Target vulnerability`);
    lines.push(`- Package: ${target.package}`);
    lines.push(`- Severity: ${target.severity}`);
    lines.push(`- From: ${target.current || '?'}`);
    lines.push(`- To: ${target.fixed}`);
    lines.push(`- Major bump: ${target.isMajorBump}`);
    if (target.title) lines.push(`- Advisory title: ${target.title}`);
    if (target.advisoryUrl) lines.push(`- Advisory URL: ${target.advisoryUrl}`);
    lines.push('');
  }

  // All vulnerabilities seen during the scan (so you can ask "why this one?")
  const scanEvt = run.events.find((e) => e.stage === 'scan.result');
  if (scanEvt?.data?.vulns) {
    lines.push(`## All scanned vulnerabilities (${scanEvt.data.count})`);
    for (const v of scanEvt.data.vulns) {
      lines.push(`- ${v.package} (${v.severity}) ${v.current || '?'} -> ${v.fixed}${v.isMajorBump ? ' [major]' : ''}${v.title ? ` — ${v.title}` : ''}`);
    }
    lines.push('');
  }

  // Context (changelog source, call sites, test command)
  const ctxEvt = run.events.find((e) => e.stage === 'context.result');
  if (ctxEvt?.data) {
    lines.push(`## Migration context`);
    lines.push(`- Call sites found: ${ctxEvt.data.callSites}`);
    lines.push(`- Changelog: ${ctxEvt.data.changelogSource} (${ctxEvt.data.changelogChars} chars)`);
    lines.push(`- Test command: ${ctxEvt.data.testCommand || '(none)'}`);
    lines.push('');
  }

  // Baseline + verify
  const baselineEvt = run.events.find((e) => e.stage === 'baseline.result');
  const verifyEvt = run.events.find((e) => e.stage === 'verify.result');
  if (baselineEvt?.data || verifyEvt?.data) {
    lines.push(`## Test results`);
    if (baselineEvt?.data) {
      lines.push(`- Baseline (pre-fix): ${baselineEvt.data.pass ? 'PASSED' : 'FAILED'}`);
    }
    if (verifyEvt?.data) {
      const baselinePassed = baselineEvt?.data?.pass ?? true;
      const postFixPassed = verifyEvt.data.pass;
      const note = !postFixPassed
        ? (baselinePassed ? 'FAILED (regression)' : 'FAILED (pre-existing)')
        : 'PASSED';
      lines.push(`- Post-fix: ${note}`);
    }
    lines.push('');
  }

  if (summary) {
    lines.push(`## Agent self-reported summary`);
    lines.push(`- Status: ${summary.status}`);
    if (summary.files_touched?.length) {
      lines.push(`- Files touched: ${summary.files_touched.join(', ')}`);
    }
    if (summary.migration_notes) {
      lines.push(`- Migration notes:`);
      lines.push(summary.migration_notes.split('\n').map((l) => '  ' + l).join('\n'));
    }
    lines.push('');
  }

  if (pr) {
    lines.push(`## PR / commit`);
    if (pr.branch) lines.push(`- Branch: ${pr.branch}`);
    if (pr.url) lines.push(`- URL: ${pr.url}`);
    if (pr.draft !== undefined) lines.push(`- Draft: ${pr.draft}`);
    if (pr.diffstat) {
      lines.push(`- Diffstat:`);
      lines.push(pr.diffstat.split('\n').map((l) => '  ' + l).join('\n'));
    }
    lines.push('');
  }

  // Truncate very long transcript to keep prompt size sane (~16KB)
  const transcript = run.chatAgentTranscript;
  if (transcript) {
    const MAX = 16000;
    const slice = transcript.length > MAX ? '...[truncated]...\n' + transcript.slice(-MAX) : transcript;
    lines.push(`## Agent transcript (live stdout from claude -p)`);
    lines.push('```');
    lines.push(slice);
    lines.push('```');
    lines.push('');
  }

  return lines.join('\n');
}

function buildChatPrompt(run, userMessage) {
  const ctx = buildRunContext(run);
  const history = run.chatHistory
    .map((t) => `${t.role === 'user' ? 'Human' : 'Assistant'}: ${t.text}`)
    .join('\n\n');
  return [
    'You are answering questions about a single AutoSec pipeline run.',
    'AutoSec is an autonomous dependency-vulnerability remediation agent that scans a repo with `npm audit`, picks one vulnerability, reads the upstream changelog, and uses a Claude headless agent to apply the bump and any required call-site edits, then runs the test suite.',
    '',
    'Below is the COMPLETE record of the run that the user is asking about. Ground every answer in this record. If the answer is not in the record, say so explicitly rather than guessing.',
    '',
    '---BEGIN RUN RECORD---',
    ctx,
    '---END RUN RECORD---',
    '',
    'Be concise (3-6 sentences typical). Prefer concrete details from the record (package names, versions, file paths, severity) over generalities. Use markdown for code/identifiers but no headings unless the answer truly needs structure.',
    '',
    history ? 'Conversation so far:\n\n' + history + '\n' : '',
    `Human: ${userMessage}`,
    '',
    'Assistant:',
  ].filter(Boolean).join('\n');
}

function inferFailedStage(events) {
  // The last non-error event before the error is the stage that was running.
  const ORDER = ['clone', 'npm-install', 'scan', 'triage', 'context', 'baseline', 'agent.start', 'verify', 'pr.open'];
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i];
    if (e.stage === 'error' || e.stage === 'agent.chunk') continue;
    if (ORDER.includes(e.stage)) return e.stage;
  }
  return null;
}

function chatWithClaude(prompt, { onChunk, timeoutMs = 90_000 }) {
  return new Promise((resolve, reject) => {
    const child = spawn('claude', ['-p', prompt, '--max-turns', '1'], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`chat timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.on('data', (d) => {
      const s = d.toString();
      stdout += s;
      onChunk?.(s);
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString();
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`claude chat exited ${code}: ${stderr.slice(-300)}`));
        return;
      }
      resolve(stdout);
    });
  });
}

export function createApp() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(express.static(WEB_DIR));

  app.get('/api/health', (_req, res) => res.json({ ok: true }));

  app.post('/api/runs', async (req, res) => {
    const { repoUrl, target, dryRun, maxIters } = req.body || {};
    if (!repoUrl || typeof repoUrl !== 'string') {
      return res.status(400).json({ error: 'repoUrl required' });
    }
    if (!/^https?:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+/.test(repoUrl)) {
      return res.status(400).json({ error: 'repoUrl must be a github.com URL' });
    }
    const run = newRun();
    run.status = 'running';
    pushEvent(run, { ts: new Date().toISOString(), stage: 'queued', data: { repoUrl, target: target || null, dryRun: !!dryRun, maxIters: maxIters || 5 } });

    // Start work in background. UI never triggers a push.
    runOrchestrator({
      repoUrl,
      target: target || undefined,
      dryRun: !!dryRun,
      maxIters: maxIters ? parseInt(maxIters, 10) : 5,
      branchBase: 'main',
      push: false,
      onLog: (evt) => pushEvent(run, evt),
    })
      .then((result) => {
        run.status = 'done';
        run.result = result;
        pushEvent(run, { ts: new Date().toISOString(), stage: 'done', data: { status: result.status } });
        writeManifest(run);
      })
      .catch(async (err) => {
        run.status = 'error';
        run.error = err.message;
        pushEvent(run, { ts: new Date().toISOString(), stage: 'error', data: { message: err.message } });

        // Self-diagnosis: spawn a Claude agent against AutoSec's own source to propose a patch.
        const failedStage = inferFailedStage(run.events);
        pushEvent(run, { ts: new Date().toISOString(), stage: 'recovery.start', data: { failedStage } });
        try {
          const { proposal } = await runRecovery({
            failedStage,
            errorMessage: err.message,
            runEvents: run.events,
            onChunk: (text) => {
              pushEvent(run, { ts: new Date().toISOString(), stage: 'recovery.chunk', data: { text } });
            },
          });
          pushEvent(run, { ts: new Date().toISOString(), stage: 'recovery.done', data: { proposal } });
          run.recoveryProposal = proposal;
        } catch (recErr) {
          pushEvent(run, { ts: new Date().toISOString(), stage: 'recovery.error', data: { message: recErr.message } });
        }
        writeManifest(run);
      });

    res.status(202).json({ runId: run.id });
  });

  app.get('/api/runs/:id', (req, res) => {
    const run = runs.get(req.params.id);
    if (!run) return res.status(404).json({ error: 'not found' });
    res.json({
      id: run.id,
      status: run.status,
      result: run.result,
      error: run.error,
      eventCount: run.events.length,
      startedAt: run.startedAt,
    });
  });

  app.get('/api/runs/:id/events', (req, res) => {
    const run = runs.get(req.params.id);
    if (!run) return res.status(404).end();
    res.set({
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.flushHeaders?.();

    const send = (evt) => {
      res.write(`data: ${JSON.stringify(evt)}\n\n`);
    };

    // Replay history
    for (const evt of run.events) send(evt);
    if (run.status === 'done' || run.status === 'error') {
      send({ stage: '__close__' });
      res.end();
      return;
    }

    const sub = (evt) => {
      send(evt);
      if (evt.stage === 'done' || evt.stage === 'error') {
        send({ stage: '__close__' });
        run.subscribers.delete(sub);
        res.end();
      }
    };
    run.subscribers.add(sub);

    // Heartbeat to keep proxies happy
    const hb = setInterval(() => res.write(': heartbeat\n\n'), 15000);
    req.on('close', () => {
      clearInterval(hb);
      run.subscribers.delete(sub);
    });
  });

  // ---- Chat about a run ----
  app.get('/api/runs/:id/chat', (req, res) => {
    const run = runs.get(req.params.id);
    if (!run) return res.status(404).json({ error: 'not found' });
    res.json({ history: run.chatHistory });
  });

  app.post('/api/runs/:id/chat', async (req, res) => {
    const run = runs.get(req.params.id);
    if (!run) return res.status(404).json({ error: 'not found' });
    const { message } = req.body || {};
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'message required' });
    }
    if (message.length > 4000) {
      return res.status(400).json({ error: 'message too long' });
    }

    const userTurn = { role: 'user', text: message, ts: new Date().toISOString() };
    run.chatHistory.push(userTurn);

    res.set({
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.flushHeaders?.();

    const send = (obj) => res.write(`data: ${JSON.stringify(obj)}\n\n`);
    send({ type: 'user', text: message });

    const prompt = buildChatPrompt(run, message);
    let assistantText = '';
    try {
      await chatWithClaude(prompt, {
        onChunk: (chunk) => {
          assistantText += chunk;
          send({ type: 'chunk', text: chunk });
        },
      });
      const cleaned = assistantText.trim();
      run.chatHistory.push({ role: 'assistant', text: cleaned, ts: new Date().toISOString() });
      send({ type: 'done', text: cleaned });
    } catch (err) {
      send({ type: 'error', message: err.message });
    } finally {
      res.end();
    }
  });

  // Catch-all: serve index.html for the SPA-style root
  app.get('/', (_req, res) => res.sendFile(path.join(WEB_DIR, 'index.html')));

  return app;
}
