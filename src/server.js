import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { run as runOrchestrator } from './orchestrator.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEB_DIR = path.resolve(__dirname, '..', 'web');

// In-memory run registry. For a real product this becomes Redis / DB.
const runs = new Map(); // runId -> { events: [], subscribers: Set, status, result, error }

function newRun() {
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const r = { id, events: [], subscribers: new Set(), status: 'pending', result: null, error: null, startedAt: Date.now() };
  runs.set(id, r);
  return r;
}

function pushEvent(run, evt) {
  run.events.push(evt);
  for (const sub of run.subscribers) {
    try { sub(evt); } catch {}
  }
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
      })
      .catch((err) => {
        run.status = 'error';
        run.error = err.message;
        pushEvent(run, { ts: new Date().toISOString(), stage: 'error', data: { message: err.message } });
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

  // Catch-all: serve index.html for the SPA-style root
  app.get('/', (_req, res) => res.sendFile(path.join(WEB_DIR, 'index.html')));

  return app;
}
