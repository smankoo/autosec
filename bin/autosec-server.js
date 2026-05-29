#!/usr/bin/env node
import { readdir, stat, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createApp } from '../src/server.js';

const port = parseInt(process.env.PORT || '8787', 10);
const host = process.env.HOST || '127.0.0.1';

await sweepStaleRuns();

const app = createApp();
app.listen(port, host, () => {
  console.log(`autosec-server listening on http://${host}:${port}`);
});

/**
 * Best-effort cleanup of leftover run dirs from prior server processes.
 * Anything older than 24h or whose entire root is from before this server
 * started is fair game — a fresh server should start with a clean slate.
 */
async function sweepStaleRuns() {
  const root = path.join(os.tmpdir(), 'autosec-runs');
  let entries;
  try { entries = await readdir(root); } catch { return; }
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  let removed = 0, freedBytes = 0;
  for (const name of entries) {
    const p = path.join(root, name);
    try {
      const s = await stat(p);
      if (s.mtimeMs < cutoff) {
        // Best-effort size for the log line — skip on failure.
        try { freedBytes += await dirSize(p); } catch {}
        await rm(p, { recursive: true, force: true });
        removed++;
      }
    } catch {}
  }
  if (removed) {
    const mb = Math.round(freedBytes / (1024 * 1024));
    console.log(`autosec-server: swept ${removed} stale run dir${removed === 1 ? '' : 's'} (~${mb}MB)`);
  }
}

async function dirSize(p) {
  let total = 0;
  let entries;
  try { entries = await readdir(p, { withFileTypes: true }); } catch { return 0; }
  for (const e of entries) {
    const full = path.join(p, e.name);
    try {
      if (e.isDirectory()) total += await dirSize(full);
      else { const s = await stat(full); total += s.size; }
    } catch {}
  }
  return total;
}
