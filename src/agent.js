import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROMPTS_DIR = path.resolve(__dirname, '..', 'prompts');

/**
 * Run claude headless inside repoDir to perform the bump+fix.
 * Returns { transcript, summary } where summary is parsed from the autosec-summary fenced block.
 */
export async function runAgent({ repoDir, vuln, ctx, maxIters, timeoutMs = 10 * 60 * 1000, onChunk }) {
  const systemPrompt = await readFile(path.join(PROMPTS_DIR, 'system.md'), 'utf8');
  const taskTemplate = await readFile(path.join(PROMPTS_DIR, 'task.md'), 'utf8');

  const callSitesText = ctx.callSites.length ? ctx.callSites.join('\n') : '(none found)';
  const changelogText = ctx.changelog.text || '(changelog unavailable)';

  const userPrompt = render(taskTemplate, {
    package: vuln.package,
    current: vuln.current || 'current',
    fixed: vuln.fixed,
    severity: vuln.severity,
    title: vuln.title || '(none)',
    advisoryUrl: vuln.advisoryUrl || '(none)',
    isMajorBump: String(vuln.isMajorBump),
    testCommand: ctx.testCommand || '',
    callSites: callSitesText,
    changelogSource: ctx.changelog.source,
    changelogNotes: ctx.changelog.notes,
    changelogText,
    maxIters: String(maxIters),
  });

  const args = [
    '-p',
    userPrompt,
    '--append-system-prompt',
    systemPrompt,
    '--permission-mode',
    'acceptEdits',
    '--allowedTools',
    'Bash,Edit,Read,Grep,Glob,Write',
    '--max-turns',
    String(maxIters * 6),
  ];

  const transcript = await spawnClaude(args, { cwd: repoDir, timeoutMs, onChunk });
  const summary = parseSummary(transcript);
  return { transcript, summary };
}

function render(tmpl, vars) {
  return tmpl.replace(/\{\{(\w+)\}\}/g, (_, k) => (vars[k] !== undefined ? String(vars[k]) : ''));
}

function parseSummary(text) {
  const m = text.match(/```autosec-summary\s*([\s\S]*?)```/);
  if (!m) return { status: 'unknown', raw: null };
  const body = m[1].trim();
  const out = { status: 'unknown', raw: body, files_touched: [] };
  const lines = body.split('\n');
  let inFiles = false;
  let inNotes = false;
  let notes = [];
  for (const line of lines) {
    if (inNotes) {
      notes.push(line.replace(/^  /, ''));
      continue;
    }
    if (/^migration_notes:\s*\|/.test(line)) {
      inNotes = true;
      continue;
    }
    if (/^files_touched:/.test(line)) {
      inFiles = true;
      continue;
    }
    if (inFiles && /^\s*-\s+/.test(line)) {
      out.files_touched.push(line.replace(/^\s*-\s+/, '').trim());
      continue;
    }
    inFiles = false;
    const kv = line.match(/^(\w+):\s*(.*)$/);
    if (kv) out[kv[1]] = kv[2].trim();
  }
  if (notes.length) out.migration_notes = notes.join('\n').trim();
  return out;
}

function spawnClaude(args, { cwd, timeoutMs, onChunk }) {
  return new Promise((resolve, reject) => {
    const child = spawn('claude', args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`claude timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.on('data', (d) => {
      const s = d.toString();
      stdout += s;
      process.stderr.write(s); // surface live to operator
      if (onChunk) {
        try { onChunk({ stream: 'stdout', text: s }); } catch {}
      }
    });
    child.stderr.on('data', (d) => {
      const s = d.toString();
      stderr += s;
      process.stderr.write(d);
      if (onChunk) {
        try { onChunk({ stream: 'stderr', text: s }); } catch {}
      }
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`claude exited ${code}: ${stderr.slice(-500)}`));
        return;
      }
      resolve(stdout);
    });
  });
}
