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
export async function runAgent({ repoDir, targets, contexts, vuln, ctx, maxIters, timeoutMs = 20 * 60 * 1000, onChunk }) {
  const systemPrompt = await readFile(path.join(PROMPTS_DIR, 'system.md'), 'utf8');

  // Back-compat: callers may pass {vuln, ctx} for single-target.
  if (!targets) targets = vuln ? [vuln] : [];
  if (!contexts) contexts = ctx ? [ctx] : [];

  const userPrompt = await buildPrompt({ targets, contexts, maxIters });

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

async function buildPrompt({ targets, contexts, maxIters }) {
  const testCommand = contexts[0]?.testCommand || '';
  const lines = [];
  lines.push('# Task');
  lines.push('');
  if (targets.length === 1) {
    const t = targets[0];
    lines.push(`Bump **${t.package}** from \`${t.current || 'current'}\` to \`${t.fixed}\` and fix any breaking-change fallout so the test suite passes.`);
  } else {
    lines.push(`Bump the following ${targets.length} dependencies and fix any breaking-change fallout so the test suite passes after ALL bumps are applied:`);
    lines.push('');
    for (const t of targets) {
      lines.push(`- **${t.package}**: \`${t.current || 'current'}\` → \`${t.fixed}\` (${t.severity}${t.isMajorBump ? ', major' : ''})`);
    }
    lines.push('');
    lines.push('You decide the order. Group bumps that touch the same files. After all bumps are applied, run the test suite once and iterate on whatever fails. The final state should be ALL bumps applied with tests green (or as close as you can get within the iteration budget).');
  }
  lines.push('');
  lines.push('## Test command');
  lines.push('');
  lines.push('```');
  lines.push(testCommand || '');
  lines.push('```');
  lines.push('');
  if (!testCommand) {
    lines.push('If the test command is empty, stop immediately and emit `status: failed` with note `no test command — refusing to operate without a test suite to verify the change`.');
    lines.push('');
  }

  for (let i = 0; i < targets.length; i++) {
    const t = targets[i];
    const c = contexts[i];
    lines.push(`## ${t.package} (${t.current || '?'} → ${t.fixed})`);
    lines.push('');
    lines.push(`- Severity: ${t.severity}`);
    lines.push(`- Title: ${t.title || '(none)'}`);
    lines.push(`- Advisory: ${t.advisoryUrl || '(none)'}`);
    lines.push(`- Major version bump: ${t.isMajorBump}`);
    lines.push('');
    lines.push('### Call sites in this repo');
    lines.push('');
    lines.push('```');
    lines.push(c.callSites.length ? c.callSites.join('\n') : '(none found)');
    lines.push('```');
    lines.push('');
    lines.push(`### Upstream changelog (${c.changelog.source}, ${c.changelog.notes})`);
    lines.push('');
    lines.push(c.changelog.text || '(changelog unavailable)');
    lines.push('');
  }

  lines.push('## Procedure');
  lines.push('');
  lines.push(`1. Apply all version bumps to \`package.json\` (using \`^X.Y.Z\` matching existing style).`);
  lines.push(`2. Run \`npm install\` ONCE to refresh the lockfile after all package.json edits.`);
  lines.push(`3. Run the test command. If green, you're done — emit the summary block.`);
  lines.push(`4. If red, read failures, consult the relevant changelogs above, edit the offending call sites, run tests again.`);
  lines.push(`5. Repeat at most ${maxIters} times.`);
  lines.push('');
  lines.push('Begin.');
  return lines.join('\n');
}

function parseSummary(text) {
  const m = text.match(/```autosec-summary\s*([\s\S]*?)```/);
  if (!m) return { status: 'unknown', raw: null };
  const body = m[1].trim();
  const out = { status: 'unknown', raw: body, files_touched: [], packages: [] };
  const lines = body.split('\n');
  let mode = null;     // 'files' | 'notes' | 'packages'
  let notes = [];
  let curPkg = null;
  for (const line of lines) {
    if (mode === 'notes') {
      notes.push(line.replace(/^  /, ''));
      continue;
    }
    if (/^migration_notes:\s*\|/.test(line)) { mode = 'notes'; continue; }
    if (/^files_touched:/.test(line)) { mode = 'files'; continue; }
    if (/^packages:/.test(line)) { mode = 'packages'; continue; }
    if (mode === 'files' && /^\s*-\s+/.test(line)) {
      out.files_touched.push(line.replace(/^\s*-\s+/, '').trim());
      continue;
    }
    if (mode === 'packages') {
      const startItem = line.match(/^\s*-\s+name:\s*(.*)$/);
      if (startItem) {
        if (curPkg) out.packages.push(curPkg);
        curPkg = { name: startItem[1].trim() };
        continue;
      }
      const sub = line.match(/^\s+(\w+):\s*(.*)$/);
      if (sub && curPkg) {
        curPkg[sub[1]] = sub[2].trim();
        continue;
      }
      // non-matching line ends the packages block
      if (curPkg && /^\w/.test(line)) {
        out.packages.push(curPkg);
        curPkg = null;
        mode = null;
      }
    }
    if (mode === null || mode === 'files') {
      const kv = line.match(/^(\w+):\s*(.*)$/);
      if (kv) {
        out[kv[1]] = kv[2].trim();
        if (mode === 'files') mode = null;
      }
    }
  }
  if (curPkg) out.packages.push(curPkg);
  if (notes.length) out.migration_notes = notes.join('\n').trim();
  // Back-compat: synthesize packages[] from flat package/from/to if needed.
  if (out.packages.length === 0 && out.package) {
    out.packages.push({ name: out.package, from: out.from, to: out.to });
  }
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
