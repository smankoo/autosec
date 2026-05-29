import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const AUTOSEC_DIR = path.resolve(__dirname, '..');

/**
 * When the orchestrator throws, run a Claude headless agent against the AutoSec
 * repo itself with read-only tools. It inspects the failure log, locates the
 * stage in src/, and proposes (does NOT apply) a code-level fix.
 *
 * Streams chunks via onChunk; resolves with { proposal: string }.
 */
export function runRecovery({ failedStage, errorMessage, runEvents, onChunk, timeoutMs = 120_000 }) {
  const failureLog = formatFailureLog(failedStage, errorMessage, runEvents);
  const prompt = buildPrompt(failureLog);

  return new Promise((resolve, reject) => {
    const args = [
      '-p', prompt,
      '--permission-mode', 'plan',
      '--allowedTools', 'Read,Grep,Glob',
      '--max-turns', '12',
    ];
    const child = spawn('claude', args, {
      cwd: AUTOSEC_DIR,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`recovery agent timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    child.stdout.on('data', (d) => {
      const s = d.toString();
      stdout += s;
      onChunk?.(s);
    });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        reject(new Error(`recovery agent exited ${code}: ${stderr.slice(-300)}`));
        return;
      }
      resolve({ proposal: stdout.trim() });
    });
  });
}

function formatFailureLog(stage, message, events) {
  const lines = [];
  lines.push(`Failed stage: ${stage || '(unknown)'}`);
  lines.push(`Error: ${message}`);
  if (events?.length) {
    const recent = events.filter((e) => e.stage !== 'agent.chunk').slice(-15);
    lines.push('');
    lines.push('Recent run events:');
    for (const e of recent) {
      const data = e.data ? ' ' + JSON.stringify(e.data).slice(0, 300) : '';
      lines.push(`  [${(e.ts || '').slice(11, 19)}] ${e.stage}${data}`);
    }
  }
  return lines.join('\n');
}

function buildPrompt(failureLog) {
  return [
    'You are AutoSec\'s self-diagnosis agent. AutoSec is a Node.js CLI/server that scans a target repo for npm vulnerabilities and uses a Claude headless agent to apply the fix. Its source lives in this directory (src/orchestrator.js, src/scan.js, src/agent.js, src/server.js, web/index.html, etc.).',
    '',
    'A pipeline run just failed. Your job: read the AutoSec source, identify the root cause in AutoSec\'s code (NOT the target repo), and propose a concrete, minimal patch that would prevent this failure or recover from it gracefully. You have READ-ONLY tools (Read, Grep, Glob). Do NOT attempt to edit files.',
    '',
    '---FAILURE LOG---',
    failureLog,
    '---END FAILURE LOG---',
    '',
    'Workflow:',
    '1. Locate the failing stage in AutoSec source (e.g. failed stage "npm-install" → src/orchestrator.js).',
    '2. Determine whether this is (a) a target-repo issue AutoSec should tolerate, or (b) an AutoSec code bug.',
    '3. Propose ONE concrete patch — exact file path, the old snippet, and the new snippet. Keep it minimal.',
    '',
    'Respond in this exact markdown shape (no preamble, no postscript):',
    '',
    '## Diagnosis',
    '<2-3 sentence root cause>',
    '',
    '## Proposed fix',
    '**File:** `path/to/file.js`',
    '',
    '```diff',
    '- old line',
    '+ new line',
    '```',
    '',
    '## Why this works',
    '<2-3 sentences>',
    '',
    '## Risk',
    '<one sentence: what could go wrong, what to test>',
  ].join('\n');
}
