import { spawn } from 'node:child_process';

/**
 * Run `npm test` in repoDir. Returns { pass, code, output, tests }.
 *  - output: last ~200 lines of stdout+stderr.
 *  - tests:  parsed { name, status: 'pass'|'fail'|'skip', file? } list — best-effort
 *            across mocha/jest/vitest/tap-style runners. May be empty.
 */
export function verify(repoDir, { timeoutMs = 5 * 60 * 1000, env } = {}) {
  return new Promise((resolve) => {
    const child = spawn('npm', ['test', '--silent'], { cwd: repoDir, env: env ?? process.env, stdio: ['ignore', 'pipe', 'pipe'] });
    let buf = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      resolve({ pass: false, code: -1, output: buf + '\n[autosec] tests timed out', tests: parseTests(buf) });
    }, timeoutMs);
    child.stdout.on('data', (d) => (buf += d.toString()));
    child.stderr.on('data', (d) => (buf += d.toString()));
    child.on('close', (code) => {
      clearTimeout(timer);
      const lines = buf.split('\n');
      const tail = lines.slice(-400).join('\n');
      resolve({ pass: code === 0, code, output: tail, tests: parseTests(buf) });
    });
  });
}

// Strip ANSI color codes
function stripAnsi(s) {
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

/**
 * Best-effort parser for common Node test runners. Returns [{name, status, file?}].
 * Detection priority: TAP → Jest/Vitest file summary → mocha/jest checkmarks.
 */
function parseTests(raw) {
  const text = stripAnsi(raw);
  const lines = text.split('\n');
  const tests = [];
  const seen = new Set();
  const add = (name, status, file) => {
    const key = (file || '') + '::' + name + '::' + status;
    if (seen.has(key)) return;
    seen.add(key);
    tests.push({ name: name.trim(), status, file });
  };

  // --- TAP format: "ok 1 - description" / "not ok 2 - description"
  for (const line of lines) {
    const m = line.match(/^(not ok|ok)\s+\d+\s*-?\s*(.*?)(\s+#\s*(SKIP|TODO).*)?$/i);
    if (m) {
      const status = m[1].toLowerCase() === 'ok'
        ? (m[4] ? 'skip' : 'pass')
        : 'fail';
      add(m[2] || '(unnamed)', status);
    }
  }

  // --- Jest/Vitest per-file summary: "PASS  src/foo.test.js" / "FAIL ..." / "SKIP ..."
  for (const line of lines) {
    const m = line.match(/^\s*(PASS|FAIL|SKIP)\s+(\S+\.(test|spec)\.[jt]sx?)/);
    if (m) add(m[2], m[1] === 'PASS' ? 'pass' : (m[1] === 'FAIL' ? 'fail' : 'skip'), m[2]);
  }

  // --- mocha/jest verbose: "✓ name", "✗ name", "✘ name", "× name", "- name (skipped)"
  // Mocha also uses a leading number for failures: "  1) name"
  for (const line of lines) {
    const m = line.match(/^\s*([✓✔])\s+(.+?)(\s+\(\d+m?s\))?$/);
    if (m) { add(m[2], 'pass'); continue; }
    const f = line.match(/^\s*([✗✘×✖])\s+(.+?)(\s+\(\d+m?s\))?$/);
    if (f) { add(f[2], 'fail'); continue; }
    const s = line.match(/^\s*-\s+(.+?)\s*\((skipped|pending)\)\s*$/i);
    if (s) { add(s[1], 'skip'); continue; }
  }

  // --- Mocha numbered failure list: "  1) Suite > test name"
  // Only add if not already captured.
  for (const line of lines) {
    const m = line.match(/^\s*\d+\)\s+(.{4,})$/);
    if (m && /[A-Za-z]/.test(m[1]) && !/^Error:/.test(m[1])) {
      add(m[1], 'fail');
    }
  }

  return tests;
}
