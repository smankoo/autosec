import { spawn } from 'node:child_process';

/**
 * Run `npm test` in repoDir. Returns { pass, output (last ~200 lines), code }.
 */
export function verify(repoDir, { timeoutMs = 5 * 60 * 1000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn('npm', ['test', '--silent'], { cwd: repoDir, stdio: ['ignore', 'pipe', 'pipe'] });
    let buf = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      resolve({ pass: false, code: -1, output: buf + '\n[autosec] tests timed out' });
    }, timeoutMs);
    child.stdout.on('data', (d) => (buf += d.toString()));
    child.stderr.on('data', (d) => (buf += d.toString()));
    child.on('close', (code) => {
      clearTimeout(timer);
      const lines = buf.split('\n');
      const tail = lines.slice(-200).join('\n');
      resolve({ pass: code === 0, code, output: tail });
    });
  });
}
