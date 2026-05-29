import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const exec = promisify(execFile);

/**
 * Build migration context for a vuln:
 *   - changelog text between current and fixed version (best-effort)
 *   - call sites in the repo
 *   - test command from package.json
 */
export async function gatherContext(vuln, repoDir) {
  const repoMeta = await readPkgRepo(vuln.package, repoDir);
  const [changelog, callSites, testCommand] = await Promise.all([
    fetchChangelog(vuln, repoMeta),
    findCallSites(vuln.package, repoDir),
    readTestCommand(repoDir),
  ]);
  return { changelog, callSites, testCommand, repoMeta };
}

async function readTestCommand(repoDir) {
  try {
    const pkg = JSON.parse(await readFile(path.join(repoDir, 'package.json'), 'utf8'));
    return pkg.scripts?.test || null;
  } catch {
    return null;
  }
}

async function readPkgRepo(pkgName, repoDir) {
  // Try installed package's package.json first; fall back to npm registry.
  try {
    const installed = JSON.parse(
      await readFile(path.join(repoDir, 'node_modules', pkgName, 'package.json'), 'utf8'),
    );
    const url = normalizeRepoUrl(installed.repository);
    if (url) return url;
  } catch {}
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkgName)}`);
    if (res.ok) {
      const j = await res.json();
      const url = normalizeRepoUrl(j.repository);
      if (url) return url;
    }
  } catch {}
  return null;
}

function normalizeRepoUrl(repo) {
  if (!repo) return null;
  const url = typeof repo === 'string' ? repo : repo.url;
  if (!url) return null;
  const m = url.match(/github\.com[/:]([^/]+)\/([^/]+?)(?:\.git)?(?:[/#?].*)?$/i);
  if (!m) return null;
  return { host: 'github.com', owner: m[1], repo: m[2] };
}

async function fetchChangelog(vuln, meta) {
  if (!meta || meta.host !== 'github.com') {
    return { source: 'unavailable', text: '', notes: 'no GitHub repo metadata' };
  }
  try {
    const headers = { 'User-Agent': 'autosec' };
    if (process.env.GITHUB_TOKEN) headers.Authorization = `token ${process.env.GITHUB_TOKEN}`;
    const res = await fetch(
      `https://api.github.com/repos/${meta.owner}/${meta.repo}/releases?per_page=100`,
      { headers },
    );
    if (!res.ok) return { source: 'github-releases', text: '', notes: `http ${res.status}` };
    const releases = await res.json();
    const filtered = releases
      .filter((r) => r.tag_name)
      .map((r) => ({ tag: r.tag_name, name: r.name, body: r.body || '' }));
    const slice = sliceBetween(filtered, vuln.current, vuln.fixed, vuln.package);
    const text = slice
      .map((r) => `## ${r.tag}${r.name ? ` — ${r.name}` : ''}\n\n${r.body}`)
      .join('\n\n---\n\n');
    return { source: 'github-releases', text, notes: `${slice.length} releases` };
  } catch (e) {
    return { source: 'github-releases', text: '', notes: e.message };
  }
}

function sliceBetween(releases, current, fixed, pkgName) {
  const c = extractSemver(current);
  const f = extractSemver(fixed);
  if (!c || !f) return releases.slice(0, 5); // fallback: most recent few
  return releases.filter((r) => {
    const t = extractSemver(r.tag);
    if (!t) return false;
    if (pkgName && r.tag.includes('@')) {
      const tagPkg = r.tag.split('@')[0].replace(/^.*\//, '');
      const wantPkg = pkgName.replace(/^.*\//, '');
      if (tagPkg && tagPkg !== wantPkg) return false;
    }
    return cmp(t, c) > 0 && cmp(t, f) <= 0;
  });
}

function extractSemver(s) {
  if (!s) return null;
  const m = String(s).match(/(\d+)\.(\d+)\.(\d+)(?:-([\w.+-]+))?/);
  if (!m) return null;
  return `${m[1]}.${m[2]}.${m[3]}${m[4] ? '-' + m[4] : ''}`;
}

function cmp(a, b) {
  const pa = a.split(/[.+-]/).map((x) => parseInt(x, 10));
  const pb = b.split(/[.+-]/).map((x) => parseInt(x, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (Number.isNaN(x) || Number.isNaN(y)) return 0;
    if (x !== y) return x - y;
  }
  return 0;
}

async function findCallSites(pkgName, repoDir) {
  const patterns = [
    `require\\(['\"]${escape(pkgName)}['\"]\\)`,
    `from ['\"]${escape(pkgName)}['\"]`,
    `import ['\"]${escape(pkgName)}['\"]`,
  ];
  const args = [
    '-rEln',
    '--include=*.js',
    '--include=*.jsx',
    '--include=*.ts',
    '--include=*.tsx',
    '--include=*.mjs',
    '--include=*.cjs',
    '--exclude-dir=node_modules',
    '--exclude-dir=.git',
    '--exclude-dir=dist',
    '--exclude-dir=build',
    '--exclude-dir=.next',
    '--exclude-dir=coverage',
    patterns.join('|'),
    '.',
  ];
  try {
    const { stdout } = await exec('grep', args, { cwd: repoDir, maxBuffer: 10 * 1024 * 1024 });
    return stdout.split('\n').filter(Boolean);
  } catch (e) {
    if (e.code === 1) return []; // no matches
    return [];
  }
}

function escape(s) {
  return s.replace(/[/\\^$*+?.()|[\]{}]/g, '\\$&');
}
