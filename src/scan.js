import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const exec = promisify(execFile);

const SEVERITY_RANK = { critical: 4, high: 3, moderate: 2, low: 1, info: 0 };

/**
 * Run `npm audit --json` in repoDir and normalize the result.
 * Returns: [{ package, current, fixed, severity, severityRank, advisoryUrl, title, via }]
 */
export async function scan(repoDir) {
  let stdout = '';
  try {
    const r = await exec('npm', ['audit', '--json'], { cwd: repoDir, maxBuffer: 50 * 1024 * 1024 });
    stdout = r.stdout;
  } catch (e) {
    // npm audit exits non-zero when vulns are found; stdout still has JSON.
    stdout = e.stdout || '';
    if (!stdout) throw new Error(`npm audit failed: ${e.message}`);
  }

  let data;
  try {
    data = JSON.parse(stdout);
  } catch {
    throw new Error('npm audit did not produce JSON');
  }

  const out = [];
  const vulns = data.vulnerabilities || {};
  for (const [pkg, v] of Object.entries(vulns)) {
    if (!v.fixAvailable) continue;
    const fixed = typeof v.fixAvailable === 'object' ? v.fixAvailable.version : null;
    if (!fixed) continue;
    const advisory = (v.via || []).find((x) => typeof x === 'object') || {};
    const installed = await readInstalledVersion(repoDir, pkg);
    if (installed && cmpSemver(installed, fixed) >= 0) continue; // already at/above fix
    out.push({
      package: pkg,
      current: installed,
      fixed,
      severity: v.severity,
      severityRank: SEVERITY_RANK[v.severity] ?? 0,
      advisoryUrl: advisory.url || null,
      title: advisory.title || null,
      isMajorBump: !!(typeof v.fixAvailable === 'object' && v.fixAvailable.isSemVerMajor),
    });
  }
  return out;
}

function cmpSemver(a, b) {
  const pa = String(a).match(/\d+/g)?.map(Number) || [];
  const pb = String(b).match(/\d+/g)?.map(Number) || [];
  for (let i = 0; i < 3; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x - y;
  }
  return 0;
}

async function readInstalledVersion(repoDir, pkg) {
  try {
    const p = JSON.parse(
      await readFile(path.join(repoDir, 'node_modules', pkg, 'package.json'), 'utf8'),
    );
    return p.version || null;
  } catch {
    return null;
  }
}
