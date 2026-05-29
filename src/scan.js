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

  // npm audit's `fixAvailable.name` is the package you actually have to bump,
  // which may be a *parent* of the vulnerable package. Several transitive
  // vulns can resolve to the same parent bump, so we dedupe by bump target.
  const byBumpTarget = new Map(); // "name@version" -> aggregated entry
  const vulns = data.vulnerabilities || {};
  for (const [pkg, v] of Object.entries(vulns)) {
    if (!v.fixAvailable || typeof v.fixAvailable !== 'object') continue;
    const bumpName = v.fixAvailable.name;
    const bumpVersion = v.fixAvailable.version;
    if (!bumpName || !bumpVersion) continue;

    const installed = await readInstalledVersion(repoDir, bumpName);
    if (installed && cmpSemver(installed, bumpVersion) >= 0) continue;

    const advisory = (v.via || []).find((x) => typeof x === 'object') || {};
    const key = `${bumpName}@${bumpVersion}`;
    let entry = byBumpTarget.get(key);
    if (!entry) {
      entry = {
        package: bumpName,
        current: installed,
        fixed: bumpVersion,
        severity: v.severity,
        severityRank: SEVERITY_RANK[v.severity] ?? 0,
        advisoryUrl: advisory.url || null,
        title: advisory.title || null,
        isMajorBump: !!v.fixAvailable.isSemVerMajor,
        // Track which audit-key vulns this single bump resolves.
        fixesVulnsIn: [],
      };
      byBumpTarget.set(key, entry);
    }
    if (!entry.fixesVulnsIn.includes(pkg)) entry.fixesVulnsIn.push(pkg);
    // Promote severity if a transitive entry has a higher one than the parent's first hit.
    const sevRank = SEVERITY_RANK[v.severity] ?? 0;
    if (sevRank > entry.severityRank) {
      entry.severity = v.severity;
      entry.severityRank = sevRank;
    }
    // Keep the most informative advisory title/url we see.
    if (!entry.advisoryUrl && advisory.url) entry.advisoryUrl = advisory.url;
    if (!entry.title && advisory.title) entry.title = advisory.title;
  }
  return [...byBumpTarget.values()];
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
