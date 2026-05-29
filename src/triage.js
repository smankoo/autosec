import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const exec = promisify(execFile);

/**
 * Pick the best vuln to fix:
 *   - prefer direct dependencies of the repo (transitive bumps usually need upstream fixes)
 *   - then highest severity
 *   - skip anything already covered by an open autosec PR
 */
export async function triage(vulns, { repoDir }) {
  if (!vulns.length) return null;
  const direct = await readDirectDeps(repoDir);
  const openPRs = await listOpenAutosecPRs(repoDir);
  const taken = new Set(openPRs.map((p) => p.headRefName));

  const annotated = vulns.map((v) => ({ ...v, isDirect: direct.has(v.package) }));
  const sorted = annotated.sort((a, b) => {
    if (a.isDirect !== b.isDirect) return a.isDirect ? -1 : 1;
    return b.severityRank - a.severityRank;
  });
  for (const v of sorted) {
    const branch = autosecBranchName(v);
    if (!taken.has(branch)) return v;
  }
  return null;
}

async function readDirectDeps(repoDir) {
  try {
    const pkg = JSON.parse(await readFile(path.join(repoDir, 'package.json'), 'utf8'));
    const all = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
      ...(pkg.optionalDependencies || {}),
      ...(pkg.peerDependencies || {}),
    };
    return new Set(Object.keys(all));
  } catch {
    return new Set();
  }
}

export function autosecBranchName(vuln) {
  const safe = vuln.package.replace(/[^a-zA-Z0-9._-]/g, '-');
  return `autosec/${safe}-${vuln.fixed}`;
}

async function listOpenAutosecPRs(repoDir) {
  try {
    const { stdout } = await exec(
      'gh',
      ['pr', 'list', '--state', 'open', '--json', 'headRefName,number,title', '--limit', '200'],
      { cwd: repoDir },
    );
    const arr = JSON.parse(stdout);
    return arr.filter((p) => p.headRefName?.startsWith('autosec/'));
  } catch {
    // gh missing or unauth — treat as no open PRs; surface in caller logs.
    return [];
  }
}
