import { createHash } from 'node:crypto';
import { readFile, mkdir, stat, access } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import os from 'node:os';

const exec = promisify(execFile);

export const NPM_CACHE_DIR = path.join(os.homedir(), '.autosec', 'npm-cache');
export const NODE_MODULES_CACHE_DIR = path.join(os.homedir(), '.autosec', 'node-modules-cache');

/**
 * Build a cache key from the repo's lockfile + node binary path.
 * Different node versions produce different node_modules contents (native
 * bindings, etc.), so we key on both.
 */
export async function nodeModulesCacheKey(repoDir, nodeBinHint) {
  const lockCandidates = ['package-lock.json', 'npm-shrinkwrap.json'];
  let lockContent = null;
  for (const f of lockCandidates) {
    try {
      lockContent = await readFile(path.join(repoDir, f), 'utf8');
      break;
    } catch {}
  }
  if (!lockContent) return null;
  const h = createHash('sha256');
  h.update(lockContent);
  h.update('|');
  h.update(nodeBinHint || process.version);
  h.update('|');
  // arch matters for native bindings
  h.update(process.arch + '-' + process.platform);
  return h.digest('hex').slice(0, 24);
}

export async function exists(p) {
  try { await access(p); return true; } catch { return false; }
}

/**
 * Hardlink-copy a cached node_modules tree into repoDir. On macOS APFS this is
 * effectively instant (clone-on-write); on Linux ext4 hardlinks are nearly so.
 */
export async function restoreNodeModules(cacheKey, repoDir) {
  const src = path.join(NODE_MODULES_CACHE_DIR, cacheKey);
  if (!(await exists(src))) return false;
  const dst = path.join(repoDir, 'node_modules');
  // -R preserves structure, -c uses APFS clone on macOS, -l falls back to hardlink on Linux.
  // Try the fast path first, then fall back.
  for (const flags of [['-R', '-c'], ['-R', '-l'], ['-R']]) {
    try {
      await exec('cp', [...flags, src + '/.', dst]);
      return true;
    } catch {}
  }
  return false;
}

/**
 * Snapshot the freshly-installed node_modules to the cache. Best-effort —
 * failures here are non-fatal (we just won't get a cache hit next time).
 */
export async function snapshotNodeModules(cacheKey, repoDir) {
  const src = path.join(repoDir, 'node_modules');
  if (!(await exists(src))) return false;
  const dst = path.join(NODE_MODULES_CACHE_DIR, cacheKey);
  if (await exists(dst)) return false; // already cached
  await mkdir(NODE_MODULES_CACHE_DIR, { recursive: true });
  for (const flags of [['-R', '-c'], ['-R', '-l'], ['-R']]) {
    try {
      await exec('cp', [...flags, src + '/.', dst]);
      return true;
    } catch {}
  }
  return false;
}

/**
 * `npm ci` if a lockfile exists (faster, deterministic), otherwise `npm install`.
 */
export function preferredInstallCmd(hasLockfile) {
  return hasLockfile ? 'ci' : 'install';
}

export async function hasLockfile(repoDir) {
  for (const f of ['package-lock.json', 'npm-shrinkwrap.json']) {
    if (await exists(path.join(repoDir, f))) return true;
  }
  return false;
}
