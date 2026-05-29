import { readdir, stat, mkdir, copyFile, access } from 'node:fs/promises';
import path from 'node:path';

/**
 * Walk node_modules and find every native binding (*.node) the runtime would load.
 * Returns relative paths from `repoDir`.
 */
export async function findNativeBindings(repoDir) {
  const root = path.join(repoDir, 'node_modules');
  const found = [];
  await walk(root, repoDir, found, 0);
  return found;
}

async function walk(dir, repoDir, out, depth) {
  if (depth > 12) return;
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); }
  catch { return; }
  for (const ent of entries) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      // Skip nested node_modules at depth > 0 only briefly to avoid pathological depth;
      // native bindings can live anywhere so we still descend.
      await walk(p, repoDir, out, depth + 1);
    } else if (ent.isFile() && ent.name.endsWith('.node')) {
      out.push(path.relative(repoDir, p));
    }
  }
}

/**
 * Copy each binding from repoDir to a sidecar snapshot directory.
 * Returns the snapshot dir path.
 */
export async function snapshotNatives(repoDir, snapshotDir) {
  const bindings = await findNativeBindings(repoDir);
  await mkdir(snapshotDir, { recursive: true });
  for (const rel of bindings) {
    const src = path.join(repoDir, rel);
    const dst = path.join(snapshotDir, rel);
    await mkdir(path.dirname(dst), { recursive: true });
    try { await copyFile(src, dst); } catch {}
  }
  return { snapshotDir, count: bindings.length, paths: bindings };
}

/**
 * For every binding present in `snapshotDir` that is now missing in `repoDir`,
 * copy it back. Returns the list of restored paths.
 */
export async function restoreMissingNatives(repoDir, snapshotDir) {
  const restored = [];
  const snapshotted = [];
  await walk(snapshotDir, snapshotDir, snapshotted, 0);
  for (const rel of snapshotted) {
    const target = path.join(repoDir, rel);
    if (await exists(target)) continue;
    const src = path.join(snapshotDir, rel);
    try {
      await mkdir(path.dirname(target), { recursive: true });
      await copyFile(src, target);
      restored.push(rel);
    } catch {}
  }
  return restored;
}

async function exists(p) {
  try { await access(p); return true; } catch { return false; }
}
