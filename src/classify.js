/**
 * Classify a verify result against its baseline.
 *
 * Returns one of:
 *   - 'pass'                 : verify passed
 *   - 'regression'            : baseline passed, verify failed *due to test logic*
 *   - 'pre-existing-failure' : baseline already failed
 *   - 'environment-broken'   : verify failed because the test environment broke
 *                              (e.g. missing native binding, runner crash) and
 *                              the failures look symptomatic of env, not the bump
 */
export function classifyVerify({ baseline, verify }) {
  if (verify.pass) return { label: 'pass', reason: 'all tests green' };

  const envSignal = detectEnvironmentBreakage(verify.output || '');
  if (envSignal.matched) {
    // Environment-broken takes precedence even if baseline passed —
    // the bump didn't introduce assertion failures, it broke the runner.
    return {
      label: 'environment-broken',
      reason: envSignal.reason,
      hint: envSignal.hint,
    };
  }

  if (!baseline.pass) {
    return { label: 'pre-existing-failure', reason: 'baseline was already failing' };
  }
  return { label: 'regression', reason: 'baseline passed; verify failed' };
}

function detectEnvironmentBreakage(output) {
  const text = output || '';

  // Missing native binding (canvas, sharp, better-sqlite3, etc.)
  const nativeMissing = text.match(/Cannot find module ['"]([^'"]*\.node)['"]/);
  if (nativeMissing) {
    return {
      matched: true,
      reason: `Test runner cannot load native binding "${nativeMissing[1]}"`,
      hint: 'Native module was likely re-extracted by a post-bump install without recompiling. Snapshotting .node files before the agent runs and restoring missing ones afterward avoids this.',
    };
  }

  // Missing peer/transitive package the agent's install dropped. Common when
  // the agent uses --legacy-peer-deps (which we explicitly forbid) or when a
  // peer dep is silently omitted. Same shape as missing native binding: the
  // runner crashes during loader, not during assertions.
  const moduleMissing = text.match(/Cannot find module ['"]([^'"]+)['"]/);
  if (moduleMissing && !moduleMissing[1].endsWith('.node')) {
    const m = moduleMissing[1];
    if (/^(@testing-library\/|jest-|@jest\/|@types\/|@swc\/|@babel\/|babel-|ts-jest|ts-node|tsx)/.test(m)) {
      return {
        matched: true,
        reason: `Test runner cannot resolve "${m}" — peer/transitive package is missing from node_modules`,
        hint: `Likely the install dropped this peer dep (e.g. via --legacy-peer-deps). Re-run install without that flag, or include the peer in the bump set.`,
      };
    }
  }

  // Generic "test suite failed to run" with no actual assertions executed.
  // Jest signals this with "Test suite failed to run" + "Tests: 0 total".
  if (/Test suite failed to run/i.test(text) && /Tests:\s+0 total/.test(text)) {
    return {
      matched: true,
      reason: 'Test suite failed to load (no tests executed)',
      hint: 'The runner crashed before executing assertions. This is rarely caused by a dependency bump itself.',
    };
  }

  // node-gyp / native compile errors during test bootstrap
  if (/gyp\s+ERR!|node-pre-gyp\s+ERR!/.test(text) && /no member named|undeclared identifier/i.test(text)) {
    return {
      matched: true,
      reason: 'Native module compilation failed (node-gyp / V8 ABI mismatch)',
      hint: 'A native module is incompatible with the host Node version. Not caused by the dependency bump.',
    };
  }

  return { matched: false };
}
