#!/usr/bin/env node
import { Command } from 'commander';
import { run } from '../src/orchestrator.js';

const program = new Command();

program
  .name('autosec')
  .description('Autonomous dependency vulnerability remediation agent')
  .version('0.1.0');

program
  .command('run <repoUrl>')
  .description('Scan, fix one vuln, open a PR')
  .option('--dry-run', 'Scan + triage + context only; do not invoke agent or open PR')
  .option('--max-iters <n>', 'Max agent fix iterations', '5')
  .option('--branch-base <name>', 'Base branch to PR against', 'main')
  .option('--target <pkg>', 'Force triage to pick this package (must appear in scan)')
  .option('--no-push', 'Commit locally and print the would-be PR body, but do not push or open a PR')
  .action(async (repoUrl, opts) => {
    try {
      const result = await run({
        repoUrl,
        dryRun: !!opts.dryRun,
        maxIters: parseInt(opts.maxIters, 10),
        branchBase: opts.branchBase,
        target: opts.target,
        push: opts.push !== false,
      });
      console.log(JSON.stringify(result, null, 2));
    } catch (err) {
      console.error('autosec failed:', err.message);
      process.exit(1);
    }
  });

program.parseAsync();
