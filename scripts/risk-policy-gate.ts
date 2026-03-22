#!/usr/bin/env npx tsx
// ============================================================================
// Risk Policy Gate — TypeScript alternative for complex logic
//
// Runs the same preflight checks as the shell version but with:
//   - Proper glob matching against harness.config.json patterns
//   - Type-safe JSON output
//   - Structured error handling
//
// Tailored for SSSAI security scanner (Python backend + React frontend).
//
// Usage: npx tsx scripts/risk-policy-gate.ts
//
// Environment variables (set by CI workflow):
//   EXPECTED_SHA          — PR head SHA from the CI event payload
//   BASE_REF              — PR base branch name (default: main)
//   STRICTNESS            — relaxed | standard | strict (default: relaxed)
//   REVIEW_AGENT_STATUS   — optional override from remediation loop
//   GITHUB_OUTPUT         — path to GitHub Actions output file
//   GITHUB_REPOSITORY     — owner/repo
// ============================================================================

import { execSync } from 'node:child_process';
import { readFileSync, appendFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

// --- Types ---

interface RiskTierDef {
  name: string;
  patterns: string[];
  requiredChecks: string[];
}

interface HarnessRiskConfig {
  version: string;
  riskTiers: {
    tier1: RiskTierDef;
    tier2: RiskTierDef;
    tier3: RiskTierDef;
  };
  docsDrift?: {
    trackedDocs?: string[];
    requireUpdateWithCodeChange?: boolean;
    exemptPatterns?: string[];
  };
  shaDiscipline?: {
    enabled?: boolean;
    enforceExactSha?: boolean;
  };
}

interface GateResult {
  sha: string;
  tier: 1 | 2 | 3;
  tierName: 'low' | 'medium' | 'high';
  requiredChecks: string[];
  changedFiles: {
    tier1: string[];
    tier2: string[];
    tier3: string[];
  };
  docsDrift: {
    detected: boolean;
    warning: string;
  };
  reviewAgentStatus: 'pending' | 'approved' | 'rejected' | 'skipped';
}

// --- Defaults (used when harness.config.json is missing or malformed) ---
// Patterns match SSSAI project structure: modules/, frontend/, docker/

const DEFAULT_CONFIG: HarnessRiskConfig = {
  version: '1.0.0',
  riskTiers: {
    tier1: {
      name: 'low',
      patterns: ['docs/**', '**/*.md', '**/*.txt', 'CHANGELOG*', 'LICENSE*', '.editorconfig', '.gitignore'],
      requiredChecks: ['lint', 'harness-smoke'],
    },
    tier2: {
      name: 'medium',
      patterns: [
        'modules/**/*.py',
        'frontend/src/**',
        'frontend/package.json',
        'frontend/package-lock.json',
        'scripts/**',
        'config/**',
        'templates/**',
        'tools/**',
        '*.py',
        '*.js',
        '*.jsx',
        '*.json',
        '*.yaml',
        '*.yml',
      ],
      requiredChecks: ['lint', 'test', 'build', 'structural-tests', 'review-agent', 'harness-smoke'],
    },
    tier3: {
      name: 'high',
      patterns: [
        'modules/api/auth.py',
        'modules/api/models.py',
        'modules/agent/scan_agent.py',
        'modules/infra/**',
        'modules/sandbox/**',
        'docker-compose.yml',
        'docker-compose.*.yml',
        'docker/**',
        '.github/**',
        'harness.config.json',
        '.env',
        '.env.*',
      ],
      requiredChecks: [
        'lint',
        'test',
        'build',
        'structural-tests',
        'review-agent',
        'harness-smoke',
        'manual-approval',
        'expanded-coverage',
      ],
    },
  },
  docsDrift: {
    trackedDocs: ['README.md', 'docs/**'],
    requireUpdateWithCodeChange: false,
  },
};

// --- Required checks per tier (full gate-enforced set) ---

const TIER_CHECKS: Record<number, string[]> = {
  1: ['lint', 'harness-smoke'],
  2: ['lint', 'test', 'build', 'structural-tests', 'review-agent', 'harness-smoke'],
  3: [
    'lint',
    'test',
    'build',
    'structural-tests',
    'review-agent',
    'harness-smoke',
    'manual-approval',
    'expanded-coverage',
  ],
};

// --- Glob matching ---

function globToRegex(pattern: string): RegExp {
  let regex = '^';
  let i = 0;

  while (i < pattern.length) {
    const char = pattern[i];
    const next = pattern[i + 1];

    if (char === '*' && next === '*') {
      if (pattern[i + 2] === '/') {
        regex += '(.+/)?';
        i += 3;
      } else {
        regex += '.*';
        i += 2;
      }
    } else if (char === '*') {
      regex += '[^/]*';
      i++;
    } else if (char === '?') {
      regex += '[^/]';
      i++;
    } else if (char === '.') {
      regex += '\\.';
      i++;
    } else {
      regex += char;
      i++;
    }
  }

  regex += '$';
  return new RegExp(regex);
}

function matchGlob(file: string, pattern: string): boolean {
  return globToRegex(pattern).test(file);
}

function matchesAny(file: string, patterns: string[]): boolean {
  return patterns.some((p) => matchGlob(file, p));
}

// --- Shell helpers ---

function git(...args: string[]): string {
  try {
    return execSync(`git ${args.join(' ')}`, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return '';
  }
}

function ghApi(endpoint: string, jq: string): string {
  try {
    return execSync(`gh api "${endpoint}" --jq '${jq}'`, {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
  } catch {
    return '';
  }
}

// --- Config reader ---

function loadConfig(repoRoot: string): HarnessRiskConfig {
  const configPath = join(repoRoot, 'harness.config.json');

  if (!existsSync(configPath)) {
    console.log('::notice::harness.config.json not found — using built-in defaults');
    return DEFAULT_CONFIG;
  }

  try {
    const raw = readFileSync(configPath, 'utf-8');
    const parsed = JSON.parse(raw);

    // Validate minimum expected structure
    if (!parsed.riskTiers?.tier1?.patterns || !parsed.riskTiers?.tier2?.patterns || !parsed.riskTiers?.tier3?.patterns) {
      console.log('::warning::harness.config.json has unexpected structure — merging with defaults');
      return {
        ...DEFAULT_CONFIG,
        ...parsed,
        riskTiers: {
          tier1: { ...DEFAULT_CONFIG.riskTiers.tier1, ...parsed.riskTiers?.tier1 },
          tier2: { ...DEFAULT_CONFIG.riskTiers.tier2, ...parsed.riskTiers?.tier2 },
          tier3: { ...DEFAULT_CONFIG.riskTiers.tier3, ...parsed.riskTiers?.tier3 },
        },
      };
    }

    return parsed as HarnessRiskConfig;
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.log(`::warning::Failed to parse harness.config.json: ${msg} — using defaults`);
    return DEFAULT_CONFIG;
  }
}

// ============================================================================
// Step 1: SHA Discipline
// ============================================================================
function verifySha(): string {
  const actualSha = git('rev-parse', 'HEAD');
  const expectedSha = process.env.EXPECTED_SHA ?? '';

  if (!expectedSha) {
    console.log('::notice::EXPECTED_SHA not set — skipping SHA discipline check (local mode)');
    return actualSha;
  }

  if (actualSha.toLowerCase() !== expectedSha.toLowerCase()) {
    console.error(
      `::error::SHA discipline violation: HEAD (${actualSha}) ≠ expected (${expectedSha}). ` +
        'The branch changed after this workflow was triggered. Re-run on the latest commit.',
    );
    process.exit(1);
  }

  console.log(`✔ SHA verified: ${actualSha.slice(0, 12)}`);
  return actualSha;
}

// ============================================================================
// Step 2: Changed File Classification
// ============================================================================
function classifyFiles(config: HarnessRiskConfig): {
  tier1: string[];
  tier2: string[];
  tier3: string[];
  maxTier: 1 | 2 | 3;
} {
  const baseRef = process.env.BASE_REF ?? 'main';

  if (!git('rev-parse', '--verify', `origin/${baseRef}`)) {
    git('fetch', 'origin', baseRef, '--depth=1');
  }

  const mergeBase = git('merge-base', `origin/${baseRef}`, 'HEAD');
  if (!mergeBase) {
    console.log(`::warning::Could not compute merge base against origin/${baseRef}. Defaulting to Tier 3.`);
    return { tier1: [], tier2: [], tier3: [], maxTier: 3 };
  }

  const diff = git('diff', '--name-only', `${mergeBase}...HEAD`);
  if (!diff) {
    console.log('::notice::No changed files detected. Defaulting to Tier 1.');
    return { tier1: [], tier2: [], tier3: [], maxTier: 1 };
  }

  const files = diff.split('\n').filter(Boolean);
  const tier1: string[] = [];
  const tier2: string[] = [];
  const tier3: string[] = [];

  const { tier1: t1, tier2: t2, tier3: t3 } = config.riskTiers;

  for (const file of files) {
    // Check tiers in descending order — highest match wins
    if (matchesAny(file, t3.patterns)) {
      tier3.push(file);
    } else if (matchesAny(file, t2.patterns)) {
      tier2.push(file);
    } else if (matchesAny(file, t1.patterns)) {
      tier1.push(file);
    } else {
      // Default: Tier 2 for unknown files
      tier2.push(file);
    }
  }

  const maxTier: 1 | 2 | 3 = tier3.length > 0 ? 3 : tier2.length > 0 ? 2 : 1;

  console.log(
    `✔ Classified files: ${tier1.length} tier-1, ${tier2.length} tier-2, ${tier3.length} tier-3 → overall Tier ${maxTier}`,
  );

  return { tier1, tier2, tier3, maxTier };
}

// ============================================================================
// Step 3: Required Checks
// ============================================================================
function computeChecks(tier: number): string[] {
  const checks = TIER_CHECKS[tier] ?? TIER_CHECKS[3];
  console.log(`✔ Required checks (${checks.length}): ${checks.join(', ')}`);
  return checks;
}

// ============================================================================
// Step 4: Docs Drift
// ============================================================================
function checkDocsDrift(
  strictness: string,
  changedFiles: { tier1: string[]; tier2: string[]; tier3: string[] },
): { detected: boolean; warning: string } {
  if (strictness === 'relaxed') {
    console.log('✔ Docs drift check skipped (strictness=relaxed)');
    return { detected: false, warning: '' };
  }

  const hasSource = changedFiles.tier2.length > 0 || changedFiles.tier3.length > 0;
  if (!hasSource) {
    console.log('✔ No source files changed — docs drift N/A');
    return { detected: false, warning: '' };
  }

  const hasDocs = changedFiles.tier1.some((f) => f.endsWith('.md') || f.startsWith('docs/'));

  if (!hasDocs) {
    const warning = 'Source files changed without documentation updates. Consider updating README.md or relevant docs.';

    if (strictness === 'strict') {
      console.error(`::error::Docs drift: ${warning}`);
      process.exit(1);
    } else {
      console.log(`::warning::Docs drift: ${warning}`);
    }

    return { detected: true, warning };
  }

  console.log('✔ Documentation updated alongside source changes');
  return { detected: false, warning: '' };
}

// ============================================================================
// Step 5: Review Agent Status
// ============================================================================
function checkReviewAgent(tier: number, sha: string): GateResult['reviewAgentStatus'] {
  if (tier < 2) {
    console.log('✔ Review agent: skipped (Tier 1)');
    return 'skipped';
  }

  const envStatus = process.env.REVIEW_AGENT_STATUS;
  if (envStatus) {
    console.log(`✔ Review agent: ${envStatus} (from env)`);
    return envStatus as GateResult['reviewAgentStatus'];
  }

  const repo = process.env.GITHUB_REPOSITORY;
  if (repo) {
    const conclusion = ghApi(
      `repos/${repo}/commits/${sha}/check-runs`,
      '.check_runs[] | select(.name == "review-agent") | .conclusion',
    )
      .split('\n')[0]
      ?.trim();

    if (conclusion === 'success') {
      console.log('✔ Review agent: approved');
      return 'approved';
    }
    if (conclusion === 'failure') {
      console.log('✔ Review agent: rejected');
      return 'rejected';
    }
  }

  console.log('✔ Review agent: pending');
  return 'pending';
}

// ============================================================================
// Step 6: Output
// ============================================================================
function outputResults(result: GateResult): void {
  console.log('');
  console.log('═══════════════════════════════════════════════════');
  console.log(' Risk Policy Gate Result');
  console.log('═══════════════════════════════════════════════════');
  console.log(JSON.stringify(result, null, 2));
  console.log('═══════════════════════════════════════════════════');

  const outputPath = process.env.GITHUB_OUTPUT;
  if (outputPath) {
    const lines = [
      `sha=${result.sha}`,
      `tier=${result.tier}`,
      `tier-name=${result.tierName}`,
      `required-checks=${JSON.stringify(result.requiredChecks)}`,
      `docs-drift=${result.docsDrift.detected}`,
      `review-agent-status=${result.reviewAgentStatus}`,
      `result<<GATE_EOF`,
      JSON.stringify(result, null, 2),
      'GATE_EOF',
    ];

    appendFileSync(outputPath, lines.join('\n') + '\n', 'utf-8');
    console.log('');
    console.log('✔ GitHub Actions outputs written');
  }
}

// ============================================================================
// Main
// ============================================================================
function main(): void {
  console.log('╔═════════════════════════════════════════════════╗');
  console.log('║       Risk Policy Gate — Preflight Check        ║');
  console.log('║            (TypeScript runner — SSSAI)           ║');
  console.log('╚═════════════════════════════════════════════════╝');
  console.log('');

  const repoRoot = git('rev-parse', '--show-toplevel') || process.cwd();
  const strictness = process.env.STRICTNESS ?? 'relaxed';
  const config = loadConfig(repoRoot);

  const sha = verifySha();
  const changedFiles = classifyFiles(config);
  const requiredChecks = computeChecks(changedFiles.maxTier);
  const docsDrift = checkDocsDrift(strictness, changedFiles);
  const reviewAgentStatus = checkReviewAgent(changedFiles.maxTier, sha);

  const tierNames: Record<number, GateResult['tierName']> = { 1: 'low', 2: 'medium', 3: 'high' };
  const result: GateResult = {
    sha,
    tier: changedFiles.maxTier,
    tierName: tierNames[changedFiles.maxTier] ?? 'high',
    requiredChecks,
    changedFiles: {
      tier1: changedFiles.tier1,
      tier2: changedFiles.tier2,
      tier3: changedFiles.tier3,
    },
    docsDrift,
    reviewAgentStatus,
  };

  outputResults(result);

  console.log('');
  console.log(
    `✔ Gate completed — Tier ${result.tier} (${result.tierName}) — ${requiredChecks.length} checks required`,
  );
}

main();
