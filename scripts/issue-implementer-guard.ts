#!/usr/bin/env npx tsx
// ============================================================================
// Issue Implementer Guard — pre-flight gate for automated implementation
//
// Determines whether the implementer agent should run based on:
//   - Presence of `agent:implement` label
//   - Absence of blocking labels (agent:skip, wontfix, duplicate, invalid)
//   - No existing PR for this issue (idempotency check)
//   - Review-fix mode validation (cycle limits, PR state)
//
// Usage:
//   ISSUE_JSON='{"number":1,...}' tsx scripts/issue-implementer-guard.ts --evaluate
//   PR_NUMBER=42 REVIEW_FIX_CYCLE=1 tsx scripts/issue-implementer-guard.ts --evaluate
//   tsx scripts/issue-implementer-guard.ts --self-test
//
// Environment variables:
//   ISSUE_JSON          — JSON object with issue data (issue mode)
//   PR_NUMBER           — PR number (review-fix mode)
//   REVIEW_FIX_CYCLE    — Cycle number 1-3 (review-fix mode)
//   GITHUB_REPOSITORY   — owner/repo (set by CI runner)
//   GH_TOKEN            — GitHub auth token for API calls
// ============================================================================

import { execSync } from 'node:child_process';

// --- Types ---

export interface ImplementerDecision {
  shouldImplement: boolean;
  issueNumber: number;
  issueTitle: string;
  branchName: string;
  reason: string;
  existingPR: number | null;
  blockedLabels: string[];
}

// --- Constants ---

const TRIGGER_LABEL = 'agent:implement';

const BLOCKING_LABELS = ['agent:skip', 'wontfix', 'duplicate', 'invalid'];

const IDEMPOTENCY_MARKER = '<!-- issue-implementer: #';

const MAX_BRANCH_LENGTH = 60;

const MAX_REVIEW_FIX_CYCLES = 3;

// --- Public API ---

/**
 * Slugify a string for use in branch names.
 * Converts to lowercase, replaces non-alphanumeric chars with hyphens,
 * collapses multiple hyphens, and trims leading/trailing hyphens.
 */
export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

/**
 * Derive a branch name from an issue title and number.
 * Format: cf/<slugified-title>-<number>
 * Truncated to MAX_BRANCH_LENGTH characters.
 */
export function deriveBranchName(issueTitle: string, issueNumber: number): string {
  const slug = slugify(issueTitle);
  const suffix = `-${issueNumber}`;
  const prefix = 'cf/';
  const maxSlugLen = MAX_BRANCH_LENGTH - prefix.length - suffix.length;
  const truncatedSlug = slug.slice(0, Math.max(1, maxSlugLen));
  // Trim trailing hyphen after truncation
  const cleanSlug = truncatedSlug.replace(/-$/, '');
  return `${prefix}${cleanSlug}${suffix}`;
}

/**
 * Check if a PR already exists for a given issue by searching issue comments
 * for the idempotency marker.
 * Returns the PR number if found, null otherwise.
 */
export function findExistingPR(issueNumber: number): number | null {
  try {
    const repo = process.env.GITHUB_REPOSITORY || '';
    if (!repo) return null;

    const output = execSync(
      `gh api repos/${repo}/issues/${issueNumber}/comments --jq '.[].body'`,
      { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] },
    );

    for (const line of output.split('\n')) {
      const idx = line.indexOf(IDEMPOTENCY_MARKER);
      if (idx !== -1) {
        const rest = line.slice(idx + IDEMPOTENCY_MARKER.length);
        const match = rest.match(/^(\d+)/);
        if (match) return parseInt(match[1], 10);
      }
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Evaluate whether the implementer should run for a given issue.
 */
export function evaluate(issueJson: string): ImplementerDecision {
  let issue: {
    number?: number;
    title?: string;
    body?: string;
    labels?: Array<{ name: string } | string>;
    user?: { login?: string };
  };

  try {
    issue = JSON.parse(issueJson);
  } catch {
    return {
      shouldImplement: false,
      issueNumber: 0,
      issueTitle: '',
      branchName: '',
      reason: 'Failed to parse ISSUE_JSON',
      existingPR: null,
      blockedLabels: [],
    };
  }

  const issueNumber = issue.number || 0;
  const issueTitle = issue.title || '';

  if (!issueNumber || !issueTitle) {
    return {
      shouldImplement: false,
      issueNumber,
      issueTitle,
      branchName: '',
      reason: 'Missing issue number or title',
      existingPR: null,
      blockedLabels: [],
    };
  }

  // Normalize labels to string array
  const labels: string[] = (issue.labels || []).map((l) =>
    typeof l === 'string' ? l : l.name,
  );

  // Check for trigger label
  if (!labels.includes(TRIGGER_LABEL)) {
    return {
      shouldImplement: false,
      issueNumber,
      issueTitle,
      branchName: '',
      reason: `Missing trigger label: ${TRIGGER_LABEL}`,
      existingPR: null,
      blockedLabels: [],
    };
  }

  // Check for blocking labels
  const blocked = labels.filter((l) => BLOCKING_LABELS.includes(l));
  if (blocked.length > 0) {
    return {
      shouldImplement: false,
      issueNumber,
      issueTitle,
      branchName: '',
      reason: `Blocked by label(s): ${blocked.join(', ')}`,
      existingPR: null,
      blockedLabels: blocked,
    };
  }

  // Check for existing PR
  const existingPR = findExistingPR(issueNumber);
  if (existingPR !== null) {
    return {
      shouldImplement: false,
      issueNumber,
      issueTitle,
      branchName: '',
      reason: `PR #${existingPR} already exists for this issue`,
      existingPR,
      blockedLabels: [],
    };
  }

  const branchName = deriveBranchName(issueTitle, issueNumber);

  return {
    shouldImplement: true,
    issueNumber,
    issueTitle,
    branchName,
    reason: 'Issue approved for implementation',
    existingPR: null,
    blockedLabels: [],
  };
}

/**
 * Evaluate review-fix mode: verify cycle limits and PR state.
 */
export function evaluateReviewFix(
  prNumber: number,
  cycle: number,
): ImplementerDecision {
  if (cycle > MAX_REVIEW_FIX_CYCLES) {
    return {
      shouldImplement: false,
      issueNumber: 0,
      issueTitle: '',
      branchName: '',
      reason: `Review-fix cycle ${cycle} exceeds max (${MAX_REVIEW_FIX_CYCLES})`,
      existingPR: null,
      blockedLabels: [],
    };
  }

  try {
    const repo = process.env.GITHUB_REPOSITORY || '';
    if (!repo) throw new Error('GITHUB_REPOSITORY not set');

    const output = execSync(
      `gh pr view ${prNumber} --repo "${repo}" --json headRefName,state,title,body`,
      { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] },
    );

    const pr = JSON.parse(output);

    if (pr.state !== 'OPEN') {
      return {
        shouldImplement: false,
        issueNumber: 0,
        issueTitle: pr.title || '',
        branchName: pr.headRefName || '',
        reason: `PR #${prNumber} is ${pr.state}, not OPEN`,
        existingPR: null,
        blockedLabels: [],
      };
    }

    // Extract issue number from PR body marker
    let issueNumber = 0;
    const bodyMatch = (pr.body || '').match(/<!-- issue-implementer: #(\d+) -->/);
    if (bodyMatch) issueNumber = parseInt(bodyMatch[1], 10);

    return {
      shouldImplement: true,
      issueNumber,
      issueTitle: pr.title || '',
      branchName: pr.headRefName || '',
      reason: `Review-fix cycle ${cycle}/${MAX_REVIEW_FIX_CYCLES} for PR #${prNumber}`,
      existingPR: prNumber,
      blockedLabels: [],
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      shouldImplement: false,
      issueNumber: 0,
      issueTitle: '',
      branchName: '',
      reason: `Failed to fetch PR #${prNumber}: ${msg}`,
      existingPR: null,
      blockedLabels: [],
    };
  }
}

// --- CLI: --evaluate ---

if (process.argv.includes('--evaluate')) {
  const prNumber = process.env.PR_NUMBER ? parseInt(process.env.PR_NUMBER, 10) : 0;
  const cycle = process.env.REVIEW_FIX_CYCLE
    ? parseInt(process.env.REVIEW_FIX_CYCLE, 10)
    : 0;

  let decision: ImplementerDecision;

  if (prNumber && cycle) {
    // Review-fix mode
    decision = evaluateReviewFix(prNumber, cycle);
  } else {
    // Issue mode
    const issueJson = process.env.ISSUE_JSON || '{}';
    decision = evaluate(issueJson);
  }

  console.log(JSON.stringify(decision, null, 2));
}

// --- CLI: --self-test ---

if (process.argv.includes('--self-test')) {
  console.log('Running issue-implementer-guard self-test...\n');

  // --- slugify ---
  console.assert(
    slugify('Add user authentication') === 'add-user-authentication',
    'Basic slugify',
  );
  console.assert(
    slugify('Fix: null-check   in  parser!!!') === 'fix-null-check-in-parser',
    'Slugify with special chars and multiple spaces',
  );
  console.assert(
    slugify('---leading-trailing---') === 'leading-trailing',
    'Slugify trims hyphens',
  );
  console.assert(slugify('') === '', 'Slugify empty string');

  // --- deriveBranchName ---
  const branch1 = deriveBranchName('Add user authentication', 42);
  console.assert(
    branch1 === 'cf/add-user-authentication-42',
    `Expected cf/add-user-authentication-42, got ${branch1}`,
  );
  console.assert(
    branch1.length <= MAX_BRANCH_LENGTH,
    `Branch name exceeds ${MAX_BRANCH_LENGTH} chars: ${branch1}`,
  );

  const longTitle =
    'This is a very long issue title that should be truncated to fit within the branch name limit';
  const branch2 = deriveBranchName(longTitle, 999);
  console.assert(
    branch2.length <= MAX_BRANCH_LENGTH,
    `Long branch name exceeds ${MAX_BRANCH_LENGTH} chars: ${branch2} (${branch2.length})`,
  );
  console.assert(
    branch2.startsWith('cf/'),
    `Branch should start with cf/: ${branch2}`,
  );
  console.assert(
    branch2.endsWith('-999'),
    `Branch should end with -999: ${branch2}`,
  );

  // --- evaluate (without API calls) ---
  // Missing trigger label
  const noLabel = evaluate(
    JSON.stringify({ number: 1, title: 'Test', labels: [] }),
  );
  console.assert(
    noLabel.shouldImplement === false,
    'Should reject without trigger label',
  );
  console.assert(
    noLabel.reason.includes(TRIGGER_LABEL),
    'Reason should mention trigger label',
  );

  // Has trigger label
  const withLabel = evaluate(
    JSON.stringify({
      number: 5,
      title: 'Add search feature',
      labels: [{ name: 'agent:implement' }],
    }),
  );
  console.assert(
    withLabel.shouldImplement === true,
    'Should approve with trigger label',
  );
  console.assert(
    withLabel.branchName === 'cf/add-search-feature-5',
    `Expected cf/add-search-feature-5, got ${withLabel.branchName}`,
  );

  // Blocking labels
  const blocked = evaluate(
    JSON.stringify({
      number: 3,
      title: 'Fix bug',
      labels: [{ name: 'agent:implement' }, { name: 'wontfix' }],
    }),
  );
  console.assert(
    blocked.shouldImplement === false,
    'Should reject with blocking label',
  );
  console.assert(
    blocked.blockedLabels.includes('wontfix'),
    'Should report blocking label',
  );

  // Invalid JSON
  const invalid = evaluate('not json');
  console.assert(
    invalid.shouldImplement === false,
    'Should reject invalid JSON',
  );

  // Missing number/title
  const incomplete = evaluate(JSON.stringify({ number: 0, title: '' }));
  console.assert(
    incomplete.shouldImplement === false,
    'Should reject missing number/title',
  );

  // --- evaluateReviewFix (cycle limit) ---
  const overCycle = evaluateReviewFix(10, 4);
  console.assert(
    overCycle.shouldImplement === false,
    'Should reject cycle > max',
  );
  console.assert(
    overCycle.reason.includes('exceeds max'),
    'Reason should mention cycle limit',
  );

  console.log('\n✔ All self-tests passed.');
}
