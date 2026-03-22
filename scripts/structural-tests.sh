#!/usr/bin/env bash
# ============================================================================
# Structural Tests — Architectural Boundary Validation
#
# Validates that import dependencies between modules/ packages respect the
# dependency rules defined in CLAUDE.md:
#
#   - api/routes/ → api/models, api/auth, infra/
#   - worker/ → agent/, tools/, infra/
#   - infra/ has no internal dependencies
#   - Never import from worker/ or agent/ inside api/
#
# Also reads architecturalBoundaries from harness.config.json if defined.
#
# Exit 0: all boundaries respected.
# Exit 1: one or more violations found.
# ============================================================================
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
MODULES_DIR="${REPO_ROOT}/modules"
CONFIG_FILE="${REPO_ROOT}/harness.config.json"
VIOLATIONS=0

echo "╔═════════════════════════════════════════════════╗"
echo "║     Architectural Boundary Validation            ║"
echo "╚═════════════════════════════════════════════════╝"
echo ""

# ============================================================================
# Step 1: Validate harness.config.json exists
# ============================================================================
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "::error::harness.config.json not found at ${CONFIG_FILE}"
  exit 1
fi

echo "Config: ${CONFIG_FILE}"
echo ""

# ============================================================================
# Step 2: Enforce hardcoded dependency rules from CLAUDE.md
# ============================================================================
echo "--- Dependency Rules (from CLAUDE.md) ---"
echo ""

# Rule: api/ must never import from worker/ or agent/
echo "Checking: api/ must not import from worker/ or agent/"
if [[ -d "${MODULES_DIR}/api" ]]; then
  while IFS= read -r -d '' file; do
    while IFS=: read -r lineno line; do
      rel="${file#"$REPO_ROOT"/}"
      echo "::error file=${rel},line=${lineno}::api/ imports from worker/ or agent/: ${line}"
      ((VIOLATIONS++))
    done < <(grep -n -E "from modules\.(worker|agent)\b|import modules\.(worker|agent)\b" "$file" 2>/dev/null || true)
  done < <(find "${MODULES_DIR}/api" -name '*.py' -type f -print0)
  if (( VIOLATIONS == 0 )); then
    echo "  ✔ api/ does not import from worker/ or agent/"
  fi
fi

# Rule: infra/ must have no internal dependencies (no imports from other modules)
echo "Checking: infra/ must have no internal dependencies"
infra_violations=0
if [[ -d "${MODULES_DIR}/infra" ]]; then
  INTERNAL_MODULES="api|worker|agent|scheduler|monitor|heartbeat|notifications|reports|sandbox|tools"
  while IFS= read -r -d '' file; do
    while IFS=: read -r lineno line; do
      rel="${file#"$REPO_ROOT"/}"
      echo "::error file=${rel},line=${lineno}::infra/ has forbidden internal import: ${line}"
      ((VIOLATIONS++))
      ((infra_violations++))
    done < <(grep -n -E "from modules\.(${INTERNAL_MODULES})\b|import modules\.(${INTERNAL_MODULES})\b" "$file" 2>/dev/null || true)
  done < <(find "${MODULES_DIR}/infra" -name '*.py' -type f -print0)
  if (( infra_violations == 0 )); then
    echo "  ✔ infra/ has no internal dependencies"
  fi
fi

# ============================================================================
# Step 3: Check harness.config.json architectural boundaries (if defined)
# ============================================================================
BOUNDARY_COUNT=$(python3 -c "
import json
config = json.load(open('${CONFIG_FILE}'))
print(len(config.get('architecturalBoundaries', {})))
" 2>/dev/null || echo "0")

if (( BOUNDARY_COUNT > 0 )); then
  echo ""
  echo "--- Boundaries from harness.config.json (${BOUNDARY_COUNT} modules) ---"
  echo ""

  python3 -c "
import json, os, re, sys

config = json.load(open('${CONFIG_FILE}'))
boundaries = config.get('architecturalBoundaries', {})
violations = 0

for module, rules in boundaries.items():
    allowed = set(rules.get('allowedImports', []))
    module_dir = os.path.join('${MODULES_DIR}', module)
    if not os.path.isdir(module_dir):
        continue

    module_violations = 0
    for root, dirs, files in os.walk(module_dir):
        for fname in files:
            if not fname.endswith('.py'):
                continue
            fpath = os.path.join(root, fname)
            with open(fpath) as f:
                for i, line in enumerate(f, 1):
                    m = re.search(r'from modules\.(\w+)', line)
                    if not m:
                        m = re.search(r'import modules\.(\w+)', line)
                    if not m:
                        continue
                    target = m.group(1)
                    if target == module:
                        continue
                    if target not in allowed:
                        rel = os.path.relpath(fpath, '${REPO_ROOT}')
                        print(f'::error file={rel},line={i}::{module}/ cannot import from {target}/ (allowed: {sorted(allowed) or \"none\"})')
                        violations += 1
                        module_violations += 1

    if module_violations == 0:
        print(f'  ✔ {module}/ → allowed: [{", ".join(sorted(allowed)) or \"none\"}]')
    else:
        print(f'  ✘ {module}/ → {module_violations} violation(s)')

sys.exit(1 if violations > 0 else 0)
"
  boundary_exit=$?
  if (( boundary_exit != 0 )); then
    ((VIOLATIONS++))
  fi
else
  echo ""
  echo "No architecturalBoundaries defined in harness.config.json — skipping config-based checks."
fi

# ============================================================================
# Step 4: Check Python file naming conventions (snake_case)
# ============================================================================
echo ""
echo "--- File Naming Conventions ---"
echo ""
naming_warnings=0
while IFS= read -r -d '' file; do
  basename=$(basename "$file" .py)
  if [[ "$basename" =~ [A-Z] ]] && [[ "$basename" != "__"* ]]; then
    rel="${file#"$REPO_ROOT"/}"
    echo "::warning file=${rel}::Python file uses PascalCase: ${basename}.py (should be snake_case)"
    ((naming_warnings++))
  fi
done < <(find "${MODULES_DIR}" -name '*.py' -type f -print0)

if (( naming_warnings == 0 )); then
  echo "  ✔ All Python files use snake_case naming"
else
  echo "  ⚠ ${naming_warnings} naming convention warning(s) (non-blocking)"
fi

# ============================================================================
# Step 5: Report results
# ============================================================================
echo ""
if (( VIOLATIONS > 0 )); then
  echo "✘ Found ${VIOLATIONS} architectural boundary violation(s)"
  echo ""
  echo "To fix: update the import to respect the dependency rules in CLAUDE.md,"
  echo "or update architecturalBoundaries in harness.config.json if intentional."
  exit 1
else
  echo "✔ All architectural boundaries respected"
fi
