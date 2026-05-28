#!/usr/bin/env bash
#
# CWEFT anonymization helper.
#
# Run this from the ROOT of a COPY of your project (never the original) before
# pushing for double-blind review. It (1) scans for identifying strings so you
# can see what's there, then (2) optionally rewrites common ones.
#
# Usage:
#   ./anonymize.sh scan      # just report what identifying strings exist
#   ./anonymize.sh clean     # rewrite the known identifiers (edit the maps below first)
#
# ALWAYS run `scan` first and read the output. Then edit the REPLACEMENTS below
# to match what scan found, then run `clean`. Re-run `scan` to confirm it's clean.

set -euo pipefail

# ---- Things to search for (add anything scan surfaces that you missed) -------
PATTERNS=(
  "anon"
  "anon"
  "Anon"
  "Anon"
  "anon"
  "anonanon"
  "@gmail.com"
  "/home/anon"
  "Anon@"          # the WSL hostname in prompts
)

# ---- Replacements applied by `clean` (LHS -> RHS) ---------------------------
# Edit RHS values if you prefer different placeholders.
declare -A REPLACEMENTS=(
  ["/home/anon/CWEFT/cweft"]="/home/anon/cweft"
  ["/home/anon"]="/home/anon"
  ["anon@example.com"]="anon@example.com"
  ["anon"]="anon"
  ["Anon"]="Anon"
  ["anon"]="anon"
  ["Anon"]="Anon"
  ["anon"]="anon"
)

# Files to process (text only; skip binaries, venvs, .git, backups)
FIND_FILES() {
  find . \
    -type f \
    \( -name '*.py' -o -name '*.md' -o -name '*.txt' -o -name '*.csv' \
       -o -name '*.json' -o -name '*.toml' -o -name '*.cfg' -o -name '*.yml' \
       -o -name '*.yaml' -o -name '*.sh' -o -name '*.tex' \) \
    -not -path './.git/*' \
    -not -path './*venv*/*' \
    -not -path './logs_backup/*' \
    -not -path './node_modules/*'
}

case "${1:-}" in
  scan)
    echo "=== Scanning for identifying strings ==="
    found=0
    for pat in "${PATTERNS[@]}"; do
      # grep -I skips binary; -n line numbers; -r recursive via file list
      hits=$(FIND_FILES | xargs grep -InF "$pat" 2>/dev/null || true)
      if [ -n "$hits" ]; then
        echo ""
        echo "--- '$pat' ---"
        echo "$hits" | head -40
        found=1
      fi
    done
    if [ "$found" -eq 0 ]; then
      echo "Clean: no known identifying strings found."
    else
      echo ""
      echo ">>> Review the hits above. When ready, edit REPLACEMENTS and run: ./anonymize.sh clean"
    fi
    ;;

  clean)
    echo "=== Rewriting identifiers (in place) ==="
    echo "Make sure you are in a COPY, not your original working tree."
    read -p "Type YES to proceed: " ok
    [ "$ok" = "YES" ] || { echo "Aborted."; exit 1; }
    while IFS= read -r f; do
      for lhs in "${!REPLACEMENTS[@]}"; do
        rhs="${REPLACEMENTS[$lhs]}"
        # Use a delimiter unlikely to appear in paths
        sed -i "s|${lhs}|${rhs}|g" "$f"
      done
    done < <(FIND_FILES)
    echo "Done. Now re-run: ./anonymize.sh scan   (should report Clean)"
    echo "Also manually check: .env is NOT present, and git history has no name."
    ;;

  *)
    echo "Usage: ./anonymize.sh [scan|clean]"
    exit 1
    ;;
esac
