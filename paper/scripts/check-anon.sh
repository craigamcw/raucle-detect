#!/usr/bin/env bash
# Pre-submission identity-leak check for the double-blind PDF inputs.
#
# Exit codes:
#   0  — no identity strings found in main.tex / references.bib
#   1  — identity string detected; review and re-anonymise before submission
#
# Surfaces *out of scope*: paper/DRAFT.md, paper/eval/**, paper/REVIEW-NOTES.md,
# anything not compiled into the camera-ready PDF.
#
# See paper/ANONYMISATION.md for the full checklist.

set -euo pipefail

cd "$(dirname "$0")/.."

PATTERN='raucle|craig|mcwilliams|craigamcw|github\.com/craig|raucle\.com'
TARGETS=(main.tex references.bib)

# .mmd figure sources too — they render into the PDF.
for f in figures/*.mmd; do
  [[ -f "$f" ]] && TARGETS+=("$f")
done

HITS=0
for f in "${TARGETS[@]}"; do
  if grep -niE "$PATTERN" "$f" >/dev/null 2>&1; then
    echo "IDENTITY LEAK in $f:" >&2
    grep -niE "$PATTERN" "$f" >&2
    HITS=$((HITS + 1))
  fi
done

if [[ "$HITS" -gt 0 ]]; then
  echo "" >&2
  echo "Anonymisation check FAILED ($HITS file(s) with identity strings)." >&2
  echo "Review the matches above, re-anonymise, and re-run." >&2
  echo "Reference: paper/ANONYMISATION.md" >&2
  exit 1
fi

echo "Anonymisation check passed: no identity strings in submission inputs."
exit 0
