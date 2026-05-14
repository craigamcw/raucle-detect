#!/usr/bin/env bash
# build-tex.sh — split DRAFT.md into per-section .tex files for main.tex.
#
# Requires: pandoc (≥ 2.18 recommended).
#
# Output: paper/sections/0N-<name>.tex, one per top-level §N heading in DRAFT.md.
# The mapping is:
#
#   ## 1. Introduction                     → sections/01-introduction.tex
#   ## 2. Threat Model                     → sections/02-threat-model.tex
#   ## 3. System Design                    → sections/03-design.tex
#   ## 4. Formal Analysis                  → sections/04-formal.tex
#   ## 5. Implementation                   → sections/05-implementation.tex
#   ## 6. Evaluation                       → sections/06-evaluation.tex
#   ## 7. Related Work                     → sections/07-related.tex
#   ## 8. Limitations and Future Work      → sections/08-limitations.tex
#   ## 9. Conclusion                       → sections/09-conclusion.tex
#
# The script is deliberately small; complex re-flow happens at camera-ready
# time as a manual pass on the .tex files (sections/README.md explains why).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRAFT="$ROOT/DRAFT.md"
OUT="$ROOT/sections"

if ! command -v pandoc >/dev/null 2>&1; then
  echo "pandoc not found. Install: brew install pandoc / apt install pandoc." >&2
  exit 1
fi

if [[ ! -f "$DRAFT" ]]; then
  echo "DRAFT.md not found at $DRAFT" >&2
  exit 1
fi

mkdir -p "$OUT"

# Split DRAFT.md into per-section markdown chunks using awk on lines starting
# with "## " followed by a numeric section.
SPLITDIR="$(mktemp -d)"
trap "rm -rf $SPLITDIR" EXIT

awk -v out="$SPLITDIR" '
  /^## [0-9]+\. / {
    n = $2
    gsub(/[^0-9]/, "", n)
    name = $0
    sub(/^## [0-9]+\. /, "", name)
    gsub(/[^A-Za-z]+/, "-", name)
    name = tolower(name)
    fn = sprintf("%s/%02d-%s.md", out, n, name)
    next
  }
  fn { print > fn }
' "$DRAFT"

# Convert each chunk to LaTeX with pandoc. Map markdown section names to the
# .tex filenames main.tex expects.
declare -A MAP=(
  ["01-introduction.md"]="01-introduction.tex"
  ["02-threat-model.md"]="02-threat-model.tex"
  ["03-system-design.md"]="03-design.tex"
  ["04-formal-analysis.md"]="04-formal.tex"
  ["05-implementation.md"]="05-implementation.tex"
  ["06-evaluation.md"]="06-evaluation.tex"
  ["07-related-work.md"]="07-related.tex"
  ["08-limitations-and-future-work.md"]="08-limitations.tex"
  ["09-conclusion.md"]="09-conclusion.tex"
)

for md in "$SPLITDIR"/*.md; do
  base="$(basename "$md")"
  target="${MAP[$base]:-}"
  if [[ -z "$target" ]]; then
    echo "warn: no mapping for $base" >&2
    continue
  fi
  pandoc -f markdown -t latex --no-highlight "$md" -o "$OUT/$target"
  echo "wrote $OUT/$target"
done

echo "Done. Run: latexmk -pdf $ROOT/main.tex"
