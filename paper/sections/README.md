# LaTeX section files

`main.tex` `\input{}`s nine section files from this directory. They are generated from `paper/DRAFT.md` by `paper/build-tex.sh`.

## Build

```bash
# Generate sections from DRAFT.md (requires pandoc)
cd paper
./build-tex.sh

# Compile
latexmk -pdf main.tex
```

## Why split DRAFT.md → sections/

- `main.tex` is stable: section order, document class, package list, references binding. Rarely edited.
- `sections/*.tex` are regenerated from `DRAFT.md` on every build. The markdown is the working document; the .tex files are camera-ready output.
- Splitting makes per-section diffs reviewable in pull requests.
- `pandoc` does the heavy lifting; we own a small post-processing script (`build-tex.sh`) to handle the conversions pandoc gets wrong (Mermaid figures → TikZ placeholders, our specific code-block flavour, bib-key normalisation).

## Drift detection

Camera-ready editing pass works directly on `sections/*.tex`. When that happens, `DRAFT.md` becomes stale. The two diverge intentionally during the final week before submission. CI runs `scripts/md-to-tex-diff.py` (TBD) to warn about non-trivial drift.
