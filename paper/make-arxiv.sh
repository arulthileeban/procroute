#!/usr/bin/env bash
# Build an arXiv-ready tarball from the paper directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

OUT="arxiv-submission.tar.gz"

# Compile to generate .bbl if LaTeX is available
if command -v pdflatex >/dev/null 2>&1; then
  echo "Compiling..."
  pdflatex -interaction=nonstopmode main.tex > /dev/null 2>&1
  bibtex main > /dev/null 2>&1
  pdflatex -interaction=nonstopmode main.tex > /dev/null 2>&1
  pdflatex -interaction=nonstopmode main.tex > /dev/null 2>&1
  echo "Compilation complete."
else
  echo "pdflatex not found, skipping compilation."
fi

# Verify .bbl exists
if [ ! -f main.bbl ]; then
  echo "ERROR: main.bbl not found. Install LaTeX or copy main.bbl from a machine that has it." >&2
  exit 1
fi

# Package only the required files
echo "Packaging $OUT..."
tar czf "$OUT" \
  main.tex \
  main.bbl \
  refs.bib \
  acmart.cls \
  ACM-Reference-Format.bst \
  acm-jdslogo.png \
  figures/deployment.pdf \
  figures/blockrate.pdf \
  figures/cdf_connect_latency.pdf

echo "Done. Contents:"
tar tzf "$OUT"
echo ""
echo "Upload $OUT to https://arxiv.org/submit"
