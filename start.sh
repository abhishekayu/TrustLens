#!/usr/bin/env bash
#
# TrustLens AI – Start with interactive LLM setup
#
# Usage:
#   ./start.sh
#
# This script runs the setup wizard to pick your LLM provider,
# then launches the TrustLens backend. On exit (Ctrl+C),
# your model selection is cleared for a fresh pick next time.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Use the Python from the activated venv, or fall back to python3
if [[ -n "$VIRTUAL_ENV" ]]; then
    PYTHON="$VIRTUAL_ENV/bin/python"
elif [[ -f ".venv/bin/python" ]]; then
    PYTHON=".venv/bin/python"
else
    PYTHON="python3"
fi

echo ""
echo "Using Python: $PYTHON"
echo ""

exec "$PYTHON" setup_wizard.py
