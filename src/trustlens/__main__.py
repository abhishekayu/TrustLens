"""
TrustLens AI – Package entry-point.

Run with:
    PYTHONPATH=src python3 -m trustlens

Same as running uvicorn directly — the wizard is built into main.py.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> None:
    """Start TrustLens via uvicorn (wizard runs automatically in main.py)."""
    root = Path(__file__).resolve().parent.parent.parent
    os.chdir(root)

    import uvicorn
    try:
        uvicorn.run(
            "trustlens.main:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info",
        )
    except KeyboardInterrupt:
        print("\n\033[93m👋 Server stopped.\033[0m")


if __name__ == "__main__":
    main()
