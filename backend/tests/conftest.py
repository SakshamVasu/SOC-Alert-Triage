import sys
from pathlib import Path

# Make "triage" and "app" importable when running pytest from backend/ or the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
