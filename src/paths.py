"""Repository paths shared by the generator, the trainer, the CLI, and the app."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "models"

DATA_PATH = DATA_DIR / "sample_auth_logs.csv"
JSON_PATH = DATA_DIR / "sample_auth_logs.json"
DEMO_PATH = DATA_DIR / "demo_log.csv"
MODEL_PATH = MODEL_DIR / "detector.joblib"
METRICS_PATH = MODEL_DIR / "metrics.json"
