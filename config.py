"""
Configuration settings used across the analysis engine.
Can be extended to pull environment variables or .env file.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# === Paths ===
ROOT_DIR = Path(__file__).parent.resolve()
LOG_FILE = ROOT_DIR / "analyzer.log"
RESULTS_FILE = ROOT_DIR / "analysis_results.json"

# === Agents feature switches ===
ENABLE_DOMAIN_CLASSIFIER = True
ENABLE_LLM_ANALYSIS = False  # Set to False to disable LLM calls

# === LLM Settings ===
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "openai")  # Options: "openai", "anthropic", "azure", etc.
LLM_MODEL_NAME = os.environ.get("LLM_MODEL_NAME", "gpt-4.1-nano")  # 👈 Your custom model name
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")

# === Timeout and thresholds ===
MAX_ANALYSIS_TIMEOUT = 120  # seconds per contract

# === Standard logging levels ===
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")  # e.g. DEBUG, INFO, WARNING

# === Supported domains ===
SUPPORTED_DOMAINS = ["defi", "dao", "nft", "gamefi"]

# === Debug Mode ===
DEBUG_MODE = os.environ.get("DEBUG_MODE", "False").lower() == "true"
