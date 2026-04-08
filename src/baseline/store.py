import json
from pathlib import Path
from datetime import datetime, timezone


BASELINE_PATH = Path("/var/lib/llm_attest/baseline.json")


def load_baseline() -> dict:
    """
    Load the baseline from the root-owned JSON file.
    
    The baseline file is owned by root and read-only for non-root users.
    This means the attacker (non-root) can read it to compare against,
    but cannot modify it to cover their tracks.
    
    Returns:
        Dictionary containing baseline hashes and metadata
        
    Raises:
        FileNotFoundError: if baseline has not been initialized
        PermissionError: if the file cannot be read
        ValueError: if the file is corrupted or invalid JSON
    """
    if not BASELINE_PATH.exists():
        raise FileNotFoundError(
            f"Baseline not found at {BASELINE_PATH}. "
            "Run scripts/setup_baseline.sh as root to initialize."
        )
    
    try:
        with open(BASELINE_PATH, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Baseline file is corrupted: {e}")


def save_baseline(baseline: dict) -> None:
    """
    Save the baseline to the root-owned JSON file.
    
    This function must be called with root privileges.
    Regular users (attackers) cannot call this successfully.
    
    Args:
        baseline: Dictionary containing hashes and metadata to save
        
    Raises:
        PermissionError: if called without root privileges (expected for attacker)
    """
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    baseline["last_updated"] = datetime.now(timezone.utc).isoformat()
    
    with open(BASELINE_PATH, "w") as f:
        json.dump(baseline, f, indent=2)
    
    print(f"Baseline saved to {BASELINE_PATH}")


def build_baseline(model_path: str, tokenizer_path: str | None = None) -> dict:
    """
    Build a baseline dictionary from the given file paths.
    Computes SHA-256 hashes of all specified artifacts.
    
    Args:
        model_path: Path to the model file (e.g. the GGUF blob)
        tokenizer_path: Optional path to tokenizer.json
        
    Returns:
        Dictionary ready to be saved as baseline.json
    """
    from src.utils.hashing import hash_file
    
    print(f"Hashing model file: {model_path}")
    model_hash = hash_file(model_path)
    print(f"  SHA-256: {model_hash}")
    
    baseline = {
        "version": "1.0",
        "model": {
            "path": str(model_path),
            "sha256": model_hash,
        }
    }
    
    if tokenizer_path:
        print(f"Hashing tokenizer file: {tokenizer_path}")
        tokenizer_hash = hash_file(tokenizer_path)
        print(f"  SHA-256: {tokenizer_hash}")
        baseline["tokenizer"] = {
            "path": str(tokenizer_path),
            "sha256": tokenizer_hash,
        }
    
    return baseline
