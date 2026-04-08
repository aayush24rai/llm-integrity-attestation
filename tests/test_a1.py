import pytest
import tempfile
import os
from pathlib import Path
from src.utils.hashing import hash_file, hash_bytes, hash_string


def test_hash_file_consistent():
    """Same file always produces same hash."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test model data")
        tmp_path = f.name
    
    try:
        hash1 = hash_file(tmp_path)
        hash2 = hash_file(tmp_path)
        assert hash1 == hash2
    finally:
        os.unlink(tmp_path)


def test_hash_file_detects_change():
    """Modified file produces different hash — core of A1 defense."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"original model data")
        tmp_path = f.name
    
    try:
        original_hash = hash_file(tmp_path)
        
        # Simulate attacker modifying the file
        with open(tmp_path, "wb") as f:
            f.write(b"tampered model data")
        
        tampered_hash = hash_file(tmp_path)
        
        assert original_hash != tampered_hash, \
            "CRITICAL: Hash did not change after file modification"
    finally:
        os.unlink(tmp_path)


def test_hash_file_not_found():
    """Raises FileNotFoundError for missing files."""
    with pytest.raises(FileNotFoundError):
        hash_file("/nonexistent/path/model.gguf")


def test_hash_bytes_consistent():
    """Same bytes always produce same hash."""
    data = b"tensor data"
    assert hash_bytes(data) == hash_bytes(data)


def test_hash_bytes_detects_change():
    """Different bytes produce different hash."""
    assert hash_bytes(b"weight_a") != hash_bytes(b"weight_b")


def test_hash_string_consistent():
    """Same string always produces same hash."""
    s = '{"temperature": 0.7, "system_prompt": "You are helpful"}'
    assert hash_string(s) == hash_string(s)


def test_hash_is_sha256_length():
    """SHA-256 hex digest is always 64 characters."""
    h = hash_bytes(b"any data")
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)
