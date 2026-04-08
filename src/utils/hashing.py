import hashlib
from pathlib import Path


HASH_ALGORITHM = "sha256"
CHUNK_SIZE = 8192  # 8KB chunks for reading large files


def hash_file(file_path: str | Path) -> str:
    """
    Compute SHA-256 hash of a file on disk.
    Reads in chunks to handle large model files without loading
    the entire file into memory at once.
    
    Args:
        file_path: Path to the file to hash
        
    Returns:
        Hex string of the SHA-256 digest
        
    Raises:
        FileNotFoundError: if the file does not exist
        PermissionError: if the file cannot be read
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    hasher = hashlib.new(HASH_ALGORITHM)
    
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            hasher.update(chunk)
    
    return hasher.hexdigest()


def hash_bytes(data: bytes) -> str:
    """
    Compute SHA-256 hash of raw bytes.
    Used for hashing in-memory tensor data in A3.
    
    Args:
        data: Raw bytes to hash
        
    Returns:
        Hex string of the SHA-256 digest
    """
    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update(data)
    return hasher.hexdigest()


def hash_string(data: str) -> str:
    """
    Compute SHA-256 hash of a string.
    Used for hashing configuration state in A4.
    
    Args:
        data: String to hash
        
    Returns:
        Hex string of the SHA-256 digest
    """
    return hash_bytes(data.encode("utf-8"))
