import hashlib

def generate_sha256(file_bytes):
    """Calculates SHA-256 hash of raw uploaded bytes to verify evidence integrity."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_bytes)
    return sha256_hash.hexdigest()