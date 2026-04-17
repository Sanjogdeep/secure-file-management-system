import os, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# AES-256 key (32 bytes). In production, load from env/KMS.
_raw = os.environ.get("FILE_ENC_KEY", "")
FILE_ENC_KEY: bytes = bytes.fromhex(_raw) if len(_raw) == 64 else secrets.token_bytes(32)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "storage")
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_MIME_PREFIXES = [
    "text/", "image/", "application/pdf",
    "application/json", "application/zip",
]
BLOCKED_EXTENSIONS = {".exe", ".bat", ".sh", ".ps1", ".cmd", ".msi", ".dll", ".so"}

def encrypt_file(data: bytes) -> tuple[bytes, bytes]:
    """Returns (nonce, ciphertext)."""
    aesgcm = AESGCM(FILE_ENC_KEY)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce, ct

def decrypt_file(nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(FILE_ENC_KEY)
    return aesgcm.decrypt(nonce, ciphertext, None)
