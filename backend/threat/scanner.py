import hashlib, os, re
from pathlib import Path
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from models.models import SecurityAlert

# Magic bytes for dangerous file types
MAGIC_BYTES = {
    b"MZ": "Windows PE executable",
    b"\x7fELF": "ELF executable (Linux)",
    b"\xca\xfe\xba\xbe": "Mach-O executable",
    b"\xfe\xed\xfa\xce": "Mach-O executable",
    b"PK\x03\x04": None,  # ZIP - allowed (check contents for macros)
}

DANGEROUS_PATTERNS = [
    rb"<script[\s>]",           # XSS in SVG/HTML uploads
    rb"eval\s*\(",              # JS eval
    rb"exec\s*\(",              # shell exec
    rb"__import__\s*\(",        # Python import injection
    rb"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",  # EICAR test virus
]

MAX_FILENAME_LEN = 255

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def validate_filename(filename: str) -> str:
    """Sanitize and validate filename."""
    if len(filename) > MAX_FILENAME_LEN:
        raise HTTPException(400, "Filename too long")
    # Strip path traversal
    name = Path(filename).name
    # Allow only safe characters
    name = re.sub(r"[^\w\.\-\s]", "_", name)
    if not name or name in (".", ".."):
        raise HTTPException(400, "Invalid filename")
    ext = Path(name).suffix.lower()
    from utils.config import BLOCKED_EXTENSIONS
    if ext in BLOCKED_EXTENSIONS:
        raise HTTPException(400, f"File type '{ext}' is not allowed")
    return name

def check_magic_bytes(data: bytes, filename: str) -> str | None:
    """Check file magic bytes. Returns detected threat or None."""
    for magic, threat in MAGIC_BYTES.items():
        if data[:len(magic)] == magic and threat is not None:
            return threat
    return None

def scan_content(data: bytes) -> list[str]:
    """Simple pattern-based malware scan. Returns list of threats found."""
    threats = []
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, data[:8192], re.IGNORECASE):
            threats.append(pattern.decode(errors="replace"))
    return threats

def check_buffer_overflow(data: bytes, max_size: int) -> None:
    """Validate data size to prevent buffer overflow attempts."""
    if len(data) > max_size:
        raise HTTPException(413, f"File exceeds maximum size of {max_size // (1024*1024)} MB")

def validate_mime_type(mime: str, allowed_prefixes: list[str]) -> None:
    if not any(mime.startswith(p) for p in allowed_prefixes):
        raise HTTPException(415, f"MIME type '{mime}' is not permitted")

async def run_threat_scan(
    data: bytes,
    filename: str,
    mime_type: str,
    db: AsyncSession,
    user_id: str,
    ip: str,
) -> dict:
    """Full threat scan pipeline. Raises HTTPException on critical threats."""
    from utils.config import MAX_FILE_SIZE, ALLOWED_MIME_PREFIXES

    results = {"passed": True, "warnings": [], "threats": []}

    # 1. Size check (buffer overflow prevention)
    try:
        check_buffer_overflow(data, MAX_FILE_SIZE)
    except HTTPException:
        await _alert(db, "BUFFER_OVERFLOW_ATTEMPT", "critical", ip, user_id,
                     f"File size {len(data)} bytes exceeds limit")
        raise

    # 2. Filename validation
    # (done before this call usually, but double-check extension)
    ext = Path(filename).suffix.lower()
    from utils.config import BLOCKED_EXTENSIONS
    if ext in BLOCKED_EXTENSIONS:
        await _alert(db, "BLOCKED_EXTENSION", "high", ip, user_id, f"Extension: {ext}")
        raise HTTPException(400, "Blocked file extension")

    # 3. Magic bytes
    magic_threat = check_magic_bytes(data, filename)
    if magic_threat:
        await _alert(db, "EXECUTABLE_UPLOAD", "high", ip, user_id, magic_threat)
        raise HTTPException(400, f"Detected executable content: {magic_threat}")

    # 4. Content scan
    threats = scan_content(data)
    if threats:
        await _alert(db, "MALICIOUS_CONTENT", "critical", ip, user_id, str(threats))
        raise HTTPException(400, "Malicious content detected in file")

    # 5. MIME check
    try:
        validate_mime_type(mime_type, ALLOWED_MIME_PREFIXES)
    except HTTPException:
        await _alert(db, "INVALID_MIME", "medium", ip, user_id, mime_type)
        raise

    return results

async def _alert(db: AsyncSession, alert_type: str, severity: str, ip: str, user_id: str, detail: str):
    alert = SecurityAlert(
        alert_type=alert_type,
        severity=severity,
        source_ip=ip,
        user_id=user_id,
        detail=detail,
    )
    db.add(alert)
    await db.commit()
