# 🔒 SecureFMS — Secure File Management System

A full-stack secure file management system with authentication, encryption, and threat detection.

## Features

### Module 1 — Authentication & Access Control
- ✅ Password hashing with **Bcrypt**
- ✅ **JWT** access tokens (30-min expiry)
- ✅ **TOTP-based 2FA** (Google Authenticator compatible)
- ✅ **RBAC**: admin / editor / viewer roles
- ✅ Account lockout after 5 failed attempts (15-min lock)

### Module 2 — Core File Operations
- ✅ **AES-256-GCM** encryption at rest
- ✅ **SHA-256** integrity verification on every read
- ✅ **Signed share tokens** with expiry (24h default)
- ✅ ACL-based file sharing (read/write permissions)
- ✅ File metadata viewer (MIME, size, hash, owner, ACL)
- ✅ Tamper-evident **audit log** for all operations
- ✅ Soft-delete with admin visibility

### Module 3 — Threat Detection
- ✅ **Buffer overflow prevention** (max 10MB, validated)
- ✅ **Magic byte** detection (blocks executables, ELF, Mach-O)
- ✅ **Malware signature scan** (EICAR, JS eval, shell exec patterns)
- ✅ **Blocked extensions**: .exe, .bat, .sh, .ps1, .dll, etc.
- ✅ Path traversal prevention in filenames
- ✅ XSS pattern detection in file content
- ✅ Security alerts dashboard with severity levels
- ✅ **Rate limiting** via SlowAPI

---

## Quick Start

### Prerequisites
- Python 3.10+

### Install & Run
```bash
cd backend
pip install -r requirements.txt
cd ..
bash start.sh
```

Then open **http://localhost:3000** in your browser.

### Default Credentials
| Username | Password    | Role  |
|----------|-------------|-------|
| admin    | Admin@12345 | admin |

---

## Project Structure
```
secure-fms/
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── requirements.txt
│   ├── auth/
│   │   ├── auth.py          # JWT, bcrypt, TOTP helpers
│   │   ├── routes.py        # /api/auth/* endpoints
│   │   └── admin_routes.py  # /api/admin/* endpoints
│   ├── files/
│   │   └── routes.py        # /api/files/* endpoints
│   ├── models/
│   │   ├── models.py        # SQLAlchemy ORM models
│   │   └── database.py      # Async DB session
│   ├── threat/
│   │   └── scanner.py       # Threat detection engine
│   └── utils/
│       └── config.py        # AES-256 encryption, config
├── frontend/
│   └── index.html           # Single-page React app
├── storage/                 # Encrypted file blobs (auto-created)
└── start.sh                 # Launch script
```

---

## API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/auth/register | Register new user |
| POST | /api/auth/login | Login (returns JWT) |
| POST | /api/auth/setup-2fa | Generate TOTP QR |
| POST | /api/auth/confirm-2fa | Enable 2FA |
| GET  | /api/auth/me | Current user info |
| POST | /api/files/upload | Upload & encrypt file |
| GET  | /api/files/list | List accessible files |
| GET  | /api/files/download/{id} | Download & decrypt |
| GET  | /api/files/metadata/{id} | View file metadata |
| POST | /api/files/share/{id} | Create share token |
| GET  | /api/files/shared/{token} | Anonymous download |
| POST | /api/files/acl/{id} | Grant ACL to user |
| DELETE | /api/files/{id} | Soft-delete file |
| GET  | /api/admin/audit-logs | Audit log (admin) |
| GET  | /api/admin/security-alerts | Threat alerts (admin) |
| GET  | /api/admin/users | All users (admin) |
| GET  | /api/admin/stats | Dashboard stats (admin) |
