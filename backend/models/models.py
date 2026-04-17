from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey, LargeBinary
from sqlalchemy.orm import DeclarativeBase, relationship
from datetime import datetime, timezone
import uuid

def utcnow():
    return datetime.now(timezone.utc)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(128), unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String(16), default="viewer")  # admin | editor | viewer
    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Boolean, default=False)
    failed_logins = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    files = relationship("FileRecord", back_populates="owner", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")

class FileRecord(Base):
    __tablename__ = "files"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String(256), nullable=False)
    original_name = Column(String(256), nullable=False)
    mime_type = Column(String(128), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    owner_id = Column(String, ForeignKey("users.id"), nullable=False)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    owner = relationship("User", back_populates="files")
    share_tokens = relationship("ShareToken", back_populates="file", cascade="all, delete-orphan")
    acl = relationship("FileACL", back_populates="file", cascade="all, delete-orphan")

class FileACL(Base):
    __tablename__ = "file_acl"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id = Column(String, ForeignKey("files.id"), nullable=False)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    permission = Column(String(16), default="read")  # read | write
    file = relationship("FileRecord", back_populates="acl")

class ShareToken(Base):
    __tablename__ = "share_tokens"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    token = Column(String, unique=True, nullable=False)
    file_id = Column(String, ForeignKey("files.id"), nullable=False)
    created_by = Column(String, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used = Column(Boolean, default=False)
    file = relationship("FileRecord", back_populates="share_tokens")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String(64), nullable=False)
    resource = Column(String(256), nullable=True)
    ip_address = Column(String(45), nullable=True)
    detail = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=utcnow)
    user = relationship("User", back_populates="audit_logs")

class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_type = Column(String(64), nullable=False)
    severity = Column(String(16), default="medium")  # low | medium | high | critical
    source_ip = Column(String(45), nullable=True)
    user_id = Column(String, nullable=True)
    detail = Column(Text, nullable=True)
    resolved = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), default=utcnow)
