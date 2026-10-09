from datetime import datetime
import uuid
from typing import Optional

try:
    from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON
    from sqlalchemy.orm import declarative_base, relationship
    Base = declarative_base()
except ImportError:
    # Lightweight fallback for environments where sqlalchemy is optional
    Base = object

class Organization(Base):
    __tablename__ = "organizations"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), default="security_engineer")
    created_at = Column(DateTime, default=datetime.utcnow)

class Repository(Base):
    __tablename__ = "repositories"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    path = Column(Text, nullable=False)
    source = Column(String(50), default="local") # local, github, gitlab
    default_branch = Column(String(100), default="main")
    last_scanned_at = Column(DateTime, nullable=True)
    risk_index = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

class Scan(Base):
    __tablename__ = "scans"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    repository_id = Column(String(36), ForeignKey("repositories.id"), nullable=False)
    scan_mode = Column(String(50), default="history+working_tree")
    status = Column(String(50), default="completed") # pending, running, completed, failed
    duration_seconds = Column(Float, default=0.0)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    currently_exposed_count = Column(Integer, default=0)
    historical_only_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

class Finding(Base):
    __tablename__ = "findings"
    id = Column(String(36), primary_key=True) # e.g. SS-00001
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    repository_id = Column(String(36), ForeignKey("repositories.id"), nullable=False)
    fingerprint = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    secret_type = Column(String(100), nullable=False)
    rule_id = Column(String(100), nullable=False)
    rule_name = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False) # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = Column(Float, default=0.8)
    score = Column(Integer, default=50)
    masked_secret = Column(String(255), nullable=False)
    file_path = Column(Text, nullable=False)
    line_number = Column(Integer, default=1)
    status = Column(String(50), default="Open") # Open, Investigating, Confirmed, False Positive, Resolved, Accepted Risk
    is_currently_present = Column(Boolean, default=True)
    first_seen = Column(String(100), nullable=True)
    last_seen = Column(String(100), nullable=True)
    total_occurrences = Column(Integer, default=1)
    remediation = Column(Text, nullable=True)
    risk_reasons = Column(JSON, nullable=True)
    context_snippet = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Suppression(Base):
    __tablename__ = "suppressions"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    finding_id = Column(String(36), nullable=True)
    fingerprint = Column(String(64), nullable=True)
    rule_id = Column(String(100), nullable=True)
    path_pattern = Column(Text, nullable=True)
    reason = Column(Text, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    created_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(String(36), nullable=False)
    user_email = Column(String(255), nullable=False)
    action = Column(String(100), nullable=False)
    target_type = Column(String(50), nullable=False)
    target_id = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
