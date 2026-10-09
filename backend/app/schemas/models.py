from pydantic import BaseModel, Field
from typing import List, Optional, Any, Dict
from datetime import datetime

class UserRegister(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = "Security Engineer"
    organization_name: Optional[str] = "Acme Corp DevSecOps"

class UserLogin(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]

class RepositoryCreate(BaseModel):
    name: str
    path: str
    source: Optional[str] = "local"
    default_branch: Optional[str] = "main"

class ScanTrigger(BaseModel):
    repository_id: str
    scan_history: bool = True
    scan_branches: bool = False
    max_commits: int = 150

class FindingUpdate(BaseModel):
    status: str # Open, Investigating, Confirmed, False Positive, Resolved, Accepted Risk
    comment: Optional[str] = None

class SuppressionCreate(BaseModel):
    finding_id: Optional[str] = None
    fingerprint: Optional[str] = None
    rule_id: Optional[str] = None
    path_pattern: Optional[str] = None
    reason: str
    expires_at: Optional[str] = None
