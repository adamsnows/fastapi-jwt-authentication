from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from .models import UserRole, AuditLogType

class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str = Field(..., min_length=6)
    role: Optional[UserRole] = UserRole.USER

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(UserBase):
    id: int
    is_active: bool
    role: UserRole
    email_verified: bool
    created_at: datetime

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: int
    refresh_token: Optional[str] = None

class TokenData(BaseModel):
    username: Optional[str] = None

class RefreshTokenCreate(BaseModel):
    user_id: int
    token: str
    expires_at: datetime

class RefreshTokenResponse(BaseModel):
    id: int
    token: str
    expires_at: datetime
    revoked: bool
    user_id: int
    created_at: datetime

    class Config:
        orm_mode = True

class RefreshRequest(BaseModel):
    refresh_token: str

class EmailVerificationRequest(BaseModel):
    token: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=6)

class AuditLogBase(BaseModel):
    log_type: AuditLogType
    user_id: Optional[int] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: Optional[str] = None

class AuditLogCreate(AuditLogBase):
    pass

class AuditLogResponse(AuditLogBase):
    id: int
    created_at: datetime
    
    class Config:
        orm_mode = True

class AuditLogFilter(BaseModel):
    user_id: Optional[int] = None
    log_type: Optional[AuditLogType] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    ip_address: Optional[str] = None