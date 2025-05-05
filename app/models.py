from sqlalchemy import Boolean, Column, Integer, String, DateTime, Enum, ForeignKey, JSON, Text
from sqlalchemy.sql import func
import enum
from .database import Base

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"

class AuditLogType(str, enum.Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    REGISTER = "register"
    PASSWORD_RESET = "password_reset"
    EMAIL_VERIFICATION = "email_verification"
    TOKEN_REFRESH = "token_refresh"
    ROLE_CHANGE = "role_change"
    USER_UPDATE = "user_update"
    LOGIN_FAILED = "login_failed"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    role = Column(Enum(UserRole), default=UserRole.USER)
    email_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    log_type = Column(Enum(AuditLogType), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)