from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta, datetime
from typing import List, Optional
from jose import jwt, JWTError

from . import models, schemas, auth
from .database import engine, get_db
from .config import settings
from .email import email_manager, create_email_verification_token, create_password_reset_token
from .security import rate_limiter, brute_force_protection
from .audit import log_activity, get_client_info

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="FastAPI JWT Authentication",
    description="API for user authentication using JWT tokens",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.middleware("http")(rate_limiter)

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint to check if the API is running"""
    return {"message": "Welcome to FastAPI JWT Authentication API"}


@app.post("/auth/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED, tags=["Authentication"])
async def register(
    user: schemas.UserCreate,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db)
):
    """Register a new user and send verification email"""
    db_user_by_username = auth.get_user_by_username(db, username=user.username)
    if db_user_by_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    db_user_by_email = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user_by_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role=user.role
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    verification_token = create_email_verification_token(user.username)
    await email_manager.send_verification_email(
        background_tasks,
        user.email,
        user.username,
        verification_token
    )

    client_info = get_client_info(request)
    log_activity(
        db,
        models.AuditLogType.REGISTER,
        user_id=db_user.id,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        details={
            "username": user.username,
            "email": user.email,
            "role": user.role
        }
    )

    return db_user


@app.post("/auth/verify-email", status_code=status.HTTP_200_OK, tags=["Authentication"])
async def verify_email(
    verification_data: schemas.EmailVerificationRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Verify email address using the token sent via email"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired verification token",
    )

    try:
        payload = jwt.decode(verification_data.token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "email_verification":
            raise credentials_exception

        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = auth.get_user_by_username(db, username=username)
    if not user:
        raise credentials_exception

    user.email_verified = True
    db.commit()

    client_info = get_client_info(request)
    log_activity(
        db,
        models.AuditLogType.EMAIL_VERIFICATION,
        user_id=user.id,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )

    return {"message": "Email successfully verified"}


@app.post("/auth/password-reset/request", status_code=status.HTTP_200_OK, tags=["Authentication"])
async def request_password_reset(
    reset_data: schemas.PasswordResetRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db)
):
    """Request password reset (sends email with reset link)"""
    user = db.query(models.User).filter(models.User.email == reset_data.email).first()

    if not user:
        return {"message": "If the email exists in our system, a password reset link has been sent"}

    reset_token = create_password_reset_token(user.username)
    await email_manager.send_password_reset_email(
        background_tasks,
        user.email,
        user.username,
        reset_token
    )

    client_info = get_client_info(request)
    log_activity(
        db,
        models.AuditLogType.PASSWORD_RESET,
        user_id=user.id,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        details={"action": "request"}
    )

    return {"message": "If the email exists in our system, a password reset link has been sent"}


@app.post("/auth/password-reset/confirm", status_code=status.HTTP_200_OK, tags=["Authentication"])
async def confirm_password_reset(
    reset_data: schemas.PasswordResetConfirm,
    request: Request,
    db: Session = Depends(get_db)
):
    """Reset password using the token sent via email"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired reset token",
    )

    try:
        payload = jwt.decode(reset_data.token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "password_reset":
            raise credentials_exception

        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = auth.get_user_by_username(db, username=username)
    if not user:
        raise credentials_exception

    user.hashed_password = auth.get_password_hash(reset_data.new_password)
    db.commit()

    auth.revoke_all_user_refresh_tokens(user.id, db)

    client_info = get_client_info(request)
    log_activity(
        db,
        models.AuditLogType.PASSWORD_RESET,
        user_id=user.id,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        details={"action": "confirm"}
    )

    return {"message": "Password has been reset successfully"}


@app.post("/auth/login", response_model=schemas.Token, tags=["Authentication"])
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Login to get access token"""
    client_info = get_client_info(request)

    is_locked, lock_time = brute_force_protection.is_locked_out(form_data.username)
    if is_locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Try again in {lock_time} seconds.",
            headers={"Retry-After": str(lock_time)}
        )

    user = auth.authenticate_user(db, form_data.username, form_data.password)

    login_success = user is not False
    brute_force_protection.record_login_attempt(form_data.username, login_success, client_info["ip_address"])

    if not user:
        log_activity(
            db,
            models.AuditLogType.LOGIN_FAILED,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"],
            details={"username": form_data.username}
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token, expires_at = auth.create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )

    refresh_token, _ = auth.create_refresh_token(user.id, db)

    log_activity(
        db,
        models.AuditLogType.LOGIN,
        user_id=user.id,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "refresh_token": refresh_token
    }


@app.post("/auth/refresh", response_model=schemas.Token, tags=["Authentication"])
async def refresh_token(
    refresh_req: schemas.RefreshRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Get a new access token using refresh token"""
    refresh_token = auth.get_refresh_token(refresh_req.refresh_token, db)

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(models.User).filter(models.User.id == refresh_token.user_id).first()
    if not user or not user.is_active:
        auth.revoke_refresh_token(refresh_req.refresh_token, db)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User inactive or deleted",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token, expires_at = auth.create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )

    new_refresh_token, _ = auth.create_refresh_token(user.id, db)

    auth.revoke_refresh_token(refresh_req.refresh_token, db)

    client_info = get_client_info(request)
    log_activity(
        db,
        models.AuditLogType.TOKEN_REFRESH,
        user_id=user.id,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "refresh_token": new_refresh_token
    }


@app.post("/auth/logout", status_code=status.HTTP_200_OK, tags=["Authentication"])
async def logout(
    refresh_req: schemas.RefreshRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Logout by revoking the refresh token"""
    refresh_token = db.query(models.RefreshToken).filter(
        models.RefreshToken.token == refresh_req.refresh_token,
        models.RefreshToken.revoked == False
    ).first()

    auth.revoke_refresh_token(refresh_req.refresh_token, db)

    if refresh_token:
        client_info = get_client_info(request)
        log_activity(
            db,
            models.AuditLogType.LOGOUT,
            user_id=refresh_token.user_id,
            ip_address=client_info["ip_address"],
            user_agent=client_info["user_agent"]
        )

    return {"detail": "Successfully logged out"}


@app.post("/auth/logout/all", status_code=status.HTTP_200_OK, tags=["Authentication"])
async def logout_all(
    request: Request,
    current_user = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """Logout from all devices by revoking all refresh tokens"""
    auth.revoke_all_user_refresh_tokens(current_user.id, db)

    client_info = get_client_info(request)
    log_activity(
        db,
        models.AuditLogType.LOGOUT,
        user_id=current_user.id,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        details={"action": "logout_all"}
    )

    return {"detail": "Successfully logged out from all devices"}


@app.post("/auth/resend-verification", status_code=status.HTTP_200_OK, tags=["Authentication"])
async def resend_verification_email(
    background_tasks: BackgroundTasks,
    request: Request,
    current_user = Depends(auth.get_current_active_user),
    db: Session = Depends(get_db)
):
    """Resend verification email to current user"""
    if current_user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already verified"
        )

    verification_token = create_email_verification_token(current_user.username)
    await email_manager.send_verification_email(
        background_tasks,
        current_user.email,
        current_user.username,
        verification_token
    )

    client_info = get_client_info(request)
    log_activity(
        db,
        models.AuditLogType.EMAIL_VERIFICATION,
        user_id=current_user.id,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        details={"action": "resend"}
    )

    return {"message": "Verification email has been sent"}


@app.get("/users/me", response_model=schemas.UserResponse, tags=["Users"])
async def get_current_user_info(current_user = Depends(auth.get_current_active_user)):
    """Get information about the current authenticated user"""
    return current_user


@app.get("/users", response_model=List[schemas.UserResponse], tags=["Users"])
async def get_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user = Depends(auth.has_role([models.UserRole.ADMIN, models.UserRole.USER]))
):
    """Get list of all users (requires authentication with USER or ADMIN role)"""
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users

@app.put("/users/{user_id}/role", response_model=schemas.UserResponse, tags=["Admin"])
async def update_user_role(
    user_id: int,
    role: models.UserRole,
    request: Request,
    db: Session = Depends(get_db),
    current_user = Depends(auth.admin_only)
):
    """Update user role (requires Admin privileges)"""
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    db_user.role = role
    db.commit()
    db.refresh(db_user)

    client_info = get_client_info(request)
    log_activity(
        db,
        models.AuditLogType.UPDATE_ROLE,
        user_id=db_user.id,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"],
        details={"new_role": role}
    )

    return db_user

@app.get("/users/deactivated", response_model=List[schemas.UserResponse], tags=["Admin"])
async def get_deactivated_users(
    request: Request,
    db: Session = Depends(get_db),
    current_user = Depends(auth.admin_only)
):
    """Get list of all deactivated users (Admin only)"""
    users = db.query(models.User).filter(models.User.is_active == False).all()

    client_info = get_client_info(request)
    log_activity(
        db,
        models.AuditLogType.GET_DEACTIVATED_USERS,
        user_id=current_user.id,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )

    return users

@app.put("/users/{user_id}/activate", response_model=schemas.UserResponse, tags=["Admin"])
async def activate_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user = Depends(auth.admin_only)
):
    """Activate a user (Admin only)"""
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    db_user.is_active = True
    db.commit()
    db.refresh(db_user)

    client_info = get_client_info(request)
    log_activity(
        db,
        models.AuditLogType.ACTIVATE_USER,
        user_id=db_user.id,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )

    return db_user

@app.put("/users/{user_id}/deactivate", response_model=schemas.UserResponse, tags=["Admin"])
async def deactivate_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user = Depends(auth.admin_only)
):
    """Deactivate a user (Admin only)"""
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account"
        )

    db_user.is_active = False
    db.commit()
    db.refresh(db_user)

    client_info = get_client_info(request)
    log_activity(
        db,
        models.AuditLogType.DEACTIVATE_USER,
        user_id=db_user.id,
        ip_address=client_info["ip_address"],
        user_agent=client_info["user_agent"]
    )

    return db_user


@app.get("/audit-logs", response_model=List[schemas.AuditLogResponse], tags=["Admin"])
async def get_audit_logs(
    skip: int = 0,
    limit: int = 100,
    user_id: Optional[int] = None,
    log_type: Optional[models.AuditLogType] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    ip_address: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(auth.admin_only)
):
    """Get audit logs with optional filtering (Admin only)"""
    query = db.query(models.AuditLog)

    if user_id:
        query = query.filter(models.AuditLog.user_id == user_id)

    if log_type:
        query = query.filter(models.AuditLog.log_type == log_type)

    if start_date:
        query = query.filter(models.AuditLog.created_at >= start_date)

    if end_date:
        query = query.filter(models.AuditLog.created_at <= end_date)

    if ip_address:
        query = query.filter(models.AuditLog.ip_address == ip_address)

    query = query.order_by(models.AuditLog.created_at.desc())

    audit_logs = query.offset(skip).limit(limit).all()

    return audit_logs


@app.get("/audit-logs/user/{user_id}", response_model=List[schemas.AuditLogResponse], tags=["Admin"])
async def get_user_audit_logs(
    user_id: int,
    skip: int = 0,
    limit: int = 100,
    log_type: Optional[models.AuditLogType] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_db),
    current_user = Depends(auth.admin_only)
):
    """Get audit logs for a specific user (Admin only)"""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    query = db.query(models.AuditLog).filter(models.AuditLog.user_id == user_id)

    if log_type:
        query = query.filter(models.AuditLog.log_type == log_type)

    if start_date:
        query = query.filter(models.AuditLog.created_at >= start_date)

    if end_date:
        query = query.filter(models.AuditLog.created_at <= end_date)

    query = query.order_by(models.AuditLog.created_at.desc())

    audit_logs = query.offset(skip).limit(limit).all()

    return audit_logs


@app.get("/audit-logs/types", tags=["Admin"])
async def get_audit_log_types(current_user = Depends(auth.admin_only)):
    """Get all available audit log types (Admin only)"""
    return [log_type.value for log_type in models.AuditLogType]


@app.delete("/audit-logs/{log_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Admin"])
async def delete_audit_log(
    log_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(auth.admin_only)
):
    """Delete a specific audit log entry (Admin only)"""
    db_log = db.query(models.AuditLog).filter(models.AuditLog.id == log_id).first()
    if not db_log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log entry not found"
        )

    db.delete(db_log)
    db.commit()

    return None