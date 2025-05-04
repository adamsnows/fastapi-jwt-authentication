from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
from typing import List

from . import models, schemas, auth
from .database import engine, get_db
from .config import settings

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

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint to check if the API is running"""
    return {"message": "Welcome to FastAPI JWT Authentication API"}


@app.post("/auth/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED, tags=["Authentication"])
async def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """Register a new user"""
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

    return db_user


@app.post("/auth/login", response_model=schemas.Token, tags=["Authentication"])
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login to get access token"""
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
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

    return {"access_token": access_token, "token_type": "bearer", "expires_at": expires_at}


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

    return db_user

@app.get("/users/deactivated", response_model=List[schemas.UserResponse], tags=["Admin"])
async def get_deactivated_users(
    db: Session = Depends(get_db),
    current_user = Depends(auth.admin_only)
):
    """Get list of all deactivated users (Admin only)"""
    users = db.query(models.User).filter(models.User.is_active == False).all()
    return users

@app.put("/users/{user_id}/activate", response_model=schemas.UserResponse, tags=["Admin"])
async def activate_user(
    user_id: int,
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

    return db_user

@app.put("/users/{user_id}/deactivate", response_model=schemas.UserResponse, tags=["Admin"])
async def deactivate_user(
    user_id: int,
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

    return db_user