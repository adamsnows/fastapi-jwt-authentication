from pydantic_settings import BaseSettings
import secrets
from typing import Optional


class Settings(BaseSettings):
    JWT_SECRET_KEY: str = secrets.token_urlsafe(32)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # email verification and password reset settings
    EMAIL_TOKEN_EXPIRE_HOURS: int = 24
    RESET_TOKEN_EXPIRE_HOURS: int = 1
    FRONTEND_URL: str = "http://localhost:3000"

    # email server settings
    MAIL_USERNAME: str = ""
    MAIL_PASSWORD: str = ""
    MAIL_FROM: str = "noreply@example.com"
    MAIL_FROM_NAME: str = "FastAPI JWT Auth"
    MAIL_PORT: int = 587
    MAIL_SERVER: str = "smtp.gmail.com"
    MAIL_STARTTLS: bool = True
    MAIL_SSL_TLS: bool = False
    MAIL_USE_CREDENTIALS: bool = True

    DATABASE_URL: str = "sqlite:///./app.db"


settings = Settings()