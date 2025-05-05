import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import BackgroundTasks, HTTPException
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema
from jose import jwt
from pydantic import EmailStr

from .config import settings


class EmailManager:
    """Class to manage email sending functionality"""

    def __init__(self):
        self.conf = ConnectionConfig(
            MAIL_USERNAME=settings.MAIL_USERNAME,
            MAIL_PASSWORD=settings.MAIL_PASSWORD,
            MAIL_FROM=settings.MAIL_FROM,
            MAIL_PORT=settings.MAIL_PORT,
            MAIL_SERVER=settings.MAIL_SERVER,
            MAIL_FROM_NAME=settings.MAIL_FROM_NAME,
            MAIL_STARTTLS=settings.MAIL_STARTTLS,
            MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
            USE_CREDENTIALS=settings.MAIL_USE_CREDENTIALS,
            TEMPLATE_FOLDER=Path(__file__).parent / 'email_templates'
        )
        self.fm = FastMail(self.conf)

        # store sent emails for testing
        self.test_emails = []
        # check if running in test mode
        self.test_mode = os.environ.get("TESTING") == "True"

    async def send_email(
        self,
        email_to: List[EmailStr],
        subject: str,
        body: Dict[str, str],
        template_name: str
    ) -> None:
        """Send email asynchronously"""
        # in test mode, just store the email instead of sending it
        if self.test_mode:
            self.test_emails.append({
                "email_to": email_to,
                "subject": subject,
                "body": body,
                "template_name": template_name
            })
            return

        message = MessageSchema(
            subject=subject,
            recipients=email_to,
            template_body=body,
            subtype="html"
        )
        await self.fm.send_message(message, template_name=template_name)

    async def send_verification_email(
        self,
        background_tasks: BackgroundTasks,
        email_to: EmailStr,
        username: str,
        verification_token: str
    ) -> None:
        """Send verification email to user"""
        subject = "Email Verification - FastAPI JWT Auth"
        body = {
            "username": username,
            "verification_url": f"{settings.FRONTEND_URL}/verify-email?token={verification_token}"
        }
        background_tasks.add_task(
            self.send_email,
            email_to=[email_to],
            subject=subject,
            body=body,
            template_name="email_verification.html"
        )

    async def send_password_reset_email(
        self,
        background_tasks: BackgroundTasks,
        email_to: EmailStr,
        username: str,
        reset_token: str
    ) -> None:
        """Send password reset email to user"""
        subject = "Password Reset - FastAPI JWT Auth"
        body = {
            "username": username,
            "reset_url": f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
        }
        background_tasks.add_task(
            self.send_email,
            email_to=[email_to],
            subject=subject,
            body=body,
            template_name="password_reset.html"
        )


email_manager = EmailManager()


def create_email_verification_token(username: str) -> str:
    """Create a JWT token for email verification"""
    expire = datetime.now(timezone.utc) + timedelta(hours=settings.EMAIL_TOKEN_EXPIRE_HOURS)
    to_encode = {"sub": username, "exp": expire, "type": "email_verification"}
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def create_password_reset_token(username: str) -> str:
    """Create a JWT token for password reset"""
    expire = datetime.now(timezone.utc) + timedelta(hours=settings.RESET_TOKEN_EXPIRE_HOURS)
    to_encode = {"sub": username, "exp": expire, "type": "password_reset"}
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt