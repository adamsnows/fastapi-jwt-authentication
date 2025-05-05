import pytest
from fastapi import status
import time
from jose import jwt
from app.auth import get_password_hash
from app.config import settings
from app.email import create_email_verification_token, create_password_reset_token


def test_register_user(client):
    """Test registering a new user"""
    response = client.post(
        "/auth/register",
        json={
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "password123"
        }
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "newuser@example.com"
    assert "id" in data
    assert "is_active" in data
    assert "created_at" in data


def test_register_user_duplicate_username(client, test_user):
    """Test registering a user with an existing username"""
    response = client.post(
        "/auth/register",
        json={
            "username": "testuser",  # existing username from fixture
            "email": "another@example.com",
            "password": "password123"
        }
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Username already registered" in response.json()["detail"]


def test_register_user_duplicate_email(client, test_user):
    """Test registering a user with an existing email"""
    response = client.post(
        "/auth/register",
        json={
            "username": "anotheruser",
            "email": "test@example.com",  # existing email from fixture
            "password": "password123"
        }
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Email already registered" in response.json()["detail"]


def test_login_success(client, test_user):
    """Test successful login"""
    response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "testpassword"
        }
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "expires_at" in data


def test_login_wrong_password(client, test_user):
    """Test login with wrong password"""
    response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "wrongpassword"
        }
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Incorrect username or password" in response.json()["detail"]


def test_login_nonexistent_user(client):
    """Test login with nonexistent user"""
    response = client.post(
        "/auth/login",
        data={
            "username": "nonexistent",
            "password": "password"
        }
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Incorrect username or password" in response.json()["detail"]


def test_login_returns_refresh_token(client, test_user):
    """Test login returns a refresh token"""
    response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "testpassword"
        }
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "refresh_token" in data
    assert data["refresh_token"] is not None


def test_refresh_token_endpoint(client, test_user):
    """Test refreshing an access token using refresh token"""
    # Login to get refresh token
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "testpassword"
        }
    )
    assert login_response.status_code == status.HTTP_200_OK
    login_data = login_response.json()
    refresh_token = login_data["refresh_token"]

    # Use refresh token to get new access token
    refresh_response = client.post(
        "/auth/refresh",
        json={
            "refresh_token": refresh_token
        }
    )
    assert refresh_response.status_code == status.HTTP_200_OK
    refresh_data = refresh_response.json()
    assert "access_token" in refresh_data
    assert "refresh_token" in refresh_data
    assert refresh_data["refresh_token"] != refresh_token  # Token should be rotated


def test_refresh_token_invalid(client):
    """Test using an invalid refresh token"""
    response = client.post(
        "/auth/refresh",
        json={
            "refresh_token": "invalid_token"
        }
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid or expired refresh token" in response.json()["detail"]


def test_logout_endpoint(client, test_user):
    """Test logout endpoint revokes the refresh token"""
    # Login to get refresh token
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "testpassword"
        }
    )
    refresh_token = login_response.json()["refresh_token"]

    # Logout
    logout_response = client.post(
        "/auth/logout",
        json={
            "refresh_token": refresh_token
        }
    )
    assert logout_response.status_code == status.HTTP_200_OK

    # Try to use the revoked refresh token
    refresh_response = client.post(
        "/auth/refresh",
        json={
            "refresh_token": refresh_token
        }
    )
    assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED


def test_logout_all_endpoint(client, test_user):
    """Test logout all endpoint revokes all refresh tokens"""
    # Login twice to get multiple refresh tokens
    login1 = client.post(
        "/auth/login",
        data={"username": "testuser", "password": "testpassword"}
    )
    token1 = login1.json()["access_token"]
    refresh_token1 = login1.json()["refresh_token"]

    login2 = client.post(
        "/auth/login",
        data={"username": "testuser", "password": "testpassword"}
    )
    refresh_token2 = login2.json()["refresh_token"]

    # Logout from all devices
    headers = {"Authorization": f"Bearer {token1}"}
    logout_response = client.post("/auth/logout/all", headers=headers)
    assert logout_response.status_code == status.HTTP_200_OK

    # Try to use the first refresh token
    refresh1 = client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token1}
    )
    assert refresh1.status_code == status.HTTP_401_UNAUTHORIZED

    # Try to use the second refresh token
    refresh2 = client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token2}
    )
    assert refresh2.status_code == status.HTTP_401_UNAUTHORIZED


def test_verify_email_valid_token(client, test_unverified_user, monkeypatch):
    """Test email verification with a valid token"""
    # Create a verification token
    token = create_email_verification_token(test_unverified_user.username)

    # Verify email
    response = client.post(
        "/auth/verify-email",
        json={"token": token}
    )
    assert response.status_code == status.HTTP_200_OK
    assert "Email successfully verified" in response.json()["message"]


def test_verify_email_invalid_token(client):
    """Test email verification with an invalid token"""
    response = client.post(
        "/auth/verify-email",
        json={"token": "invalid_token"}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Invalid or expired verification token" in response.json()["detail"]


def test_password_reset_request(client, test_user):
    """Test requesting a password reset"""
    response = client.post(
        "/auth/password-reset/request",
        json={"email": test_user.email}
    )
    assert response.status_code == status.HTTP_200_OK


def test_password_reset_confirm_valid_token(client, test_user, monkeypatch):
    """Test confirming a password reset with valid token"""
    # Create a password reset token
    token = create_password_reset_token(test_user.username)

    # Reset password
    response = client.post(
        "/auth/password-reset/confirm",
        json={
            "token": token,
            "new_password": "newpassword123"
        }
    )
    assert response.status_code == status.HTTP_200_OK
    assert "Password has been reset successfully" in response.json()["message"]

    # Check if login works with new password
    login_response = client.post(
        "/auth/login",
        data={
            "username": test_user.username,
            "password": "newpassword123"
        }
    )
    assert login_response.status_code == status.HTTP_200_OK


def test_password_reset_confirm_invalid_token(client):
    """Test confirming a password reset with invalid token"""
    response = client.post(
        "/auth/password-reset/confirm",
        json={
            "token": "invalid_token",
            "new_password": "newpassword123"
        }
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Invalid or expired reset token" in response.json()["detail"]


def test_resend_verification_email(client, test_unverified_user):
    """Test resending verification email"""
    # Login first
    login_response = client.post(
        "/auth/login",
        data={
            "username": test_unverified_user.username,
            "password": "testpassword"
        }
    )
    token = login_response.json()["access_token"]

    # Resend verification email
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/auth/resend-verification", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert "Verification email has been sent" in response.json()["message"]