import pytest
from fastapi import status
from app.auth import create_access_token
from datetime import timedelta
from app.config import settings


def test_get_current_user_info(client, test_user):
    """Test getting current user information with valid token"""
    access_token, _ = create_access_token(
        data={"sub": test_user.username},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    headers = {"Authorization": f"Bearer {access_token}"}
    response = client.get("/users/me", headers=headers)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["username"] == test_user.username
    assert data["email"] == test_user.email
    assert data["id"] == test_user.id


def test_get_current_user_invalid_token(client):
    """Test getting current user with invalid token"""
    headers = {"Authorization": "Bearer invalidtoken"}
    response = client.get("/users/me", headers=headers)

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Could not validate credentials" in response.json()["detail"]


def test_get_current_user_no_token(client):
    """Test getting current user without token"""
    response = client.get("/users/me")

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Not authenticated" in response.json()["detail"]


def test_get_users_list(client, test_user, test_admin):
    """Test getting list of users with valid token"""
    access_token, _ = create_access_token(
        data={"sub": test_user.username},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    headers = {"Authorization": f"Bearer {access_token}"}
    response = client.get("/users", headers=headers)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 2

    usernames = [user["username"] for user in data]
    assert "testuser" in usernames
    assert "admin" in usernames