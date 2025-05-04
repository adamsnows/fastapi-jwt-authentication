import pytest
from fastapi import status
from app.auth import get_password_hash


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