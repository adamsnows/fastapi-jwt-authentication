import pytest
from fastapi import status
from app.models import UserRole

def test_admin_access_admin_endpoint(client, test_admin):
    """Test that admin users can access admin endpoints"""
    # login as admin
    login_response = client.post(
        "/auth/login",
        data={
            "username": "admin",
            "password": "adminpassword"
        }
    )
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # access admin endpoint
    response = client.get("/users/deactivated", headers=headers)
    assert response.status_code == status.HTTP_200_OK

    # another admin endpoint
    response = client.get("/audit-logs", headers=headers)
    assert response.status_code == status.HTTP_200_OK


def test_non_admin_cannot_access_admin_endpoint(client, test_user):
    """Test that non-admin users cannot access admin endpoints"""
    # aogin as regular user
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "testpassword"
        }
    )
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # try to access admin endpoint
    response = client.get("/users/deactivated", headers=headers)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "Admin privileges required" in response.json()["detail"]

    # another admin endpoint
    response = client.get("/audit-logs", headers=headers)
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_guest_access_limited(client, test_guest_user):
    """Test that guest users have limited access"""
    # login as guest
    login_response = client.post(
        "/auth/login",
        data={
            "username": "guest",
            "password": "guestpassword"
        }
    )
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # try to access users list (requires USER or ADMIN)
    response = client.get("/users", headers=headers)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "Insufficient permissions" in response.json()["detail"]

    # can access their own profile
    response = client.get("/users/me", headers=headers)
    assert response.status_code == status.HTTP_200_OK


def test_update_user_role(client, test_admin, test_user):
    """Test that admin can update user roles"""
    # login as admin
    login_response = client.post(
        "/auth/login",
        data={
            "username": "admin",
            "password": "adminpassword"
        }
    )
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # update the role of the test user
    response = client.put(
        f"/users/{test_user.id}/role",
        headers=headers,
        params={"role": UserRole.ADMIN}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["role"] == UserRole.ADMIN

    # verify the user now has admin privileges by logging in and accessing admin endpoint
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "testpassword"
        }
    )
    new_token = login_response.json()["access_token"]
    new_headers = {"Authorization": f"Bearer {new_token}"}

    admin_response = client.get("/users/deactivated", headers=new_headers)
    assert admin_response.status_code == status.HTTP_200_OK


def test_activate_deactivate_user(client, test_admin, test_user):
    """Test activating and deactivating users"""
    # login as admin
    login_response = client.post(
        "/auth/login",
        data={
            "username": "admin",
            "password": "adminpassword"
        }
    )
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # deactivate the test user
    response = client.put(f"/users/{test_user.id}/deactivate", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["is_active"] == False

    # try to login with the deactivated user
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "testpassword"
        }
    )
    assert login_response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Inactive user" in login_response.json()["detail"]

    # activate the user again
    response = client.put(f"/users/{test_user.id}/activate", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["is_active"] == True

    # login should work again
    login_response = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "testpassword"
        }
    )
    assert login_response.status_code == status.HTTP_200_OK


def test_admin_cannot_deactivate_self(client, test_admin):
    """Test that admin cannot deactivate their own account"""
    # login as admin
    login_response = client.post(
        "/auth/login",
        data={
            "username": "admin",
            "password": "adminpassword"
        }
    )
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # try to deactivate own account
    response = client.put(f"/users/{test_admin.id}/deactivate", headers=headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "You cannot deactivate your own account" in response.json()["detail"]