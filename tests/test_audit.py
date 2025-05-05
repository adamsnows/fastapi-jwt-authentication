import pytest
from fastapi import status
from app.models import AuditLogType, AuditLog

def test_audit_logs_access(client, test_admin):
    """Test that admin can access audit logs"""
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

    # access audit logs
    response = client.get("/audit-logs", headers=headers)
    assert response.status_code == status.HTTP_200_OK

    # check that the login created an audit log entry
    logs = response.json()
    assert len(logs) > 0
    login_log = next((log for log in logs if log["log_type"] == AuditLogType.LOGIN), None)
    assert login_log is not None
    assert login_log["user_id"] == test_admin.id


def test_audit_logs_filtering(client, test_admin, test_user):
    """Test audit logs filtering functionality"""
    # login with both users to create audit logs
    admin_login = client.post(
        "/auth/login",
        data={
            "username": "admin",
            "password": "adminpassword"
        }
    )
    admin_token = admin_login.json()["access_token"]

    user_login = client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "testpassword"
        }
    )

    # access audit logs with admin token
    headers = {"Authorization": f"Bearer {admin_token}"}

    # filter by user_id
    response = client.get(f"/audit-logs?user_id={test_user.id}", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    logs = response.json()
    assert all(log["user_id"] == test_user.id for log in logs)

    # filter by log_type - using string value instead of enum object
    response = client.get(f"/audit-logs?log_type=login", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    logs = response.json()
    assert all(log["log_type"] == "login" for log in logs)


def test_user_specific_audit_logs(client, test_admin, test_user):
    """Test fetching audit logs for a specific user"""
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

    # access user-specific logs
    response = client.get(f"/audit-logs/user/{test_user.id}", headers=headers)
    assert response.status_code == status.HTTP_200_OK

    # all returned logs should be for this user
    logs = response.json()
    for log in logs:
        assert log["user_id"] == test_user.id


def test_get_audit_log_types(client, test_admin):
    """Test retrieving available audit log types"""
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

    # get audit log types
    response = client.get("/audit-logs/types", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    log_types = response.json()

    # check that expected log types are included
    expected_types = ["login", "logout", "register", "password_reset", "email_verification"]
    for expected in expected_types:
        assert expected in log_types


def test_delete_audit_log(client, test_admin):
    """Test deleting an audit log entry"""
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

    # get the logs to find one to delete
    response = client.get("/audit-logs", headers=headers)
    logs = response.json()
    assert len(logs) > 0
    log_id = logs[0]["id"]

    # delete the log
    response = client.delete(f"/audit-logs/{log_id}", headers=headers)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # verify it's gone
    response = client.get("/audit-logs", headers=headers)
    logs = response.json()
    assert not any(log["id"] == log_id for log in logs)


def test_login_creates_audit_log(client, test_user, db_session):
    """Test that login creates an audit log entry"""
    # get current log count
    logs_before = db_session.query(AuditLog).count()

    # login
    client.post(
        "/auth/login",
        data={
            "username": "testuser",
            "password": "testpassword"
        }
    )

    # check log count increased
    logs_after = db_session.query(AuditLog).count()
    assert logs_after > logs_before