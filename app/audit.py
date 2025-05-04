import json
from typing import Optional, Dict, Any, Union
from fastapi import Request
from sqlalchemy.orm import Session

from . import models


def log_activity(
    db: Session,
    log_type: models.AuditLogType,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Union[Dict[str, Any], str]] = None
):
    """
    Log user activity to the audit log
    
    Parameters:
    - db: Database session
    - log_type: Type of log entry
    - user_id: ID of the user (optional, for events not tied to a user)
    - ip_address: IP address of the user
    - user_agent: User agent string
    - details: Additional details as dict or string
    """
    # Convert dict to JSON string if provided
    if isinstance(details, dict):
        details_str = json.dumps(details)
    else:
        details_str = details
    
    log_entry = models.AuditLog(
        user_id=user_id,
        log_type=log_type,
        ip_address=ip_address,
        user_agent=user_agent,
        details=details_str
    )
    
    db.add(log_entry)
    db.commit()
    
    return log_entry


def get_client_info(request: Request) -> Dict[str, str]:
    """Extract client information from the request"""
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("User-Agent")
    
    # Check for forwarded IP if behind a proxy
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Get the first IP in case of proxy chains
        client_ip = forwarded_for.split(",")[0].strip()
    
    return {
        "ip_address": client_ip,
        "user_agent": user_agent
    }