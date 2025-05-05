# FastAPI JWT Authentication

A comprehensive authentication system built with FastAPI, featuring JWT tokens, refresh tokens, role-based access control, email verification, and more.

<p align="center">
  <img src="https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/SQLAlchemy-FF0000?style=for-the-badge" alt="SQLAlchemy"/>
  <img src="https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=json-web-tokens" alt="JWT"/>
</p>


## Features

- 🔐 **Secure Authentication** with JWT tokens
- 🔄 **Refresh Token Mechanism** for seamless user experience
- 👮 **Role-Based Access Control** (Admin, User, Guest roles)
- ✉️ **Email Verification** for new accounts
- 🔑 **Password Reset** functionality
- 🛡️ **Rate Limiting** to prevent brute force attacks
- 📊 **Audit Logging** for tracking authentication events
- 🧪 **Comprehensive Test Suite** with pytest
- 🐳 **Docker Support** for easy deployment
- 🔄 **CI/CD Pipeline** with GitHub Actions

## Installation

### Local Development

1. Clone the repository:
```bash
git clone https://github.com/username/fastapi-jwt-authentication.git
cd fastapi-jwt-authentication
```

2. Create a virtual environment and install dependencies:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Run the application:
```bash
uvicorn app.main:app --reload
```

### Docker Deployment

1. Build and run with Docker Compose:
```bash
docker-compose up -d
```

## Environment Variables

Configure these environment variables for production usage:

- `JWT_SECRET_KEY`: Secret key for JWT token generation (mandatory)
- `ACCESS_TOKEN_EXPIRE_MINUTES`: Expiry time for access tokens (default: 30)
- `REFRESH_TOKEN_EXPIRE_DAYS`: Expiry time for refresh tokens (default: 7)
- `DATABASE_URL`: Database connection string (default: SQLite)
- `MAIL_USERNAME`: SMTP username for sending emails
- `MAIL_PASSWORD`: SMTP password
- `MAIL_FROM`: Sender email address
- `MAIL_SERVER`: SMTP server address (default: smtp.gmail.com)
- `MAIL_PORT`: SMTP port (default: 587)
- `FRONTEND_URL`: URL of the frontend application for email links

## API Documentation

Once the application is running, access the API documentation at:

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Authentication Endpoints

### Register a New User
```
POST /auth/register
```

### Login
```
POST /auth/login
```

### Refresh Token
```
POST /auth/refresh
```

### Logout
```
POST /auth/logout
```

### Logout from All Devices
```
POST /auth/logout/all
```

### Email Verification
```
POST /auth/verify-email
```

### Request Password Reset
```
POST /auth/password-reset/request
```

### Confirm Password Reset
```
POST /auth/password-reset/confirm
```

### Resend Verification Email
```
POST /auth/resend-verification
```

## User Endpoints

### Get Current User
```
GET /users/me
```

### List All Users
```
GET /users
```

## Admin Endpoints

### Update User Role
```
PUT /users/{user_id}/role
```

### Activate User
```
PUT /users/{user_id}/activate
```

### Deactivate User
```
PUT /users/{user_id}/deactivate
```

### Get Audit Logs
```
GET /audit-logs
```

### Get User-Specific Audit Logs
```
GET /audit-logs/user/{user_id}
```

## Testing

Run the test suite:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=app tests/
```

## License

MIT
