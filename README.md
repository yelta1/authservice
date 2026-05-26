# AuthService

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white">
  <img src="https://img.shields.io/badge/PostgreSQL-16+-316192?style=for-the-badge&logo=postgresql&logoColor=white">
  <img src="https://img.shields.io/badge/LDAP-Active%20Directory-0A66C2?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">
</p>

<p align="center">
  Lightweight authentication service written in Go with LDAP/Active Directory integration, session management, role-based access control, and PostgreSQL storage.
</p>

---

## Features

- LDAP / Active Directory authentication
- Session-based authentication via HttpOnly cookies
- Role-based access control (RBAC)
- Active session management
- Login attempt protection & temporary blocking
- Middleware authorization system
- PostgreSQL integration
- CORS support
- Audit logging
- Graceful shutdown support
- Clean project structure

Because apparently modern systems need 14 layers of authentication just to open a dashboard with three buttons and one broken chart.

---

# Tech Stack

| Technology | Purpose |
|---|---|
| Go | Backend |
| PostgreSQL | Database |
| LDAP / Active Directory | Authentication |
| net/http | HTTP server |
| go-ldap/ldap | LDAP integration |

---

# Project Structure



```bash

authservice/

│

├── internal/

│   ├── auth/              # LDAP authentication logic

│   ├── handlers/          # HTTP handlers & middleware

│   ├── models/            # Models & DTOs

│   └── repository/        # Database layer

│

├── api.go

├── routes.go

├── main.go

├── go.mod

└── .env.example

```
---

# Environment Variables

Create a `.env` file:

```env
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=password
DB_NAME=authservice
DB_SSLMODE=disable

SERVER_PORT=8080

LDAP_SERVER=10.0.0.1:389
LDAP_BIND_DN=CN=ldap_user,OU=Service Accounts,DC=company,DC=local
LDAP_BIND_PASSWORD=password
LDAP_BASE_DN=DC=company,DC=local
LDAP_REQUIRED_GROUP=CN=AUTH_USERS,OU=Groups,DC=company,DC=local
```

---

# Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/authservice.git
cd authservice
```

## Install Dependencies

```bash
go mod download
```

## Run Application

```bash
go run .
```

Server will start on:

```bash
http://localhost:8080
```

---

# API Endpoints

## Authentication

### Login

```http
POST /api/login
```

### Request

```json
{
  "username": "user12345",
  "password": "password"
}
```

### Response

```json
{
  "success": true,
  "data": {
    "id": 1,
    "username": "user12345",
    "name": "John Doe",
    "role": "admin"
  }
}
```

---

## Current User

```http
GET /api/user
```

Returns authenticated user based on active session.

---

## Logout

```http
POST /api/logout
```

Destroys current session.

---

## User Sessions

```http
GET /api/user-sessions
```

Available for:

- `manager`
- `admin`

---

## Roles

```http
GET /api/roles
```

Available only for:

- `admin`

---

# Security

Implemented security features:

- HttpOnly cookies
- Session expiration
- Session limits per user
- Failed login protection
- LDAP group membership validation
- Authorization middleware
- Role validation middleware

Humans remain the weakest part of any authentication system. The code merely documents the tragedy.

---

# Middleware

| Middleware | Description |
|---|---|
| AuthMiddleware | Checks active session |
| ManagerMiddleware | Allows manager/admin access |
| AdminMiddleware | Allows admin only |
| CorsMiddleware | Handles CORS |

---

# Database Tables

Core tables:

- `users`
- `user_sessions`
- `user_roles`
- `logs`

---

# Login Format Restriction

Allowed usernames:

```txt
user12345
```

Pattern:

```txt
userXXXXX
```

---

# Future Improvements

- JWT support
- Refresh tokens
- Redis session storage
- Docker support
- Swagger/OpenAPI
- HTTPS support
- Rate limiting
- OAuth2 support
- Multi-factor authentication

Because one authentication mechanism is never enough. The industry feeds on paranoia and expired sessions.

---

# Author

**Elnur Talgat**

Backend Developer â¢ Infrastructure Engineer â¢ Anti-Fraud Systems

- Go
- PostgreSQL
- Active Directory
- Windows Infrastructure
- Enterprise Systems

---

# License

MIT License
