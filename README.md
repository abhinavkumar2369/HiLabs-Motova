## DOCUMENTATION

```md
### Postgresql Database
DB_USER = 
DB_HOST = 
DB_NAME =
DB_PASSWORD = 
DB_PORT = 

### Authentication
JWT_SECRET=
JWT_EXPIRES_IN=

### Nodemailer (OTP emails)
SMTP_HOST=
SMTP_PORT=
SMTP_SECURE=       # true/false
SMTP_USER=
SMTP_PASS=
SMTP_FROM_EMAIL=
```


### Sign Up Table
```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    reset_otp_code VARCHAR(6),
    reset_otp_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

```

## Sign Up

`POST /api/v1/auth/signup`
#### Request
```json
{
    "name": "...",
    "email": "...",
    "password": "..."
}
```

#### Response
```json
{
    "success": true,
    "message": "Signup successful",
    "data": {
        "user": {
            "id": "...",
            "name": "...",
            "email": "..."
        },
        "access_token": "...."
    }
}
```
## Sign In

`POST /api/v1/auth/signin`
#### Request
```json
{
    "email": "...",
    "password": "..."
}
```

#### Response
```json
{
    "success": true,
    "message": "Signin successful",
    "data": {
        "user": {
            "id": "...",
            "name": "...",
            "email": "..."
        },
        "access_token": "...."
    }
}
```

## Forgot Password Flow

1. `POST /api/v1/auth/forgot-password` —
If the email is registered, generates a 6-digit OTP with a 10 minute expiry, stores it, and emails it via Resend.

#### Request
```json
{ 
    "email": "..."
}
```

#### Response
```json
{
    "success": true,
    "message": "If that email is registered, an OTP has been sent"
}
```

2. `POST /api/v1/auth/verify-reset-otp`
User receives the OTP by email, then Validates the OTP (single-use, cleared once verified) and returns a short-lived `reset_token` (valid for 10 minutes).


#### Request
```json
{ 
    "email": "...",
    "otp": "1234" 
}
```

#### Response
```json
{
    "success": true,
    "message": "OTP verified",
    "data": {
        "reset_token": "...."
    }
}
```

3.`POST /api/v1/auth/reset-password`
On the "set new password" screen. Validates the reset token and updates the password.

#### Request
```json
{ 
    "resetToken": "....",
    "newPassword": "..." 
}
```

#### Response
```json
{
    "success": true,
    "message": "Password reset successfully"
}
```

Get `RESEND_API_KEY` from the [Resend dashboard](https://resend.com/api-keys). `RESEND_FROM_EMAIL` must be a verified sender/domain in Resend (use `onboarding@resend.dev` for testing).


