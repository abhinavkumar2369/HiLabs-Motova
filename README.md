## DOCUMENTATION

```
### Postgresql Database
DB_USER = 
DB_HOST = 
DB_NAME =
DB_PASSWORD = 
DB_PORT = 

### Authentication
JWT_SECRET=
JWT_EXPIRES_IN=

### Resend (OTP emails)
RESEND_API_KEY=
RESEND_FROM_EMAIL=
```


### Sign Up Table
```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    otp_code VARCHAR(6),
    otp_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);


```
### OTP Auth Flow
1. `POST /api/v1/auth/signup` — creates the user (unverified), generates a 6-digit OTP, stores it with a 10 minute expiry, and emails it via Resend. No access token is returned yet.

```json
{
    "success": true,
    "message": "Signup successful. Please verify the OTP sent to your email",
    "data": {
        "user": {
            "id": "...",
            "name": "...",
            "email": "..."
        }
    }
}
```

2. `POST /api/v1/auth/verify-otp` — body: `{ "email": "...", "otp": "123456" }`. Validates the OTP, marks the user verified, clears the OTP, and returns an access token.

```json
{
    "success": true,
    "message": "Email verified successfully",
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

3. `POST /api/v1/auth/resend-otp` — body: `{ "email": "..." }`. Generates and emails a new OTP for an unverified user.




Get `RESEND_API_KEY` from the [Resend dashboard](https://resend.com/api-keys). `RESEND_FROM_EMAIL` must be a verified sender/domain in Resend (use `onboarding@resend.dev` for testing).
