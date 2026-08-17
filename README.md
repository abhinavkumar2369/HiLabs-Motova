## DOCUMENTATION


### Postgresql Database
DB_USER = 
DB_HOST = 
DB_NAME =
DB_PASSWORD = 
DB_PORT = 

### Authentication
JWT_SECRET=
JWT_EXPIRES_IN=




```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```