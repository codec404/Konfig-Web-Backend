# Konfig Web Backend

HTTP/WebSocket gateway that bridges the React frontend to the Konfig gRPC services, with JWT auth, Google OAuth, and per-IP rate limiting.

## Overview

| | |
|---|---|
| **Port** | `8090` |
| **Auth** | httpOnly cookie JWT (`konfig_session`, 7-day TTL) + Google OAuth2 |
| **Rate limits** | Auth routes: 10 req/min · API routes: 300 req/min |
| **DB** | Separate PostgreSQL (`konfig_auth`) — isolated from Konfig C++ DB |
| **Roles** | `super_admin` · `admin` · `user` |

## Project Structure

```
cmd/server/         # Entry point — router, middleware wiring
internal/
  auth/             # User store, JWT, middleware, Google OAuth
    models.go       # User struct + Role constants
    store.go        # Migrate, SeedSuperAdmin, CreateLocal, Login, UpsertGoogle, FindByID
    jwt.go          # CreateToken / ValidateToken
    middleware.go   # Cookie reader → User injected into context
  config/           # Environment config loader
  db/               # PostgreSQL connection (lib/pq)
  grpc/             # gRPC client connections to C++ services
  handlers/         # HTTP + WebSocket handlers
    auth.go         # Login, Signup, Me, Logout, GoogleLogin, GoogleCallback
    configs.go      # Config CRUD
    rollouts.go     # Rollout start/promote/rollback/status
    schemas.go      # Schema register/list/get
    stats.go        # Stats + audit log
  middleware/
    cors.go         # Origin-specific CORS with credentials
    ratelimit.go    # Token bucket rate limiter (per-IP, background cleanup)
```

## API Routes

### Auth (rate limited: 10 req/min)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Email + password login, sets `konfig_session` cookie |
| `POST` | `/api/auth/signup` | Register new user |
| `POST` | `/api/auth/logout` | Clears cookie |
| `GET` | `/api/auth/google` | Redirects to Google OAuth consent |
| `GET` | `/api/auth/google/callback` | OAuth callback → sets cookie → redirects to frontend |

### Protected (JWT required, rate limited: 300 req/min)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/auth/me` | Current user info |
| `GET` | `/api/services` | List services |
| `GET` | `/api/services/{serviceName}/configs` | List configs for service |
| `GET` | `/api/configs/{configId}` | Get config |
| `POST` | `/api/configs` | Upload config |
| `DELETE` | `/api/configs/{configId}` | Delete config |
| `GET` | `/api/rollouts` | List rollouts |
| `POST` | `/api/rollouts` | Start rollout |
| `GET` | `/api/rollouts/{configId}/status` | Rollout status |
| `POST` | `/api/rollouts/{configId}/promote` | Promote canary |
| `POST` | `/api/rollouts/{configId}/rollback` | Rollback |
| `POST` | `/api/validate` | Validate config |
| `GET` | `/api/schemas` | List schemas |
| `GET` | `/api/schemas/{schemaId}` | Get schema |
| `POST` | `/api/schemas` | Register schema |
| `GET` | `/api/stats` | Dashboard stats |
| `GET` | `/api/audit-log` | Audit log |
| `WS` | `/ws/subscribe/{serviceName}` | Real-time config update stream |

## Running Locally

```bash
cp .env.example .env
# edit .env — set DATABASE_URL, JWT_SECRET, GOOGLE_CLIENT_ID/SECRET

go run ./cmd/server
```

Requires the Konfig C++ services running:

```bash
cd ../Konfig
docker compose up -d api-service distribution-service validation-service
```

## Docker

```bash
cd ../Konfig
docker compose up --build -d web-backend
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PORT` | Server port (default `8090`) |
| `APP_URL` | Frontend URL for CORS and OAuth redirect (e.g. `http://localhost:5173`) |
| `SECURE_COOKIE` | Set `true` in production (HTTPS only) |
| `DATABASE_URL` | PostgreSQL DSN for the auth DB |
| `JWT_SECRET` | Long random string for signing JWTs |
| `GOOGLE_CLIENT_ID` | Google OAuth2 client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth2 client secret |
| `SUPER_ADMIN_NAME` | Name for seeded super admin account |
| `SUPER_ADMIN_EMAIL` | Email for seeded super admin account |
| `SUPER_ADMIN_PASSWORD` | Password for seeded super admin account |
| `KONFIG_API_ADDR` | gRPC address of api-service (default `localhost:8081`) |
| `KONFIG_DIST_ADDR` | gRPC address of distribution-service (default `localhost:8082`) |
| `KONFIG_VAL_ADDR` | gRPC address of validation-service (default `localhost:8083`) |
