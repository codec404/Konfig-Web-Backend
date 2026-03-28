# Konfig Web Backend

HTTP/WebSocket gateway that bridges the React frontend to the Konfig gRPC services, with OTP-based auth, Google OAuth, JWT sessions, organisation management, and per-IP rate limiting.

## Overview

| | |
|---|---|
| **Port** | `8090` |
| **Auth** | httpOnly cookie JWT (`konfig_session`, 7-day TTL) + OTP email login + Google OAuth2 |
| **Rate limits** | Auth routes: 10 req/min · API routes: 300 req/min |
| **Body limit** | 2 MB per request |
| **DB** | Separate PostgreSQL (`konfig_auth`) — isolated from Konfig C++ DB |
| **Roles** | `super_admin` · `admin` · `user` |

## Project Structure

```
cmd/server/         # Entry point — router, middleware wiring
internal/
  auth/             # User store, JWT, session middleware, Google OAuth
    models.go       # User struct + Role constants
    store.go        # Migrate, SeedSuperAdmin, OTP, FindByID, org/invite ops
    jwt.go          # CreateToken / ValidateToken
    middleware.go   # Cookie reader → User injected into context
  config/           # Environment config loader
  db/               # PostgreSQL connection (lib/pq)
  grpc/             # gRPC client connections to C++ services
  handlers/         # HTTP + WebSocket handlers
    auth.go         # SendOTP, LoginWithOTP, Me, UpdateMe, Logout, GoogleLogin, GoogleCallback
    configs.go      # Config CRUD + service listing
    orgs.go         # Org management, invites, permissions, bug reports
    rollouts.go     # Rollout start/promote/rollback/status
    validation.go   # ValidateConfig, schema register/list/get
    websocket.go    # Real-time config update stream via WebSocket
    logs.go         # Frontend log ingestion, admin log viewer + settings
  logger/           # In-process structured log writer + level filter
  mailer/           # Resend API email sender (falls back to stdout)
  middleware/
    cors.go         # Origin-specific CORS with credentials
    logging.go      # Request logger (method, path, status, latency)
    ratelimit.go    # Token bucket rate limiter (per-IP, background cleanup)
    security.go     # Security headers + body size limit
```

## API Routes

### Public (no auth required)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/public/orgs` | List all organisations (name + slug) |
| `GET` | `/api/public/orgs/by-slug/{slug}` | Look up org by subdomain slug |
| `GET` | `/api/public/tls-check` | Check TLS/subdomain routing status |

### Auth (rate limited: 10 req/min)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/send-otp` | Send a one-time code to the given email |
| `POST` | `/api/auth/login-otp` | Verify OTP → sets `konfig_session` cookie |
| `POST` | `/api/auth/logout` | Clears session cookie |
| `GET` | `/api/auth/google` | Redirects to Google OAuth consent |
| `GET` | `/api/auth/google/callback` | OAuth callback → sets cookie → redirects to frontend |

### Protected — current user (JWT required, rate limited: 300 req/min)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/auth/me` | Current user info |
| `PUT` | `/api/me` | Update display name |
| `GET` | `/api/me/orgs` | Orgs the current user belongs to |
| `GET` | `/api/me/invites` | Pending invites for the current user |
| `POST` | `/api/me/invites/accept` | Accept an invite |
| `POST` | `/api/me/invites/decline` | Decline an invite |
| `POST` | `/api/bugs` | Submit a bug report |
| `POST` | `/api/logs` | Ingest frontend log entries (max 100 per request) |
| `GET` | `/api/orgs/{orgId}/services` | Services visible to current user in org |
| `GET` | `/api/orgs/{orgId}/my-permissions` | Current user's permission set for an org |

### Protected — config/rollout/schema (approved org members only)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/services` | List services |
| `GET` | `/api/services/{serviceName}/named-configs` | Named configs for a service |
| `GET` | `/api/services/{serviceName}/configs/{configName}/versions` | Config version history |
| `GET` | `/api/configs/{configId}` | Get config |
| `POST` | `/api/configs` | Upload config |
| `DELETE` | `/api/configs/{configId}` | Delete config |
| `GET` | `/api/rollouts` | List rollouts |
| `POST` | `/api/rollouts` | Start rollout |
| `GET` | `/api/rollouts/{configId}/status` | Rollout status |
| `POST` | `/api/rollouts/{configId}/promote` | Promote canary |
| `POST` | `/api/rollbacks` | Rollback |
| `POST` | `/api/validate` | Validate config |
| `GET` | `/api/schemas` | List schemas |
| `GET` | `/api/schemas/{schemaId}` | Get schema |
| `POST` | `/api/schemas` | Register schema |
| `GET` | `/api/stats` | Dashboard stats |
| `GET` | `/api/audit-log` | Audit log |
| `WS` | `/ws/subscribe/{serviceName}` | Real-time config update stream |

### Super admin only (`/api/admin/*`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/orgs` | List all orgs |
| `POST` | `/api/admin/orgs` | Create org |
| `DELETE` | `/api/admin/orgs/{orgId}` | Delete org |
| `GET` | `/api/admin/orgs/{orgId}/members` | Org member list |
| `DELETE` | `/api/admin/orgs/{orgId}/members/{userId}` | Remove member from org |
| `GET` | `/api/admin/orgs/{orgId}/services` | Services under an org |
| `GET` | `/api/admin/users` | List all users |
| `POST` | `/api/admin/users` | Add user |
| `DELETE` | `/api/admin/users/{userId}` | Remove user |
| `PUT` | `/api/admin/users/{userId}` | Update user |
| `POST` | `/api/admin/users/{userId}/block` | Block user |
| `POST` | `/api/admin/users/{userId}/unblock` | Unblock user |
| `GET` | `/api/admin/bugs` | List bug reports |
| `PUT` | `/api/admin/bugs/{reportId}/status` | Update bug report status |
| `GET` | `/api/admin/email-preview` | Preview email template |
| `GET` | `/api/admin/logs` | Paginated app log viewer |
| `GET` | `/api/admin/logs/settings` | Current enabled log levels |
| `PUT` | `/api/admin/logs/settings` | Update enabled log levels |

### Org admin only (`/api/org/*`)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/org/pending` | Pending join requests |
| `GET` | `/api/org/members` | Current org members |
| `POST` | `/api/org/members/{userId}/approve` | Approve join request |
| `POST` | `/api/org/members/{userId}/reject` | Reject join request |
| `DELETE` | `/api/org/members/{userId}` | Remove member |
| `PUT` | `/api/org/members/{userId}` | Update member |
| `PUT` | `/api/org/members/{userId}/role` | Change member role |
| `GET` | `/api/org/members/{userId}/permissions` | Get member permissions |
| `PUT` | `/api/org/members/{userId}/permissions` | Set member permissions |
| `POST` | `/api/org/invite` | Invite user by email |
| `GET` | `/api/org/invites` | List pending invites |
| `GET` | `/api/org/services/{serviceName}/visibility` | Service visibility list |
| `POST` | `/api/org/services/{serviceName}/visibility` | Grant service visibility |
| `DELETE` | `/api/org/services/{serviceName}/visibility/{userId}` | Revoke service visibility |

## Running Locally

```bash
cp .env.example .env
# edit .env — set DATABASE_URL, JWT_SECRET, and optionally Google OAuth / Resend keys

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

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8090` | Server listen port |
| `DATABASE_URL` | *(postgres://…/configservice)* | PostgreSQL DSN for the auth DB |
| `JWT_SECRET` | *(required — no default in prod)* | Long random string for signing JWTs |
| `APP_URL` | `http://localhost:5173` | Frontend URL for CORS and OAuth redirect |
| `SECURE_COOKIE` | `false` | Set `true` in production (HTTPS-only cookies) |
| `BASE_DOMAIN` | `localhost` | Root domain used for WebSocket origin check |
| `COOKIE_DOMAIN` | *(empty)* | Cookie domain attribute (e.g. `.example.com`) |
| `GOOGLE_CLIENT_ID` | *(empty)* | Google OAuth2 client ID |
| `GOOGLE_CLIENT_SECRET` | *(empty)* | Google OAuth2 client secret |
| `SUPER_ADMIN_NAME` | `Super Admin` | Display name for seeded super admin |
| `SUPER_ADMIN_EMAIL` | `admin@konfig.local` | Email for seeded super admin (OTP login) |
| `RESEND_API_KEY` | *(empty)* | Resend API key — leave empty to log OTPs to stdout |
| `RESEND_FROM` | `noreply@konfig.org.in` | From address for OTP emails |
| `DEVELOPER_EMAIL` | *(empty)* | CC address for org-related admin emails |
| `KONFIG_API_ADDR` | `localhost:8081` | gRPC address of api-service |
| `KONFIG_DIST_ADDR` | `localhost:8082` | gRPC address of distribution-service |
| `KONFIG_VAL_ADDR` | `localhost:8083` | gRPC address of validation-service |

> **Note:** The server refuses to start if `JWT_SECRET` is the default `change-me-in-production` value.

## Security Features

- **OTP authentication** — no passwords stored; one-time codes sent via email (Resend) or logged to stdout in dev
- **Constant-time OTP comparison** — prevents timing attacks; locks after 5 failed attempts
- **WebSocket origin check** — `CheckOrigin` validates against `BASE_DOMAIN` allow-list
- **Security headers** — X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, HSTS (HTTPS only)
- **Body limit** — 2 MB max per request
- **Rate limiting** — per-IP token bucket (10 req/min auth, 300 req/min API)
- **Google OAuth CSRF** — random state stored in short-lived HttpOnly cookie, validated on callback
- **gRPC error sanitisation** — upstream error details never exposed in HTTP responses
- **Namespace enforcement** — org slug prefix prevents cross-tenant config/schema access
- **Input validation** — service and config names validated against `^[a-zA-Z0-9._\-]{1,128}$`
- **IP extraction** — uses rightmost X-Forwarded-For entry (Caddy appends real IP at end)
