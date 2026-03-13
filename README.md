# Konfig Web Backend

HTTP/WebSocket gateway that bridges the React frontend to the Konfig gRPC services.

## Overview

- Listens on port `8090`
- Proxies REST calls to the C++ gRPC services (`api-service`, `distribution-service`, `validation-service`)
- Serves a WebSocket endpoint for real-time rollout log streaming

## Project Structure

```
cmd/server/         # Entry point
internal/
  config/           # Environment config loader
  grpc/             # gRPC client connections
  handlers/         # HTTP + WebSocket handlers
  middleware/       # CORS, logging, etc.
```

## Running Locally

```bash
go run ./cmd/server
```

Requires the Konfig C++ services to be running. Start them via the `docker-compose.yml` in the `Konfig/` directory:

```bash
cd ../Konfig
docker compose up -d api-service distribution-service validation-service
```

## Docker

Built as part of the root `docker-compose.yml` in `Konfig/`. The build context must be the parent `Konfig-Web/` directory since this module depends on the local `Konfig` Go module.

```bash
cd ../Konfig
docker compose up --build -d web-backend
```
