# Build context is the parent Konfig-Web/ directory
FROM golang:1.25-alpine AS builder
WORKDIR /workspace

# Install protoc for Go proto generation
RUN apk add --no-cache protobuf

# Copy the local Konfig module (required by replace directive)
COPY Konfig/go.mod Konfig/go.sum ./Konfig/
COPY Konfig/ ./Konfig/

# Generate Go protobuf files
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
RUN cd /workspace/Konfig && \
    mkdir -p pkg/pb && \
    protoc --proto_path=proto \
      --go_out=. --go_opt=module=github.com/codec404/Konfig \
      --go-grpc_out=. --go-grpc_opt=module=github.com/codec404/Konfig \
      proto/*.proto

# Copy the web backend
COPY Konfig-Web-Backend/go.mod Konfig-Web-Backend/go.sum ./Konfig-Web-Backend/
WORKDIR /workspace/Konfig-Web-Backend
RUN go mod download
COPY Konfig-Web-Backend/ .
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /workspace/Konfig-Web-Backend/server .
EXPOSE 8090
CMD ["./server"]
