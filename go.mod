module github.com/codec404/konfig-web-backend

go 1.25.1

require (
	github.com/codec404/Konfig v0.0.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.5.3
	github.com/lib/pq v1.11.2
	golang.org/x/crypto v0.49.0
	golang.org/x/oauth2 v0.36.0
	google.golang.org/grpc v1.79.1
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/codec404/Konfig => ../Konfig
