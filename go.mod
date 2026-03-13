module github.com/codec404/konfig-web-backend

go 1.25.1

require (
	github.com/codec404/Konfig v0.0.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.5.3
	google.golang.org/grpc v1.79.1
)

require (
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/codec404/Konfig => ../Konfig
