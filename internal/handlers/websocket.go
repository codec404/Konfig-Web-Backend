package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/codec404/Konfig/pkg/pb"
	grpcclient "github.com/codec404/konfig-web-backend/internal/grpc"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Subscribe handles WS /ws/subscribe/:serviceName
//
// It upgrades the HTTP connection to a WebSocket, opens a bidirectional gRPC
// stream to the Distribution Service, and bridges the two:
//   - gRPC stream → WebSocket: config updates are forwarded as JSON.
//   - WebSocket → gRPC stream: incoming messages (heartbeats) are silently ignored.
func Subscribe(clients *grpcclient.Clients) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		serviceName := vars["serviceName"]
		instanceID := r.URL.Query().Get("instance_id")
		if instanceID == "" {
			instanceID = "web-bff"
		}

		// Upgrade to WebSocket.
		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("websocket upgrade error: %v", err)
			return
		}
		defer wsConn.Close()

		// Open long-lived gRPC bidirectional stream. We use a background context
		// so the stream lifetime is tied to the WebSocket connection, not the
		// original HTTP request context (which is cancelled on upgrade).
		streamCtx, streamCancel := context.WithCancel(context.Background())
		defer streamCancel()

		stream, err := clients.Dist.Subscribe(streamCtx)
		if err != nil {
			log.Printf("grpc Subscribe error: %v", err)
			wsConn.WriteJSON(map[string]string{"error": "failed to open gRPC stream: " + err.Error()})
			return
		}

		// Send initial subscription request.
		if err := stream.Send(&pb.SubscribeRequest{
			ServiceName:    serviceName,
			InstanceId:     instanceID,
			CurrentVersion: 0,
		}); err != nil {
			log.Printf("grpc stream Send error: %v", err)
			wsConn.WriteJSON(map[string]string{"error": "failed to subscribe: " + err.Error()})
			return
		}

		done := make(chan struct{})

		// Goroutine: read from gRPC stream and forward to WebSocket.
		go func() {
			defer close(done)
			for {
				update, err := stream.Recv()
				if err != nil {
					log.Printf("grpc stream Recv error: %v", err)
					return
				}

				payload, err := marshalConfigUpdate(update)
				if err != nil {
					log.Printf("marshal ConfigUpdate error: %v", err)
					continue
				}

				if err := wsConn.WriteMessage(websocket.TextMessage, payload); err != nil {
					log.Printf("websocket write error: %v", err)
					return
				}
			}
		}()

		// Goroutine: read from WebSocket (heartbeats / control frames) and discard.
		go func() {
			for {
				_, _, err := wsConn.ReadMessage()
				if err != nil {
					log.Printf("websocket read error: %v", err)
					streamCancel()
					return
				}
				// Heartbeat messages are intentionally ignored.
			}
		}()

		// Block until the gRPC side closes.
		<-done
	}
}

// marshalConfigUpdate converts a ConfigUpdate proto to a JSON byte slice
// with timestamp fields rendered as RFC3339 strings.
func marshalConfigUpdate(u *pb.ConfigUpdate) ([]byte, error) {
	type configDataJSON struct {
		ConfigID    string `json:"config_id"`
		ServiceName string `json:"service_name"`
		Version     int64  `json:"version"`
		Content     string `json:"content"`
		Format      string `json:"format"`
		ContentHash string `json:"content_hash"`
		CreatedAt   string `json:"created_at"`
		CreatedBy   string `json:"created_by"`
	}

	type payload struct {
		Config      *configDataJSON `json:"config,omitempty"`
		ForceReload bool            `json:"force_reload"`
		UpdateType  string          `json:"update_type"`
	}

	p := payload{
		ForceReload: u.GetForceReload(),
		UpdateType:  updateTypeString(u.GetUpdateType()),
	}

	if cd := u.GetConfig(); cd != nil {
		p.Config = &configDataJSON{
			ConfigID:    cd.GetConfigId(),
			ServiceName: cd.GetServiceName(),
			Version:     cd.GetVersion(),
			Content:     cd.GetContent(),
			Format:      cd.GetFormat(),
			ContentHash: cd.GetContentHash(),
			CreatedAt:   time.Unix(cd.GetCreatedAt(), 0).UTC().Format(time.RFC3339),
			CreatedBy:   cd.GetCreatedBy(),
		}
	}

	return json.Marshal(p)
}

func updateTypeString(t pb.UpdateType) string {
	switch t {
	case pb.UpdateType_VERSION_UPDATE:
		return "VERSION_UPDATE"
	case pb.UpdateType_ROLLBACK:
		return "ROLLBACK"
	case pb.UpdateType_HEARTBEAT_ACK:
		return "HEARTBEAT_ACK"
	default:
		return "NEW_CONFIG"
	}
}
