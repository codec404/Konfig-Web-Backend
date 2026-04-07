package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/codec404/Konfig/pkg/pb"
	"github.com/codec404/konfig-web-backend/internal/auth"
	grpcclient "github.com/codec404/konfig-web-backend/internal/grpc"
	"github.com/codec404/konfig-web-backend/internal/middleware"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// Subscribe handles WS /ws/subscribe/:serviceName
func Subscribe(clients *grpcclient.Clients, store *auth.Store, baseDomain string) http.HandlerFunc {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			return middleware.IsAllowedOrigin(origin, baseDomain)
		},
	}
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)
		vars := mux.Vars(r)
		cleanSvcName := vars["serviceName"]
		if !validName.MatchString(cleanSvcName) {
			writeError(w, http.StatusBadRequest, "invalid service name")
			return
		}
		internalSvcName := applyNS(ns, cleanSvcName)

		if !checkPerm(r, user, ns, "live.view", store) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}

		instanceID := r.URL.Query().Get("instance_id")
		if instanceID == "" {
			instanceID = "web-bff"
		}

		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("websocket upgrade error: %v", err)
			return
		}
		defer wsConn.Close()

		streamCtx, streamCancel := context.WithCancel(context.Background())
		defer streamCancel()

		stream, err := clients.Dist.Subscribe(streamCtx)
		if err != nil {
			log.Printf("grpc Subscribe error: %v", err)
			wsConn.WriteJSON(map[string]string{"error": "failed to open stream"})
			return
		}

		if err := stream.Send(&pb.SubscribeRequest{
			ServiceName:    internalSvcName,
			InstanceId:     instanceID,
			CurrentVersion: 0,
		}); err != nil {
			log.Printf("grpc stream Send error: %v", err)
			wsConn.WriteJSON(map[string]string{"error": "subscription failed"})
			return
		}

		done := make(chan struct{})

		go func() {
			defer close(done)
			for {
				update, err := stream.Recv()
				if err != nil {
					log.Printf("grpc stream Recv error: %v", err)
					return
				}

				payload, err := marshalConfigUpdate(update, ns)
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

		go func() {
			for {
				_, _, err := wsConn.ReadMessage()
				if err != nil {
					log.Printf("websocket read error: %v", err)
					streamCancel()
					return
				}
			}
		}()

		<-done
	}
}

// SDKSubscribe handles WS /ws/sdk/subscribe/:serviceName
// Auth: Bearer service token (ServiceTokenMiddleware must wrap this handler).
// Unlike Subscribe, origin checking is skipped — SDK clients (Node, Go, etc.)
// do not send Origin headers, and security is enforced by the token itself.
func SDKSubscribe(clients *grpcclient.Clients) http.HandlerFunc {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	return func(w http.ResponseWriter, r *http.Request) {
		token := auth.ServiceTokenFromContext(r.Context())
		if token == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		vars := mux.Vars(r)
		cleanSvcName := vars["serviceName"]
		if !validName.MatchString(cleanSvcName) {
			writeError(w, http.StatusBadRequest, "invalid service name")
			return
		}

		// Enforce token binding — token must have been issued for this service.
		if token.ServiceName != cleanSvcName {
			writeError(w, http.StatusForbidden, "token not valid for this service")
			return
		}

		internalSvcName := applyNS(token.Namespace, cleanSvcName)

		instanceID := r.URL.Query().Get("instance_id")
		if instanceID == "" {
			instanceID = "sdk-client"
		}

		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("sdk websocket upgrade error: %v", err)
			return
		}
		defer wsConn.Close()

		streamCtx, streamCancel := context.WithCancel(context.Background())
		defer streamCancel()

		stream, err := clients.Dist.Subscribe(streamCtx)
		if err != nil {
			log.Printf("sdk grpc Subscribe error: %v", err)
			wsConn.WriteJSON(map[string]string{"error": "failed to open stream"})
			return
		}

		if err := stream.Send(&pb.SubscribeRequest{
			ServiceName:    internalSvcName,
			InstanceId:     instanceID,
			CurrentVersion: 0,
		}); err != nil {
			log.Printf("sdk grpc stream Send error: %v", err)
			wsConn.WriteJSON(map[string]string{"error": "subscription failed"})
			return
		}

		done := make(chan struct{})

		go func() {
			defer close(done)
			for {
				update, err := stream.Recv()
				if err != nil {
					log.Printf("sdk grpc stream Recv error: %v", err)
					return
				}

				payload, err := marshalConfigUpdate(update, token.Namespace)
				if err != nil {
					log.Printf("sdk marshal ConfigUpdate error: %v", err)
					continue
				}

				if err := wsConn.WriteMessage(websocket.TextMessage, payload); err != nil {
					log.Printf("sdk websocket write error: %v", err)
					return
				}
			}
		}()

		go func() {
			for {
				_, _, err := wsConn.ReadMessage()
				if err != nil {
					log.Printf("sdk websocket read error: %v", err)
					streamCancel()
					return
				}
			}
		}()

		<-done
	}
}

// marshalConfigUpdate converts a ConfigUpdate proto to JSON, stripping the namespace prefix from service_name.
func marshalConfigUpdate(u *pb.ConfigUpdate, ns string) ([]byte, error) {
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
		cleanSvc := cd.GetServiceName()
		if ns != "" && len(cleanSvc) > len(ns) {
			cleanSvc = cleanSvc[len(ns):]
		}
		p.Config = &configDataJSON{
			ConfigID:    cd.GetConfigId(),
			ServiceName: cleanSvc,
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
