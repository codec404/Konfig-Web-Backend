package main

import (
	"log"
	"net/http"

	"github.com/codec404/konfig-web-backend/internal/config"
	grpcclient "github.com/codec404/konfig-web-backend/internal/grpc"
	"github.com/codec404/konfig-web-backend/internal/handlers"
	"github.com/codec404/konfig-web-backend/internal/middleware"
	"github.com/gorilla/mux"
)

func main() {
	cfg := config.Load()

	clients, err := grpcclient.NewClients(cfg)
	if err != nil {
		log.Fatalf("failed to initialise gRPC clients: %v", err)
	}
	defer clients.Close()

	r := mux.NewRouter()

	// Config routes
	r.HandleFunc("/api/services", handlers.ListServices(clients)).Methods(http.MethodGet)
	r.HandleFunc("/api/services/{serviceName}/configs", handlers.ListConfigs(clients)).Methods(http.MethodGet)
	r.HandleFunc("/api/configs/{configId}", handlers.GetConfig(clients)).Methods(http.MethodGet)
	r.HandleFunc("/api/configs", handlers.UploadConfig(clients)).Methods(http.MethodPost)
	r.HandleFunc("/api/configs/{configId}", handlers.DeleteConfig(clients)).Methods(http.MethodDelete)

	// Rollout routes
	r.HandleFunc("/api/rollouts", handlers.ListRollouts(clients)).Methods(http.MethodGet)
	r.HandleFunc("/api/rollouts", handlers.StartRollout(clients)).Methods(http.MethodPost)
	r.HandleFunc("/api/rollouts/{configId}/status", handlers.GetRolloutStatus(clients)).Methods(http.MethodGet)
	r.HandleFunc("/api/rollouts/{configId}/promote", handlers.PromoteRollout(clients)).Methods(http.MethodPost)
	r.HandleFunc("/api/rollouts/{configId}/rollback", handlers.Rollback(clients)).Methods(http.MethodPost)

	// Validation routes
	r.HandleFunc("/api/validate", handlers.ValidateConfig(clients)).Methods(http.MethodPost)
	r.HandleFunc("/api/schemas", handlers.ListSchemas(clients)).Methods(http.MethodGet)
	r.HandleFunc("/api/schemas/{schemaId}", handlers.GetSchema(clients)).Methods(http.MethodGet)
	r.HandleFunc("/api/schemas", handlers.RegisterSchema(clients)).Methods(http.MethodPost)

	// Stats and audit routes
	r.Handle("/api/stats", handlers.GetStats(clients)).Methods(http.MethodGet, http.MethodOptions)
	r.Handle("/api/audit-log", handlers.GetAuditLog(clients)).Methods(http.MethodGet, http.MethodOptions)

	// WebSocket route
	r.HandleFunc("/ws/subscribe/{serviceName}", handlers.Subscribe(clients))

	log.Printf("Starting server on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, middleware.CORS(r)); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
