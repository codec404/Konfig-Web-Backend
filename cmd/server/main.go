package main

import (
	"log"
	"net/http"

	"github.com/codec404/konfig-web-backend/internal/auth"
	"github.com/codec404/konfig-web-backend/internal/config"
	"github.com/codec404/konfig-web-backend/internal/db"
	grpcclient "github.com/codec404/konfig-web-backend/internal/grpc"
	"github.com/codec404/konfig-web-backend/internal/handlers"
	"github.com/codec404/konfig-web-backend/internal/middleware"
	"github.com/gorilla/mux"
)

func main() {
	cfg := config.Load()

	// ── Database ──────────────────────────────────────────────────────
	database, err := db.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer database.Close()

	store := auth.NewStore(database)
	if err := store.Migrate(); err != nil {
		log.Fatalf("failed to run auth migration: %v", err)
	}
	if err := store.SeedSuperAdmin(cfg.SuperAdminName, cfg.SuperAdminEmail, cfg.SuperAdminPassword); err != nil {
		log.Printf("warn: could not seed super admin: %v", err)
	}

	// ── gRPC clients ──────────────────────────────────────────────────
	clients, err := grpcclient.NewClients(cfg)
	if err != nil {
		log.Fatalf("failed to initialise gRPC clients: %v", err)
	}
	defer clients.Close()

	// ── Router ────────────────────────────────────────────────────────
	r := mux.NewRouter()

	// Rate limiters
	authLimiter := middleware.NewRateLimiter(10, 5)   // 10 req/min, burst 5 — for login/signup
	apiLimiter := middleware.NewRateLimiter(300, 50)  // 300 req/min, burst 50 — for API

	// Auth routes (public, strict rate limit)
	authHandler := handlers.NewAuthHandler(
		store, cfg.JWTSecret,
		cfg.GoogleClientID, cfg.GoogleClientSecret,
		cfg.AppURL, cfg.SecureCookie,
	)
	authRouter := r.PathPrefix("/api/auth").Subrouter()
	authRouter.Use(authLimiter.Middleware)
	authRouter.HandleFunc("/login", authHandler.Login).Methods(http.MethodPost)
	authRouter.HandleFunc("/signup", authHandler.Signup).Methods(http.MethodPost)
	authRouter.HandleFunc("/logout", authHandler.Logout).Methods(http.MethodPost)
	authRouter.HandleFunc("/google", authHandler.GoogleLogin).Methods(http.MethodGet)
	authRouter.HandleFunc("/google/callback", authHandler.GoogleCallback).Methods(http.MethodGet)

	// Protected subrouter
	protected := r.PathPrefix("").Subrouter()
	protected.Use(apiLimiter.Middleware)
	protected.Use(auth.Middleware(store, cfg.JWTSecret))

	protected.HandleFunc("/api/auth/me", authHandler.Me).Methods(http.MethodGet)

	// Config routes
	protected.HandleFunc("/api/services", handlers.ListServices(clients)).Methods(http.MethodGet)
	protected.HandleFunc("/api/services/{serviceName}/named-configs", handlers.ListNamedConfigs(clients)).Methods(http.MethodGet)
	protected.HandleFunc("/api/services/{serviceName}/configs/{configName}/versions", handlers.ListConfigs(clients)).Methods(http.MethodGet)
	protected.HandleFunc("/api/configs/{configId}", handlers.GetConfig(clients)).Methods(http.MethodGet)
	protected.HandleFunc("/api/configs", handlers.UploadConfig(clients)).Methods(http.MethodPost)
	protected.HandleFunc("/api/configs/{configId}", handlers.DeleteConfig(clients)).Methods(http.MethodDelete)

	// Rollout routes
	protected.HandleFunc("/api/rollouts", handlers.ListRollouts(clients)).Methods(http.MethodGet)
	protected.HandleFunc("/api/rollouts", handlers.StartRollout(clients)).Methods(http.MethodPost)
	protected.HandleFunc("/api/rollouts/{configId}/status", handlers.GetRolloutStatus(clients)).Methods(http.MethodGet)
	protected.HandleFunc("/api/rollouts/{configId}/promote", handlers.PromoteRollout(clients)).Methods(http.MethodPost)
	protected.HandleFunc("/api/rollbacks", handlers.Rollback(clients)).Methods(http.MethodPost)

	// Validation routes
	protected.HandleFunc("/api/validate", handlers.ValidateConfig(clients)).Methods(http.MethodPost)
	protected.HandleFunc("/api/schemas", handlers.ListSchemas(clients)).Methods(http.MethodGet)
	protected.HandleFunc("/api/schemas/{schemaId}", handlers.GetSchema(clients)).Methods(http.MethodGet)
	protected.HandleFunc("/api/schemas", handlers.RegisterSchema(clients)).Methods(http.MethodPost)

	// Stats and audit routes
	protected.Handle("/api/stats", handlers.GetStats(clients)).Methods(http.MethodGet, http.MethodOptions)
	protected.Handle("/api/audit-log", handlers.GetAuditLog(clients)).Methods(http.MethodGet, http.MethodOptions)

	// WebSocket route
	protected.HandleFunc("/ws/subscribe/{serviceName}", handlers.Subscribe(clients))

	log.Printf("Starting server on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, middleware.CORS(r)); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
