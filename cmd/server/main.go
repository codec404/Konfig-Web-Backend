package main

import (
	"log"
	"net/http"

	"github.com/codec404/konfig-web-backend/internal/auth"
	"github.com/codec404/konfig-web-backend/internal/config"
	"github.com/codec404/konfig-web-backend/internal/db"
	grpcclient "github.com/codec404/konfig-web-backend/internal/grpc"
	"github.com/codec404/konfig-web-backend/internal/handlers"
	"github.com/codec404/konfig-web-backend/internal/mailer"
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
	if err := store.SeedSuperAdmin(cfg.SuperAdminName, cfg.SuperAdminEmail); err != nil {
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

	authLimiter := middleware.NewRateLimiter(10, 5)
	apiLimiter := middleware.NewRateLimiter(300, 50)

	ml := mailer.New(cfg.ResendAPIKey, cfg.ResendFrom)

	authHandler := handlers.NewAuthHandler(
		store, cfg.JWTSecret,
		cfg.GoogleClientID, cfg.GoogleClientSecret,
		cfg.AppURL, cfg.SecureCookie,
		ml,
	)
	orgHandler := handlers.NewOrgHandler(store, clients, ml, cfg.AppURL)

	// ── Public routes (no auth required) ─────────────────────────────
	r.HandleFunc("/api/public/orgs", orgHandler.ListPublicOrgs).Methods(http.MethodGet)

	// ── Auth routes (public, strict rate limit) ───────────────────────
	authRouter := r.PathPrefix("/api/auth").Subrouter()
	authRouter.Use(authLimiter.Middleware)
	authRouter.HandleFunc("/logout", authHandler.Logout).Methods(http.MethodPost)
	authRouter.HandleFunc("/google", authHandler.GoogleLogin).Methods(http.MethodGet)
	authRouter.HandleFunc("/google/callback", authHandler.GoogleCallback).Methods(http.MethodGet)
	authRouter.HandleFunc("/send-otp", authHandler.SendOTP).Methods(http.MethodPost)
	authRouter.HandleFunc("/login-otp", authHandler.LoginWithOTP).Methods(http.MethodPost)

	// ── Protected base subrouter (session required) ───────────────────
	protected := r.PathPrefix("").Subrouter()
	protected.Use(apiLimiter.Middleware)
	protected.Use(auth.Middleware(store, cfg.JWTSecret))

	// Me + self-service creds
	protected.HandleFunc("/api/auth/me", authHandler.Me).Methods(http.MethodGet)
	protected.HandleFunc("/api/me", authHandler.UpdateMe).Methods(http.MethodPut)

	// ── Super admin: org + user management ───────────────────────────
	superAdminRouter := protected.PathPrefix("/api/admin").Subrouter()
	superAdminRouter.Use(auth.RequireSuperAdmin())
	superAdminRouter.HandleFunc("/orgs", orgHandler.ListOrgs).Methods(http.MethodGet)
	superAdminRouter.HandleFunc("/orgs", orgHandler.CreateOrg).Methods(http.MethodPost)
	superAdminRouter.HandleFunc("/orgs/{orgId}", orgHandler.DeleteOrg).Methods(http.MethodDelete)
	superAdminRouter.HandleFunc("/orgs/{orgId}/members", orgHandler.GetOrgMembers).Methods(http.MethodGet)
	superAdminRouter.HandleFunc("/orgs/{orgId}/services", orgHandler.ListOrgServices).Methods(http.MethodGet)
	superAdminRouter.HandleFunc("/users", orgHandler.ListAllUsers).Methods(http.MethodGet)
	superAdminRouter.HandleFunc("/users", orgHandler.AddUser).Methods(http.MethodPost)
	superAdminRouter.HandleFunc("/users/{userId}", orgHandler.RemoveUser).Methods(http.MethodDelete)
	superAdminRouter.HandleFunc("/users/{userId}", orgHandler.UpdateUser).Methods(http.MethodPut)

	// ── Org admin: member approval + service visibility ───────────────
	orgAdminRouter := protected.PathPrefix("/api/org").Subrouter()
	orgAdminRouter.Use(auth.RequireOrgAdmin())
	orgAdminRouter.HandleFunc("/pending", orgHandler.ListPending).Methods(http.MethodGet)
	orgAdminRouter.HandleFunc("/members", orgHandler.ListMembers).Methods(http.MethodGet)
	orgAdminRouter.HandleFunc("/members/{userId}/approve", orgHandler.ApproveMember).Methods(http.MethodPost)
	orgAdminRouter.HandleFunc("/members/{userId}/reject", orgHandler.RejectMember).Methods(http.MethodPost)
	orgAdminRouter.HandleFunc("/members/{userId}", orgHandler.RemoveOrgMember).Methods(http.MethodDelete)
	orgAdminRouter.HandleFunc("/members/{userId}", orgHandler.UpdateOrgMember).Methods(http.MethodPut)
	orgAdminRouter.HandleFunc("/services/{serviceName}/visibility", orgHandler.ListServiceVisibility).Methods(http.MethodGet)
	orgAdminRouter.HandleFunc("/services/{serviceName}/visibility", orgHandler.GrantServiceVisibility).Methods(http.MethodPost)
	orgAdminRouter.HandleFunc("/services/{serviceName}/visibility/{userId}", orgHandler.RevokeServiceVisibility).Methods(http.MethodDelete)
	orgAdminRouter.HandleFunc("/invite", orgHandler.InviteUser).Methods(http.MethodPost)
	orgAdminRouter.HandleFunc("/invites", orgHandler.ListOrgInvites).Methods(http.MethodGet)

	// ── User: my orgs & invites ───────────────────────────────────────
	protected.HandleFunc("/api/me/orgs", orgHandler.ListMyOrgs).Methods(http.MethodGet)
	protected.HandleFunc("/api/me/invites", orgHandler.ListMyInvites).Methods(http.MethodGet)
	protected.HandleFunc("/api/me/invites/accept", orgHandler.AcceptInvite).Methods(http.MethodPost)
	protected.HandleFunc("/api/me/invites/decline", orgHandler.DeclineInvite).Methods(http.MethodPost)

	// Org-specific services (any member)
	protected.HandleFunc("/api/orgs/{orgId}/services", orgHandler.GetOrgServicesForUser).Methods(http.MethodGet)

	// ── Service/config routes (approved users only) ───────────────────
	svcRouter := protected.PathPrefix("").Subrouter()
	svcRouter.Use(auth.RequireActiveUser())

	svcRouter.HandleFunc("/api/services", handlers.ListServices(clients, store)).Methods(http.MethodGet)
	svcRouter.HandleFunc("/api/services/{serviceName}/named-configs", handlers.ListNamedConfigs(clients, store)).Methods(http.MethodGet)
	svcRouter.HandleFunc("/api/services/{serviceName}/configs/{configName}/versions", handlers.ListConfigs(clients, store)).Methods(http.MethodGet)
	svcRouter.HandleFunc("/api/configs/{configId}", handlers.GetConfig(clients, store)).Methods(http.MethodGet)
	svcRouter.HandleFunc("/api/configs", handlers.UploadConfig(clients, store)).Methods(http.MethodPost)
	svcRouter.HandleFunc("/api/configs/{configId}", handlers.DeleteConfig(clients, store)).Methods(http.MethodDelete)

	svcRouter.HandleFunc("/api/rollouts", handlers.ListRollouts(clients, store)).Methods(http.MethodGet)
	svcRouter.HandleFunc("/api/rollouts", handlers.StartRollout(clients, store)).Methods(http.MethodPost)
	svcRouter.HandleFunc("/api/rollouts/{configId}/status", handlers.GetRolloutStatus(clients, store)).Methods(http.MethodGet)
	svcRouter.HandleFunc("/api/rollouts/{configId}/promote", handlers.PromoteRollout(clients, store)).Methods(http.MethodPost)
	svcRouter.HandleFunc("/api/rollbacks", handlers.Rollback(clients, store)).Methods(http.MethodPost)

	svcRouter.HandleFunc("/api/validate", handlers.ValidateConfig(clients, store)).Methods(http.MethodPost)
	svcRouter.HandleFunc("/api/schemas", handlers.ListSchemas(clients, store)).Methods(http.MethodGet)
	svcRouter.HandleFunc("/api/schemas/{schemaId}", handlers.GetSchema(clients, store)).Methods(http.MethodGet)
	svcRouter.HandleFunc("/api/schemas", handlers.RegisterSchema(clients, store)).Methods(http.MethodPost)

	svcRouter.Handle("/api/stats", handlers.GetStats(clients, store)).Methods(http.MethodGet, http.MethodOptions)
	svcRouter.Handle("/api/audit-log", handlers.GetAuditLog(clients, store)).Methods(http.MethodGet, http.MethodOptions)

	svcRouter.HandleFunc("/ws/subscribe/{serviceName}", handlers.Subscribe(clients, store))

	log.Printf("Starting server on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, middleware.CORS(r)); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
