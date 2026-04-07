package main

import (
	"log"
	"net/http"
	"time"

	"github.com/codec404/konfig-web-backend/internal/auth"
	"github.com/codec404/konfig-web-backend/internal/config"
	"github.com/codec404/konfig-web-backend/internal/db"
	grpcclient "github.com/codec404/konfig-web-backend/internal/grpc"
	"github.com/codec404/konfig-web-backend/internal/handlers"
	applogger "github.com/codec404/konfig-web-backend/internal/logger"
	"github.com/codec404/konfig-web-backend/internal/mailer"
	"github.com/codec404/konfig-web-backend/internal/middleware"
	"github.com/gorilla/mux"
)

func main() {
	cfg := config.Load()

	// ── Security guards ───────────────────────────────────────────────
	if cfg.JWTSecret == "change-me-in-production" {
		log.Fatal("FATAL: JWT_SECRET is set to the insecure default. Set a strong secret before starting.")
	}

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

	// ── Logger + prune worker ─────────────────────────────────────────
	applogger.Init(store)
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := store.PruneLogs(); err != nil {
				log.Printf("warn: log prune failed: %v", err)
			}
		}
	}()

	// ── gRPC clients ──────────────────────────────────────────────────
	clients, err := grpcclient.NewClients(cfg)
	if err != nil {
		log.Fatalf("failed to initialise gRPC clients: %v", err)
	}
	defer clients.Close()

	// ── Router ────────────────────────────────────────────────────────
	r := mux.NewRouter()
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.MaxBodySize(2 << 20)) // 2 MB
	r.Use(middleware.RequestLogger(store))

	authLimiter := middleware.NewRateLimiter(10, 5)
	apiLimiter := middleware.NewRateLimiter(300, 50)

	ml := mailer.New(cfg.ResendAPIKey, cfg.ResendFrom)

	authHandler := handlers.NewAuthHandler(
		store, cfg.JWTSecret,
		cfg.GoogleClientID, cfg.GoogleClientSecret,
		cfg.AppURL, cfg.SecureCookie,
		ml, cfg.CookieDomain,
	)
	orgHandler := handlers.NewOrgHandler(store, clients, ml, cfg.AppURL, cfg.DeveloperEmail)

	// ── Public routes (no auth required) ─────────────────────────────
	r.HandleFunc("/api/public/orgs", orgHandler.ListPublicOrgs).Methods(http.MethodGet)
	r.HandleFunc("/api/public/orgs/by-slug/{slug}", orgHandler.GetOrgBySlug).Methods(http.MethodGet)
	r.HandleFunc("/api/public/tls-check", handlers.TLSCheck(store, cfg.BaseDomain)).Methods(http.MethodGet)

	// ── SDK routes (service token auth, no user session required) ────────
	sdkRouter := r.PathPrefix("/api/public").Subrouter()
	sdkRouter.Use(apiLimiter.Middleware)
	sdkRouter.Use(auth.ServiceTokenMiddleware(store))
	sdkRouter.HandleFunc("/services/{serviceName}/configs/{configName}/latest",
		handlers.GetLatestConfig(clients, store)).Methods(http.MethodGet)

	// SDK WebSocket (token-authed, no origin check)
	r.Handle("/ws/sdk/subscribe/{serviceName}",
		auth.ServiceTokenMiddleware(store)(
			http.HandlerFunc(handlers.SDKSubscribe(clients)),
		),
	)

	// ── Auth routes (public, strict rate limit) ───────────────────────
	authRouter := r.PathPrefix("/api/auth").Subrouter()
	authRouter.Use(authLimiter.Middleware)
	authRouter.HandleFunc("/logout", authHandler.Logout).Methods(http.MethodPost)
	authRouter.HandleFunc("/google", authHandler.GoogleLogin).Methods(http.MethodGet)
	authRouter.HandleFunc("/google/callback", authHandler.GoogleCallback).Methods(http.MethodGet)
	authRouter.HandleFunc("/send-otp", authHandler.SendOTP).Methods(http.MethodPost)
	authRouter.HandleFunc("/login-otp", authHandler.LoginWithOTP).Methods(http.MethodPost)
	authRouter.HandleFunc("/totp-init", authHandler.TOTPInit).Methods(http.MethodPost)
	authRouter.HandleFunc("/totp-login", authHandler.TOTPLogin).Methods(http.MethodPost)

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
	superAdminRouter.HandleFunc("/orgs/{orgId}/members/{userId}", orgHandler.RemoveUserFromOrg).Methods(http.MethodDelete)
	superAdminRouter.HandleFunc("/orgs/{orgId}/services", orgHandler.ListOrgServices).Methods(http.MethodGet)
	superAdminRouter.HandleFunc("/users", orgHandler.ListAllUsers).Methods(http.MethodGet)
	superAdminRouter.HandleFunc("/users", orgHandler.AddUser).Methods(http.MethodPost)
	superAdminRouter.HandleFunc("/users/{userId}", orgHandler.RemoveUser).Methods(http.MethodDelete)
	superAdminRouter.HandleFunc("/users/{userId}", orgHandler.UpdateUser).Methods(http.MethodPut)
	superAdminRouter.HandleFunc("/users/{userId}/block", orgHandler.BlockUser).Methods(http.MethodPost)
	superAdminRouter.HandleFunc("/users/{userId}/unblock", orgHandler.UnblockUser).Methods(http.MethodPost)
	superAdminRouter.HandleFunc("/bugs", orgHandler.ListBugReports).Methods(http.MethodGet)
	superAdminRouter.HandleFunc("/bugs/{reportId}/status", orgHandler.UpdateBugReportStatus).Methods(http.MethodPut)
	superAdminRouter.HandleFunc("/email-preview", orgHandler.PreviewEmail).Methods(http.MethodGet)
	superAdminRouter.HandleFunc("/logs", handlers.ListLogs(store)).Methods(http.MethodGet)
	superAdminRouter.HandleFunc("/logs/settings", handlers.GetLogSettings()).Methods(http.MethodGet)
	superAdminRouter.HandleFunc("/logs/settings", handlers.SetLogSettings()).Methods(http.MethodPut)

	// ── Org admin: member approval + service visibility ───────────────
	orgAdminRouter := protected.PathPrefix("/api/org").Subrouter()
	orgAdminRouter.Use(auth.RequireOrgAdmin(store))
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
	orgAdminRouter.HandleFunc("/members/{userId}/role", orgHandler.ChangeOrgMemberRole).Methods(http.MethodPut)
	orgAdminRouter.HandleFunc("/members/{userId}/permissions", orgHandler.GetMemberPermissions).Methods(http.MethodGet)
	orgAdminRouter.HandleFunc("/members/{userId}/permissions", orgHandler.SetMemberPermissions).Methods(http.MethodPut)

	// ── User: my orgs & invites ───────────────────────────────────────
	protected.HandleFunc("/api/me/orgs", orgHandler.ListMyOrgs).Methods(http.MethodGet)
	protected.HandleFunc("/api/me/invites", orgHandler.ListMyInvites).Methods(http.MethodGet)
	protected.HandleFunc("/api/me/invites/accept", orgHandler.AcceptInvite).Methods(http.MethodPost)
	protected.HandleFunc("/api/me/invites/decline", orgHandler.DeclineInvite).Methods(http.MethodPost)
	protected.HandleFunc("/api/bugs", orgHandler.SubmitBugReport).Methods(http.MethodPost)
	protected.HandleFunc("/api/logs", handlers.IngestFrontendLogs(store)).Methods(http.MethodPost)

	// Org-specific services (any member)
	protected.HandleFunc("/api/orgs/{orgId}/services", orgHandler.GetOrgServicesForUser).Methods(http.MethodGet)
	protected.HandleFunc("/api/orgs/{orgId}/my-permissions", orgHandler.GetMyOrgPermissions).Methods(http.MethodGet)

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

	// ── Service tokens (SDK credentials) ─────────────────────────────────
	svcRouter.HandleFunc("/api/services/{serviceName}/tokens", handlers.GenerateServiceToken(store)).Methods(http.MethodPost)
	svcRouter.HandleFunc("/api/services/{serviceName}/tokens", handlers.ListServiceTokens(store)).Methods(http.MethodGet)
	svcRouter.HandleFunc("/api/services/{serviceName}/tokens/{tokenId}", handlers.RevokeServiceToken(store)).Methods(http.MethodDelete)

	svcRouter.HandleFunc("/ws/subscribe/{serviceName}", handlers.Subscribe(clients, store, cfg.BaseDomain))

	log.Printf("Starting server on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, middleware.CORS(r, cfg.BaseDomain)); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
