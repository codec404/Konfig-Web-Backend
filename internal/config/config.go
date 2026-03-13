package config

import "os"

type Config struct {
	Port           string
	KonfigAPIAddr  string
	KonfigDistAddr string
	KonfigValAddr  string

	// Database (for auth users table)
	DatabaseURL string

	// Auth
	JWTSecret    string
	AppURL       string
	SecureCookie bool

	// Google OAuth
	GoogleClientID     string
	GoogleClientSecret string

	// Super admin seed (created on first startup if no super_admin exists)
	SuperAdminName     string
	SuperAdminEmail    string
	SuperAdminPassword string
}

func Load() *Config {
	return &Config{
		Port:           getEnv("PORT", "8090"),
		KonfigAPIAddr:  getEnv("KONFIG_API_ADDR", "localhost:8081"),
		KonfigDistAddr: getEnv("KONFIG_DIST_ADDR", "localhost:8082"),
		KonfigValAddr:  getEnv("KONFIG_VAL_ADDR", "localhost:8083"),

		DatabaseURL: getEnv("DATABASE_URL", "postgres://configuser:configpass@localhost:5432/configservice?sslmode=disable"),

		JWTSecret:    getEnv("JWT_SECRET", "change-me-in-production"),
		AppURL:       getEnv("APP_URL", "http://localhost:5173"),
		SecureCookie: getEnv("SECURE_COOKIE", "false") == "true",

		GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),

		SuperAdminName:     getEnv("SUPER_ADMIN_NAME", "Super Admin"),
		SuperAdminEmail:    getEnv("SUPER_ADMIN_EMAIL", "admin@konfig.local"),
		SuperAdminPassword: getEnv("SUPER_ADMIN_PASSWORD", "changeme123"),
	}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
