package config

import "os"

// Config holds the application configuration loaded from environment variables.
type Config struct {
	Port          string
	KonfigAPIAddr string
	KonfigDistAddr string
	KonfigValAddr  string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		Port:           getEnv("PORT", "8090"),
		KonfigAPIAddr:  getEnv("KONFIG_API_ADDR", "localhost:8081"),
		KonfigDistAddr: getEnv("KONFIG_DIST_ADDR", "localhost:8082"),
		KonfigValAddr:  getEnv("KONFIG_VAL_ADDR", "localhost:8083"),
	}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
