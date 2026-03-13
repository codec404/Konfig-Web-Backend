package middleware

import (
	"net/http"
	"os"
)

// CORS handles cross-origin requests. Uses a specific allowed origin with
// credentials support (required for httpOnly cookie auth).
func CORS(h http.Handler) http.Handler {
	appURL := os.Getenv("APP_URL")
	if appURL == "" {
		appURL = "http://localhost:5173"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == appURL {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		h.ServeHTTP(w, r)
	})
}
