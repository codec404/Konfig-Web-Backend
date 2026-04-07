package middleware

import (
	"net/http"
	"os"
	"strings"
)

func CORS(h http.Handler, baseDomain string) http.Handler {
	if baseDomain == "" {
		baseDomain = os.Getenv("BASE_DOMAIN")
	}
	if baseDomain == "" {
		baseDomain = "localhost"
	}

	// ALLOWED_ORIGINS is a comma-separated list of extra origins to allow
	// (e.g. the portfolio domain). Used in addition to baseDomain subdomains.
	var extraOrigins []string
	if raw := os.Getenv("ALLOWED_ORIGINS"); raw != "" {
		for _, o := range strings.Split(raw, ",") {
			if o = strings.TrimSpace(o); o != "" {
				extraOrigins = append(extraOrigins, o)
			}
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if IsAllowedOrigin(origin, baseDomain) || isExtraOrigin(origin, extraOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Org-ID, X-Org-Slug")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		h.ServeHTTP(w, r)
	})
}

func IsAllowedOrigin(origin, baseDomain string) bool {
	if origin == "" {
		return false
	}
	// Strip protocol
	host := origin
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	// Strip port
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	// Allow exact base domain or any subdomain of it
	return host == baseDomain || strings.HasSuffix(host, "."+baseDomain)
}

func isExtraOrigin(origin string, extra []string) bool {
	for _, o := range extra {
		if strings.EqualFold(o, origin) {
			return true
		}
	}
	return false
}
