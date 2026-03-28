package middleware

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/codec404/konfig-web-backend/internal/auth"
)

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.status = code
	rr.ResponseWriter.WriteHeader(code)
}

// Hijack forwards the Hijack call to the underlying ResponseWriter so that
// WebSocket upgrades work correctly through this middleware.
func (rr *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := rr.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	return h.Hijack()
}

// RequestLogger logs every HTTP request (method, path, status, latency) to the DB.
func RequestLogger(s *auth.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rr := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rr, r)

			level := "info"
			if rr.status >= 500 {
				level = "error"
			} else if rr.status >= 400 {
				level = "warn"
			}

			ctx := map[string]any{
				"method":      r.Method,
				"path":        r.URL.Path,
				"status":      rr.status,
				"duration_ms": time.Since(start).Milliseconds(),
				"ip":          realIP(r),
			}

			go s.CreateLog("backend", level, r.Method+" "+r.URL.Path, ctx)
		})
	}
}
