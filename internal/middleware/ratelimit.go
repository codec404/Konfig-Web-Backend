package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// RateLimiter implements a per-IP token bucket rate limiter.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens refilled per second
	capacity float64 // max tokens (burst size)
}

func NewRateLimiter(requestsPerMinute int, burst int) *RateLimiter {
	rl := &RateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     float64(requestsPerMinute) / 60.0,
		capacity: float64(burst),
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		rl.buckets[ip] = &bucket{tokens: rl.capacity - 1, lastSeen: now}
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens = min(rl.capacity, b.tokens+elapsed*rl.rate)
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// cleanup removes buckets that haven't been seen in 10 minutes.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		for ip, b := range rl.buckets {
			if time.Since(b.lastSeen) > 10*time.Minute {
				delete(rl.buckets, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Middleware returns an http.Handler middleware that rate limits by IP.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := realIP(r)
		if !rl.allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"too many requests, please slow down"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// realIP extracts the real client IP from reverse proxy headers.
// Caddy (our reverse proxy) appends the client IP to X-Forwarded-For, so the
// rightmost entry is the most recently added and trustworthy value.
// We intentionally do NOT trust the leftmost entry to prevent header spoofing.
func realIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the rightmost (last) entry — added by our trusted proxy (Caddy)
		last := xff
		if i := strings.LastIndex(xff, ","); i >= 0 {
			last = strings.TrimSpace(xff[i+1:])
		}
		if last != "" {
			return last
		}
	}
	// Fall back to RemoteAddr (strip port)
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
