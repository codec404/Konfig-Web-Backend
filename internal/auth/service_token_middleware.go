package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

type serviceTokenContextKey string

const svcTokenContextKey serviceTokenContextKey = "service_token"

// ServiceTokenMiddleware validates an SDK bearer token from the Authorization header.
// On success it stores the *ServiceToken in the request context.
// On failure it responds 401 immediately.
//
// Expected header format:  Authorization: Bearer sk_svc_<hex>
func ServiceTokenMiddleware(store *Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := bearerToken(r)
			if !ok || !strings.HasPrefix(raw, "sk_svc_") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// Hash the raw token value (strip the "sk_svc_" prefix before hashing,
			// consistent with how GenerateServiceToken hashes only the hex portion).
			hexPart := strings.TrimPrefix(raw, "sk_svc_")
			sum := sha256.Sum256([]byte(hexPart))
			hash := hex.EncodeToString(sum[:])

			token, err := store.ValidateServiceToken(hash)
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), svcTokenContextKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ServiceTokenFromContext retrieves the validated ServiceToken from the request context.
// Returns nil if the request was not authenticated via a service token.
func ServiceTokenFromContext(ctx context.Context) *ServiceToken {
	t, _ := ctx.Value(svcTokenContextKey).(*ServiceToken)
	return t
}

// bearerToken extracts the token value from an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) (string, bool) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return "", false
	}
	parts := strings.SplitN(hdr, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", false
	}
	val := strings.TrimSpace(parts[1])
	if val == "" {
		return "", false
	}
	return val, true
}
