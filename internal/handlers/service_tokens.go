package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/codec404/konfig-web-backend/internal/auth"
	"github.com/gorilla/mux"
)

// tokenRawLen is the number of random bytes in the raw token (before hex encoding).
// 32 bytes → 64-char hex string → full token is "sk_svc_" + 64 chars.
const tokenRawLen = 32

func generateRawToken() (raw, hash, prefix string, err error) {
	b := make([]byte, tokenRawLen)
	if _, err = rand.Read(b); err != nil {
		return
	}
	raw = hex.EncodeToString(b)            // 64-char hex
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])      // 64-char SHA-256 hex
	prefix = "sk_svc_" + raw[:12] + "..." // safe display prefix shown in UI
	raw = "sk_svc_" + raw                 // full token returned once to user
	return
}

// GenerateServiceToken handles POST /api/services/{serviceName}/tokens
func GenerateServiceToken(store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		serviceName := mux.Vars(r)["serviceName"]
		if !validName.MatchString(serviceName) {
			http.Error(w, `{"error":"invalid service name"}`, http.StatusBadRequest)
			return
		}

		var body struct {
			Label string `json:"label"`
		}
		json.NewDecoder(r.Body).Decode(&body) // label is optional

		ns := resolveNS(r, user, store)
		internalName := applyNS(ns, serviceName)
		_ = internalName // namespace is stored, not re-validated against gRPC here

		raw, hash, prefix, err := generateRawToken()
		if err != nil {
			http.Error(w, `{"error":"failed to generate token"}`, http.StatusInternalServerError)
			return
		}

		label := strings.TrimSpace(body.Label)
		if label == "" {
			label = "default"
		}

		token, err := store.CreateServiceToken(serviceName, ns, hash, prefix, label, user.ID)
		if err != nil {
			http.Error(w, `{"error":"failed to save token"}`, http.StatusInternalServerError)
			return
		}

		// Return the raw token once — it will never be retrievable again.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"token":    raw,
			"id":       token.ID,
			"prefix":   token.Prefix,
			"label":    token.Label,
			"created_at": token.CreatedAt,
		})
	}
}

// ListServiceTokens handles GET /api/services/{serviceName}/tokens
func ListServiceTokens(store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		serviceName := mux.Vars(r)["serviceName"]
		if !validName.MatchString(serviceName) {
			http.Error(w, `{"error":"invalid service name"}`, http.StatusBadRequest)
			return
		}

		ns := resolveNS(r, user, store)
		tokens, err := store.ListServiceTokens(serviceName, ns)
		if err != nil {
			http.Error(w, `{"error":"failed to list tokens"}`, http.StatusInternalServerError)
			return
		}
		if tokens == nil {
			tokens = []auth.ServiceToken{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokens)
	}
}

// RevokeServiceToken handles DELETE /api/services/{serviceName}/tokens/{tokenId}
func RevokeServiceToken(store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		serviceName := mux.Vars(r)["serviceName"]
		tokenID := mux.Vars(r)["tokenId"]
		if !validName.MatchString(serviceName) {
			http.Error(w, `{"error":"invalid service name"}`, http.StatusBadRequest)
			return
		}

		ns := resolveNS(r, user, store)
		if err := store.RevokeServiceToken(tokenID, ns); err != nil {
			if err == auth.ErrNotFound {
				http.Error(w, `{"error":"token not found"}`, http.StatusNotFound)
				return
			}
			http.Error(w, `{"error":"failed to revoke token"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
	}
}
