package auth

import (
	"context"
	"net/http"
)

type contextKey string

const userContextKey contextKey = "auth_user"

// Middleware validates the session cookie and loads the user into context.
func Middleware(store *Store, secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(CookieName())
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			claims, err := ValidateToken(cookie.Value, secret)
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			user, err := store.FindByID(claims.UserID)
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), userContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserFromContext retrieves the authenticated user from the request context.
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(userContextKey).(*User)
	return u
}

// RequireSuperAdmin rejects requests from non-super-admins with 403.
func RequireSuperAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil || user.Role != RoleSuperAdmin {
				http.Error(w, `{"error":"forbidden: super admin only"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireOrgAdmin checks that the requesting user is an admin in the org identified by
// the X-Org-ID or X-Org-Slug request header. Super admins always pass.
// If no org header is present it falls back to checking users.role (legacy path).
func RequireOrgAdmin(store *Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if user.Role == RoleSuperAdmin {
				next.ServeHTTP(w, r)
				return
			}

			// Resolve org ID from request headers.
			orgID := r.Header.Get("X-Org-ID")
			if orgID == "" {
				if slug := r.Header.Get("X-Org-Slug"); slug != "" {
					if org, err := store.FindOrgBySlug(slug); err == nil {
						orgID = org.ID
					}
				}
			}

			if orgID != "" {
				// Check org-specific role from org_memberships.
				membership, err := store.GetOrgMembership(user.ID, orgID)
				if err != nil || membership.Role != RoleAdmin {
					http.Error(w, `{"error":"forbidden: admin only"}`, http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// No org context — fall back to global role check.
			if user.Role != RoleAdmin {
				http.Error(w, `{"error":"forbidden: admin only"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireActiveUser rejects org users who are pending or rejected.
// Individual users and super admins are always allowed through.
func RequireActiveUser() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			if user.AccountType == AccountTypeOrg && user.MemberStatus != MemberStatusApproved {
				http.Error(w, `{"error":"your account is pending admin approval"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
