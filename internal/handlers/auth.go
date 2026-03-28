package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/codec404/konfig-web-backend/internal/auth"
	applogger "github.com/codec404/konfig-web-backend/internal/logger"
	"github.com/codec404/konfig-web-backend/internal/mailer"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type AuthHandler struct {
	store        *auth.Store
	secret       string
	oauthCfg     *oauth2.Config
	appURL       string
	secureCookie bool
	cookieDomain string
	mailer       *mailer.Mailer
}

func NewAuthHandler(store *auth.Store, secret, googleClientID, googleClientSecret, appURL string, secureCookie bool, ml *mailer.Mailer, cookieDomain string) *AuthHandler {
	oauthCfg := &oauth2.Config{
		ClientID:     googleClientID,
		ClientSecret: googleClientSecret,
		RedirectURL:  appURL + "/api/auth/google/callback",
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}
	return &AuthHandler{
		store:        store,
		secret:       secret,
		oauthCfg:     oauthCfg,
		appURL:       appURL,
		secureCookie: secureCookie,
		cookieDomain: cookieDomain,
		mailer:       ml,
	}
}

type userResponse struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Email        string            `json:"email"`
	Role         auth.Role         `json:"role"`
	AccountType  auth.AccountType  `json:"account_type,omitempty"`
	OrgID        string            `json:"org_id,omitempty"`
	MemberStatus auth.MemberStatus `json:"member_status,omitempty"`
	Phone        string            `json:"phone,omitempty"`
	AvatarURL    string            `json:"avatar_url,omitempty"`
}

func toUserResponse(u *auth.User) userResponse {
	return userResponse{
		ID:           u.ID,
		Name:         u.Name,
		Email:        u.Email,
		Role:         u.Role,
		AccountType:  u.AccountType,
		OrgID:        u.OrgID,
		MemberStatus: u.MemberStatus,
		Phone:        u.Phone,
		AvatarURL:    u.AvatarURL,
	}
}

func (h *AuthHandler) setSessionCookie(w http.ResponseWriter, user *auth.User) error {
	token, err := auth.CreateToken(user, h.secret)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName(),
		Value:    token,
		Path:     "/",
		Domain:   h.cookieDomain,
		HttpOnly: true,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(auth.CookieTTL().Seconds()),
	})
	return nil
}

// Signup handles POST /api/auth/signup
// Password is no longer required — login is via OTP only.
func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string           `json:"name"`
		Email       string           `json:"email"`
		AccountType auth.AccountType `json:"account_type"`
		OrgID       string           `json:"org_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if req.AccountType != auth.AccountTypeIndividual && req.AccountType != auth.AccountTypeOrg {
		http.Error(w, `{"error":"account_type must be 'individual' or 'org'"}`, http.StatusBadRequest)
		return
	}
	if req.AccountType == auth.AccountTypeOrg && req.OrgID == "" {
		http.Error(w, `{"error":"org_id is required for org accounts"}`, http.StatusBadRequest)
		return
	}

	if err := h.store.CheckEmailConflict(req.Email, req.AccountType); err != nil {
		if errors.Is(err, auth.ErrEmailConflict) {
			http.Error(w, `{"error":"this email is already registered under a different account type"}`, http.StatusConflict)
			return
		}
		if errors.Is(err, auth.ErrEmailTaken) {
			// Email exists — could be a pre-created org admin. Tell frontend to use OTP login.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]any{
				"error": "already_registered",
				"email": req.Email,
			})
			return
		}
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	if req.AccountType == auth.AccountTypeOrg {
		if _, err := h.store.GetOrg(req.OrgID); err != nil {
			http.Error(w, `{"error":"organization not found"}`, http.StatusBadRequest)
			return
		}
	}

	memberStatus := auth.MemberStatus("")
	if req.AccountType == auth.AccountTypeOrg {
		memberStatus = auth.MemberStatusPending
	}

	user, err := h.store.CreateLocal(req.Name, req.Email, req.AccountType, req.OrgID, memberStatus)
	if errors.Is(err, auth.ErrEmailTaken) {
		http.Error(w, `{"error":"email already registered"}`, http.StatusConflict)
		return
	}
	if err != nil {
		applogger.Error("signup: create user failed", map[string]any{"email": req.Email, "err": err.Error()})
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if err := h.setSessionCookie(w, user); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	applogger.Info("user registered", map[string]any{"user_id": user.ID, "email": user.Email, "account_type": string(req.AccountType)})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"user": toUserResponse(user)})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toUserResponse(user))
}

func (h *AuthHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		Name      string `json:"name"`
		Phone     string `json:"phone"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if err := h.store.UpdateOwnCreds(user.ID, req.Name, req.Phone, req.AvatarURL); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	updated, _ := h.store.FindByID(user.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"user": toUserResponse(updated)})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
	w.WriteHeader(http.StatusNoContent)
}

// ── OTP-based flows ───────────────────────────────────────────────────────────

// SendOTP handles POST /api/auth/send-otp
// Body: {"email":"...", "purpose":"login", "org_slug":"..."}
func (h *AuthHandler) SendOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email   string `json:"email"`
		Purpose string `json:"purpose"`
		OrgSlug string `json:"org_slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}
	if req.Purpose != "login" {
		writeError(w, http.StatusBadRequest, "purpose must be 'login'")
		return
	}

	// On org subdomains: verify the account exists, is not blocked, and belongs to the org.
	// On the main domain: only reject if explicitly blocked; new users are auto-created by LoginWithOTP.
	if req.OrgSlug != "" {
		activeUser, err := h.store.FindActiveByEmail(req.Email)
		if err != nil {
			if !errors.Is(err, auth.ErrNotFound) {
				applogger.Error("send-otp: user lookup failed", map[string]any{"email": req.Email, "err": err.Error()})
			} else {
				applogger.Warn("send-otp: account not found on org subdomain", map[string]any{"email": req.Email, "org_slug": req.OrgSlug})
			}
			writeError(w, http.StatusForbidden, "account not found or is blocked")
			return
		}
		org, err := h.store.FindOrgBySlug(req.OrgSlug)
		if err != nil {
			writeError(w, http.StatusForbidden, "email not registered with this organization")
			return
		}
		if _, err := h.store.GetOrgMembership(activeUser.ID, org.ID); err != nil {
			writeError(w, http.StatusForbidden, "email not registered with this organization")
			return
		}
	} else {
		// Main domain: only block explicitly blocked accounts.
		if blocked, err := h.store.IsBlocked(req.Email); err == nil && blocked {
			writeError(w, http.StatusForbidden, "account not found or is blocked")
			return
		}
	}

	code, err := h.store.CreateOTP(req.Email, req.Purpose)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := h.mailer.SendOTP(req.Email, code, req.Purpose); err != nil {
		applogger.Error("send-otp: email delivery failed", map[string]any{"email": req.Email, "err": err.Error()})
		writeError(w, http.StatusInternalServerError, "failed to send OTP email")
		return
	}
	applogger.Debug("OTP sent", map[string]any{"email": req.Email, "purpose": req.Purpose})
	writeJSON(w, http.StatusOK, map[string]any{"sent": true})
}

// LoginWithOTP handles POST /api/auth/login-otp
// Body: {"email":"...", "code":"123456"}
func (h *AuthHandler) LoginWithOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "email and code are required")
		return
	}

	if err := h.store.VerifyAndConsumeOTP(req.Email, req.Code, "login"); err != nil {
		applogger.Warn("OTP login failed: invalid or expired code", map[string]any{"email": req.Email})
		writeError(w, http.StatusUnauthorized, "invalid or expired OTP")
		return
	}

	user, err := h.store.FindActiveByEmail(req.Email)
	if err != nil {
		// First-time login — auto-register as individual user.
		// Use the local part of the email as their display name.
		name := req.Email
		if i := strings.Index(req.Email, "@"); i > 0 {
			name = req.Email[:i]
		}
		var createErr error
		user, createErr = h.store.CreateLocal(name, req.Email, auth.AccountTypeIndividual, "", "")
		if createErr != nil {
			applogger.Error("OTP login: auto-register failed", map[string]any{"email": req.Email, "err": createErr.Error()})
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		applogger.Info("user auto-registered via OTP", map[string]any{"user_id": user.ID, "email": user.Email})
	}
	if err := h.setSessionCookie(w, user); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	applogger.Info("user login", map[string]any{"user_id": user.ID, "email": user.Email})
	writeJSON(w, http.StatusOK, map[string]any{"user": toUserResponse(user)})
}

// ── Google OAuth ──────────────────────────────────────────────────────────────

func (h *AuthHandler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := h.oauthCfg.AuthCodeURL("state", oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *AuthHandler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		applogger.Warn("google oauth: missing code parameter", nil)
		http.Redirect(w, r, h.appURL+"/login?error=oauth_failed", http.StatusTemporaryRedirect)
		return
	}
	token, err := h.oauthCfg.Exchange(context.Background(), code)
	if err != nil {
		applogger.Error("google oauth: token exchange failed", map[string]any{"err": err.Error()})
		http.Redirect(w, r, h.appURL+"/login?error=oauth_failed", http.StatusTemporaryRedirect)
		return
	}
	client := h.oauthCfg.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil || resp.StatusCode != http.StatusOK {
		applogger.Error("google oauth: userinfo fetch failed", map[string]any{"err": err, "status": resp.StatusCode})
		http.Redirect(w, r, h.appURL+"/login?error=oauth_failed", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	var info struct {
		Sub     string `json:"sub"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		applogger.Error("google oauth: decode userinfo failed", map[string]any{"err": err.Error()})
		http.Redirect(w, r, h.appURL+"/login?error=oauth_failed", http.StatusTemporaryRedirect)
		return
	}
	user, err := h.store.UpsertGoogle(info.Sub, info.Name, info.Email)
	if err != nil {
		applogger.Error("google oauth: upsert user failed", map[string]any{"email": info.Email, "err": err.Error()})
		http.Redirect(w, r, h.appURL+"/login?error=oauth_failed", http.StatusTemporaryRedirect)
		return
	}
	if info.Picture != "" {
		_ = h.store.SetAvatarURLIfEmpty(user.ID, info.Picture)
	}
	if err := h.setSessionCookie(w, user); err != nil {
		applogger.Error("google oauth: set session cookie failed", map[string]any{"user_id": user.ID, "err": err.Error()})
		http.Redirect(w, r, h.appURL+"/login?error=oauth_failed", http.StatusTemporaryRedirect)
		return
	}
	applogger.Info("user login via google", map[string]any{"user_id": user.ID, "email": user.Email})
	http.Redirect(w, r, h.appURL+"/", http.StatusTemporaryRedirect)
}
