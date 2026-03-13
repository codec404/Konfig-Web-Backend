package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/codec404/konfig-web-backend/internal/auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type AuthHandler struct {
	store       *auth.Store
	secret      string
	oauthCfg    *oauth2.Config
	appURL      string
	secureCookie bool
}

func NewAuthHandler(store *auth.Store, secret, googleClientID, googleClientSecret, appURL string, secureCookie bool) *AuthHandler {
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
	}
}

type userResponse struct {
	ID    string    `json:"id"`
	Name  string    `json:"name"`
	Email string    `json:"email"`
	Role  auth.Role `json:"role"`
}

func toUserResponse(u *auth.User) userResponse {
	return userResponse{ID: u.ID, Name: u.Name, Email: u.Email, Role: u.Role}
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
		HttpOnly: true,
		Secure:   h.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(auth.CookieTTL().Seconds()),
	})
	return nil
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	user, err := h.store.Login(req.Email, req.Password)
	if err != nil {
		http.Error(w, `{"error":"invalid email or password"}`, http.StatusUnauthorized)
		return
	}
	if err := h.setSessionCookie(w, user); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"user": toUserResponse(user)})
}

func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 {
		http.Error(w, `{"error":"password must be at least 8 characters"}`, http.StatusBadRequest)
		return
	}
	user, err := h.store.CreateLocal(req.Name, req.Email, req.Password)
	if errors.Is(err, auth.ErrEmailTaken) {
		http.Error(w, `{"error":"email already registered"}`, http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if err := h.setSessionCookie(w, user); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
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

func (h *AuthHandler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := h.oauthCfg.AuthCodeURL("state", oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *AuthHandler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, h.appURL+"/login?error=oauth_failed", http.StatusTemporaryRedirect)
		return
	}
	token, err := h.oauthCfg.Exchange(context.Background(), code)
	if err != nil {
		http.Redirect(w, r, h.appURL+"/login?error=oauth_failed", http.StatusTemporaryRedirect)
		return
	}
	client := h.oauthCfg.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil || resp.StatusCode != http.StatusOK {
		http.Redirect(w, r, h.appURL+"/login?error=oauth_failed", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	var info struct {
		Sub   string `json:"sub"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		http.Redirect(w, r, h.appURL+"/login?error=oauth_failed", http.StatusTemporaryRedirect)
		return
	}
	user, err := h.store.UpsertGoogle(info.Sub, info.Name, info.Email)
	if err != nil {
		http.Redirect(w, r, h.appURL+"/login?error=oauth_failed", http.StatusTemporaryRedirect)
		return
	}
	if err := h.setSessionCookie(w, user); err != nil {
		http.Redirect(w, r, h.appURL+"/login?error=oauth_failed", http.StatusTemporaryRedirect)
		return
	}
	http.Redirect(w, r, h.appURL+"/", http.StatusTemporaryRedirect)
}
