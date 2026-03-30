package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"net/http"
	"strings"

	"github.com/codec404/konfig-web-backend/internal/auth"
	applogger "github.com/codec404/konfig-web-backend/internal/logger"
	"github.com/pquerna/otp/totp"
)

const totpIssuer = "Konfig"

// TOTPInit handles POST /api/auth/totp-init
// Body: {"email": "..."}
//
// Returns {"enrolled": true} when the user already has TOTP set up — the login
// page should jump straight to the code input.
//
// Returns {"enrolled": false, "qr": "<data:image/png;base64,...>", "secret": "ABCD..."} for a
// first-time enrolment. The client must re-submit the secret alongside the code in totp-login
// (for new users who have no DB row yet; existing users get the pending secret stored server-side).
func (h *AuthHandler) TOTPInit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	applogger.Debug("totp-init: request received", map[string]any{"email": email})

	user, err := h.store.FindActiveByEmail(email)
	if err != nil && err != auth.ErrNotFound {
		applogger.Error("totp-init: user lookup failed", map[string]any{"email": email, "err": err.Error()})
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Already enrolled — no QR needed.
	if user != nil {
		applogger.Debug("totp-init: user found in DB", map[string]any{"email": email, "user_id": user.ID})
		st, err := h.store.GetTOTPStatus(user.ID)
		if err != nil {
			applogger.Error("totp-init: failed to read TOTP status", map[string]any{"user_id": user.ID, "err": err.Error()})
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if st.Enabled {
			applogger.Debug("totp-init: user already enrolled, skipping QR", map[string]any{"user_id": user.ID, "email": email})
			writeJSON(w, http.StatusOK, map[string]any{"enrolled": true})
			return
		}
		applogger.Debug("totp-init: user exists but not yet enrolled, generating QR", map[string]any{"user_id": user.ID, "email": email})
	} else {
		applogger.Debug("totp-init: no existing account, new-user enrolment flow", map[string]any{"email": email})
	}

	// Generate a fresh TOTP key for this enrolment attempt.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: email,
	})
	if err != nil {
		applogger.Error("totp-init: key generation failed", map[string]any{"email": email, "err": err.Error()})
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Encode the QR code as a base64 PNG data URL.
	img, err := key.Image(200, 200)
	if err != nil {
		applogger.Error("totp-init: QR image render failed", map[string]any{"email": email, "err": err.Error()})
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		applogger.Error("totp-init: QR PNG encode failed", map[string]any{"email": email, "err": err.Error()})
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	qrDataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	// For existing (not-yet-enrolled) users, persist the pending secret so a page
	// refresh does not require a new QR scan.
	if user != nil {
		if err := h.store.SetTOTPPendingSecret(user.ID, key.Secret()); err != nil {
			applogger.Error("totp-init: failed to save pending secret", map[string]any{"user_id": user.ID, "err": err.Error()})
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		applogger.Debug("totp-init: pending secret stored", map[string]any{"user_id": user.ID})
	}
	// For brand-new users the secret travels back with the client and is re-submitted
	// in totp-login; the user row doesn't exist yet so there is nowhere to persist it.

	applogger.Debug("totp-init: QR generated and returned", map[string]any{"email": email, "new_user": user == nil})
	writeJSON(w, http.StatusOK, map[string]any{
		"enrolled": false,
		"qr":       qrDataURL,
		"secret":   key.Secret(), // shown as plaintext fallback for manual entry in the app
	})
}

// TOTPLogin handles POST /api/auth/totp-login
// Body: {"email": "...", "code": "123456", "secret": "..."}
//
// The "secret" field is only required during first-time enrolment for users who
// do not yet have a DB row (brand-new accounts). For existing users the pending
// secret is read from the DB.
//
// On success the full session cookie is set and the user object is returned.
func (h *AuthHandler) TOTPLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email  string `json:"email"`
		Code   string `json:"code"`
		Secret string `json:"secret"` // needed for brand-new users only
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Code == "" {
		writeError(w, http.StatusBadRequest, "email and code are required")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	applogger.Debug("totp-login: request received", map[string]any{"email": email})

	user, err := h.store.FindActiveByEmail(email)
	if err != nil && err != auth.ErrNotFound {
		applogger.Error("totp-login: user lookup failed", map[string]any{"email": email, "err": err.Error()})
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	var secretToVerify string
	firstEnrolment := false

	if user != nil {
		applogger.Debug("totp-login: user found in DB", map[string]any{"email": email, "user_id": user.ID})
		st, err := h.store.GetTOTPStatus(user.ID)
		if err != nil {
			applogger.Error("totp-login: failed to read TOTP status", map[string]any{"user_id": user.ID, "err": err.Error()})
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		switch {
		case st.Enabled:
			applogger.Debug("totp-login: using active secret (enrolled user)", map[string]any{"user_id": user.ID})
			secretToVerify = st.Secret
		case st.PendingSecret != "":
			applogger.Debug("totp-login: using pending secret from DB (first-time enrolment)", map[string]any{"user_id": user.ID})
			secretToVerify = st.PendingSecret
			firstEnrolment = true
		case req.Secret != "":
			applogger.Debug("totp-login: using client-supplied secret (pending secret lost, e.g. server restart)", map[string]any{"user_id": user.ID})
			secretToVerify = req.Secret
			firstEnrolment = true
		default:
			applogger.Warn("totp-login: no secret available for verification", map[string]any{"email": email, "user_id": user.ID})
			writeError(w, http.StatusBadRequest, "no TOTP setup in progress — call totp-init first")
			return
		}
	} else {
		// Brand-new user: secret came from the totp-init response.
		applogger.Debug("totp-login: no existing account, first-time enrolment for new user", map[string]any{"email": email})
		if req.Secret == "" {
			applogger.Warn("totp-login: new user login attempt with no secret supplied", map[string]any{"email": email})
			writeError(w, http.StatusBadRequest, "no TOTP setup in progress — call totp-init first")
			return
		}
		secretToVerify = req.Secret
		firstEnrolment = true
	}

	if !totp.Validate(req.Code, secretToVerify) {
		applogger.Warn("totp-login: invalid code", map[string]any{"email": email, "first_enrolment": firstEnrolment})
		writeError(w, http.StatusUnauthorized, "invalid authenticator code")
		return
	}
	applogger.Debug("totp-login: code verified successfully", map[string]any{"email": email, "first_enrolment": firstEnrolment})

	// Code is valid. Create the user account if this is the very first login.
	if user == nil {
		name := email
		if i := strings.Index(email, "@"); i > 0 {
			name = email[:i]
		}
		user, err = h.store.CreateLocal(name, email, auth.AccountTypeIndividual, "", "")
		if err != nil {
			applogger.Error("totp-login: failed to auto-create user", map[string]any{"email": email, "err": err.Error()})
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		applogger.Info("user auto-registered via TOTP", map[string]any{"user_id": user.ID, "email": email})
	}

	// Activate TOTP on first enrolment.
	if firstEnrolment {
		if err := h.store.ActivateTOTP(user.ID, secretToVerify); err != nil {
			applogger.Error("totp-login: failed to activate TOTP", map[string]any{"user_id": user.ID, "err": err.Error()})
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		applogger.Info("totp enrolled", map[string]any{"user_id": user.ID, "email": email})
	}

	if err := h.setSessionCookie(w, user); err != nil {
		applogger.Error("totp-login: failed to set session cookie", map[string]any{"user_id": user.ID, "err": err.Error()})
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	applogger.Info("user login via totp", map[string]any{"user_id": user.ID, "email": email})
	writeJSON(w, http.StatusOK, map[string]any{"user": toUserResponse(user)})
}
