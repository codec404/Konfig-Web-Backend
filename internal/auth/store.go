package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrEmailTaken = errors.New("email already registered")
var ErrNotFound = errors.New("user not found")
var ErrEmailConflict = errors.New("email already in use by a different account type")
var ErrInvalidOTP = errors.New("invalid or expired OTP")
var ErrTOTPInvalid = errors.New("invalid TOTP code")

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) DB() *sql.DB { return s.db
}

func (s *Store) Migrate() error {
	// Users table (base)
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id         TEXT PRIMARY KEY,
			name       TEXT NOT NULL,
			email      TEXT UNIQUE NOT NULL,
			role       TEXT NOT NULL DEFAULT 'user',
			provider   TEXT NOT NULL DEFAULT 'local',
			google_id  TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return err
	}

	// New columns added/removed idempotently
	for _, stmt := range []string{
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS account_type          TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS org_id                TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS member_status         TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at            TIMESTAMPTZ`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS blocked_at            TIMESTAMPTZ`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone                 TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url            TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret           TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_pending_secret   TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled          BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE users DROP COLUMN IF EXISTS password_hash`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}

	// Organizations
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS organizations (
			id         TEXT PRIMARY KEY,
			name       TEXT NOT NULL,
			created_by TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			deleted_at TIMESTAMPTZ
		)
	`); err != nil {
		return err
	}

	// Idempotent org column additions
	for _, stmt := range []string{
		`ALTER TABLE organizations ADD COLUMN IF NOT EXISTS slug TEXT`,
	} {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}

	// Backfill slugs for existing orgs that don't have one.
	if err := s.backfillOrgSlugs(); err != nil {
		return err
	}

	// Service visibility grants
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS service_visibility (
			id           TEXT PRIMARY KEY,
			org_id       TEXT NOT NULL,
			user_id      TEXT NOT NULL,
			service_name TEXT NOT NULL,
			granted_by   TEXT NOT NULL,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			deleted_at   TIMESTAMPTZ,
			UNIQUE (org_id, user_id, service_name)
		)
	`); err != nil {
		return err
	}

	// One-time passwords (login & first-time password setup)
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS otps (
			id              TEXT PRIMARY KEY,
			email           TEXT NOT NULL,
			code            TEXT NOT NULL,
			purpose         TEXT NOT NULL,
			expires_at      TIMESTAMPTZ NOT NULL,
			used_at         TIMESTAMPTZ,
			failed_attempts INTEGER NOT NULL DEFAULT 0,
			created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`ALTER TABLE otps ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0`); err != nil {
		return err
	}

	// Org memberships (multi-org support)
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS org_memberships (
			id         TEXT PRIMARY KEY,
			org_id     TEXT NOT NULL,
			user_id    TEXT NOT NULL,
			role       TEXT NOT NULL DEFAULT 'user',
			status     TEXT NOT NULL DEFAULT 'invited',
			invited_by TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (org_id, user_id)
		)
	`); err != nil {
		return err
	}

	// Org invites
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS org_invites (
			id          TEXT PRIMARY KEY,
			org_id      TEXT NOT NULL,
			email       TEXT NOT NULL,
			role        TEXT NOT NULL DEFAULT 'user',
			invited_by  TEXT NOT NULL,
			token       TEXT NOT NULL UNIQUE,
			expires_at  TIMESTAMPTZ NOT NULL,
			accepted_at TIMESTAMPTZ,
			declined_at TIMESTAMPTZ,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return err
	}

	// Org permissions (granular per-user per-org grants)
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS org_permissions (
			id         TEXT PRIMARY KEY,
			org_id     TEXT NOT NULL,
			user_id    TEXT NOT NULL,
			permission TEXT NOT NULL,
			granted_by TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (org_id, user_id, permission)
		)
	`); err != nil {
		return err
	}

	// Bug reports
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS bug_reports (
			id          TEXT PRIMARY KEY,
			user_id     TEXT NOT NULL,
			user_email  TEXT NOT NULL,
			issue_type  TEXT NOT NULL,
			title       TEXT NOT NULL,
			description TEXT NOT NULL,
			status      TEXT NOT NULL DEFAULT 'open',
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return err
	}

	// Application logs (backend + frontend, 3-day rolling window)
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS app_logs (
			id         BIGSERIAL    PRIMARY KEY,
			source     VARCHAR(10)  NOT NULL,
			level      VARCHAR(10)  NOT NULL,
			message    TEXT         NOT NULL,
			context    JSONB,
			created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return err
	}
	for _, idx := range []string{
		`CREATE INDEX IF NOT EXISTS app_logs_created_at_idx ON app_logs (created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS app_logs_level_idx      ON app_logs (level)`,
		`CREATE INDEX IF NOT EXISTS app_logs_source_idx     ON app_logs (source)`,
	} {
		if _, err := s.db.Exec(idx); err != nil {
			return err
		}
	}

	// Service tokens (SDK / external service credentials)
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS service_tokens (
			id           TEXT PRIMARY KEY,
			service_name TEXT        NOT NULL,
			namespace    TEXT        NOT NULL DEFAULT '',
			token_hash   TEXT        NOT NULL UNIQUE,
			prefix       TEXT        NOT NULL,
			label        TEXT        NOT NULL DEFAULT '',
			created_by   TEXT        NOT NULL,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_used_at TIMESTAMPTZ,
			revoked      BOOLEAN     NOT NULL DEFAULT FALSE
		)
	`); err != nil {
		return err
	}
	for _, idx := range []string{
		`CREATE INDEX IF NOT EXISTS service_tokens_service_name_idx ON service_tokens (service_name)`,
		`CREATE INDEX IF NOT EXISTS service_tokens_token_hash_idx   ON service_tokens (token_hash)`,
	} {
		if _, err := s.db.Exec(idx); err != nil {
			return err
		}
	}

	return nil
}

// ── App logs ──────────────────────────────────────────────────────────────────

type AppLog struct {
	ID        int64          `json:"id"`
	Source    string         `json:"source"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Context   map[string]any `json:"context,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

func (s *Store) CreateLog(source, level, message string, ctx map[string]any) error {
	var ctxJSON []byte
	if ctx != nil {
		ctxJSON, _ = json.Marshal(ctx)
	}
	_, err := s.db.Exec(
		`INSERT INTO app_logs (source, level, message, context) VALUES ($1, $2, $3, $4)`,
		source, level, message, ctxJSON,
	)
	return err
}

type LogFilter struct {
	Source string
	Level  string
	From   time.Time
	To     time.Time
	Limit  int
	Offset int
}

func (s *Store) ListLogs(f LogFilter) ([]AppLog, int, error) {
	args := []any{}
	conds := []string{}
	i := 1

	if f.Source != "" && f.Source != "all" {
		conds = append(conds, fmt.Sprintf("source = $%d", i))
		args = append(args, f.Source)
		i++
	}
	if f.Level != "" && f.Level != "all" {
		conds = append(conds, fmt.Sprintf("level = $%d", i))
		args = append(args, f.Level)
		i++
	}
	if !f.From.IsZero() {
		conds = append(conds, fmt.Sprintf("created_at >= $%d", i))
		args = append(args, f.From)
		i++
	}
	if !f.To.IsZero() {
		conds = append(conds, fmt.Sprintf("created_at <= $%d", i))
		args = append(args, f.To)
		i++
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM app_logs `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	if f.Limit <= 0 {
		f.Limit = 100
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := s.db.Query(
		`SELECT id, source, level, message, context, created_at FROM app_logs `+
			where+fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, i, i+1),
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []AppLog
	for rows.Next() {
		var l AppLog
		var ctxRaw []byte
		if err := rows.Scan(&l.ID, &l.Source, &l.Level, &l.Message, &ctxRaw, &l.CreatedAt); err != nil {
			return nil, 0, err
		}
		if len(ctxRaw) > 0 {
			_ = json.Unmarshal(ctxRaw, &l.Context)
		}
		logs = append(logs, l)
	}
	return logs, total, rows.Err()
}

func (s *Store) PruneLogs() error {
	_, err := s.db.Exec(`DELETE FROM app_logs WHERE created_at < NOW() - INTERVAL '3 days'`)
	return err
}

// ── Bug reports ───────────────────────────────────────────────────────────────

type BugReport struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	UserEmail   string    `json:"user_email"`
	IssueType   string    `json:"issue_type"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Store) CreateBugReport(userID, userEmail, issueType, title, description string) error {
	_, err := s.db.Exec(
		`INSERT INTO bug_reports (id, user_id, user_email, issue_type, title, description)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.NewString(), userID, userEmail, issueType, title, description,
	)
	return err
}

func (s *Store) ListBugReports() ([]BugReport, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, user_email, issue_type, title, description, status, created_at
		 FROM bug_reports ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []BugReport
	for rows.Next() {
		var r BugReport
		if err := rows.Scan(&r.ID, &r.UserID, &r.UserEmail, &r.IssueType, &r.Title, &r.Description, &r.Status, &r.CreatedAt); err != nil {
			return nil, err
		}
		reports = append(reports, r)
	}
	return reports, rows.Err()
}

func (s *Store) UpdateBugReportStatus(id, status string) error {
	res, err := s.db.Exec(`UPDATE bug_reports SET status = $1 WHERE id = $2`, status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── OTP management ────────────────────────────────────────────────────────────

// CreateOTP generates a fresh 6-digit OTP for the given email + purpose,
// invalidates any previous unused codes for the same pair, and stores it.
func (s *Store) CreateOTP(email, purpose string) (string, error) {
	// Invalidate old unused OTPs for this email+purpose
	s.db.Exec(
		`DELETE FROM otps WHERE email = $1 AND purpose = $2 AND used_at IS NULL`,
		email, purpose,
	)
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	code := fmt.Sprintf("%06d", n.Int64())
	_, err = s.db.Exec(
		`INSERT INTO otps (id, email, code, purpose, expires_at) VALUES ($1, $2, $3, $4, $5)`,
		uuid.NewString(), email, code, purpose, time.Now().Add(15*time.Minute),
	)
	return code, err
}

// VerifyAndConsumeOTP checks that the code is valid, unexpired and unused,
// then marks it consumed. Returns ErrInvalidOTP on any mismatch.
// After 5 failed attempts the OTP is permanently locked.
func (s *Store) VerifyAndConsumeOTP(email, code, purpose string) error {
	var id, storedCode string
	var attempts int
	err := s.db.QueryRow(
		`SELECT id, code, failed_attempts FROM otps
		 WHERE email = $1 AND purpose = $2
		   AND used_at IS NULL AND expires_at > NOW()
		 ORDER BY created_at DESC LIMIT 1`,
		email, purpose,
	).Scan(&id, &storedCode, &attempts)
	if err == sql.ErrNoRows {
		return ErrInvalidOTP
	}
	if err != nil {
		return err
	}
	if attempts >= 5 {
		return ErrInvalidOTP
	}
	if subtle.ConstantTimeCompare([]byte(storedCode), []byte(code)) != 1 {
		s.db.Exec(`UPDATE otps SET failed_attempts = failed_attempts + 1 WHERE id = $1`, id)
		return ErrInvalidOTP
	}
	_, err = s.db.Exec(`UPDATE otps SET used_at = NOW() WHERE id = $1`, id)
	return err
}

// FindActiveByEmail returns a non-deleted, non-blocked user by email.
func (s *Store) FindActiveByEmail(email string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT `+userSelectCols+` FROM users WHERE email = $1 AND deleted_at IS NULL AND blocked_at IS NULL`, email,
	)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) SeedSuperAdmin(name, email string) error {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'super_admin'`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	_, err := s.db.Exec(
		`INSERT INTO users (id, name, email, role, provider) VALUES ($1, $2, $3, 'super_admin', 'local')`,
		uuid.NewString(), name, email,
	)
	return err
}

// CheckEmailConflict returns ErrEmailConflict if the email belongs to a user
// with a different account type, or ErrEmailTaken if the same type already exists.
func (s *Store) CheckEmailConflict(email string, wantType AccountType) error {
	var existingType sql.NullString
	err := s.db.QueryRow(
		`SELECT account_type FROM users WHERE email = $1 AND deleted_at IS NULL`, email,
	).Scan(&existingType)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if existingType.Valid && existingType.String != "" && AccountType(existingType.String) != wantType {
		return ErrEmailConflict
	}
	return ErrEmailTaken
}

// CreateLocal creates a new local user with the given account type.
func (s *Store) CreateLocal(name, email string, accountType AccountType, orgID string, memberStatus MemberStatus) (*User, error) {
	var exists bool
	s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND deleted_at IS NULL)`, email).Scan(&exists)
	if exists {
		return nil, ErrEmailTaken
	}
	u := &User{
		ID:           uuid.NewString(),
		Name:         name,
		Email:        email,
		Role:         RoleUser,
		AccountType:  accountType,
		OrgID:        orgID,
		MemberStatus: memberStatus,
		Provider:     "local",
	}
	_, err := s.db.Exec(
		`INSERT INTO users (id, name, email, role, provider, account_type, org_id, member_status)
		 VALUES ($1, $2, $3, $4, 'local', $5, $6, $7)`,
		u.ID, u.Name, u.Email, string(u.Role),
		string(accountType), orgID, string(memberStatus),
	)
	return u, err
}


func (s *Store) UpsertGoogle(googleID, name, email string) (*User, error) {
	u, err := s.findByGoogleID(googleID)
	if err == nil {
		return u, nil
	}
	u, err = s.findByEmail(email)
	if err == nil {
		_, err = s.db.Exec(`UPDATE users SET google_id = $1, provider = 'google' WHERE id = $2`, googleID, u.ID)
		return u, err
	}
	u = &User{
		ID:       uuid.NewString(),
		Name:     name,
		Email:    email,
		Role:     RoleUser,
		Provider: "google",
		GoogleID: googleID,
	}
	_, err = s.db.Exec(
		`INSERT INTO users (id, name, email, role, provider, google_id) VALUES ($1, $2, $3, $4, 'google', $5)`,
		u.ID, u.Name, u.Email, u.Role, u.GoogleID,
	)
	return u, err
}

func (s *Store) FindByID(id string) (*User, error) {
	return s.findByID(id)
}

// UpdateOwnCreds lets a user update their own profile fields.
func (s *Store) UpdateOwnCreds(userID, name, phone, avatarURL string) error {
	_, err := s.db.Exec(
		`UPDATE users SET
			name       = CASE WHEN $1 != '' THEN $1 ELSE name END,
			phone      = CASE WHEN $2 != '' THEN $2 ELSE phone END,
			avatar_url = CASE WHEN $3 != '' THEN $3 ELSE avatar_url END
		WHERE id = $4`,
		name, phone, avatarURL, userID,
	)
	return err
}

// SetAvatarURLIfEmpty sets avatar_url only when it is not already set (used for Google photo).
func (s *Store) SetAvatarURLIfEmpty(userID, avatarURL string) error {
	_, err := s.db.Exec(
		`UPDATE users SET avatar_url = $1 WHERE id = $2 AND (avatar_url IS NULL OR avatar_url = '')`,
		avatarURL, userID,
	)
	return err
}

// ChangeOrgMemberRole changes a user's role within a specific org (org_memberships.role).
func (s *Store) ChangeOrgMemberRole(orgID, targetUserID string, newRole Role) error {
	if newRole != RoleAdmin && newRole != RoleUser {
		return errors.New("role must be admin or user")
	}
	res, err := s.db.Exec(
		`UPDATE org_memberships SET role = $1 WHERE org_id = $2 AND user_id = $3`,
		string(newRole), orgID, targetUserID,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateUserCreds lets an admin/super_admin update another user's name.
func (s *Store) UpdateUserCreds(callerRole Role, callerOrgID, targetUserID, name string) error {
	u, err := s.findByID(targetUserID)
	if err != nil {
		return ErrNotFound
	}
	if callerRole != RoleSuperAdmin {
		if callerRole == RoleAdmin {
			if u.Role == RoleAdmin || u.Role == RoleSuperAdmin {
				return errors.New("insufficient permissions")
			}
			if u.OrgID != callerOrgID {
				return errors.New("user not in same org")
			}
		} else {
			return errors.New("insufficient permissions")
		}
	}
	if name != "" {
		if _, err := s.db.Exec(`UPDATE users SET name = $1 WHERE id = $2`, name, targetUserID); err != nil {
			return err
		}
	}
	return nil
}

// SoftDeleteUser soft-deletes a user (admin can remove non-admin in same org, super_admin can remove anyone).
func (s *Store) SoftDeleteUser(callerRole Role, callerOrgID, targetUserID string) error {
	u, err := s.findByID(targetUserID)
	if err != nil {
		return ErrNotFound
	}
	if callerRole != RoleSuperAdmin {
		if callerRole == RoleAdmin {
			if u.Role == RoleAdmin || u.Role == RoleSuperAdmin {
				return errors.New("insufficient permissions")
			}
			if u.OrgID != callerOrgID {
				return errors.New("user not in same org")
			}
		} else {
			return errors.New("insufficient permissions")
		}
	}
	now := time.Now()
	_, err = s.db.Exec(`UPDATE users SET deleted_at = $1 WHERE id = $2`, now, targetUserID)
	return err
}

// RemoveFromOrg removes a user from an org without deleting the user account.
// For invite-based members it deletes the org_memberships row.
// For primary org members it falls back to SoftDeleteUser.
func (s *Store) RemoveFromOrg(callerRole Role, callerOrgID, targetUserID string) error {
	u, err := s.findByID(targetUserID)
	if err != nil {
		return ErrNotFound
	}
	if u.Role == RoleAdmin || u.Role == RoleSuperAdmin {
		return errors.New("cannot remove an admin")
	}
	// Try invite-based membership first
	res, err := s.db.Exec(
		`DELETE FROM org_memberships WHERE org_id = $1 AND user_id = $2`,
		callerOrgID, targetUserID,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	// Fall back to primary org membership
	return s.SoftDeleteUser(callerRole, callerOrgID, targetUserID)
}

// IsBlocked returns true if the email belongs to an existing user with blocked_at set.
// Returns false (not an error) when the email is not found — unknown emails are allowed through.
func (s *Store) IsBlocked(email string) (bool, error) {
	var blocked bool
	err := s.db.QueryRow(
		`SELECT blocked_at IS NOT NULL FROM users WHERE email = $1 AND deleted_at IS NULL`,
		email,
	).Scan(&blocked)
	if err == sql.ErrNoRows {
		return false, nil // unknown email — let LoginWithOTP handle it
	}
	return blocked, err
}

// BlockUser sets blocked_at for a user, preventing login.
func (s *Store) BlockUser(userID string) error {
	now := time.Now()
	_, err := s.db.Exec(`UPDATE users SET blocked_at = $1 WHERE id = $2`, now, userID)
	return err
}

// UnblockUser clears blocked_at, allowing login again.
func (s *Store) UnblockUser(userID string) error {
	_, err := s.db.Exec(`UPDATE users SET blocked_at = NULL WHERE id = $1`, userID)
	return err
}

// RemoveUserFromOrg removes a user from a specific org without deleting the account.
// Used by super admin — no role restrictions.
// If this was their last org, downgrades them to an individual user.
func (s *Store) RemoveUserFromOrg(orgID, userID string) error {
	s.db.Exec(`DELETE FROM org_memberships WHERE org_id = $1 AND user_id = $2`, orgID, userID)
	s.db.Exec(`UPDATE users SET org_id = '' WHERE id = $1 AND org_id = $2`, userID, orgID)
	// Check remaining org memberships
	var remaining int
	s.db.QueryRow(
		`SELECT COUNT(*) FROM org_memberships WHERE user_id = $1 AND status = 'active'`, userID,
	).Scan(&remaining)
	var primaryOrg string
	s.db.QueryRow(`SELECT COALESCE(org_id,'') FROM users WHERE id = $1`, userID).Scan(&primaryOrg)
	if remaining == 0 && primaryOrg == "" {
		s.db.Exec(`UPDATE users SET role = 'user', account_type = 'individual', member_status = NULL WHERE id = $1`, userID)
	}
	return nil
}

// ── Organization management ───────────────────────────────────────────────────

func (s *Store) CreateOrg(name, createdBy string) (*Organization, error) {
	slug := generateOrgSlug(name)
	org := &Organization{
		ID:        uuid.NewString(),
		Name:      name,
		CreatedBy: createdBy,
		Slug:      slug,
		CreatedAt: time.Now(),
	}
	_, err := s.db.Exec(
		`INSERT INTO organizations (id, name, created_by, slug) VALUES ($1, $2, $3, $4)`,
		org.ID, org.Name, org.CreatedBy, slug,
	)
	return org, err
}

// backfillOrgSlugs generates slugs for any org that has slug = NULL.
func (s *Store) backfillOrgSlugs() error {
	rows, err := s.db.Query(`SELECT id, name FROM organizations WHERE slug IS NULL AND deleted_at IS NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type row struct{ id, name string }
	var orgs []row
	for rows.Next() {
		var o row
		if err := rows.Scan(&o.id, &o.name); err != nil {
			return err
		}
		orgs = append(orgs, o)
	}
	for _, o := range orgs {
		slug := generateOrgSlug(o.name)
		if _, err := s.db.Exec(`UPDATE organizations SET slug = $1 WHERE id = $2`, slug, o.id); err != nil {
			return err
		}
	}
	return nil
}

func generateOrgSlug(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	// collapse multiple dashes
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return s
}

func (s *Store) GetOrg(orgID string) (*Organization, error) {
	org := &Organization{}
	err := s.db.QueryRow(
		`SELECT id, name, COALESCE(slug,''), created_by, created_at FROM organizations WHERE id = $1 AND deleted_at IS NULL`,
		orgID,
	).Scan(&org.ID, &org.Name, &org.Slug, &org.CreatedBy, &org.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return org, err
}

func (s *Store) ListOrgs() ([]Organization, error) {
	rows, err := s.db.Query(
		`SELECT id, name, COALESCE(slug,''), created_by, created_at FROM organizations WHERE deleted_at IS NULL ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orgs []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedBy, &o.CreatedAt); err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}

func (s *Store) FindOrgBySlug(slug string) (*Organization, error) {
	org := &Organization{}
	err := s.db.QueryRow(
		`SELECT id, name, COALESCE(slug,''), created_by, created_at FROM organizations WHERE slug = $1 AND deleted_at IS NULL`,
		slug,
	).Scan(&org.ID, &org.Name, &org.Slug, &org.CreatedBy, &org.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return org, err
}

func (s *Store) DeleteOrg(orgID string) error {
	now := time.Now()
	_, err := s.db.Exec(`UPDATE organizations SET deleted_at = $1 WHERE id = $2`, now, orgID)
	return err
}

// LinkExistingUserToOrg finds an existing user by email and adds them to the org
// with the given role. Returns ErrNotFound if no user with that email exists.
func (s *Store) LinkExistingUserToOrg(email, orgID string, role Role) error {
	u, err := s.findByEmail(email)
	if err != nil {
		return ErrNotFound
	}
	// Only update org-level fields on the users row — never touch users.role.
	if _, err := s.db.Exec(
		`UPDATE users SET account_type = 'org', member_status = 'approved', org_id = $2 WHERE id = $1`,
		u.ID, orgID,
	); err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO org_memberships (id, org_id, user_id, role, status, invited_by)
		 VALUES ($1, $2, $3, $4, 'active', $3)
		 ON CONFLICT (org_id, user_id) DO UPDATE SET role = $4, status = 'active'`,
		uuid.NewString(), orgID, u.ID, string(role),
	)
	return err
}

// SetOrgFirstAdmin promotes an existing user to admin of the given org.
// Called by super admin when creating an org with an existing user email.
func (s *Store) SetOrgFirstAdmin(email, orgID string) error {
	return s.LinkExistingUserToOrg(email, orgID, RoleAdmin)
}

// FindByEmail returns a user by email (exported for pre-validation).
func (s *Store) FindByEmail(email string) (*User, error) {
	u, err := s.findByEmail(email)
	if err != nil {
		return nil, ErrNotFound
	}
	return u, nil
}

// ── Member management ─────────────────────────────────────────────────────────

func (s *Store) ListOrgMembers(orgID string) ([]OrgMemberDetail, error) {
	rows, err := s.db.Query(
		`SELECT u.id, u.name, u.email, m.role, 'approved', m.created_at, u.blocked_at IS NOT NULL, COALESCE(u.avatar_url,'')
		 FROM org_memberships m
		 JOIN users u ON u.id = m.user_id
		 WHERE m.org_id = $1 AND m.status = 'active' AND u.deleted_at IS NULL
		 ORDER BY m.created_at ASC`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []OrgMemberDetail
	for rows.Next() {
		var m OrgMemberDetail
		var roleStr, statusStr string
		if err := rows.Scan(&m.UserID, &m.Name, &m.Email, &roleStr, &statusStr, &m.CreatedAt, &m.Blocked, &m.AvatarURL); err != nil {
			return nil, err
		}
		m.Role = Role(roleStr)
		m.MemberStatus = MemberStatus(statusStr)
		members = append(members, m)
	}
	return members, rows.Err()
}

func (s *Store) ListPendingMembers(orgID string) ([]OrgMemberDetail, error) {
	rows, err := s.db.Query(
		`SELECT id, name, email, role, COALESCE(member_status,''), created_at
		 FROM users WHERE org_id = $1 AND member_status = 'pending' AND deleted_at IS NULL ORDER BY created_at ASC`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []OrgMemberDetail
	for rows.Next() {
		var m OrgMemberDetail
		var roleStr, statusStr string
		if err := rows.Scan(&m.UserID, &m.Name, &m.Email, &roleStr, &statusStr, &m.CreatedAt); err != nil {
			return nil, err
		}
		m.Role = Role(roleStr)
		m.MemberStatus = MemberStatus(statusStr)
		members = append(members, m)
	}
	return members, rows.Err()
}

func (s *Store) ApproveMember(orgID, userID string) error {
	result, err := s.db.Exec(
		`UPDATE users SET member_status = 'approved' WHERE id = $1 AND org_id = $2 AND member_status = 'pending'`,
		userID, orgID,
	)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RejectMember(orgID, userID string) error {
	result, err := s.db.Exec(
		`UPDATE users SET member_status = 'rejected' WHERE id = $1 AND org_id = $2 AND member_status = 'pending'`,
		userID, orgID,
	)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Service visibility ────────────────────────────────────────────────────────

// GetVisibleServices returns the list of service names (without namespace prefix)
// that a user has been explicitly granted visibility to within an org.
func (s *Store) GetVisibleServices(orgID, userID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT service_name FROM service_visibility
		 WHERE org_id = $1 AND user_id = $2 AND deleted_at IS NULL`,
		orgID, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var services []string
	for rows.Next() {
		var svc string
		if err := rows.Scan(&svc); err != nil {
			return nil, err
		}
		services = append(services, svc)
	}
	return services, rows.Err()
}

func (s *Store) ListServiceVisibility(orgID, serviceName string) ([]ServiceVisibility, error) {
	rows, err := s.db.Query(
		`SELECT id, org_id, user_id, service_name, granted_by, created_at FROM service_visibility
		 WHERE org_id = $1 AND service_name = $2 AND deleted_at IS NULL`,
		orgID, serviceName,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var vis []ServiceVisibility
	for rows.Next() {
		var v ServiceVisibility
		if err := rows.Scan(&v.ID, &v.OrgID, &v.UserID, &v.ServiceName, &v.GrantedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		vis = append(vis, v)
	}
	return vis, rows.Err()
}

func (s *Store) GrantServiceVisibility(orgID, userID, serviceName, grantedBy string) error {
	_, err := s.db.Exec(
		`INSERT INTO service_visibility (id, org_id, user_id, service_name, granted_by)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (org_id, user_id, service_name) DO UPDATE SET deleted_at = NULL`,
		uuid.NewString(), orgID, userID, serviceName, grantedBy,
	)
	return err
}

func (s *Store) RevokeServiceVisibility(orgID, userID, serviceName string) error {
	now := time.Now()
	_, err := s.db.Exec(
		`UPDATE service_visibility SET deleted_at = $1
		 WHERE org_id = $2 AND user_id = $3 AND service_name = $4 AND deleted_at IS NULL`,
		now, orgID, userID, serviceName,
	)
	return err
}

// ── Org membership (multi-org) ────────────────────────────────────────────────

// InviteToOrg invites a registered user to an org.
// Creates an org_memberships row (status=invited) + an org_invites row (for the accept token).
// Returns ErrNotFound if the email has no account, ErrEmailTaken if already a member.
func (s *Store) InviteToOrg(orgID, email, role, invitedByID string) (token string, err error) {
	u, err := s.findByEmail(email)
	if err != nil {
		return "", ErrNotFound
	}
	// Check not already a member
	var exists bool
	s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM org_memberships WHERE org_id=$1 AND user_id=$2)`, orgID, u.ID).Scan(&exists)
	if exists {
		return "", ErrEmailTaken
	}
	// Also check primary org on user row
	if u.OrgID == orgID {
		return "", ErrEmailTaken
	}

	memberID := uuid.NewString()
	if _, err := s.db.Exec(
		`INSERT INTO org_memberships (id, org_id, user_id, role, status, invited_by) VALUES ($1,$2,$3,$4,'invited',$5)`,
		memberID, orgID, u.ID, role, invitedByID,
	); err != nil {
		return "", err
	}

	tokenBytes := make([]byte, 16)
	rand.Read(tokenBytes)
	tok := fmt.Sprintf("%x", tokenBytes)
	if _, err := s.db.Exec(
		`INSERT INTO org_invites (id, org_id, email, role, invited_by, token, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.NewString(), orgID, email, role, invitedByID, tok, time.Now().Add(7*24*time.Hour),
	); err != nil {
		return "", err
	}
	return tok, nil
}

// AcceptOrgInvite activates the membership and marks the invite accepted.
func (s *Store) AcceptOrgInvite(userID, token string) error {
	// Find invite
	var inviteID, orgID, email string
	err := s.db.QueryRow(
		`SELECT id, org_id, email FROM org_invites WHERE token=$1 AND accepted_at IS NULL AND declined_at IS NULL AND expires_at > NOW()`,
		token,
	).Scan(&inviteID, &orgID, &email)
	if err == sql.ErrNoRows {
		return ErrInvalidOTP // reuse sentinel for "invalid token"
	}
	if err != nil {
		return err
	}
	// Verify the user's email matches invite
	u, err := s.findByID(userID)
	if err != nil {
		return ErrNotFound
	}
	if u.Email != email {
		return ErrInvalidOTP
	}
	// Activate membership
	if _, err := s.db.Exec(
		`UPDATE org_memberships SET status='active' WHERE org_id=$1 AND user_id=$2`,
		orgID, userID,
	); err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE org_invites SET accepted_at=NOW() WHERE id=$1`, inviteID)
	return err
}

// DeclineOrgInvite removes the membership and marks the invite declined.
func (s *Store) DeclineOrgInvite(userID, token string) error {
	var inviteID, orgID, email string
	err := s.db.QueryRow(
		`SELECT id, org_id, email FROM org_invites WHERE token=$1 AND accepted_at IS NULL AND declined_at IS NULL`,
		token,
	).Scan(&inviteID, &orgID, &email)
	if err == sql.ErrNoRows {
		return ErrInvalidOTP
	}
	if err != nil {
		return err
	}
	u, err := s.findByID(userID)
	if err != nil {
		return ErrNotFound
	}
	if u.Email != email {
		return ErrInvalidOTP
	}
	s.db.Exec(`DELETE FROM org_memberships WHERE org_id=$1 AND user_id=$2`, orgID, userID)
	_, err = s.db.Exec(`UPDATE org_invites SET declined_at=NOW() WHERE id=$1`, inviteID)
	return err
}

// ListMyOrgs returns all orgs the user is an active member of (from org_memberships + primary org).
func (s *Store) ListMyOrgs(userID string) ([]OrgMembership, error) {
	rows, err := s.db.Query(`
		SELECT m.id, m.org_id, o.name, COALESCE(o.slug,''), m.user_id, m.role, m.status, m.invited_by, m.created_at
		FROM org_memberships m
		JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
		WHERE m.user_id=$1 AND m.status='active'
		ORDER BY m.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []OrgMembership
	for rows.Next() {
		var m OrgMembership
		if err := rows.Scan(&m.ID, &m.OrgID, &m.OrgName, &m.OrgSlug, &m.UserID, &m.Role, &m.Status, &m.InvitedBy, &m.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

// ListMyInvites returns all pending invites for a user's email.
func (s *Store) ListMyInvites(email string) ([]OrgInvite, error) {
	rows, err := s.db.Query(`
		SELECT i.id, i.org_id, o.name, i.email, i.role, i.invited_by, u.name, i.token, i.expires_at, i.created_at
		FROM org_invites i
		JOIN organizations o ON o.id = i.org_id AND o.deleted_at IS NULL
		LEFT JOIN users u ON u.id = i.invited_by
		WHERE i.email=$1 AND i.accepted_at IS NULL AND i.declined_at IS NULL AND i.expires_at > NOW()
		ORDER BY i.created_at DESC`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []OrgInvite
	for rows.Next() {
		var inv OrgInvite
		var inviterName sql.NullString
		if err := rows.Scan(&inv.ID, &inv.OrgID, &inv.OrgName, &inv.Email, &inv.Role,
			&inv.InvitedBy, &inviterName, &inv.Token, &inv.ExpiresAt, &inv.CreatedAt); err != nil {
			return nil, err
		}
		inv.InviterName = inviterName.String
		result = append(result, inv)
	}
	return result, rows.Err()
}

// ListOrgInvites returns all pending invites for an org (admin view).
// Token is intentionally omitted — admins have no need to act on other users' invite tokens.
func (s *Store) ListOrgInvites(orgID string) ([]OrgInvite, error) {
	rows, err := s.db.Query(`
		SELECT i.id, i.org_id, o.name, i.email, i.role, i.invited_by, u.name, i.expires_at, i.created_at
		FROM org_invites i
		JOIN organizations o ON o.id = i.org_id
		LEFT JOIN users u ON u.id = i.invited_by
		WHERE i.org_id=$1 AND i.accepted_at IS NULL AND i.declined_at IS NULL AND i.expires_at > NOW()
		ORDER BY i.created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []OrgInvite
	for rows.Next() {
		var inv OrgInvite
		var inviterName sql.NullString
		if err := rows.Scan(&inv.ID, &inv.OrgID, &inv.OrgName, &inv.Email, &inv.Role,
			&inv.InvitedBy, &inviterName, &inv.ExpiresAt, &inv.CreatedAt); err != nil {
			return nil, err
		}
		inv.InviterName = inviterName.String
		result = append(result, inv)
	}
	return result, rows.Err()
}

// GetOrgMembership returns the org membership for a user in a specific org (checks both primary org and org_memberships).
func (s *Store) GetOrgMembership(userID, orgID string) (*OrgMembership, error) {
	// Check org_memberships table
	var m OrgMembership
	err := s.db.QueryRow(`
		SELECT m.id, m.org_id, COALESCE(o.name,''), m.user_id, m.role, m.status, m.invited_by, m.created_at
		FROM org_memberships m
		LEFT JOIN organizations o ON o.id = m.org_id
		WHERE m.user_id=$1 AND m.org_id=$2 AND m.status='active'`, userID, orgID,
	).Scan(&m.ID, &m.OrgID, &m.OrgName, &m.UserID, &m.Role, &m.Status, &m.InvitedBy, &m.CreatedAt)
	if err == nil {
		return &m, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	// Fall back to primary org on user row
	u, err := s.findByID(userID)
	if err != nil {
		return nil, ErrNotFound
	}
	if u.OrgID == orgID && string(u.MemberStatus) == "approved" {
		return &OrgMembership{
			OrgID:  orgID,
			UserID: userID,
			Role:   u.Role,
			Status: "active",
		}, nil
	}
	return nil, ErrNotFound
}

// GetOrgVisibleServices returns services visible to a user in an org.
// Admins see all org services. Regular members see only services granted to them.
func (s *Store) GetOrgVisibleServices(userID, orgID string) ([]string, error) {
	membership, err := s.GetOrgMembership(userID, orgID)
	if err != nil {
		return nil, ErrNotFound
	}
	if membership.Role == RoleAdmin || membership.Role == RoleSuperAdmin {
		return nil, nil // nil = all services (caller handles this)
	}
	return s.GetVisibleServices(orgID, userID)
}

// ── TOTP ──────────────────────────────────────────────────────────────────────

// TOTPStatus holds the TOTP enrollment state for a user.
type TOTPStatus struct {
	Enabled       bool
	Secret        string // empty if not enrolled
	PendingSecret string // non-empty during first-time setup
}

func (s *Store) GetTOTPStatus(userID string) (TOTPStatus, error) {
	var enabled bool
	var secret, pending sql.NullString
	err := s.db.QueryRow(
		`SELECT COALESCE(totp_enabled, FALSE), totp_secret, totp_pending_secret FROM users WHERE id = $1`,
		userID,
	).Scan(&enabled, &secret, &pending)
	if err != nil {
		return TOTPStatus{}, err
	}
	return TOTPStatus{
		Enabled:       enabled,
		Secret:        secret.String,
		PendingSecret: pending.String,
	}, nil
}

// SetTOTPPendingSecret stores a not-yet-confirmed TOTP secret for a user.
func (s *Store) SetTOTPPendingSecret(userID, secret string) error {
	_, err := s.db.Exec(
		`UPDATE users SET totp_pending_secret = $1 WHERE id = $2`,
		secret, userID,
	)
	return err
}

// ActivateTOTP moves the pending secret to the active secret and sets totp_enabled.
func (s *Store) ActivateTOTP(userID, secret string) error {
	_, err := s.db.Exec(
		`UPDATE users SET totp_secret = $1, totp_pending_secret = NULL, totp_enabled = TRUE WHERE id = $2`,
		secret, userID,
	)
	return err
}

// ── Internal helpers ──────────────────────────────────────────────────────────

const userSelectCols = `id, name, email, role, provider, google_id,
	COALESCE(account_type,''), COALESCE(org_id,''), COALESCE(member_status,''), created_at, deleted_at, blocked_at,
	COALESCE(phone,''), COALESCE(avatar_url,'')`

func scanUser(row interface {
	Scan(...any) error
}) (*User, error) {
	u := &User{}
	var accountType, orgID, memberStatus string
	var deletedAt, blockedAt sql.NullTime
	if err := row.Scan(
		&u.ID, &u.Name, &u.Email, &u.Role, &u.Provider, &u.GoogleID,
		&accountType, &orgID, &memberStatus, &u.CreatedAt, &deletedAt, &blockedAt,
		&u.Phone, &u.AvatarURL,
	); err != nil {
		return nil, err
	}
	u.AccountType = AccountType(accountType)
	u.OrgID = orgID
	u.MemberStatus = MemberStatus(memberStatus)
	if deletedAt.Valid {
		u.DeletedAt = &deletedAt.Time
	}
	if blockedAt.Valid {
		u.BlockedAt = &blockedAt.Time
	}
	return u, nil
}

// ListAllUsers returns all non-deleted users (super admin).
func (s *Store) ListAllUsers() ([]User, error) {
	rows, err := s.db.Query(
		`SELECT ` + userSelectCols + ` FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

func (s *Store) findByEmail(email string) (*User, error) {
	row := s.db.QueryRow(`SELECT `+userSelectCols+` FROM users WHERE email = $1`, email)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) findByGoogleID(googleID string) (*User, error) {
	row := s.db.QueryRow(`SELECT `+userSelectCols+` FROM users WHERE google_id = $1`, googleID)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) findByID(id string) (*User, error) {
	row := s.db.QueryRow(`SELECT `+userSelectCols+` FROM users WHERE id = $1 AND deleted_at IS NULL AND blocked_at IS NULL`, id)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

// ── Org permissions ────────────────────────────────────────────────────────────

// GetUserPermissions returns all permission strings granted to a user in an org.
// Returns an empty slice (not an error) if the user has no grants.
func (s *Store) GetUserPermissions(orgID, userID string) ([]string, error) {
	rows, err := s.db.Query(
		`SELECT permission FROM org_permissions WHERE org_id = $1 AND user_id = $2`,
		orgID, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	perms := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

// SetUserPermissions replaces all permissions for a user in an org atomically.
// It deletes existing rows then inserts the new set in a transaction.
func (s *Store) SetUserPermissions(orgID, userID, grantedBy string, permissions []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`DELETE FROM org_permissions WHERE org_id = $1 AND user_id = $2`,
		orgID, userID,
	); err != nil {
		return err
	}

	for _, perm := range permissions {
		if _, err := tx.Exec(
			`INSERT INTO org_permissions (id, org_id, user_id, permission, granted_by)
			 VALUES ($1, $2, $3, $4, $5)`,
			uuid.NewString(), orgID, userID, perm, grantedBy,
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// HasOrgPermission returns true if the user has been granted the given permission in the org.
func (s *Store) HasOrgPermission(orgID, userID, permission string) bool {
	var exists bool
	s.db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM org_permissions WHERE org_id = $1 AND user_id = $2 AND permission = $3)`,
		orgID, userID, permission,
	).Scan(&exists)
	return exists
}

// ── Service tokens ────────────────────────────────────────────────────────────

// ServiceToken is the DB record for a service SDK token.
// The actual token value is never stored — only a SHA-256 hash.
type ServiceToken struct {
	ID          string     `json:"id"`
	ServiceName string     `json:"service_name"`
	Namespace   string     `json:"namespace"`
	Prefix      string     `json:"prefix"`
	Label       string     `json:"label"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	Revoked     bool       `json:"revoked"`
}

// CreateServiceToken inserts a new token record.
// tokenHash is SHA-256(rawToken), prefix is the first 12 chars of rawToken for display.
func (s *Store) CreateServiceToken(serviceName, namespace, tokenHash, prefix, label, createdBy string) (*ServiceToken, error) {
	id := uuid.NewString()
	_, err := s.db.Exec(
		`INSERT INTO service_tokens (id, service_name, namespace, token_hash, prefix, label, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, serviceName, namespace, tokenHash, prefix, label, createdBy,
	)
	if err != nil {
		return nil, err
	}
	return s.GetServiceToken(id)
}

// GetServiceToken fetches a single token record by its ID.
func (s *Store) GetServiceToken(id string) (*ServiceToken, error) {
	var t ServiceToken
	err := s.db.QueryRow(
		`SELECT id, service_name, namespace, prefix, label, created_by, created_at, last_used_at, revoked
		 FROM service_tokens WHERE id = $1`,
		id,
	).Scan(&t.ID, &t.ServiceName, &t.Namespace, &t.Prefix, &t.Label, &t.CreatedBy, &t.CreatedAt, &t.LastUsedAt, &t.Revoked)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return &t, err
}

// ListServiceTokens returns all non-revoked tokens for a service+namespace pair.
func (s *Store) ListServiceTokens(serviceName, namespace string) ([]ServiceToken, error) {
	rows, err := s.db.Query(
		`SELECT id, service_name, namespace, prefix, label, created_by, created_at, last_used_at, revoked
		 FROM service_tokens
		 WHERE service_name = $1 AND namespace = $2 AND revoked = FALSE
		 ORDER BY created_at DESC`,
		serviceName, namespace,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []ServiceToken
	for rows.Next() {
		var t ServiceToken
		if err := rows.Scan(&t.ID, &t.ServiceName, &t.Namespace, &t.Prefix, &t.Label, &t.CreatedBy, &t.CreatedAt, &t.LastUsedAt, &t.Revoked); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// RevokeServiceToken marks a token as revoked. Returns ErrNotFound if it doesn't exist.
func (s *Store) RevokeServiceToken(id, namespace string) error {
	res, err := s.db.Exec(
		`UPDATE service_tokens SET revoked = TRUE WHERE id = $1 AND namespace = $2`,
		id, namespace,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ValidateServiceToken looks up a token by its SHA-256 hash, confirms it is active,
// updates last_used_at, and returns the token record.
func (s *Store) ValidateServiceToken(tokenHash string) (*ServiceToken, error) {
	var t ServiceToken
	err := s.db.QueryRow(
		`SELECT id, service_name, namespace, prefix, label, created_by, created_at, last_used_at, revoked
		 FROM service_tokens WHERE token_hash = $1`,
		tokenHash,
	).Scan(&t.ID, &t.ServiceName, &t.Namespace, &t.Prefix, &t.Label, &t.CreatedBy, &t.CreatedAt, &t.LastUsedAt, &t.Revoked)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if t.Revoked {
		return nil, errors.New("token revoked")
	}
	// Best-effort update of last_used_at; ignore errors.
	s.db.Exec(`UPDATE service_tokens SET last_used_at = NOW() WHERE id = $1`, t.ID)
	return &t, nil
}
