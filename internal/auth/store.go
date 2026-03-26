package auth

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
)

var ErrEmailTaken = errors.New("email already registered")
var ErrNotFound = errors.New("user not found")
var ErrEmailConflict = errors.New("email already in use by a different account type")
var ErrInvalidOTP = errors.New("invalid or expired OTP")

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
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
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS account_type   TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS org_id         TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS member_status  TEXT`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at     TIMESTAMPTZ`,
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
			id         TEXT PRIMARY KEY,
			email      TEXT NOT NULL,
			code       TEXT NOT NULL,
			purpose    TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			used_at    TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
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
func (s *Store) VerifyAndConsumeOTP(email, code, purpose string) error {
	var id string
	err := s.db.QueryRow(
		`SELECT id FROM otps
		 WHERE email = $1 AND code = $2 AND purpose = $3
		   AND used_at IS NULL AND expires_at > NOW()`,
		email, code, purpose,
	).Scan(&id)
	if err == sql.ErrNoRows {
		return ErrInvalidOTP
	}
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE otps SET used_at = NOW() WHERE id = $1`, id)
	return err
}

// FindActiveByEmail returns a non-deleted user by email.
func (s *Store) FindActiveByEmail(email string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT `+userSelectCols+` FROM users WHERE email = $1 AND deleted_at IS NULL`, email,
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

// UpdateOwnCreds lets a user update their own name.
func (s *Store) UpdateOwnCreds(userID, name string) error {
	if name != "" {
		if _, err := s.db.Exec(`UPDATE users SET name = $1 WHERE id = $2`, name, userID); err != nil {
			return err
		}
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

// ── Organization management ───────────────────────────────────────────────────

func (s *Store) CreateOrg(name, createdBy string) (*Organization, error) {
	org := &Organization{
		ID:        uuid.NewString(),
		Name:      name,
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
	}
	_, err := s.db.Exec(
		`INSERT INTO organizations (id, name, created_by) VALUES ($1, $2, $3)`,
		org.ID, org.Name, org.CreatedBy,
	)
	return org, err
}

func (s *Store) GetOrg(orgID string) (*Organization, error) {
	org := &Organization{}
	err := s.db.QueryRow(
		`SELECT id, name, created_by, created_at FROM organizations WHERE id = $1 AND deleted_at IS NULL`,
		orgID,
	).Scan(&org.ID, &org.Name, &org.CreatedBy, &org.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return org, err
}

func (s *Store) ListOrgs() ([]Organization, error) {
	rows, err := s.db.Query(
		`SELECT id, name, created_by, created_at FROM organizations WHERE deleted_at IS NULL ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orgs []Organization
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.CreatedBy, &o.CreatedAt); err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}

func (s *Store) DeleteOrg(orgID string) error {
	now := time.Now()
	_, err := s.db.Exec(`UPDATE organizations SET deleted_at = $1 WHERE id = $2`, now, orgID)
	return err
}

// SetOrgFirstAdmin promotes an existing user to admin of the given org.
// Called by super admin when creating an org with an existing user email.
func (s *Store) SetOrgFirstAdmin(email, orgID string) error {
	u, err := s.findByEmail(email)
	if err != nil {
		return ErrNotFound
	}
	_, err = s.db.Exec(
		`UPDATE users SET org_id = $1, role = 'admin', account_type = 'org', member_status = 'approved' WHERE id = $2`,
		orgID, u.ID,
	)
	return err
}

// AddUserToOrg creates a new user directly into an org with a given role (used by super admin).
func (s *Store) AddUserToOrg(name, email, orgID string, role Role) (*User, error) {
	var exists bool
	s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND deleted_at IS NULL)`, email).Scan(&exists)
	if exists {
		return nil, ErrEmailTaken
	}
	u := &User{
		ID:           uuid.NewString(),
		Name:         name,
		Email:        email,
		Role:         role,
		AccountType:  AccountTypeOrg,
		OrgID:        orgID,
		MemberStatus: MemberStatusApproved,
		Provider:     "local",
	}
	_, err := s.db.Exec(
		`INSERT INTO users (id, name, email, role, provider, account_type, org_id, member_status)
		 VALUES ($1, $2, $3, $4, 'local', 'org', $5, 'approved')`,
		u.ID, u.Name, u.Email, string(role), orgID,
	)
	return u, err
}

// ── Member management ─────────────────────────────────────────────────────────

func (s *Store) ListOrgMembers(orgID string) ([]OrgMemberDetail, error) {
	rows, err := s.db.Query(
		`SELECT u.id, u.name, u.email, u.role, COALESCE(u.member_status,'approved'), u.created_at
		 FROM users u WHERE u.org_id = $1 AND u.deleted_at IS NULL
		 UNION
		 SELECT u.id, u.name, u.email, m.role, 'approved', m.created_at
		 FROM org_memberships m JOIN users u ON u.id = m.user_id
		 WHERE m.org_id = $1 AND m.status = 'active' AND u.deleted_at IS NULL
		 ORDER BY created_at ASC`,
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
		SELECT m.id, m.org_id, o.name, m.user_id, m.role, m.status, m.invited_by, m.created_at
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
		if err := rows.Scan(&m.ID, &m.OrgID, &m.OrgName, &m.UserID, &m.Role, &m.Status, &m.InvitedBy, &m.CreatedAt); err != nil {
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
func (s *Store) ListOrgInvites(orgID string) ([]OrgInvite, error) {
	rows, err := s.db.Query(`
		SELECT i.id, i.org_id, o.name, i.email, i.role, i.invited_by, u.name, i.token, i.expires_at, i.created_at
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
			&inv.InvitedBy, &inviterName, &inv.Token, &inv.ExpiresAt, &inv.CreatedAt); err != nil {
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

// ── Internal helpers ──────────────────────────────────────────────────────────

const userSelectCols = `id, name, email, role, provider, google_id,
	COALESCE(account_type,''), COALESCE(org_id,''), COALESCE(member_status,''), created_at, deleted_at`

func scanUser(row interface {
	Scan(...any) error
}) (*User, error) {
	u := &User{}
	var accountType, orgID, memberStatus string
	var deletedAt sql.NullTime
	if err := row.Scan(
		&u.ID, &u.Name, &u.Email, &u.Role, &u.Provider, &u.GoogleID,
		&accountType, &orgID, &memberStatus, &u.CreatedAt, &deletedAt,
	); err != nil {
		return nil, err
	}
	u.AccountType = AccountType(accountType)
	u.OrgID = orgID
	u.MemberStatus = MemberStatus(memberStatus)
	if deletedAt.Valid {
		u.DeletedAt = &deletedAt.Time
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
	row := s.db.QueryRow(`SELECT `+userSelectCols+` FROM users WHERE id = $1`, id)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}
