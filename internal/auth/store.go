package auth

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var ErrEmailTaken = errors.New("email already registered")
var ErrNotFound = errors.New("user not found")
var ErrInvalidCredentials = errors.New("invalid email or password")

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL,
			email        TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL DEFAULT '',
			role         TEXT NOT NULL DEFAULT 'user',
			provider     TEXT NOT NULL DEFAULT 'local',
			google_id    TEXT NOT NULL DEFAULT '',
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

func (s *Store) SeedSuperAdmin(name, email, password string) error {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'super_admin'`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil // already seeded
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO users (id, name, email, password_hash, role, provider) VALUES ($1, $2, $3, $4, 'super_admin', 'local')`,
		uuid.NewString(), name, email, string(hash),
	)
	return err
}

func (s *Store) CreateLocal(name, email, password string) (*User, error) {
	var exists bool
	s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`, email).Scan(&exists)
	if exists {
		return nil, ErrEmailTaken
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	u := &User{
		ID:           uuid.NewString(),
		Name:         name,
		Email:        email,
		PasswordHash: string(hash),
		Role:         RoleUser,
		Provider:     "local",
	}
	_, err = s.db.Exec(
		`INSERT INTO users (id, name, email, password_hash, role, provider) VALUES ($1, $2, $3, $4, $5, 'local')`,
		u.ID, u.Name, u.Email, u.PasswordHash, u.Role,
	)
	return u, err
}

func (s *Store) Login(email, password string) (*User, error) {
	u, err := s.findByEmail(email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if u.Provider != "local" {
		return nil, fmt.Errorf("this account uses %s login", u.Provider)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

func (s *Store) UpsertGoogle(googleID, name, email string) (*User, error) {
	// Check by google_id first
	u, err := s.findByGoogleID(googleID)
	if err == nil {
		return u, nil
	}
	// Check by email (link accounts)
	u, err = s.findByEmail(email)
	if err == nil {
		_, err = s.db.Exec(`UPDATE users SET google_id = $1, provider = 'google' WHERE id = $2`, googleID, u.ID)
		return u, err
	}
	// New user
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

func (s *Store) findByEmail(email string) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(
		`SELECT id, name, email, password_hash, role, provider, google_id FROM users WHERE email = $1`, email,
	).Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.Role, &u.Provider, &u.GoogleID)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) findByGoogleID(googleID string) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(
		`SELECT id, name, email, password_hash, role, provider, google_id FROM users WHERE google_id = $1`, googleID,
	).Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.Role, &u.Provider, &u.GoogleID)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}

func (s *Store) findByID(id string) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(
		`SELECT id, name, email, password_hash, role, provider, google_id FROM users WHERE id = $1`, id,
	).Scan(&u.ID, &u.Name, &u.Email, &u.PasswordHash, &u.Role, &u.Provider, &u.GoogleID)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return u, err
}
