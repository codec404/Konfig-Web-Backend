package auth

type Role string

const (
	RoleSuperAdmin Role = "super_admin"
	RoleAdmin      Role = "admin"
	RoleUser       Role = "user"
)

type User struct {
	ID           string
	Name         string
	Email        string
	PasswordHash string
	Role         Role
	Provider     string // "local" or "google"
	GoogleID     string
}
