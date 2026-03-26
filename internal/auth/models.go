package auth

import "time"

type OrgMembership struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	OrgName   string    `json:"org_name"`
	UserID    string    `json:"user_id"`
	Role      Role      `json:"role"`
	Status    string    `json:"status"` // "invited" | "active"
	InvitedBy string    `json:"invited_by"`
	CreatedAt time.Time `json:"created_at"`
}

type OrgInvite struct {
	ID          string     `json:"id"`
	OrgID       string     `json:"org_id"`
	OrgName     string     `json:"org_name"`
	Email       string     `json:"email"`
	Role        Role       `json:"role"`
	InvitedBy   string     `json:"invited_by"`
	InviterName string     `json:"inviter_name"`
	Token       string     `json:"token"`
	ExpiresAt   time.Time  `json:"expires_at"`
	AcceptedAt  *time.Time `json:"accepted_at"`
	DeclinedAt  *time.Time `json:"declined_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

type Role string

const (
	RoleSuperAdmin Role = "super_admin"
	RoleAdmin      Role = "admin"
	RoleUser       Role = "user"
)

type AccountType string

const (
	AccountTypeIndividual AccountType = "individual"
	AccountTypeOrg        AccountType = "org"
)

type MemberStatus string

const (
	MemberStatusPending  MemberStatus = "pending"
	MemberStatusApproved MemberStatus = "approved"
	MemberStatusRejected MemberStatus = "rejected"
)

type User struct {
	ID    string
	Name  string
	Email string
	Role  Role
	AccountType  AccountType  // "individual" or "org"; empty for super_admin
	OrgID        string       // set when AccountType == "org"
	MemberStatus MemberStatus // pending/approved/rejected for org users
	Provider     string       // "local" or "google"
	GoogleID     string
	CreatedAt    time.Time
	DeletedAt    *time.Time
}

// Namespace returns the service namespace prefix for this user.
// Individual: "u__{userID}__"
// Org (approved): "o__{orgID}__"
// Super admin or unset: "" (no restriction)
func (u *User) Namespace() string {
	switch u.AccountType {
	case AccountTypeIndividual:
		return "u__" + u.ID + "__"
	case AccountTypeOrg:
		if u.OrgID != "" {
			return "o__" + u.OrgID + "__"
		}
	}
	return ""
}

type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

type OrgMemberDetail struct {
	UserID       string       `json:"user_id"`
	Name         string       `json:"name"`
	Email        string       `json:"email"`
	Role         Role         `json:"role"`
	MemberStatus MemberStatus `json:"member_status"`
	CreatedAt    time.Time    `json:"joined_at"`
}

type ServiceVisibility struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	UserID      string    `json:"user_id"`
	ServiceName string    `json:"service_name"`
	GrantedBy   string    `json:"granted_by"`
	CreatedAt   time.Time `json:"created_at"`
}
