package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/codec404/Konfig/pkg/pb"
	"github.com/codec404/konfig-web-backend/internal/auth"
	grpcclient "github.com/codec404/konfig-web-backend/internal/grpc"
	"github.com/codec404/konfig-web-backend/internal/mailer"
	"github.com/gorilla/mux"
)

type OrgHandler struct {
	store   *auth.Store
	clients *grpcclient.Clients
	mailer  *mailer.Mailer
	appURL  string
}

func NewOrgHandler(store *auth.Store, clients *grpcclient.Clients, ml *mailer.Mailer, appURL string) *OrgHandler {
	return &OrgHandler{store: store, clients: clients, mailer: ml, appURL: appURL}
}

// ── Public ────────────────────────────────────────────────────────────────────

// ListPublicOrgs returns org names for the signup page (no auth required).
// GET /api/public/orgs
func (h *OrgHandler) ListPublicOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.store.ListOrgs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	type publicOrg struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	result := make([]publicOrg, 0, len(orgs))
	for _, o := range orgs {
		result = append(result, publicOrg{ID: o.ID, Name: o.Name})
	}
	writeJSON(w, http.StatusOK, map[string]any{"orgs": result})
}

// ── Super admin: org management ───────────────────────────────────────────────

// ListOrgs returns all organizations.
// GET /api/admin/orgs
func (h *OrgHandler) ListOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.store.ListOrgs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if orgs == nil {
		orgs = []auth.Organization{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"orgs": orgs})
}

// CreateOrg creates a new organization and maps a first admin to it.
// If the email belongs to an existing user, that user is promoted to admin.
// If no user exists with that email, one is auto-created with password {orgName}@123.
// POST /api/admin/orgs
// Body: {"name": "Acme", "first_admin_email": "admin@acme.com"}
func (h *OrgHandler) CreateOrg(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	var req struct {
		Name            string `json:"name"`
		FirstAdminEmail string `json:"first_admin_email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "organization name cannot be blank")
		return
	}
	if req.FirstAdminEmail == "" {
		writeError(w, http.StatusBadRequest, "first_admin_email is required")
		return
	}

	org, err := h.store.CreateOrg(req.Name, caller.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := h.store.SetOrgFirstAdmin(req.FirstAdminEmail, org.ID); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			// User doesn't exist — auto-create. They log in via OTP.
			localPart := strings.Split(req.FirstAdminEmail, "@")[0]
			if _, err2 := h.store.AddUserToOrg(localPart, req.FirstAdminEmail, org.ID, auth.RoleAdmin); err2 != nil {
				h.store.DeleteOrg(org.ID)
				if errors.Is(err2, auth.ErrEmailTaken) {
					writeError(w, http.StatusConflict, "email already registered")
				} else {
					writeError(w, http.StatusInternalServerError, "could not create admin user")
				}
				return
			}
		} else {
			h.store.DeleteOrg(org.ID)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}

	writeJSON(w, http.StatusCreated, map[string]any{"org": org})
}

// ListAllUsers returns all users with their org info (super admin).
// GET /api/admin/users
func (h *OrgHandler) ListAllUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListAllUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	orgs, _ := h.store.ListOrgs()
	orgMap := make(map[string]string, len(orgs))
	for _, o := range orgs {
		orgMap[o.ID] = o.Name
	}
	type userItem struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		Email        string `json:"email"`
		Role         string `json:"role"`
		AccountType  string `json:"account_type"`
		OrgID        string `json:"org_id"`
		OrgName      string `json:"org_name"`
		MemberStatus string `json:"member_status"`
		CreatedAt    string `json:"created_at"`
	}
	items := make([]userItem, 0, len(users))
	for _, u := range users {
		items = append(items, userItem{
			ID:           u.ID,
			Name:         u.Name,
			Email:        u.Email,
			Role:         string(u.Role),
			AccountType:  string(u.AccountType),
			OrgID:        u.OrgID,
			OrgName:      orgMap[u.OrgID],
			MemberStatus: string(u.MemberStatus),
			CreatedAt:    u.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": items})
}

// ListOrgServices lists all services belonging to an org's namespace.
// GET /api/admin/orgs/{orgId}/services
func (h *OrgHandler) ListOrgServices(w http.ResponseWriter, r *http.Request) {
	orgID := mux.Vars(r)["orgId"]
	ns := "o__" + orgID + "__"
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	resp, err := h.clients.API.ListServices(ctx, &pb.ListServicesRequest{})
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	services := make([]map[string]any, 0)
	for _, s := range resp.GetServices() {
		if !strings.HasPrefix(s.GetServiceName(), ns) {
			continue
		}
		services = append(services, map[string]any{
			"service_name":   strings.TrimPrefix(s.GetServiceName(), ns),
			"latest_version": s.GetLatestVersion(),
			"config_count":   s.GetConfigCount(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": services})
}

// DeleteOrg soft-deletes an organization.
// DELETE /api/admin/orgs/{orgId}
func (h *OrgHandler) DeleteOrg(w http.ResponseWriter, r *http.Request) {
	orgID := mux.Vars(r)["orgId"]
	if err := h.store.DeleteOrg(orgID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// GetOrgMembers lists all members of an org (super admin view).
// GET /api/admin/orgs/{orgId}/members
func (h *OrgHandler) GetOrgMembers(w http.ResponseWriter, r *http.Request) {
	orgID := mux.Vars(r)["orgId"]
	members, err := h.store.ListOrgMembers(orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if members == nil {
		members = []auth.OrgMemberDetail{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

// AddUser creates or links a user to an org (super admin only).
// POST /api/admin/users
// Body: {"name","email","org_id","role"}
func (h *OrgHandler) AddUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string    `json:"name"`
		Email string    `json:"email"`
		OrgID string    `json:"org_id"`
		Role  auth.Role `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Name == "" || req.Email == "" || req.OrgID == "" {
		writeError(w, http.StatusBadRequest, "name, email, and org_id are required")
		return
	}
	if req.Role == "" {
		req.Role = auth.RoleUser
	}
	if req.Role != auth.RoleAdmin && req.Role != auth.RoleUser {
		writeError(w, http.StatusBadRequest, "role must be 'admin' or 'user'")
		return
	}
	user, err := h.store.AddUserToOrg(req.Name, req.Email, req.OrgID, req.Role)
	if errors.Is(err, auth.ErrEmailTaken) {
		writeError(w, http.StatusConflict, "email already registered")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": map[string]any{
		"id":    user.ID,
		"name":  user.Name,
		"email": user.Email,
		"role":  user.Role,
	}})
}

// RemoveUser soft-deletes a user (super admin can remove any user).
// DELETE /api/admin/users/{userId}
func (h *OrgHandler) RemoveUser(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	userID := mux.Vars(r)["userId"]
	if err := h.store.SoftDeleteUser(caller.Role, caller.OrgID, userID); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// UpdateUser updates another user's name (super admin or admin within org).
// PUT /api/admin/users/{userId}
func (h *OrgHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	userID := mux.Vars(r)["userId"]
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := h.store.UpdateUserCreds(caller.Role, caller.OrgID, userID, req.Name); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// ── Admin: member management within own org ───────────────────────────────────

// ListPending returns pending members for the admin's org.
// GET /api/org/pending
func (h *OrgHandler) ListPending(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	members, err := h.store.ListPendingMembers(caller.OrgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if members == nil {
		members = []auth.OrgMemberDetail{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

// ListMembers returns all members of the admin's org.
// GET /api/org/members
func (h *OrgHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	members, err := h.store.ListOrgMembers(caller.OrgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if members == nil {
		members = []auth.OrgMemberDetail{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

// ApproveMember approves a pending org member.
// POST /api/org/members/{userId}/approve
func (h *OrgHandler) ApproveMember(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	userID := mux.Vars(r)["userId"]
	if err := h.store.ApproveMember(caller.OrgID, userID); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "pending member not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// RejectMember rejects a pending org member.
// POST /api/org/members/{userId}/reject
func (h *OrgHandler) RejectMember(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	userID := mux.Vars(r)["userId"]
	if err := h.store.RejectMember(caller.OrgID, userID); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "pending member not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// RemoveOrgMember removes a non-admin member from the org.
// DELETE /api/org/members/{userId}
func (h *OrgHandler) RemoveOrgMember(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	userID := mux.Vars(r)["userId"]
	if err := h.store.RemoveFromOrg(caller.Role, caller.OrgID, userID); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// UpdateOrgMember updates a non-admin member's name.
// PUT /api/org/members/{userId}
func (h *OrgHandler) UpdateOrgMember(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	userID := mux.Vars(r)["userId"]
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := h.store.UpdateUserCreds(caller.Role, caller.OrgID, userID, req.Name); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// ── Admin: service visibility management ─────────────────────────────────────

// ListServiceVisibility returns all visibility grants for a service.
// GET /api/org/services/{serviceName}/visibility
func (h *OrgHandler) ListServiceVisibility(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	serviceName := mux.Vars(r)["serviceName"]
	vis, err := h.store.ListServiceVisibility(caller.OrgID, serviceName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if vis == nil {
		vis = []auth.ServiceVisibility{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"visibility": vis})
}

// GrantServiceVisibility grants a user visibility to a service.
// POST /api/org/services/{serviceName}/visibility
// Body: {"user_id": "..."}
func (h *OrgHandler) GrantServiceVisibility(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	serviceName := mux.Vars(r)["serviceName"]
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	if err := h.store.GrantServiceVisibility(caller.OrgID, req.UserID, serviceName, caller.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// RevokeServiceVisibility revokes a user's visibility to a service.
// DELETE /api/org/services/{serviceName}/visibility/{userId}
func (h *OrgHandler) RevokeServiceVisibility(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	vars := mux.Vars(r)
	serviceName := vars["serviceName"]
	userID := vars["userId"]
	if err := h.store.RevokeServiceVisibility(caller.OrgID, userID, serviceName); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// ── User: my orgs & invites ───────────────────────────────────────────────────

// ListMyOrgs returns all orgs the logged-in user is an active member of.
// GET /api/me/orgs
func (h *OrgHandler) ListMyOrgs(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	orgs, err := h.store.ListMyOrgs(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Also include primary org from user row if set and approved
	if user.OrgID != "" && string(user.MemberStatus) == "approved" {
		org, err := h.store.GetOrg(user.OrgID)
		if err == nil {
			// Check if not already in list
			found := false
			for _, m := range orgs {
				if m.OrgID == user.OrgID {
					found = true
					break
				}
			}
			if !found {
				orgs = append([]auth.OrgMembership{{
					OrgID:   org.ID,
					OrgName: org.Name,
					UserID:  user.ID,
					Role:    user.Role,
					Status:  "active",
				}}, orgs...)
			}
		}
	}
	if orgs == nil {
		orgs = []auth.OrgMembership{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"orgs": orgs})
}

// ListMyInvites returns pending org invites for the logged-in user.
// GET /api/me/invites
func (h *OrgHandler) ListMyInvites(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	invites, err := h.store.ListMyInvites(user.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if invites == nil {
		invites = []auth.OrgInvite{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": invites})
}

// AcceptInvite accepts a pending org invite.
// POST /api/me/invites/accept
// Body: {"token": "..."}
func (h *OrgHandler) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	if err := h.store.AcceptOrgInvite(user.ID, req.Token); err != nil {
		if errors.Is(err, auth.ErrInvalidOTP) {
			writeError(w, http.StatusBadRequest, "invalid or expired invite")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// DeclineInvite declines a pending org invite.
// POST /api/me/invites/decline
// Body: {"token": "..."}
func (h *OrgHandler) DeclineInvite(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	if err := h.store.DeclineOrgInvite(user.ID, req.Token); err != nil {
		if errors.Is(err, auth.ErrInvalidOTP) {
			writeError(w, http.StatusBadRequest, "invalid or expired invite")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// ── Org admin: invite management ──────────────────────────────────────────────

// InviteUser invites a registered user to the admin's org.
// POST /api/org/invite
// Body: {"email": "...", "role": "user"|"admin"}
func (h *OrgHandler) InviteUser(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	var req struct {
		Email string    `json:"email"`
		Role  auth.Role `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}
	if req.Role == "" {
		req.Role = auth.RoleUser
	}
	if req.Role != auth.RoleAdmin && req.Role != auth.RoleUser {
		writeError(w, http.StatusBadRequest, "role must be 'admin' or 'user'")
		return
	}

	token, err := h.store.InviteToOrg(caller.OrgID, req.Email, string(req.Role), caller.ID)
	if errors.Is(err, auth.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not registered")
		return
	}
	if errors.Is(err, auth.ErrEmailTaken) {
		writeError(w, http.StatusConflict, "already a member")
		return
	}
	if err != nil {
		log.Printf("[InviteUser] unexpected error for org %s, email %s: %v", caller.OrgID, req.Email, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	org, _ := h.store.GetOrg(caller.OrgID)
	orgName := ""
	if org != nil {
		orgName = org.Name
	}
	if err := h.mailer.SendInvite(req.Email, orgName, caller.Name, token, h.appURL); err != nil {
		log.Printf("[InviteUser] failed to send invite email to %s: %v", req.Email, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// ListOrgInvites returns pending invites for the admin's org.
// GET /api/org/invites
func (h *OrgHandler) ListOrgInvites(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	invites, err := h.store.ListOrgInvites(caller.OrgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if invites == nil {
		invites = []auth.OrgInvite{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": invites})
}

// GetOrgServicesForUser lists services in an org visible to the requesting user.
// GET /api/orgs/{orgId}/services
func (h *OrgHandler) GetOrgServicesForUser(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	orgID := mux.Vars(r)["orgId"]

	membership, err := h.store.GetOrgMembership(caller.ID, orgID)
	if err != nil {
		writeError(w, http.StatusForbidden, "not a member of this organization")
		return
	}

	ns := "o__" + orgID + "__"
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	resp, err := h.clients.API.ListServices(ctx, &pb.ListServicesRequest{})
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	// Get visible service names for regular users
	var visibleSet map[string]bool
	if membership.Role == auth.RoleUser {
		visible, err := h.store.GetOrgVisibleServices(caller.ID, orgID)
		if err == nil && visible != nil {
			visibleSet = make(map[string]bool, len(visible))
			for _, s := range visible {
				visibleSet[s] = true
			}
		}
	}

	services := make([]map[string]any, 0)
	for _, s := range resp.GetServices() {
		if !strings.HasPrefix(s.GetServiceName(), ns) {
			continue
		}
		shortName := strings.TrimPrefix(s.GetServiceName(), ns)
		if visibleSet != nil && !visibleSet[shortName] {
			continue
		}
		services = append(services, map[string]any{
			"service_name":   shortName,
			"latest_version": s.GetLatestVersion(),
			"config_count":   s.GetConfigCount(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": services, "org_id": orgID, "role": membership.Role})
}
