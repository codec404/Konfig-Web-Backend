package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/codec404/Konfig/pkg/pb"
	"github.com/codec404/konfig-web-backend/internal/auth"
	grpcclient "github.com/codec404/konfig-web-backend/internal/grpc"
	applogger "github.com/codec404/konfig-web-backend/internal/logger"
	"github.com/codec404/konfig-web-backend/internal/mailer"
	"github.com/gorilla/mux"
)

type OrgHandler struct {
	developerEmail string
	store   *auth.Store
	clients *grpcclient.Clients
	mailer  *mailer.Mailer
	appURL  string
}

func NewOrgHandler(store *auth.Store, clients *grpcclient.Clients, ml *mailer.Mailer, appURL, developerEmail string) *OrgHandler {
	return &OrgHandler{store: store, clients: clients, mailer: ml, appURL: appURL, developerEmail: developerEmail}
}

// ── Public ────────────────────────────────────────────────────────────────────

// GetOrgBySlug resolves an org slug to org info (public endpoint for subdomain routing).
// GET /api/public/orgs/by-slug/{slug}
func (h *OrgHandler) GetOrgBySlug(w http.ResponseWriter, r *http.Request) {
	slug := mux.Vars(r)["slug"]
	org, err := h.store.FindOrgBySlug(slug)
	if errors.Is(err, auth.ErrNotFound) {
		writeError(w, http.StatusNotFound, "org not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"org_id": org.ID, "org_name": org.Name, "slug": org.Slug})
}

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

// ListOrgs returns all organizations with member counts.
// GET /api/admin/orgs
func (h *OrgHandler) ListOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.store.ListOrgs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	type orgItem struct {
		auth.Organization
		MemberCount int `json:"member_count"`
	}
	result := make([]orgItem, 0, len(orgs))
	for _, o := range orgs {
		members, _ := h.store.ListOrgMembers(o.ID)
		result = append(result, orgItem{Organization: o, MemberCount: len(members)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"orgs": result})
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

	// Validate the admin email exists before creating anything
	if _, err := h.store.FindByEmail(req.FirstAdminEmail); err != nil {
		writeError(w, http.StatusBadRequest, "no account found with that email")
		return
	}

	org, err := h.store.CreateOrg(req.Name, caller.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := h.store.SetOrgFirstAdmin(req.FirstAdminEmail, org.ID); err != nil {
		h.store.DeleteOrg(org.ID)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	applogger.Info("org created", map[string]any{"org_id": org.ID, "org_name": org.Name, "first_admin_email": req.FirstAdminEmail, "created_by": caller.ID})
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
	allOrgs, _ := h.store.ListOrgs()
	orgMap := make(map[string]string, len(allOrgs))
	for _, o := range allOrgs {
		orgMap[o.ID] = o.Name
	}

	// Build per-user invite org memberships map
	inviteOrgs := make(map[string][]string)
	if rows, err := h.store.DB().Query(
		`SELECT om.user_id, o.name FROM org_memberships om
		 JOIN organizations o ON o.id = om.org_id WHERE om.status = 'active'`,
	); err == nil {
		defer rows.Close()
		for rows.Next() {
			var uid, oname string
			if rows.Scan(&uid, &oname) == nil {
				inviteOrgs[uid] = append(inviteOrgs[uid], oname)
			}
		}
	}

	type userItem struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Email        string   `json:"email"`
		Role         string   `json:"role"`
		OrgID        string   `json:"org_id"`
		Orgs         []string `json:"orgs"`
		MemberStatus string   `json:"member_status"`
		CreatedAt    string   `json:"created_at"`
		Blocked      bool     `json:"blocked"`
		AvatarURL    string   `json:"avatar_url,omitempty"`
	}
	items := make([]userItem, 0, len(users))
	for _, u := range users {
		// Collect all org names for this user
		orgNames := make([]string, 0)
		if name := orgMap[u.OrgID]; name != "" {
			orgNames = append(orgNames, name)
		}
		for _, n := range inviteOrgs[u.ID] {
			// Avoid duplicating primary org
			if orgMap[u.OrgID] != n {
				orgNames = append(orgNames, n)
			}
		}

		status := string(u.MemberStatus)
		if status == "" {
			status = "active"
		}

		items = append(items, userItem{
			ID:           u.ID,
			Name:         u.Name,
			Email:        u.Email,
			Role:         string(u.Role),
			OrgID:        u.OrgID,
			Orgs:         orgNames,
			MemberStatus: status,
			CreatedAt:    u.CreatedAt.UTC().Format(time.RFC3339),
			Blocked:      u.BlockedAt != nil,
			AvatarURL:    u.AvatarURL,
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

// DeleteOrg soft-deletes an organization. Blocked if any members exist.
// DELETE /api/admin/orgs/{orgId}
func (h *OrgHandler) DeleteOrg(w http.ResponseWriter, r *http.Request) {
	orgID := mux.Vars(r)["orgId"]
	members, err := h.store.ListOrgMembers(orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if len(members) > 0 {
		writeError(w, http.StatusConflict, "cannot delete an organization with existing members")
		return
	}
	if err := h.store.DeleteOrg(orgID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	applogger.Info("org deleted", map[string]any{"org_id": orgID})
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

// AddUser links an existing user to an org (super admin only).
// POST /api/admin/users
// Body: {"email","org_id","role"}
func (h *OrgHandler) AddUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string    `json:"email"`
		OrgID string    `json:"org_id"`
		Role  auth.Role `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Email == "" || req.OrgID == "" {
		writeError(w, http.StatusBadRequest, "email and org_id are required")
		return
	}
	if req.Role == "" {
		req.Role = auth.RoleUser
	}
	if req.Role != auth.RoleAdmin && req.Role != auth.RoleUser {
		writeError(w, http.StatusBadRequest, "role must be 'admin' or 'user'")
		return
	}
	if err := h.store.LinkExistingUserToOrg(req.Email, req.OrgID, req.Role); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "no account found with that email")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	applogger.Info("user added to org", map[string]any{"email": req.Email, "org_id": req.OrgID, "role": string(req.Role)})
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true})
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
	applogger.Info("user removed", map[string]any{"user_id": userID, "removed_by": caller.ID})
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
	members, err := h.store.ListPendingMembers(callerOrgID(r, caller, h.store))
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
	members, err := h.store.ListOrgMembers(callerOrgID(r, caller, h.store))
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
	orgID := callerOrgID(r, caller, h.store)
	if err := h.store.ApproveMember(orgID, userID); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "pending member not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	applogger.Info("org member approved", map[string]any{"user_id": userID, "org_id": orgID, "approved_by": caller.ID})
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// RejectMember rejects a pending org member.
// POST /api/org/members/{userId}/reject
func (h *OrgHandler) RejectMember(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	userID := mux.Vars(r)["userId"]
	rejectOrgID := callerOrgID(r, caller, h.store)
	if err := h.store.RejectMember(rejectOrgID, userID); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "pending member not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	applogger.Info("org member rejected", map[string]any{"user_id": userID, "org_id": rejectOrgID, "rejected_by": caller.ID})
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// RemoveOrgMember removes a non-admin member from the org.
// DELETE /api/org/members/{userId}
func (h *OrgHandler) RemoveOrgMember(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	userID := mux.Vars(r)["userId"]
	removeOrgID := callerOrgID(r, caller, h.store)
	if err := h.store.RemoveFromOrg(caller.Role, removeOrgID, userID); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	applogger.Info("org member removed", map[string]any{"user_id": userID, "org_id": removeOrgID, "removed_by": caller.ID})
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
	if err := h.store.UpdateUserCreds(caller.Role, callerOrgID(r, caller, h.store), userID, req.Name); err != nil {
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
	vis, err := h.store.ListServiceVisibility(callerOrgID(r, caller, h.store), serviceName)
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
	if err := h.store.GrantServiceVisibility(callerOrgID(r, caller, h.store), req.UserID, serviceName, caller.ID); err != nil {
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
	if err := h.store.RevokeServiceVisibility(callerOrgID(r, caller, h.store), userID, serviceName); err != nil {
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
	applogger.Info("org invite accepted", map[string]any{"user_id": user.ID, "email": user.Email})
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

	orgID := callerOrgID(r, caller, h.store)
	token, err := h.store.InviteToOrg(orgID, req.Email, string(req.Role), caller.ID)
	if errors.Is(err, auth.ErrNotFound) {
		writeError(w, http.StatusNotFound, "user not registered")
		return
	}
	if errors.Is(err, auth.ErrEmailTaken) {
		writeError(w, http.StatusConflict, "already a member")
		return
	}
	if err != nil {
		applogger.Error("invite user: unexpected error", map[string]any{"org_id": orgID, "email": req.Email, "err": err.Error()})
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	org, _ := h.store.GetOrg(orgID)
	orgName := ""
	if org != nil {
		orgName = org.Name
	}
	if err := h.mailer.SendInvite(req.Email, orgName, caller.Name, token, h.appURL); err != nil {
		applogger.Error("invite user: email delivery failed", map[string]any{"email": req.Email, "org_id": orgID, "err": err.Error()})
	}
	applogger.Info("user invited to org", map[string]any{"email": req.Email, "org_id": orgID, "role": string(req.Role), "invited_by": caller.ID})
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// ListOrgInvites returns pending invites for the admin's org.
// GET /api/org/invites
func (h *OrgHandler) ListOrgInvites(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	invites, err := h.store.ListOrgInvites(callerOrgID(r, caller, h.store))
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

// BlockUser blocks a user (super admin only).
// POST /api/admin/users/{userId}/block
func (h *OrgHandler) BlockUser(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["userId"]
	if err := h.store.BlockUser(userID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	applogger.Info("user blocked", map[string]any{"user_id": userID})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// UnblockUser unblocks a user (super admin only).
// POST /api/admin/users/{userId}/unblock
func (h *OrgHandler) UnblockUser(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["userId"]
	if err := h.store.UnblockUser(userID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	applogger.Info("user unblocked", map[string]any{"user_id": userID})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ChangeOrgMemberRole changes a member's role within the admin's org.
// PUT /api/org/members/{userId}/role
// Body: {"role": "admin"|"user"}
func (h *OrgHandler) ChangeOrgMemberRole(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	userID := mux.Vars(r)["userId"]
	orgID := callerOrgID(r, caller, h.store)
	var req struct {
		Role auth.Role `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := h.store.ChangeOrgMemberRole(orgID, userID, req.Role); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "member not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	applogger.Info("org member role changed", map[string]any{"user_id": userID, "org_id": orgID, "new_role": string(req.Role), "changed_by": caller.ID})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// RemoveUserFromOrg removes a user from a specific org without deleting the account (super admin only).
// For admins: allowed only if multiple admins exist OR the admin is the sole member.
// DELETE /api/admin/orgs/{orgId}/members/{userId}
func (h *OrgHandler) RemoveUserFromOrg(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orgID, userID := vars["orgId"], vars["userId"]

	members, err := h.store.ListOrgMembers(orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Find the target member
	var targetRole auth.Role
	found := false
	for _, m := range members {
		if m.UserID == userID {
			targetRole = m.Role
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "user is not a member of this org")
		return
	}

	if targetRole == auth.RoleAdmin {
		adminCount := 0
		for _, m := range members {
			if m.Role == auth.RoleAdmin {
				adminCount++
			}
		}
		// Block removal if: only one admin AND other members exist
		if adminCount == 1 && len(members) > 1 {
			writeError(w, http.StatusConflict, "cannot remove the only admin while other members exist")
			return
		}
	}

	if err := h.store.RemoveUserFromOrg(orgID, userID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ── Org permissions ────────────────────────────────────────────────────────────

// resolveOrgIDFromRequest extracts the org ID from X-Org-ID or X-Org-Slug headers.
func resolveOrgIDFromRequest(r *http.Request, store *auth.Store) string {
	if id := r.Header.Get("X-Org-ID"); id != "" {
		return id
	}
	if slug := r.Header.Get("X-Org-Slug"); slug != "" {
		if org, err := store.FindOrgBySlug(slug); err == nil {
			return org.ID
		}
	}
	return ""
}

// callerOrgID resolves the effective org ID for the request.
// Prefers request headers (X-Org-ID / X-Org-Slug) over caller.OrgID so that
// admins who belong to multiple orgs operate on the correct one.
func callerOrgID(r *http.Request, caller *auth.User, store *auth.Store) string {
	if id := resolveOrgIDFromRequest(r, store); id != "" {
		return id
	}
	return caller.OrgID
}

// GetMemberPermissions returns a member's org permission grants.
// GET /api/org/members/{userId}/permissions
func (h *OrgHandler) GetMemberPermissions(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["userId"]
	caller := auth.UserFromContext(r.Context())
	orgID := callerOrgID(r, caller, h.store)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "org context required")
		return
	}
	perms, err := h.store.GetUserPermissions(orgID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": perms})
}

// SetMemberPermissions replaces a member's org permission grants.
// PUT /api/org/members/{userId}/permissions
func (h *OrgHandler) SetMemberPermissions(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFromContext(r.Context())
	userID := mux.Vars(r)["userId"]
	orgID := callerOrgID(r, caller, h.store)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "org context required")
		return
	}
	var req struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Permissions == nil {
		req.Permissions = []string{}
	}
	if err := h.store.SetUserPermissions(orgID, userID, caller.ID, req.Permissions); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// GetMyOrgPermissions returns the calling user's permissions (or all perms if admin).
// GET /api/orgs/{orgId}/my-permissions
func (h *OrgHandler) GetMyOrgPermissions(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	orgID := mux.Vars(r)["orgId"]
	// Check membership
	membership, err := h.store.GetOrgMembership(user.ID, orgID)
	if err != nil {
		// Super admin can access any org
		if user.Role == auth.RoleSuperAdmin {
			allPerms := []string{
				"services.view", "services.create",
				"configs.create", "configs.delete",
				"rollouts.view", "rollouts.manage",
				"schemas.view", "schemas.manage",
				"live.view",
			}
			writeJSON(w, http.StatusOK, map[string]any{"permissions": allPerms, "is_admin": true})
			return
		}
		writeError(w, http.StatusForbidden, "not a member")
		return
	}
	// Admins have all permissions
	if membership.Role == auth.RoleAdmin || user.Role == auth.RoleSuperAdmin {
		allPerms := []string{
			"services.view", "services.create",
			"configs.create", "configs.delete",
			"rollouts.view", "rollouts.manage",
			"schemas.view", "schemas.manage",
			"live.view",
		}
		writeJSON(w, http.StatusOK, map[string]any{"permissions": allPerms, "is_admin": true})
		return
	}
	perms, err := h.store.GetUserPermissions(orgID, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"permissions": perms, "is_admin": false})
}

// ── Bug reports ───────────────────────────────────────────────────────────────

// SubmitBugReport creates a new bug report from the logged-in user.
// POST /api/bugs
func (h *OrgHandler) SubmitBugReport(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	var req struct {
		IssueType   string `json:"issue_type"`
		Title       string `json:"title"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Title == "" || req.Description == "" || req.IssueType == "" {
		writeError(w, http.StatusBadRequest, "issue_type, title and description are required")
		return
	}
	if err := h.store.CreateBugReport(user.ID, user.Email, req.IssueType, req.Title, req.Description); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	applogger.Info("bug report submitted", map[string]any{"user_id": user.ID, "issue_type": req.IssueType, "title": req.Title})
	if h.developerEmail != "" {
		go h.mailer.SendBugReport(h.developerEmail, req.IssueType, req.Title, req.Description, user.Email)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ListBugReports returns all bug reports (super admin only).
// GET /api/admin/bugs
func (h *OrgHandler) ListBugReports(w http.ResponseWriter, r *http.Request) {
	reports, err := h.store.ListBugReports()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if reports == nil {
		reports = []auth.BugReport{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": reports})
}

// UpdateBugReportStatus updates the status of a bug report (super admin only).
// PUT /api/admin/bugs/{reportId}/status
func (h *OrgHandler) UpdateBugReportStatus(w http.ResponseWriter, r *http.Request) {
	reportID := mux.Vars(r)["reportId"]
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if err := h.store.UpdateBugReportStatus(reportID, req.Status); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			writeError(w, http.StatusNotFound, "report not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ── Email preview (SA only, dev aid) ──────────────────────────────────────────

// PreviewEmail renders an email template as HTML directly in the browser.
// GET /api/admin/email-preview?template=otp|invite|bug_report
func (h *OrgHandler) PreviewEmail(w http.ResponseWriter, r *http.Request) {
	tmpl := r.URL.Query().Get("template")
	var (
		html string
		err  error
	)
	switch tmpl {
	case "otp":
		html, err = mailer.RenderOTP("482917")
	case "invite":
		html, err = mailer.RenderInvite("Acme Corp", "Alice", "http://localhost:5173/invites/tok_preview123")
	case "bug_report":
		html, err = mailer.RenderBugReport(
			"bug",
			"Login page crashes on mobile Safari",
			"Steps to reproduce:\n1. Open the login page on iPhone Safari 17\n2. Tap 'Send OTP'\n3. App freezes\n\nExpected: OTP sent\nActual: White screen",
			"user@example.com",
		)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body style="font-family:sans-serif;padding:32px;background:#0f0f17;color:#e0e0f0;">
			<h2>Email Template Previews</h2>
			<ul>
				<li><a href="?template=otp" style="color:#6366f1;">OTP / Login</a></li>
				<li><a href="?template=invite" style="color:#6366f1;">Org Invite</a></li>
				<li><a href="?template=bug_report" style="color:#6366f1;">Bug Report</a></li>
			</ul>
		</body></html>`))
		return
	}
	if err != nil {
		http.Error(w, "render error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}
