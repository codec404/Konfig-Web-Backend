package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codec404/Konfig/pkg/pb"
	"github.com/codec404/konfig-web-backend/internal/auth"
	grpcclient "github.com/codec404/konfig-web-backend/internal/grpc"
	"github.com/gorilla/mux"
)

// ── Namespace helpers ─────────────────────────────────────────────────────────

// resolveNS returns the effective namespace for the request.
// If the X-Org-ID header is present and the user is a member of that org,
// the org namespace is returned. Otherwise falls back to user.Namespace().
func resolveNS(r *http.Request, user *auth.User, store *auth.Store) string {
	orgID := r.Header.Get("X-Org-ID")
	if orgID == "" {
		return user.Namespace()
	}
	if _, err := store.GetOrgMembership(user.ID, orgID); err != nil {
		return user.Namespace()
	}
	return "o__" + orgID + "__"
}

// applyNS prepends a namespace prefix to an external service name.
func applyNS(ns, svcName string) string {
	if ns == "" {
		return svcName
	}
	return ns + svcName
}

// stripNS removes a namespace prefix from an internal service name.
// Returns ("", false) if the name doesn't belong to this namespace.
func stripNS(ns, internal string) (string, bool) {
	if ns == "" {
		return internal, true
	}
	if strings.HasPrefix(internal, ns) {
		return strings.TrimPrefix(internal, ns), true
	}
	return "", false
}

// ownsConfigID checks whether a config_id belongs to the given namespace.
func ownsConfigID(ns, configID string) bool {
	if ns == "" {
		return true
	}
	return strings.HasPrefix(configID, ns)
}

// canAccessService returns true if the user can access the given clean service name
// within the resolved namespace/org context.
func canAccessService(r *http.Request, user *auth.User, ns, cleanSvcName string, store *auth.Store) bool {
	if ns == "" {
		return true // super admin
	}
	if user.Role == auth.RoleAdmin {
		return true
	}
	// Extract orgID from namespace "o__{orgID}__"
	if strings.HasPrefix(ns, "o__") {
		orgID := strings.TrimPrefix(strings.TrimSuffix(ns, "__"), "o__")
		visible, err := store.GetVisibleServices(orgID, user.ID)
		if err != nil {
			return false
		}
		for _, svc := range visible {
			if svc == cleanSvcName {
				return true
			}
		}
		return false
	}
	return true // individual namespace — user owns it
}

// ── Response types ────────────────────────────────────────────────────────────

type configDataResponse struct {
	ConfigID    string `json:"config_id"`
	ServiceName string `json:"service_name"`
	ConfigName  string `json:"config_name"`
	Version     int64  `json:"version"`
	Content     string `json:"content"`
	Format      string `json:"format"`
	ContentHash string `json:"content_hash"`
	CreatedAt   string `json:"created_at"`
	CreatedBy   string `json:"created_by"`
}

type configMetaResponse struct {
	ConfigID    string `json:"config_id"`
	ServiceName string `json:"service_name"`
	ConfigName  string `json:"config_name"`
	Version     int64  `json:"version"`
	Format      string `json:"format"`
	CreatedAt   string `json:"created_at"`
	CreatedBy   string `json:"created_by"`
	Description string `json:"description"`
	IsActive    bool   `json:"is_active"`
}

type namedConfigSummaryResponse struct {
	ServiceName      string `json:"service_name"`
	ConfigName       string `json:"config_name"`
	Format           string `json:"format"`
	VersionCount     int32  `json:"version_count"`
	LatestVersion    int64  `json:"latest_version"`
	LatestUpdatedAt  string `json:"latest_updated_at"`
	HasActiveRollout bool   `json:"has_active_rollout"`
}

func toConfigDataResp(c *pb.ConfigData, cleanSvcName string) configDataResponse {
	return configDataResponse{
		ConfigID:    c.GetConfigId(),
		ServiceName: cleanSvcName,
		ConfigName:  c.GetConfigName(),
		Version:     c.GetVersion(),
		Content:     c.GetContent(),
		Format:      c.GetFormat(),
		ContentHash: c.GetContentHash(),
		CreatedAt:   time.Unix(c.GetCreatedAt(), 0).UTC().Format(time.RFC3339),
		CreatedBy:   c.GetCreatedBy(),
	}
}

func toConfigMetaResp(m *pb.ConfigMetadata, cleanSvcName string) configMetaResponse {
	return configMetaResponse{
		ConfigID:    m.GetConfigId(),
		ServiceName: cleanSvcName,
		ConfigName:  m.GetConfigName(),
		Version:     m.GetVersion(),
		Format:      m.GetFormat(),
		CreatedAt:   time.Unix(m.GetCreatedAt(), 0).UTC().Format(time.RFC3339),
		CreatedBy:   m.GetCreatedBy(),
		Description: m.GetDescription(),
		IsActive:    m.GetIsActive(),
	}
}

func toNamedConfigSummaryResp(n *pb.NamedConfigSummary, cleanSvcName string) namedConfigSummaryResponse {
	return namedConfigSummaryResponse{
		ServiceName:      cleanSvcName,
		ConfigName:       n.GetConfigName(),
		Format:           n.GetFormat(),
		VersionCount:     n.GetVersionCount(),
		LatestVersion:    n.GetLatestVersion(),
		LatestUpdatedAt:  n.GetLatestUpdatedAt(),
		HasActiveRollout: n.GetHasActiveRollout(),
	}
}

// writeJSON serialises v as JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON {"error": "..."} response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// ListServices handles GET /api/services
func ListServices(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.ListServices(ctx, &pb.ListServicesRequest{})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		// Pre-fetch visible services for non-admin users in an org namespace
		var visibleSet map[string]bool
		if strings.HasPrefix(ns, "o__") && user.Role == auth.RoleUser {
			orgID := strings.TrimSuffix(strings.TrimPrefix(ns, "o__"), "__")
			visible, err := store.GetVisibleServices(orgID, user.ID)
			if err == nil {
				visibleSet = make(map[string]bool, len(visible))
				for _, svc := range visible {
					visibleSet[svc] = true
				}
			}
		}

		services := make([]map[string]any, 0)
		for _, s := range resp.GetServices() {
			cleanName, ok := stripNS(ns, s.GetServiceName())
			if !ok {
				continue // belongs to a different namespace
			}
			if visibleSet != nil && !visibleSet[cleanName] {
				continue
			}
			services = append(services, map[string]any{
				"service_name":       cleanName,
				"latest_version":     s.GetLatestVersion(),
				"config_count":       s.GetConfigCount(),
				"latest_updated_at":  s.GetLatestUpdatedAt(),
				"has_active_rollout": s.GetHasActiveRollout(),
			})
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"services": services,
			"success":  resp.GetSuccess(),
		})
	}
}

// ListNamedConfigs handles GET /api/services/:serviceName/named-configs
func ListNamedConfigs(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)
		vars := mux.Vars(r)
		cleanSvcName := vars["serviceName"]
		internalSvcName := applyNS(ns, cleanSvcName)

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.ListNamedConfigs(ctx, &pb.ListNamedConfigsRequest{
			ServiceName: internalSvcName,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		summaries := make([]namedConfigSummaryResponse, 0, len(resp.GetConfigs()))
		for _, nc := range resp.GetConfigs() {
			summaries = append(summaries, toNamedConfigSummaryResp(nc, cleanSvcName))
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"configs": summaries,
			"success": resp.GetSuccess(),
		})
	}
}

// ListConfigs handles GET /api/services/:serviceName/configs/:configName/versions
func ListConfigs(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)
		vars := mux.Vars(r)
		cleanSvcName := vars["serviceName"]
		configName := vars["configName"]
		internalSvcName := applyNS(ns, cleanSvcName)

		limit := int32(20)
		offset := int32(0)
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 32); err == nil {
				limit = int32(n)
			}
		}
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 32); err == nil {
				offset = int32(n)
			}
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.ListConfigs(ctx, &pb.ListConfigsRequest{
			ServiceName: internalSvcName,
			ConfigName:  configName,
			Limit:       limit,
			Offset:      offset,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		metas := make([]configMetaResponse, 0, len(resp.GetConfigs()))
		for _, m := range resp.GetConfigs() {
			metas = append(metas, toConfigMetaResp(m, cleanSvcName))
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"configs":     metas,
			"total_count": resp.GetTotalCount(),
			"success":     resp.GetSuccess(),
		})
	}
}

// GetConfig handles GET /api/configs/:configId
func GetConfig(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)
		vars := mux.Vars(r)
		configID := vars["configId"]

		if !ownsConfigID(ns, configID) {
			writeError(w, http.StatusForbidden, "access denied")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.GetConfig(ctx, &pb.GetConfigRequest{ConfigId: configID})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		if !resp.GetSuccess() {
			writeError(w, http.StatusNotFound, resp.GetMessage())
			return
		}

		cleanSvcName, _ := stripNS(ns, resp.GetConfig().GetServiceName())
		writeJSON(w, http.StatusOK, map[string]any{
			"config":  toConfigDataResp(resp.GetConfig(), cleanSvcName),
			"success": resp.GetSuccess(),
			"message": resp.GetMessage(),
		})
	}
}

// UploadConfig handles POST /api/configs
func UploadConfig(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)
		var body struct {
			ServiceName string `json:"service_name"`
			ConfigName  string `json:"config_name"`
			Content     string `json:"content"`
			Format      string `json:"format"`
			CreatedBy   string `json:"created_by"`
			Description string `json:"description"`
			Validate    bool   `json:"validate"`
		}

		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}

		internalSvcName := applyNS(ns, body.ServiceName)
		// Use the authenticated user's ID as creator if not specified
		createdBy := body.CreatedBy
		if createdBy == "" {
			createdBy = user.Name
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.UploadConfig(ctx, &pb.UploadConfigRequest{
			ServiceName: internalSvcName,
			ConfigName:  body.ConfigName,
			Content:     body.Content,
			Format:      body.Format,
			CreatedBy:   createdBy,
			Description: body.Description,
			Validate:    body.Validate,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		status := http.StatusCreated
		if !resp.GetSuccess() {
			status = http.StatusUnprocessableEntity
		}

		writeJSON(w, status, map[string]any{
			"config_id":         resp.GetConfigId(),
			"version":           resp.GetVersion(),
			"success":           resp.GetSuccess(),
			"message":           resp.GetMessage(),
			"validation_errors": resp.GetValidationErrors(),
		})
	}
}

// DeleteConfig handles DELETE /api/configs/:configId
func DeleteConfig(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)
		vars := mux.Vars(r)
		configID := vars["configId"]

		if !ownsConfigID(ns, configID) {
			writeError(w, http.StatusForbidden, "access denied")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.DeleteConfig(ctx, &pb.DeleteConfigRequest{ConfigId: configID})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"success": resp.GetSuccess(),
			"message": resp.GetMessage(),
		})
	}
}

// GetStats handles GET /api/stats
func GetStats(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		// Super admin has no namespace — return global stats directly from gRPC.
		if ns == "" {
			resp, err := clients.API.GetStats(ctx, &pb.GetStatsRequest{})
			if err != nil {
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
			s := resp.GetStats()
			writeJSON(w, http.StatusOK, map[string]any{
				"total_configs":       s.GetTotalConfigs(),
				"active_rollouts":     s.GetActiveRollouts(),
				"total_schemas":       s.GetTotalSchemas(),
				"connected_instances": s.GetConnectedInstances(),
				"total_services":      s.GetTotalServices(),
			})
			return
		}

		// Org-scoped stats: aggregate from namespace-filtered list calls.
		var totalServices, totalConfigs, activeRollouts, totalSchemas int32

		// Services + configs
		svcResp, err := clients.API.ListServices(ctx, &pb.ListServicesRequest{})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		for _, s := range svcResp.GetServices() {
			if strings.HasPrefix(s.GetServiceName(), ns) {
				totalServices++
				totalConfigs += s.GetConfigCount()
			}
		}

		// Active rollouts
		roResp, err := clients.API.ListRollouts(ctx, &pb.ListRolloutsRequest{
			StatusFilter: "ACTIVE",
			Limit:        10000,
		})
		if err == nil {
			for _, ro := range roResp.GetRollouts() {
				if strings.HasPrefix(ro.GetConfigId(), ns) {
					activeRollouts++
				}
			}
		}

		// Schemas
		schResp, err := clients.Val.ListSchemas(ctx, &pb.ListSchemasRequest{})
		if err == nil {
			for _, s := range schResp.GetSchemas() {
				if strings.HasPrefix(s.GetServiceName(), ns) {
					totalSchemas++
				}
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"total_configs":       totalConfigs,
			"active_rollouts":     activeRollouts,
			"total_schemas":       totalSchemas,
			"connected_instances": int32(0),
			"total_services":      totalServices,
		})
	}
}

// GetAuditLog handles GET /api/audit-log
func GetAuditLog(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)

		// If a service_name query param is given, prefix it; otherwise leave empty (gRPC returns all).
		// We'll post-filter by namespace.
		serviceName := r.URL.Query().Get("service_name")
		if serviceName != "" {
			serviceName = applyNS(ns, serviceName)
		}

		limit := int32(20)
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 32); err == nil {
				limit = int32(n)
			}
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.GetAuditLog(ctx, &pb.GetAuditLogRequest{
			ServiceName: serviceName,
			Limit:       limit,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		entries := make([]map[string]any, 0, len(resp.GetEntries()))
		for _, e := range resp.GetEntries() {
			// Filter by namespace
			if ns != "" && !strings.HasPrefix(e.GetServiceName(), ns) {
				continue
			}
			cleanSvc, _ := stripNS(ns, e.GetServiceName())
			entry := map[string]any{
				"id":           e.GetId(),
				"config_id":    e.GetConfigId(),
				"action":       e.GetAction(),
				"performed_by": e.GetPerformedBy(),
				"service_name": cleanSvc,
				"details":      e.GetDetails(),
			}
			if e.GetCreatedAt() != 0 {
				entry["created_at"] = time.Unix(e.GetCreatedAt(), 0).UTC().Format(time.RFC3339)
			}
			entries = append(entries, entry)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"entries": entries,
			"success": resp.GetSuccess(),
		})
	}
}
