package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/codec404/Konfig/pkg/pb"
	grpcclient "github.com/codec404/konfig-web-backend/internal/grpc"
	"github.com/gorilla/mux"
)

// configDataResponse is the JSON shape returned for a single ConfigData.
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

// configMetaResponse is the JSON shape returned for ConfigMetadata.
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

// namedConfigSummaryResponse is the JSON shape for a NamedConfigSummary.
type namedConfigSummaryResponse struct {
	ServiceName      string `json:"service_name"`
	ConfigName       string `json:"config_name"`
	Format           string `json:"format"`
	VersionCount     int32  `json:"version_count"`
	LatestVersion    int64  `json:"latest_version"`
	LatestUpdatedAt  string `json:"latest_updated_at"`
	HasActiveRollout bool   `json:"has_active_rollout"`
}

func toConfigDataResp(c *pb.ConfigData) configDataResponse {
	return configDataResponse{
		ConfigID:    c.GetConfigId(),
		ServiceName: c.GetServiceName(),
		ConfigName:  c.GetConfigName(),
		Version:     c.GetVersion(),
		Content:     c.GetContent(),
		Format:      c.GetFormat(),
		ContentHash: c.GetContentHash(),
		CreatedAt:   time.Unix(c.GetCreatedAt(), 0).UTC().Format(time.RFC3339),
		CreatedBy:   c.GetCreatedBy(),
	}
}

func toConfigMetaResp(m *pb.ConfigMetadata) configMetaResponse {
	return configMetaResponse{
		ConfigID:    m.GetConfigId(),
		ServiceName: m.GetServiceName(),
		ConfigName:  m.GetConfigName(),
		Version:     m.GetVersion(),
		Format:      m.GetFormat(),
		CreatedAt:   time.Unix(m.GetCreatedAt(), 0).UTC().Format(time.RFC3339),
		CreatedBy:   m.GetCreatedBy(),
		Description: m.GetDescription(),
		IsActive:    m.GetIsActive(),
	}
}

func toNamedConfigSummaryResp(n *pb.NamedConfigSummary) namedConfigSummaryResponse {
	return namedConfigSummaryResponse{
		ServiceName:      n.GetServiceName(),
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

// ListNamedConfigs handles GET /api/services/:serviceName/named-configs
func ListNamedConfigs(clients *grpcclient.Clients) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		serviceName := vars["serviceName"]

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.ListNamedConfigs(ctx, &pb.ListNamedConfigsRequest{
			ServiceName: serviceName,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		summaries := make([]namedConfigSummaryResponse, 0, len(resp.GetConfigs()))
		for _, nc := range resp.GetConfigs() {
			summaries = append(summaries, toNamedConfigSummaryResp(nc))
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"configs": summaries,
			"success": resp.GetSuccess(),
		})
	}
}

// ListConfigs handles GET /api/services/:serviceName/configs/:configName/versions
func ListConfigs(clients *grpcclient.Clients) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		serviceName := vars["serviceName"]
		configName := vars["configName"]

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
			ServiceName: serviceName,
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
			metas = append(metas, toConfigMetaResp(m))
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"configs":     metas,
			"total_count": resp.GetTotalCount(),
			"success":     resp.GetSuccess(),
		})
	}
}

// GetConfig handles GET /api/configs/:configId
func GetConfig(clients *grpcclient.Clients) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		configID := vars["configId"]

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

		writeJSON(w, http.StatusOK, map[string]any{
			"config":  toConfigDataResp(resp.GetConfig()),
			"success": resp.GetSuccess(),
			"message": resp.GetMessage(),
		})
	}
}

// UploadConfig handles POST /api/configs
func UploadConfig(clients *grpcclient.Clients) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.UploadConfig(ctx, &pb.UploadConfigRequest{
			ServiceName: body.ServiceName,
			ConfigName:  body.ConfigName,
			Content:     body.Content,
			Format:      body.Format,
			CreatedBy:   body.CreatedBy,
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
func DeleteConfig(clients *grpcclient.Clients) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		configID := vars["configId"]

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
func GetStats(clients *grpcclient.Clients) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

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
	}
}

// ListServices handles GET /api/services
func ListServices(clients *grpcclient.Clients) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.ListServices(ctx, &pb.ListServicesRequest{})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		services := make([]map[string]any, 0, len(resp.GetServices()))
		for _, s := range resp.GetServices() {
			services = append(services, map[string]any{
				"service_name":       s.GetServiceName(),
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

// GetAuditLog handles GET /api/audit-log
func GetAuditLog(clients *grpcclient.Clients) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serviceName := r.URL.Query().Get("service_name")
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
			entry := map[string]any{
				"id":           e.GetId(),
				"config_id":    e.GetConfigId(),
				"action":       e.GetAction(),
				"performed_by": e.GetPerformedBy(),
				"service_name": e.GetServiceName(),
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
