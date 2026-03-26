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

func parseStrategy(s string) pb.RolloutStrategy {
	switch s {
	case "CANARY":
		return pb.RolloutStrategy_CANARY
	case "PERCENTAGE":
		return pb.RolloutStrategy_PERCENTAGE
	default:
		return pb.RolloutStrategy_ALL_AT_ONCE
	}
}

func rolloutStatusString(s pb.RolloutStatus) string {
	switch s {
	case pb.RolloutStatus_PENDING:
		return "PENDING"
	case pb.RolloutStatus_IN_PROGRESS:
		return "IN_PROGRESS"
	case pb.RolloutStatus_COMPLETED:
		return "COMPLETED"
	case pb.RolloutStatus_FAILED:
		return "FAILED"
	case pb.RolloutStatus_ROLLED_BACK:
		return "ROLLED_BACK"
	default:
		return "UNKNOWN"
	}
}

func rolloutStrategyString(s pb.RolloutStrategy) string {
	switch s {
	case pb.RolloutStrategy_CANARY:
		return "CANARY"
	case pb.RolloutStrategy_PERCENTAGE:
		return "PERCENTAGE"
	default:
		return "ALL_AT_ONCE"
	}
}

func rolloutStateToMap(rs *pb.RolloutState) map[string]any {
	if rs == nil {
		return nil
	}
	m := map[string]any{
		"config_id":          rs.GetConfigId(),
		"strategy":           rolloutStrategyString(rs.GetStrategy()),
		"target_percentage":  rs.GetTargetPercentage(),
		"current_percentage": rs.GetCurrentPercentage(),
		"status":             rolloutStatusString(rs.GetStatus()),
	}
	if rs.GetStartedAt() != 0 {
		m["started_at"] = time.Unix(rs.GetStartedAt(), 0).UTC().Format(time.RFC3339)
	}
	if rs.GetCompletedAt() != 0 {
		m["completed_at"] = time.Unix(rs.GetCompletedAt(), 0).UTC().Format(time.RFC3339)
	}
	return m
}

func serviceInstanceToMap(si *pb.ServiceInstance) map[string]any {
	if si == nil {
		return nil
	}
	m := map[string]any{
		"service_name":           si.GetServiceName(),
		"instance_id":            si.GetInstanceId(),
		"current_config_version": si.GetCurrentConfigVersion(),
		"status":                 si.GetStatus(),
	}
	if si.GetLastHeartbeat() != 0 {
		m["last_heartbeat"] = time.Unix(si.GetLastHeartbeat(), 0).UTC().Format(time.RFC3339)
	}
	if len(si.GetMetadata()) > 0 {
		m["metadata"] = si.GetMetadata()
	}
	return m
}

// StartRollout handles POST /api/rollouts
func StartRollout(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)
		var body struct {
			ConfigID         string `json:"config_id"`
			Strategy         string `json:"strategy"`
			TargetPercentage int32  `json:"target_percentage"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		if !ownsConfigID(ns, body.ConfigID) {
			writeError(w, http.StatusForbidden, "access denied")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.StartRollout(ctx, &pb.StartRolloutRequest{
			ConfigId:         body.ConfigID,
			Strategy:         parseStrategy(body.Strategy),
			TargetPercentage: body.TargetPercentage,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"success":    resp.GetSuccess(),
			"message":    resp.GetMessage(),
			"rollout_id": resp.GetRolloutId(),
		})
	}
}

// GetRolloutStatus handles GET /api/rollouts/:configId/status
func GetRolloutStatus(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
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

		resp, err := clients.API.GetRolloutStatus(ctx, &pb.GetRolloutStatusRequest{
			ConfigId: configID,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		instances := make([]map[string]any, 0, len(resp.GetInstances()))
		for _, inst := range resp.GetInstances() {
			instances = append(instances, serviceInstanceToMap(inst))
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"rollout_state": rolloutStateToMap(resp.GetRolloutState()),
			"instances":     instances,
			"success":       resp.GetSuccess(),
		})
	}
}

// Rollback handles POST /api/rollbacks
func Rollback(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)
		var body struct {
			ServiceName string `json:"service_name"`
			ConfigName  string `json:"config_name"`
			ToVersion   int64  `json:"to_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.Rollback(ctx, &pb.RollbackRequest{
			ServiceName:   applyNS(ns, body.ServiceName),
			ConfigName:    body.ConfigName,
			TargetVersion: body.ToVersion,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"success":   resp.GetSuccess(),
			"message":   resp.GetMessage(),
			"config_id": resp.GetConfigId(),
		})
	}
}

// PromoteRollout handles POST /api/rollouts/:configId/promote
func PromoteRollout(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)
		vars := mux.Vars(r)
		configID := vars["configId"]

		if !ownsConfigID(ns, configID) {
			writeError(w, http.StatusForbidden, "access denied")
			return
		}

		var body struct {
			NewTargetPercentage int32 `json:"new_target_percentage"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.PromoteRollout(ctx, &pb.PromoteRolloutRequest{
			ConfigId:            configID,
			NewTargetPercentage: body.NewTargetPercentage,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"success":       resp.GetSuccess(),
			"message":       resp.GetMessage(),
			"rollout_state": rolloutStateToMap(resp.GetRolloutState()),
		})
	}
}

// ListRollouts handles GET /api/rollouts?status_filter=ACTIVE&limit=50
func ListRollouts(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)
		statusFilter := r.URL.Query().Get("status_filter")
		limit := int32(50)
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 32); err == nil {
				limit = int32(n)
			}
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.API.ListRollouts(ctx, &pb.ListRolloutsRequest{
			StatusFilter: statusFilter,
			Limit:        limit,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		rollouts := make([]map[string]any, 0)
		for _, ro := range resp.GetRollouts() {
			if ns != "" && !strings.HasPrefix(ro.GetConfigId(), ns) {
				continue
			}
			cleanSvc, _ := stripNS(ns, ro.GetServiceName())
			rollouts = append(rollouts, map[string]any{
				"config_id":          ro.GetConfigId(),
				"service_name":       cleanSvc,
				"strategy":           ro.GetStrategy(),
				"target_percentage":  ro.GetTargetPercentage(),
				"current_percentage": ro.GetCurrentPercentage(),
				"status":             ro.GetStatus(),
				"started_at":         ro.GetStartedAt(),
				"completed_at":       ro.GetCompletedAt(),
			})
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"rollouts": rollouts,
			"success":  resp.GetSuccess(),
		})
	}
}
