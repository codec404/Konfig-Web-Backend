package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/codec404/Konfig/pkg/pb"
	"github.com/codec404/konfig-web-backend/internal/auth"
	grpcclient "github.com/codec404/konfig-web-backend/internal/grpc"
	"github.com/gorilla/mux"
)

// GetLatestConfig handles GET /api/public/services/{serviceName}/configs/{configName}/latest
//
// Auth: Bearer service token (ServiceTokenMiddleware must wrap this handler).
//
// Security properties enforced here:
//   - token.ServiceName must match the {serviceName} path param — a token for
//     "portfolio" cannot read configs belonging to "billing".
//   - namespace is taken from the token itself, never from request headers —
//     the caller cannot escalate to a different org by adding X-Org-ID.
func GetLatestConfig(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := auth.ServiceTokenFromContext(r.Context())
		if token == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		vars := mux.Vars(r)
		serviceName := vars["serviceName"]
		configName := vars["configName"]

		if !validName.MatchString(serviceName) || !validName.MatchString(configName) {
			writeError(w, http.StatusBadRequest, "invalid service or config name")
			return
		}

		// Enforce token binding: the token must have been issued for this service.
		if token.ServiceName != serviceName {
			writeError(w, http.StatusForbidden, "token not valid for this service")
			return
		}

		internalSvcName := applyNS(token.Namespace, serviceName)

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		// Fetch recent versions (limit 20 is more than enough to find the active one).
		listResp, err := clients.API.ListConfigs(ctx, &pb.ListConfigsRequest{
			ServiceName: internalSvcName,
			ConfigName:  configName,
			Limit:       20,
			Offset:      0,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, "upstream service error")
			return
		}

		// Find the highest-version active config (list order may be ASC or unspecified).
		var activeID string
		var activeVersion int64
		for _, m := range listResp.GetConfigs() {
			if m.GetIsActive() && m.GetVersion() > activeVersion {
				activeID = m.GetConfigId()
				activeVersion = m.GetVersion()
			}
		}
		if activeID == "" {
			writeError(w, http.StatusNotFound, "no active config found")
			return
		}

		// Fetch full content for the active version.
		getResp, err := clients.API.GetConfig(ctx, &pb.GetConfigRequest{ConfigId: activeID})
		if err != nil {
			writeError(w, http.StatusBadGateway, "upstream service error")
			return
		}
		if !getResp.GetSuccess() {
			writeError(w, http.StatusNotFound, getResp.GetMessage())
			return
		}

		cfg := getResp.GetConfig()
		writeJSON(w, http.StatusOK, map[string]any{
			"config": toConfigDataResp(cfg, serviceName),
		})
	}
}
