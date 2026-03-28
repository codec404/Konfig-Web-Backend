package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/codec404/Konfig/pkg/pb"
	"github.com/codec404/konfig-web-backend/internal/auth"
	grpcclient "github.com/codec404/konfig-web-backend/internal/grpc"
	"github.com/gorilla/mux"
)

// ValidateConfig handles POST /api/validate
func ValidateConfig(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)
		var body struct {
			ServiceName string `json:"service_name"`
			Content     string `json:"content"`
			Format      string `json:"format"`
			SchemaID    string `json:"schema_id"`
			Strict      bool   `json:"strict"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}

		internalSvcName := applyNS(ns, body.ServiceName)

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.Val.ValidateConfig(ctx, &pb.ValidateConfigRequest{
			ServiceName: internalSvcName,
			Content:     body.Content,
			Format:      body.Format,
			SchemaId:    body.SchemaID,
			Strict:      body.Strict,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		type valError struct {
			Field     string `json:"field"`
			ErrorType string `json:"error_type"`
			Message   string `json:"message"`
			Line      int32  `json:"line"`
			Column    int32  `json:"column"`
		}
		type valWarning struct {
			Field       string `json:"field"`
			WarningType string `json:"warning_type"`
			Message     string `json:"message"`
		}

		errs := make([]valError, 0, len(resp.GetErrors()))
		for _, e := range resp.GetErrors() {
			errs = append(errs, valError{
				Field:     e.GetField(),
				ErrorType: e.GetErrorType(),
				Message:   e.GetMessage(),
				Line:      e.GetLine(),
				Column:    e.GetColumn(),
			})
		}

		warns := make([]valWarning, 0, len(resp.GetWarnings()))
		for _, wn := range resp.GetWarnings() {
			warns = append(warns, valWarning{
				Field:       wn.GetField(),
				WarningType: wn.GetWarningType(),
				Message:     wn.GetMessage(),
			})
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"valid":    resp.GetValid(),
			"errors":   errs,
			"warnings": warns,
			"message":  resp.GetMessage(),
		})
	}
}

func schemaToMap(s *pb.ValidationSchema, cleanSvcName string) map[string]any {
	if s == nil {
		return nil
	}
	return map[string]any{
		"schema_id":      s.GetSchemaId(),
		"service_name":   cleanSvcName,
		"schema_type":    s.GetSchemaType(),
		"schema_content": s.GetSchemaContent(),
		"description":    s.GetDescription(),
		"created_by":     s.GetCreatedBy(),
		"created_at":     time.Unix(s.GetCreatedAt(), 0).UTC().Format(time.RFC3339),
		"is_active":      s.GetIsActive(),
	}
}

// ListSchemas handles GET /api/schemas
func ListSchemas(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)

		if !checkPerm(r, user, ns, "schemas.view", store) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}

		cleanSvcParam := r.URL.Query().Get("service_name")

		// If a filter is provided, namespace it; otherwise list all and filter below.
		internalSvcName := ""
		if cleanSvcParam != "" {
			internalSvcName = applyNS(ns, cleanSvcParam)
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.Val.ListSchemas(ctx, &pb.ListSchemasRequest{
			ServiceName: internalSvcName,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		schemas := make([]map[string]any, 0, len(resp.GetSchemas()))
		for _, s := range resp.GetSchemas() {
			if ns != "" && !strings.HasPrefix(s.GetServiceName(), ns) {
				continue
			}
			cleanSvc, _ := stripNS(ns, s.GetServiceName())
			schemas = append(schemas, schemaToMap(s, cleanSvc))
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"schemas":     schemas,
			"total_count": len(schemas),
		})
	}
}

// GetSchema handles GET /api/schemas/:schemaId
func GetSchema(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)
		vars := mux.Vars(r)
		schemaID := vars["schemaId"]

		if !checkPerm(r, user, ns, "schemas.view", store) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.Val.GetSchema(ctx, &pb.GetSchemaRequest{SchemaId: schemaID})
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		if !resp.GetSuccess() {
			writeError(w, http.StatusNotFound, resp.GetMessage())
			return
		}

		cleanSvc, _ := stripNS(ns, resp.GetSchema().GetServiceName())
		writeJSON(w, http.StatusOK, map[string]any{
			"schema":  schemaToMap(resp.GetSchema(), cleanSvc),
			"success": resp.GetSuccess(),
			"message": resp.GetMessage(),
		})
	}
}

// RegisterSchema handles POST /api/schemas
func RegisterSchema(clients *grpcclient.Clients, store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		ns := resolveNS(r, user, store)

		if !checkPerm(r, user, ns, "schemas.manage", store) {
			writeError(w, http.StatusForbidden, "permission denied")
			return
		}

		var body struct {
			ServiceName   string `json:"service_name"`
			SchemaID      string `json:"schema_id"`
			SchemaType    string `json:"schema_type"`
			SchemaContent string `json:"schema_content"`
			Description   string `json:"description"`
			CreatedBy     string `json:"created_by"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}

		internalSvcName := applyNS(ns, body.ServiceName)
		createdBy := body.CreatedBy
		if createdBy == "" {
			createdBy = user.Name
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		resp, err := clients.Val.RegisterSchema(ctx, &pb.RegisterSchemaRequest{
			SchemaId:      body.SchemaID,
			ServiceName:   internalSvcName,
			SchemaType:    body.SchemaType,
			SchemaContent: body.SchemaContent,
			Description:   body.Description,
			CreatedBy:     createdBy,
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
			"success":   resp.GetSuccess(),
			"message":   resp.GetMessage(),
			"schema_id": resp.GetSchemaId(),
		})
	}
}
