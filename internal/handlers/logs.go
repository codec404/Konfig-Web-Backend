package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/codec404/konfig-web-backend/internal/auth"
	applogger "github.com/codec404/konfig-web-backend/internal/logger"
)

// IngestFrontendLogs accepts a batch of log entries from the frontend.
// POST /api/logs
func IngestFrontendLogs(store *auth.Store) http.HandlerFunc {
	type entry struct {
		Level     string         `json:"level"`
		Message   string         `json:"message"`
		Context   map[string]any `json:"context"`
		Timestamp string         `json:"timestamp"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var entries []entry
		if err := json.NewDecoder(r.Body).Decode(&entries); err != nil {
			writeError(w, http.StatusBadRequest, "invalid body")
			return
		}
		for _, e := range entries {
			level := e.Level
			if level == "" {
				level = "info"
			}
			if !applogger.IsEnabled(level) {
				continue
			}
			ctx := e.Context
			if ctx == nil {
				ctx = map[string]any{}
			}
			if e.Timestamp != "" {
				ctx["client_time"] = e.Timestamp
			}
			go store.CreateLog("frontend", level, e.Message, ctx)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListLogs returns paginated logs for the super-admin dashboard.
// GET /api/admin/logs?source=&level=&from=&to=&limit=&offset=
func ListLogs(store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		f := auth.LogFilter{
			Source: q.Get("source"),
			Level:  q.Get("level"),
			Limit:  100,
			Offset: 0,
		}

		if v := q.Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
				f.Limit = n
			}
		}
		if v := q.Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				f.Offset = n
			}
		}
		if v := q.Get("from"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.From = t
			}
		}
		if v := q.Get("to"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				f.To = t
			}
		}

		logs, total, err := store.ListLogs(f)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if logs == nil {
			logs = []auth.AppLog{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"logs": logs, "total": total})
	}
}

// GetLogSettings returns the currently enabled log levels.
// GET /api/admin/logs/settings
func GetLogSettings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"levels": applogger.GetLevels()})
	}
}

// SetLogSettings updates which log levels are stored.
// info and error are always forced on by the logger regardless of input.
// PUT /api/admin/logs/settings
func SetLogSettings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Levels []string `json:"levels"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid body")
			return
		}
		applogger.SetLevels(body.Levels)
		writeJSON(w, http.StatusOK, map[string]any{"levels": applogger.GetLevels()})
	}
}
