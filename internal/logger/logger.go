package logger

import (
	"log"
	"sync"

	"github.com/codec404/konfig-web-backend/internal/auth"
)

var store *auth.Store

var (
	mu            sync.RWMutex
	enabledLevels = map[string]bool{
		"debug": false,
		"info":  true,
		"warn":  true,
		"error": true,
	}
)

// Init wires the logger to the database store. Call once at startup.
func Init(s *auth.Store) { store = s }

// SetLevels replaces the enabled set. info and error are always forced on.
func SetLevels(levels []string) {
	mu.Lock()
	defer mu.Unlock()
	enabledLevels = map[string]bool{"info": true, "error": true}
	for _, l := range levels {
		if l == "debug" || l == "warn" {
			enabledLevels[l] = true
		}
	}
}

// GetLevels returns the currently enabled levels in order.
func GetLevels() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := []string{}
	for _, l := range []string{"debug", "info", "warn", "error"} {
		if enabledLevels[l] {
			out = append(out, l)
		}
	}
	return out
}

// IsEnabled reports whether a given level is currently being stored.
func IsEnabled(level string) bool {
	mu.RLock()
	defer mu.RUnlock()
	return enabledLevels[level]
}

func Debug(msg string, ctx map[string]any) { emit("debug", msg, ctx) }
func Info(msg string, ctx map[string]any)  { emit("info", msg, ctx) }
func Warn(msg string, ctx map[string]any)  { emit("warn", msg, ctx) }
func Error(msg string, ctx map[string]any) { emit("error", msg, ctx) }

func emit(level, msg string, ctx map[string]any) {
	log.Printf("[%s] %s %v", level, msg, ctx)
	if store == nil || !IsEnabled(level) {
		return
	}
	go func() {
		if err := store.CreateLog("backend", level, msg, ctx); err != nil {
			log.Printf("[logger] db write failed: %v", err)
		}
	}()
}
