package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestNewAuthManagerBootstrapModeWhenNoUsers(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "users.json")

	manager, err := newAuthManager(Config{
		AuthEnabled:   true,
		AuthUsers:     "",
		AuthStorePath: storePath,
	})
	if err != nil {
		t.Fatalf("create auth manager: %v", err)
	}
	if !manager.BootstrapRequired() {
		t.Fatalf("expected bootstrap-required mode when no users are configured")
	}
}

func TestParseAuthUsersSupportsBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("super-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate bcrypt hash: %v", err)
	}

	users, err := parseAuthUsers("viewer|viewer|viewer-pass;admin|admin|bcrypt:" + string(hash))
	if err != nil {
		t.Fatalf("parse auth users: %v", err)
	}

	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if !users["admin"].Bcrypt {
		t.Fatalf("expected admin user to be marked as bcrypt")
	}
}

func TestAuthManagerLoginAndSession(t *testing.T) {
	manager, err := newAuthManager(Config{
		AuthEnabled:          true,
		AuthUsers:            "viewer|viewer|viewer-pass;ops|operator|ops-pass;admin|admin|admin-pass",
		AuthSessionTTL:       30 * time.Minute,
		AuthLoginMaxAttempts: 5,
		AuthLoginWindow:      15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("create auth manager: %v", err)
	}

	identity, token, err := manager.Login("ops", "ops-pass")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if identity.Role != RoleOperator {
		t.Fatalf("expected operator role, got %q", identity.Role)
	}
	if token == "" {
		t.Fatalf("expected non-empty session token")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/vms", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	got, ok := manager.IdentityFromRequest(req)
	if !ok {
		t.Fatalf("expected authenticated request")
	}
	if got.Username != "ops" || got.Role != RoleOperator {
		t.Fatalf("unexpected identity: %#v", got)
	}

	manager.LogoutToken(token)
	if _, ok := manager.IdentityFromRequest(req); ok {
		t.Fatalf("expected session to be removed after logout")
	}
}

func TestBootstrapAdminStoresHashedPasswordAndCanReload(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "users.json")
	manager, err := newAuthManager(Config{
		AuthEnabled:   true,
		AuthStorePath: storePath,
	})
	if err != nil {
		t.Fatalf("create auth manager: %v", err)
	}

	if err := manager.BootstrapAdmin("short"); err == nil {
		t.Fatalf("expected bootstrap to reject short password")
	}

	password := "very-strong-admin-password"
	if err := manager.BootstrapAdmin(password); err != nil {
		t.Fatalf("bootstrap admin: %v", err)
	}
	if manager.BootstrapRequired() {
		t.Fatalf("expected bootstrap mode to be cleared")
	}

	raw, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read auth store: %v", err)
	}
	if strings.Contains(string(raw), password) {
		t.Fatalf("auth store must not contain plaintext password")
	}

	identity, _, err := manager.Login(defaultBootstrapUsername, password)
	if err != nil {
		t.Fatalf("bootstrap login failed: %v", err)
	}
	if identity.Role != RoleAdmin {
		t.Fatalf("expected bootstrap user to be admin, got %q", identity.Role)
	}

	reloaded, err := newAuthManager(Config{
		AuthEnabled:   true,
		AuthStorePath: storePath,
	})
	if err != nil {
		t.Fatalf("reload auth manager from store: %v", err)
	}
	if reloaded.BootstrapRequired() {
		t.Fatalf("expected persisted auth store to disable bootstrap mode")
	}
	if _, _, err := reloaded.Login(defaultBootstrapUsername, password); err != nil {
		t.Fatalf("reloaded manager login failed: %v", err)
	}
}

func TestLoginRateLimiter(t *testing.T) {
	manager, err := newAuthManager(Config{
		AuthEnabled:          true,
		AuthUsers:            "admin|admin|admin-pass",
		AuthLoginMaxAttempts: 2,
		AuthLoginWindow:      10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("create auth manager: %v", err)
	}

	ok, _ := manager.AllowLoginAttempt("192.0.2.10")
	if !ok {
		t.Fatalf("first login attempt should be allowed")
	}
	ok, _ = manager.AllowLoginAttempt("192.0.2.10")
	if !ok {
		t.Fatalf("second login attempt should be allowed")
	}
	ok, retryAfter := manager.AllowLoginAttempt("192.0.2.10")
	if ok {
		t.Fatalf("third attempt should be rate-limited")
	}
	if retryAfter <= 0 {
		t.Fatalf("expected retry-after duration to be positive")
	}

	manager.ResetLoginAttempts("192.0.2.10")
	ok, _ = manager.AllowLoginAttempt("192.0.2.10")
	if !ok {
		t.Fatalf("attempt should be allowed after limiter reset")
	}
}

func TestWithRoleEnforcesPermissions(t *testing.T) {
	manager, err := newAuthManager(Config{
		AuthEnabled: true,
		AuthUsers:   "viewer|viewer|viewer-pass;ops|operator|ops-pass;admin|admin|admin-pass",
	})
	if err != nil {
		t.Fatalf("create auth manager: %v", err)
	}

	_, operatorToken, err := manager.Login("ops", "ops-pass")
	if err != nil {
		t.Fatalf("operator login failed: %v", err)
	}
	_, adminToken, err := manager.Login("admin", "admin-pass")
	if err != nil {
		t.Fatalf("admin login failed: %v", err)
	}

	ws := &WebServer{auth: manager}
	handler := ws.withRole(RoleAdmin, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	unauthReq := httptest.NewRequest(http.MethodDelete, "/api/vms/500", nil)
	unauthRec := httptest.NewRecorder()
	handler(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated request, got %d", unauthRec.Code)
	}

	operatorReq := httptest.NewRequest(http.MethodDelete, "/api/vms/500", nil)
	operatorReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: operatorToken})
	operatorRec := httptest.NewRecorder()
	handler(operatorRec, operatorReq)
	if operatorRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for operator role, got %d", operatorRec.Code)
	}

	adminReq := httptest.NewRequest(http.MethodDelete, "/api/vms/500", nil)
	adminReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: adminToken})
	adminRec := httptest.NewRecorder()
	handler(adminRec, adminReq)
	if adminRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for admin role, got %d", adminRec.Code)
	}
}
