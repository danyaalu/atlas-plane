package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionCookieName = "atlas_session"
const defaultBootstrapUsername = "admin"
const minBootstrapPasswordLength = 12

type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

func parseRole(raw string) (Role, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(RoleViewer):
		return RoleViewer, nil
	case string(RoleOperator):
		return RoleOperator, nil
	case string(RoleAdmin):
		return RoleAdmin, nil
	default:
		return "", fmt.Errorf("invalid role %q (expected viewer, operator, or admin)", raw)
	}
}

func (r Role) rank() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}

func (r Role) Allows(required Role) bool {
	return r.rank() >= required.rank()
}

type authUser struct {
	Username string
	Role     Role
	Secret   string
	Bcrypt   bool
}

type authSession struct {
	Username  string
	Role      Role
	ExpiresAt time.Time
}

type AuthIdentity struct {
	Username string `json:"username"`
	Role     Role   `json:"role"`
	Token    string `json:"-"`
}

type AuthManager struct {
	enabled           bool
	bootstrapRequired bool

	sessionTTL time.Duration
	storePath  string
	users      map[string]authUser
	sessions   map[string]authSession
	limiter    *loginRateLimiter

	mu    sync.Mutex
	clock func() time.Time
}

type authStorePayload struct {
	Version int             `json:"version"`
	Users   []authStoreUser `json:"users"`
}

type authStoreUser struct {
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	PasswordHash string    `json:"passwordHash"`
	CreatedAt    time.Time `json:"createdAt"`
}

type loginAttemptBucket struct {
	Count       int
	WindowStart time.Time
}

type loginRateLimiter struct {
	maxAttempts int
	window      time.Duration
	attempts    map[string]loginAttemptBucket
	mu          sync.Mutex
	clock       func() time.Time
}

func newLoginRateLimiter(maxAttempts int, window time.Duration, clock func() time.Time) *loginRateLimiter {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if window <= 0 {
		window = 15 * time.Minute
	}
	return &loginRateLimiter{
		maxAttempts: maxAttempts,
		window:      window,
		attempts:    make(map[string]loginAttemptBucket),
		clock:       clock,
	}
}

func (l *loginRateLimiter) allow(clientIP string) (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	key := strings.TrimSpace(clientIP)
	if key == "" {
		key = "unknown"
	}

	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()

	for k, bucket := range l.attempts {
		if now.Sub(bucket.WindowStart) >= l.window {
			delete(l.attempts, k)
		}
	}

	bucket := l.attempts[key]
	if bucket.WindowStart.IsZero() || now.Sub(bucket.WindowStart) >= l.window {
		bucket = loginAttemptBucket{WindowStart: now}
	}

	if bucket.Count >= l.maxAttempts {
		retryAfter := l.window - now.Sub(bucket.WindowStart)
		if retryAfter < 0 {
			retryAfter = 0
		}
		l.attempts[key] = bucket
		return false, retryAfter
	}

	bucket.Count++
	l.attempts[key] = bucket
	return true, 0
}

func (l *loginRateLimiter) reset(clientIP string) {
	if l == nil {
		return
	}
	key := strings.TrimSpace(clientIP)
	if key == "" {
		key = "unknown"
	}
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}

func newAuthManager(cfg Config) (*AuthManager, error) {
	ttl := cfg.AuthSessionTTL
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	storePath := strings.TrimSpace(cfg.AuthStorePath)
	if storePath == "" {
		storePath = ".atlas/auth/users.json"
	}
	clock := time.Now

	a := &AuthManager{
		enabled:    cfg.AuthEnabled,
		sessionTTL: ttl,
		storePath:  storePath,
		users:      make(map[string]authUser),
		sessions:   make(map[string]authSession),
		clock:      clock,
		limiter:    newLoginRateLimiter(cfg.AuthLoginMaxAttempts, cfg.AuthLoginWindow, clock),
	}
	if !cfg.AuthEnabled {
		return a, nil
	}

	if strings.TrimSpace(cfg.AuthUsers) != "" {
		users, err := parseAuthUsers(cfg.AuthUsers)
		if err != nil {
			return nil, err
		}
		if len(users) == 0 {
			return nil, fmt.Errorf("ATLAS_AUTH_USERS cannot be empty when provided")
		}
		a.users = users
		a.bootstrapRequired = false
		return a, nil
	}

	users, found, err := loadAuthUsersFromStore(storePath)
	if err != nil {
		return nil, err
	}
	if !found || len(users) == 0 {
		a.bootstrapRequired = true
		return a, nil
	}

	a.users = users
	return a, nil
}

func parseAuthUsers(raw string) (map[string]authUser, error) {
	users := make(map[string]authUser)
	for _, item := range strings.Split(raw, ";") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		parts := strings.Split(item, "|")
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid ATLAS_AUTH_USERS entry %q (expected username|role|password)", item)
		}

		username := strings.TrimSpace(parts[0])
		if username == "" {
			return nil, fmt.Errorf("invalid ATLAS_AUTH_USERS entry %q: username is required", item)
		}

		role, err := parseRole(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid ATLAS_AUTH_USERS entry %q: %w", item, err)
		}

		secret := strings.TrimSpace(parts[2])
		if secret == "" {
			return nil, fmt.Errorf("invalid ATLAS_AUTH_USERS entry %q: password is required", item)
		}

		isBcrypt := false
		if strings.HasPrefix(secret, "bcrypt:") {
			secret = strings.TrimPrefix(secret, "bcrypt:")
			isBcrypt = true
		} else if strings.HasPrefix(secret, "$2a$") || strings.HasPrefix(secret, "$2b$") || strings.HasPrefix(secret, "$2y$") {
			isBcrypt = true
		}
		if isBcrypt {
			if _, err := bcrypt.Cost([]byte(secret)); err != nil {
				return nil, fmt.Errorf("invalid bcrypt hash for user %q: %w", username, err)
			}
		}

		key := strings.ToLower(username)
		if _, exists := users[key]; exists {
			return nil, fmt.Errorf("duplicate user %q in ATLAS_AUTH_USERS", username)
		}
		users[key] = authUser{
			Username: username,
			Role:     role,
			Secret:   secret,
			Bcrypt:   isBcrypt,
		}
	}
	return users, nil
}

func (a *AuthManager) Enabled() bool {
	return a != nil && a.enabled
}

func (a *AuthManager) BootstrapRequired() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.bootstrapRequired
}

func (a *AuthManager) ConfiguredUserCount() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.users)
}

func (a *AuthManager) AllowLoginAttempt(clientIP string) (bool, time.Duration) {
	return a.limiter.allow(clientIP)
}

func (a *AuthManager) ResetLoginAttempts(clientIP string) {
	a.limiter.reset(clientIP)
}

func (a *AuthManager) Login(username, password string) (*AuthIdentity, string, error) {
	if !a.Enabled() {
		return nil, "", fmt.Errorf("authentication is disabled")
	}

	lookup := strings.ToLower(strings.TrimSpace(username))
	a.mu.Lock()
	bootstrapRequired := a.bootstrapRequired
	user, ok := a.users[lookup]
	a.mu.Unlock()
	if bootstrapRequired {
		return nil, "", fmt.Errorf("first-time bootstrap is required")
	}
	if !ok || !verifyUserSecret(user, password) {
		return nil, "", fmt.Errorf("invalid username or password")
	}

	token, err := randomSessionToken()
	if err != nil {
		return nil, "", fmt.Errorf("generate session token: %w", err)
	}

	now := a.clock()
	a.mu.Lock()
	a.cleanupExpiredLocked(now)
	a.sessions[token] = authSession{
		Username:  user.Username,
		Role:      user.Role,
		ExpiresAt: now.Add(a.sessionTTL),
	}
	a.mu.Unlock()

	return &AuthIdentity{Username: user.Username, Role: user.Role, Token: token}, token, nil
}

func (a *AuthManager) BootstrapAdmin(password string) error {
	if !a.Enabled() {
		return fmt.Errorf("authentication is disabled")
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("password is required")
	}
	if len(password) < minBootstrapPasswordLength {
		return fmt.Errorf("password must be at least %d characters", minBootstrapPasswordLength)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.bootstrapRequired {
		return fmt.Errorf("bootstrap has already been completed")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("generate password hash: %w", err)
	}

	users := map[string]authUser{
		strings.ToLower(defaultBootstrapUsername): {
			Username: defaultBootstrapUsername,
			Role:     RoleAdmin,
			Secret:   string(hash),
			Bcrypt:   true,
		},
	}
	if err := saveAuthUsersToStore(a.storePath, users, a.clock()); err != nil {
		return err
	}

	a.users = users
	a.bootstrapRequired = false
	return nil
}

func verifyUserSecret(user authUser, supplied string) bool {
	if user.Bcrypt {
		return bcrypt.CompareHashAndPassword([]byte(user.Secret), []byte(supplied)) == nil
	}
	return secureEqual(user.Secret, supplied)
}

func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func randomSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (a *AuthManager) IdentityFromRequest(r *http.Request) (*AuthIdentity, bool) {
	if !a.Enabled() {
		return &AuthIdentity{Role: RoleAdmin}, true
	}
	if a.BootstrapRequired() {
		return nil, false
	}

	token := a.TokenFromRequest(r)
	if token == "" {
		return nil, false
	}

	now := a.clock()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupExpiredLocked(now)

	session, ok := a.sessions[token]
	if !ok {
		return nil, false
	}
	if !now.Before(session.ExpiresAt) {
		delete(a.sessions, token)
		return nil, false
	}

	// Sliding session expiration.
	session.ExpiresAt = now.Add(a.sessionTTL)
	a.sessions[token] = session

	return &AuthIdentity{
		Username: session.Username,
		Role:     session.Role,
		Token:    token,
	}, true
}

func (a *AuthManager) TokenFromRequest(r *http.Request) string {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		if token := strings.TrimSpace(authz[7:]); token != "" {
			return token
		}
	}

	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(c.Value)
}

func (a *AuthManager) LogoutToken(token string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	a.mu.Lock()
	delete(a.sessions, token)
	a.mu.Unlock()
}

func (a *AuthManager) SetSessionCookie(w http.ResponseWriter, token string, secure bool) {
	maxAge := int(a.sessionTTL.Seconds())
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
		Expires:  a.clock().Add(a.sessionTTL),
	})
}

func (a *AuthManager) ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (a *AuthManager) cleanupExpiredLocked(now time.Time) {
	for token, session := range a.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(a.sessions, token)
		}
	}
}

func loadAuthUsersFromStore(path string) (map[string]authUser, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false, fmt.Errorf("auth store path is required")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read auth store: %w", err)
	}

	var payload authStorePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, false, fmt.Errorf("parse auth store: %w", err)
	}

	users := make(map[string]authUser, len(payload.Users))
	for _, record := range payload.Users {
		username := strings.TrimSpace(record.Username)
		if username == "" {
			return nil, false, fmt.Errorf("auth store contains an empty username")
		}

		role, err := parseRole(record.Role)
		if err != nil {
			return nil, false, fmt.Errorf("invalid role in auth store for user %s: %w", username, err)
		}

		hash := strings.TrimSpace(record.PasswordHash)
		if hash == "" {
			return nil, false, fmt.Errorf("missing password hash in auth store for user %s", username)
		}
		if _, err := bcrypt.Cost([]byte(hash)); err != nil {
			return nil, false, fmt.Errorf("invalid password hash in auth store for user %s: %w", username, err)
		}

		key := strings.ToLower(username)
		if _, exists := users[key]; exists {
			return nil, false, fmt.Errorf("duplicate user %s in auth store", username)
		}

		users[key] = authUser{
			Username: username,
			Role:     role,
			Secret:   hash,
			Bcrypt:   true,
		}
	}

	return users, true, nil
}

func saveAuthUsersToStore(path string, users map[string]authUser, now time.Time) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("auth store path is required")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create auth store directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("secure auth store directory permissions: %w", err)
	}

	keys := make([]string, 0, len(users))
	for key := range users {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	records := make([]authStoreUser, 0, len(users))
	for _, key := range keys {
		user := users[key]
		records = append(records, authStoreUser{
			Username:     user.Username,
			Role:         string(user.Role),
			PasswordHash: user.Secret,
			CreatedAt:    now,
		})
	}

	payload := authStorePayload{
		Version: 1,
		Users:   records,
	}
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal auth store: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0600); err != nil {
		return fmt.Errorf("write auth store: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace auth store: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("secure auth store file permissions: %w", err)
	}
	return nil
}

func requestClientIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}

	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return ip
			}
		}
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}

	host := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
		return h
	}
	if host == "" {
		return "unknown"
	}
	return host
}

type authIdentityContextKey struct{}

func withAuthIdentity(r *http.Request, identity *AuthIdentity) *http.Request {
	ctx := context.WithValue(r.Context(), authIdentityContextKey{}, identity)
	return r.WithContext(ctx)
}

func authIdentityFromContext(ctx context.Context) (*AuthIdentity, bool) {
	v := ctx.Value(authIdentityContextKey{})
	identity, ok := v.(*AuthIdentity)
	return identity, ok
}
