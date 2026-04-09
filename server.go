package main

import (
	"bufio"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

//go:embed web/index.html
var indexHTML []byte

//go:embed setup.sh
var setupSh []byte

//go:embed setup.ps1
var setupPs1 []byte

// ════════════════════════════════════════════════════════════════════════════
// Provision Event — shared between CLI and Web modes
// ════════════════════════════════════════════════════════════════════════════

// ProvisionEvent represents a single step update during VM provisioning.
type ProvisionEvent struct {
	VMID    int    `json:"vmid"`
	VMName  string `json:"name"`
	Step    string `json:"step"`
	Message string `json:"message"`
	IP      string `json:"ip,omitempty"`
	KeyFile string `json:"keyFile,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ════════════════════════════════════════════════════════════════════════════
// Job Tracking
// ════════════════════════════════════════════════════════════════════════════

// Job tracks a single provisioning run (which may include multiple VMs).
type Job struct {
	ID        string           `json:"id"`
	Status    string           `json:"status"` // running, completed, failed
	StartedAt time.Time        `json:"startedAt"`
	Specs     []VMSpec         `json:"specs"`
	Results   []VMResult       `json:"-"`
	Events    []ProvisionEvent `json:"events"`

	mu        sync.Mutex
	listeners []chan ProvisionEvent
	done      chan struct{}
}

// ProvisionParams are the per-job overrides sent by the web UI.
type ProvisionParams struct {
	VMCount    int    `json:"vmCount"`
	VMName     string `json:"vmName"`
	TemplateID int    `json:"templateId"`
	Template   string `json:"templateName"`
	Cores      int    `json:"cores"`
	Memory     int    `json:"memory"`
	DiskSize   string `json:"diskSize"`
	DiskDevice string `json:"diskDevice"`
	User       string `json:"user"`
	VMStartID  int    `json:"vmStartId"`
	Node       string `json:"node"`
}

type preflightRequest struct {
	VMCount    int    `json:"vmCount"`
	VMStartID  int    `json:"vmStartId"`
	TemplateID int    `json:"templateId"`
	Template   string `json:"templateName"`
	Node       string `json:"node"`
}

type preflightCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // pass, fail
	Message string `json:"message"`
}

// VMResultJSON is the JSON-safe view of VMResult for API responses.
type VMResultJSON struct {
	VMID    int    `json:"vmid"`
	Name    string `json:"name"`
	IP      string `json:"ip,omitempty"`
	KeyFile string `json:"keyFile,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ════════════════════════════════════════════════════════════════════════════
// Template Source of Truth
// ════════════════════════════════════════════════════════════════════════════

const defaultTemplateName = "debian12-cloud"
const templateSoTFile = "atlas-template-sot.json"

type TemplateNodeState struct {
	Node        string    `json:"node"`
	VMID        int       `json:"vmid,omitempty"`
	StorageID   string    `json:"storageId,omitempty"`
	VolumeID    string    `json:"volumeId,omitempty"`
	Status      string    `json:"status"`
	Reachable   bool      `json:"reachable"`
	LastMessage string    `json:"lastMessage,omitempty"`
	LastError   string    `json:"lastError,omitempty"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type TemplateState struct {
	Name       string                        `json:"name"`
	NodeStates map[string]*TemplateNodeState `json:"-"`
}

type TemplateLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Template  string    `json:"template"`
	Node      string    `json:"node"`
	Stage     string    `json:"stage"`
	Message   string    `json:"message"`
}

type templateStorageAssignRequest struct {
	StorageID string `json:"storageId"`
}

type templateBuildRequest struct {
	Node  string `json:"node"`
	VMID  int    `json:"vmid"`
	Image string `json:"image"`
}

// ════════════════════════════════════════════════════════════════════════════
// Web Server
// ════════════════════════════════════════════════════════════════════════════

// WebServer holds the shared state for the HTTP handlers.
type WebServer struct {
	cfg      Config
	pve      *ProxmoxClient
	pveHost  string
	keyVault *SSHKeyVault
	auth     *AuthManager

	mu   sync.Mutex
	jobs map[string]*Job

	templateMu      sync.Mutex
	templates       map[string]*TemplateState
	templateLogs    map[string][]TemplateLogEntry
	activeTplBuilds map[string]bool
	templateSoTPath string
}

func startWebServer(cfg Config, port string) {
	pve := newProxmoxClient(cfg)
	pveHost, err := proxmoxHost(cfg.ProxmoxURL)
	if err != nil {
		fatalf("Cannot determine Proxmox host: %v", err)
	}
	auth, err := newAuthManager(cfg)
	if err != nil {
		fatalf("Authentication configuration is invalid: %v", err)
	}

	ws := &WebServer{
		cfg:      cfg,
		pve:      pve,
		pveHost:  pveHost,
		keyVault: sshKeyVault,
		auth:     auth,
		jobs:     make(map[string]*Job),
		templates: map[string]*TemplateState{
			defaultTemplateName: {
				Name:       defaultTemplateName,
				NodeStates: make(map[string]*TemplateNodeState),
			},
		},
		templateLogs:    make(map[string][]TemplateLogEntry),
		activeTplBuilds: make(map[string]bool),
		templateSoTPath: templateSoTFile,
	}

	if err := ws.loadTemplateSoT(); err != nil {
		fmt.Printf("WARN: unable to load template source of truth: %v\n", err)
	}

	mux := http.NewServeMux()

	// Frontend
	mux.HandleFunc("GET /", ws.handleIndex)

	// API — Authentication
	mux.HandleFunc("GET /api/auth/me", ws.handleAuthMe)
	mux.HandleFunc("POST /api/auth/bootstrap", ws.handleAuthBootstrap)
	mux.HandleFunc("POST /api/auth/login", ws.handleAuthLogin)
	mux.HandleFunc("POST /api/auth/logout", ws.handleAuthLogout)

	// API — Config
	mux.HandleFunc("GET /api/config", ws.withRole(RoleViewer, ws.handleGetConfig))

	// API — Nodes
	mux.HandleFunc("GET /api/nodes", ws.withRole(RoleViewer, ws.handleListNodes))

	// API — VMs
	mux.HandleFunc("GET /api/vms", ws.withRole(RoleViewer, ws.handleListVMs))
	mux.HandleFunc("GET /api/vms/{id}/ssh-connect", ws.withRole(RoleOperator, ws.handleVMSSHConnect))
	mux.HandleFunc("POST /api/vms/{id}/start", ws.withRole(RoleOperator, ws.handleStartVM))
	mux.HandleFunc("POST /api/vms/{id}/stop", ws.withRole(RoleOperator, ws.handleStopVM))
	mux.HandleFunc("POST /api/vms/{id}/restart", ws.withRole(RoleOperator, ws.handleRestartVM))
	mux.HandleFunc("DELETE /api/vms/{id}", ws.withRole(RoleAdmin, ws.handleDeleteVM))

	// API — Keys (download provisioned SSH keys)
	mux.HandleFunc("GET /api/keys/{filename}", ws.withRole(RoleOperator, ws.handleDownloadKey))
	mux.HandleFunc("GET /api/vms/{id}/ssh-key", ws.withRole(RoleOperator, ws.handleDownloadVMKey))
	// Setup scripts must remain public so post-deploy one-liners work outside authenticated UI sessions.
	mux.HandleFunc("GET /api/setup.sh", ws.handleSetupSh)
	mux.HandleFunc("GET /api/setup.ps1", ws.handleSetupPs1)

	// API — Provisioning
	mux.HandleFunc("POST /api/preflight", ws.withRole(RoleOperator, ws.handlePreflight))
	mux.HandleFunc("POST /api/provision", ws.withRole(RoleOperator, ws.handleProvision))
	mux.HandleFunc("GET /api/jobs", ws.withRole(RoleViewer, ws.handleListJobs))
	mux.HandleFunc("GET /api/jobs/{id}/events", ws.withRole(RoleViewer, ws.handleJobEvents))

	// API — Template Management
	mux.HandleFunc("GET /api/templates/state", ws.withRole(RoleViewer, ws.handleTemplateState))
	mux.HandleFunc("POST /api/templates/{name}/nodes/{node}/storage", ws.withRole(RoleAdmin, ws.handleAssignTemplateStorage))
	mux.HandleFunc("POST /api/templates/{name}/build", ws.withRole(RoleAdmin, ws.handleBuildTemplate))
	mux.HandleFunc("GET /api/templates/logs/{node}", ws.withRole(RoleViewer, ws.handleTemplateNodeLogs))

	fmt.Printf("\n✦  Atlas Plane — Web UI\n")
	fmt.Printf("   http://localhost:%s\n", port)
	fmt.Printf("   Proxmox: %s (node: %s)\n\n", cfg.ProxmoxURL, cfg.Node)
	if auth.Enabled() {
		if auth.BootstrapRequired() {
			fmt.Printf("   Auth: enabled (bootstrap required)\n\n")
		} else {
			fmt.Printf("   Auth: enabled (%d configured users)\n\n", auth.ConfiguredUserCount())
		}
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // SSE needs unlimited write timeout
		IdleTimeout:  120 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		fatalf("Web server failed: %v", err)
	}
}

// ── Handlers ─────────────────────────────────────────────────────────────

func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func (ws *WebServer) withRole(required Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ws.auth == nil || !ws.auth.Enabled() {
			next(w, r)
			return
		}

		identity, ok := ws.auth.IdentityFromRequest(r)
		if !ok {
			jsonError(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if !identity.Role.Allows(required) {
			jsonError(w, "insufficient permissions", http.StatusForbidden)
			return
		}

		next(w, withAuthIdentity(r, identity))
	}
}

type authLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authBootstrapRequest struct {
	Password string `json:"password"`
}

func (ws *WebServer) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if ws.auth == nil || !ws.auth.Enabled() {
		jsonOK(w, map[string]interface{}{
			"enabled":           false,
			"authenticated":     true,
			"bootstrapRequired": false,
			"role":              string(RoleAdmin),
		})
		return
	}
	if ws.auth.BootstrapRequired() {
		jsonOK(w, map[string]interface{}{
			"enabled":           true,
			"authenticated":     false,
			"bootstrapRequired": true,
			"username":          defaultBootstrapUsername,
		})
		return
	}

	identity, ok := ws.auth.IdentityFromRequest(r)
	if !ok {
		jsonOK(w, map[string]interface{}{
			"enabled":           true,
			"authenticated":     false,
			"bootstrapRequired": false,
		})
		return
	}

	jsonOK(w, map[string]interface{}{
		"enabled":           true,
		"authenticated":     true,
		"bootstrapRequired": false,
		"username":          identity.Username,
		"role":              string(identity.Role),
	})
}

func (ws *WebServer) handleAuthBootstrap(w http.ResponseWriter, r *http.Request) {
	if ws.auth == nil || !ws.auth.Enabled() {
		jsonError(w, "authentication is disabled", http.StatusBadRequest)
		return
	}
	if !ws.auth.BootstrapRequired() {
		jsonError(w, "bootstrap has already been completed", http.StatusConflict)
		return
	}

	var req authBootstrapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := ws.auth.BootstrapAdmin(req.Password); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	identity, token, err := ws.auth.Login(defaultBootstrapUsername, req.Password)
	if err != nil {
		jsonError(w, "bootstrap succeeded, but login failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	clientIP := requestClientIP(r)
	ws.auth.ResetLoginAttempts(clientIP)
	ws.auth.SetSessionCookie(w, token, r.TLS != nil)
	jsonOK(w, map[string]interface{}{
		"authenticated":     true,
		"bootstrapRequired": false,
		"username":          identity.Username,
		"role":              string(identity.Role),
	})
}

func (ws *WebServer) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if ws.auth == nil || !ws.auth.Enabled() {
		jsonError(w, "authentication is disabled", http.StatusBadRequest)
		return
	}
	if ws.auth.BootstrapRequired() {
		jsonError(w, "first-time bootstrap is required before login", http.StatusConflict)
		return
	}

	var req authLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	clientIP := requestClientIP(r)
	allowed, retryAfter := ws.auth.AllowLoginAttempt(clientIP)
	if !allowed {
		retrySeconds := int(retryAfter.Seconds())
		if retrySeconds < 1 {
			retrySeconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
		jsonError(w, "too many login attempts, please try again later", http.StatusTooManyRequests)
		return
	}

	identity, token, err := ws.auth.Login(req.Username, req.Password)
	if err != nil {
		jsonError(w, "invalid username or password", http.StatusUnauthorized)
		return
	}

	ws.auth.ResetLoginAttempts(clientIP)
	ws.auth.SetSessionCookie(w, token, r.TLS != nil)
	jsonOK(w, map[string]interface{}{
		"authenticated": true,
		"username":      identity.Username,
		"role":          string(identity.Role),
	})
}

func (ws *WebServer) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if ws.auth != nil && ws.auth.Enabled() {
		if token := ws.auth.TokenFromRequest(r); token != "" {
			ws.auth.LogoutToken(token)
		}
		ws.auth.ClearSessionCookie(w, r.TLS != nil)
	}

	jsonOK(w, map[string]string{"status": "logged_out"})
}

func (ws *WebServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"proxmoxUrl":   ws.cfg.ProxmoxURL,
		"node":         ws.cfg.Node,
		"sshBridgeUrl": ws.cfg.SSHBridgeURL,
		"templateId":   ws.cfg.TemplateID,
		"cores":        ws.cfg.Cores,
		"memory":       ws.cfg.Memory,
		"diskSize":     ws.cfg.DiskSize,
		"diskDevice":   ws.cfg.DiskDevice,
		"user":         ws.cfg.User,
		"vmStartId":    ws.cfg.VMStartID,
	})
}

func (ws *WebServer) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := ws.pve.listNodes()
	if err != nil {
		jsonError(w, "failed to list nodes: "+err.Error(), 500)
		return
	}
	jsonOK(w, nodes)
}

func (ws *WebServer) handleListVMs(w http.ResponseWriter, r *http.Request) {
	vms, err := ws.pve.listVMs()
	if err != nil {
		jsonError(w, "failed to list VMs: "+err.Error(), 500)
		return
	}

	if ws.keyVault != nil {
		for _, vm := range vms {
			rawVMID, ok := vm["vmid"].(float64)
			if !ok {
				continue
			}
			vmid := int(rawVMID)
			hasKey := ws.keyVault.HasKeyForVM(vmid)
			vm["hasSshKey"] = hasKey
			if hasKey {
				if keyName := ws.keyVault.KeyFileNameForVM(vmid); keyName != "" {
					vm["sshKeyFile"] = keyName
				}
			}
		}
	}

	jsonOK(w, vms)
}

func (ws *WebServer) handleStartVM(w http.ResponseWriter, r *http.Request) {
	vmid, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		jsonError(w, "invalid VMID", 400)
		return
	}
	node, err := ws.pve.resolveVMNode(vmid)
	if err != nil {
		jsonError(w, err.Error(), 404)
		return
	}
	if err := ws.pve.startVMOnNode(node, vmid); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	jsonOK(w, map[string]string{"status": "started"})
}

func (ws *WebServer) handleVMSSHConnect(w http.ResponseWriter, r *http.Request) {
	if ws.keyVault == nil {
		jsonError(w, "key vault is not initialized", 500)
		return
	}

	vmid, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || vmid <= 0 {
		jsonError(w, "invalid VMID", 400)
		return
	}

	if !ws.keyVault.HasKeyForVM(vmid) {
		jsonError(w, "key not found for VM", 404)
		return
	}

	node, err := ws.pve.resolveVMNode(vmid)
	if err != nil {
		jsonError(w, err.Error(), 404)
		return
	}

	vms, err := ws.pve.listVMs()
	if err != nil {
		jsonError(w, "failed to list VMs: "+err.Error(), 500)
		return
	}

	vmName := fmt.Sprintf("vm-%d", vmid)
	status := "unknown"
	for _, vm := range vms {
		rawVMID, ok := vm["vmid"].(float64)
		if !ok || int(rawVMID) != vmid {
			continue
		}
		if name, ok := vm["name"].(string); ok && strings.TrimSpace(name) != "" {
			vmName = name
		}
		if vmStatus, ok := vm["status"].(string); ok {
			status = vmStatus
		}
		break
	}

	if status != "running" {
		jsonError(w, "vm must be running to connect", 409)
		return
	}

	path := fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/agent/network-get-interfaces", node, vmid)
	ipData, err := ws.pve.get(path)
	if err != nil {
		jsonError(w, "failed to query VM network interfaces: "+err.Error(), 502)
		return
	}

	host := extractIPv4(ipData)
	if strings.TrimSpace(host) == "" {
		jsonError(w, "no IPv4 address reported by guest agent", 409)
		return
	}

	jsonOK(w, map[string]interface{}{
		"vmid":       vmid,
		"vmName":     vmName,
		"node":       node,
		"status":     status,
		"host":       host,
		"user":       ws.cfg.User,
		"sshKeyFile": ws.keyVault.KeyFileNameForVM(vmid),
	})
}

func (ws *WebServer) handleStopVM(w http.ResponseWriter, r *http.Request) {
	vmid, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		jsonError(w, "invalid VMID", 400)
		return
	}
	node, err := ws.pve.resolveVMNode(vmid)
	if err != nil {
		jsonError(w, err.Error(), 404)
		return
	}
	if err := ws.pve.stopVMOnNode(node, vmid); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	jsonOK(w, map[string]string{"status": "stopped"})
}

func (ws *WebServer) handleRestartVM(w http.ResponseWriter, r *http.Request) {
	vmid, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		jsonError(w, "invalid VMID", 400)
		return
	}
	node, err := ws.pve.resolveVMNode(vmid)
	if err != nil {
		jsonError(w, err.Error(), 404)
		return
	}
	if err := ws.pve.rebootVMOnNode(node, vmid); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	jsonOK(w, map[string]string{"status": "restarting"})
}

func (ws *WebServer) handleDeleteVM(w http.ResponseWriter, r *http.Request) {
	vmid, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		jsonError(w, "invalid VMID", 400)
		return
	}
	node, err := ws.pve.resolveVMNode(vmid)
	if err != nil {
		jsonError(w, err.Error(), 404)
		return
	}
	if err := ws.pve.deleteVMOnNode(node, vmid); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	jsonOK(w, map[string]string{"status": "deleted"})
}

// ── Key Download ─────────────────────────────────────────────────────────

func (ws *WebServer) handleDownloadKey(w http.ResponseWriter, r *http.Request) {
	if ws.keyVault == nil {
		jsonError(w, "key vault is not initialized", 500)
		return
	}

	filename := strings.TrimSpace(r.PathValue("filename"))
	if filename == "" || strings.Contains(filename, "/") || strings.Contains(filename, `\\`) {
		jsonError(w, "invalid filename", 400)
		return
	}

	name, data, err := ws.keyVault.GetPrivateKeyByFilename(filename)
	if err != nil {
		if os.IsNotExist(err) {
			jsonError(w, "key not found", 404)
			return
		}
		jsonError(w, "failed to read key", 500)
		return
	}

	ws.writeKeyDownload(w, name, data)
}

func (ws *WebServer) handleDownloadVMKey(w http.ResponseWriter, r *http.Request) {
	if ws.keyVault == nil {
		jsonError(w, "key vault is not initialized", 500)
		return
	}

	vmid, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || vmid <= 0 {
		jsonError(w, "invalid VMID", 400)
		return
	}

	name, data, err := ws.keyVault.GetPrivateKeyByVMID(vmid)
	if err != nil {
		if os.IsNotExist(err) {
			jsonError(w, "key not found for VM", 404)
			return
		}
		jsonError(w, "failed to read key", 500)
		return
	}

	ws.writeKeyDownload(w, name, data)
}

func (ws *WebServer) writeKeyDownload(w http.ResponseWriter, filename string, data []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (ws *WebServer) handleSetupSh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(setupSh)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(setupSh)
}

func (ws *WebServer) handleSetupPs1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(setupPs1)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(setupPs1)
}

func (ws *WebServer) handlePreflight(w http.ResponseWriter, r *http.Request) {
	var req preflightRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	cfg := ws.cfg
	if req.VMCount > 0 {
		cfg.VMCount = req.VMCount
	}
	if req.VMStartID > 0 {
		cfg.VMStartID = req.VMStartID
	}
	if strings.TrimSpace(req.Node) != "" {
		cfg.Node = strings.TrimSpace(req.Node)
	}

	resolvedTemplateID := cfg.TemplateID
	var templateResolveErr error
	if strings.TrimSpace(req.Template) != "" {
		templateVMID, err := ws.templateVMIDForNode(strings.TrimSpace(req.Template), cfg.Node)
		if err != nil {
			resolvedTemplateID = 0
			templateResolveErr = err
		} else {
			resolvedTemplateID = templateVMID
		}
	} else if req.TemplateID > 0 {
		resolvedTemplateID = req.TemplateID
	}

	checks := make([]preflightCheck, 0, 10)
	ready := true
	addPass := func(name, msg string) {
		checks = append(checks, preflightCheck{Name: name, Status: "pass", Message: msg})
	}
	addFail := func(name string, err error) {
		ready = false
		msg := "check failed"
		if err != nil {
			msg = err.Error()
		}
		checks = append(checks, preflightCheck{Name: name, Status: "fail", Message: msg})
	}

	nodes, err := ws.pve.listNodes()
	if err != nil {
		addFail("proxmox_api", fmt.Errorf("proxmox API is unreachable: %w", err))
	} else {
		addPass("proxmox_api", "Proxmox API is reachable")
	}

	nodeReachable := false
	if err == nil {
		found := false
		for _, node := range nodes {
			name, _ := node["node"].(string)
			if strings.TrimSpace(name) != cfg.Node {
				continue
			}
			found = true
			if status, _ := node["status"].(string); status == "online" {
				nodeReachable = true
				addPass("target_node", fmt.Sprintf("Node %s is online", cfg.Node))
			} else {
				addFail("target_node", fmt.Errorf("node %s is not online", cfg.Node))
			}
			break
		}
		if !found {
			addFail("target_node", fmt.Errorf("node %s was not found in cluster nodes", cfg.Node))
		}
	}

	if resolvedTemplateID > 0 {
		addPass("template", fmt.Sprintf("Template VMID resolved to %d", resolvedTemplateID))
	} else {
		if templateResolveErr != nil {
			addFail("template", fmt.Errorf("template resolution failed: %w", templateResolveErr))
		} else {
			addFail("template", fmt.Errorf("template could not be resolved for node %s", cfg.Node))
		}
	}

	if nodeReachable {
		storages, storageErr := ws.pve.listNodeStorages(cfg.Node)
		if storageErr != nil {
			addFail("snippet_storage", fmt.Errorf("failed to list storages for node %s: %w", cfg.Node, storageErr))
		} else {
			foundStorage := false
			snippetsEnabled := false
			for _, st := range storages {
				id, _ := st["storage"].(string)
				if id != cfg.SnippetStore {
					continue
				}
				foundStorage = true
				content := strings.ToLower(fmt.Sprint(st["content"]))
				snippetsEnabled = strings.Contains(content, "snippets")
				break
			}
			if !foundStorage {
				addFail("snippet_storage", fmt.Errorf("storage %s is not visible on node %s", cfg.SnippetStore, cfg.Node))
			} else if !snippetsEnabled {
				addFail("snippet_storage", fmt.Errorf("storage %s does not expose snippets content", cfg.SnippetStore))
			} else {
				addPass("snippet_storage", fmt.Sprintf("Storage %s supports snippets", cfg.SnippetStore))
			}
		}

		host := ws.sshHostForNode(cfg.Node)
		checkDirCmd := fmt.Sprintf("test -d %s && test -w %s", shellQuote(cfg.SnippetDir), shellQuote(cfg.SnippetDir))
		if sshErr := ws.execSSHCommand(host, checkDirCmd, nil); sshErr != nil {
			addFail("snippet_dir_access", fmt.Errorf("cannot access snippet directory %s over SSH: %w", cfg.SnippetDir, sshErr))
		} else {
			addPass("snippet_dir_access", fmt.Sprintf("SSH can access writable snippet directory %s", cfg.SnippetDir))
		}
	}

	if _, caErr := os.ReadFile(cfg.CAKeyPath); caErr != nil {
		addFail("ca_key", fmt.Errorf("cannot read CA key %s: %w", cfg.CAKeyPath, caErr))
	} else {
		addPass("ca_key", fmt.Sprintf("CA key is readable at %s", cfg.CAKeyPath))
	}

	if ws.keyVault == nil {
		addFail("key_vault", fmt.Errorf("key vault is not initialized"))
	} else {
		addPass("key_vault", "encrypted key vault is initialized")
	}

	if cfg.VMCount < 1 {
		addFail("vm_count", fmt.Errorf("vmCount must be >= 1"))
	} else {
		addPass("vm_count", fmt.Sprintf("requested VM count: %d", cfg.VMCount))
	}

	var candidateVMIDs []int
	if cfg.VMCount > 0 {
		ids, allocErr := ws.pve.allocateVMIDs(cfg.VMStartID, cfg.VMCount)
		if allocErr != nil {
			addFail("vmid_allocation", fmt.Errorf("VMID allocation check failed: %w", allocErr))
		} else {
			candidateVMIDs = ids
			addPass("vmid_allocation", fmt.Sprintf("found %d free VMID(s) starting from %d", len(ids), cfg.VMStartID))
		}
	}

	jsonOK(w, map[string]interface{}{
		"ready":              ready,
		"node":               cfg.Node,
		"templateId":         resolvedTemplateID,
		"vmCount":            cfg.VMCount,
		"vmStartId":          cfg.VMStartID,
		"candidateVmids":     candidateVMIDs,
		"checks":             checks,
		"checkedAtUnixMilli": time.Now().UnixMilli(),
	})
}

func (ws *WebServer) handleProvision(w http.ResponseWriter, r *http.Request) {
	var params ProvisionParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), 400)
		return
	}

	// Merge request params with base config defaults.
	cfg := ws.cfg
	if params.VMCount > 0 {
		cfg.VMCount = params.VMCount
	}
	if params.Cores > 0 {
		cfg.Cores = params.Cores
	}
	if params.Memory > 0 {
		cfg.Memory = params.Memory
	}
	if params.DiskSize != "" {
		cfg.DiskSize = params.DiskSize
	}
	if params.DiskDevice != "" {
		cfg.DiskDevice = params.DiskDevice
	}
	if params.User != "" {
		cfg.User = params.User
	}
	if params.VMStartID > 0 {
		cfg.VMStartID = params.VMStartID
	}
	if params.VMName != "" {
		cfg.VMName = params.VMName
	}
	if params.Node != "" {
		cfg.Node = params.Node
	}

	if strings.TrimSpace(params.Template) != "" {
		templateVMID, err := ws.templateVMIDForNode(strings.TrimSpace(params.Template), cfg.Node)
		if err != nil {
			jsonError(w, "template resolution failed: "+err.Error(), 400)
			return
		}
		cfg.TemplateID = templateVMID
	} else if params.TemplateID > 0 {
		cfg.TemplateID = params.TemplateID
	}

	// Allocate VMIDs.
	ids, err := ws.pve.allocateVMIDs(cfg.VMStartID, cfg.VMCount)
	if err != nil {
		jsonError(w, "VMID allocation failed: "+err.Error(), 500)
		return
	}

	specs := make([]VMSpec, cfg.VMCount)
	for i, id := range ids {
		specs[i] = VMSpec{VMID: id, Name: vmName(cfg.VMName, i, cfg.VMCount)}
	}

	// Create job.
	job := &Job{
		ID:        generateJobID(),
		Status:    "running",
		StartedAt: time.Now(),
		Specs:     specs,
		Results:   make([]VMResult, cfg.VMCount),
		done:      make(chan struct{}),
	}

	ws.mu.Lock()
	ws.jobs[job.ID] = job
	ws.mu.Unlock()

	// Launch provisioning in background.
	go ws.runJob(job, cfg, specs)

	jsonOK(w, map[string]interface{}{
		"jobId": job.ID,
		"specs": specs,
	})
}

func (ws *WebServer) templateVMIDForNode(templateName, nodeName string) (int, error) {
	if strings.TrimSpace(templateName) == "" {
		return 0, fmt.Errorf("template name is required")
	}
	if strings.TrimSpace(nodeName) == "" {
		return 0, fmt.Errorf("node is required")
	}

	ws.templateMu.Lock()
	defer ws.templateMu.Unlock()

	t := ws.templates[templateName]
	if t == nil {
		return 0, fmt.Errorf("template %s not found in source of truth", templateName)
	}
	ns := t.NodeStates[nodeName]
	if ns == nil {
		return 0, fmt.Errorf("template %s is not configured for node %s", templateName, nodeName)
	}
	if ns.VMID <= 0 {
		return 0, fmt.Errorf("template %s has no VMID configured for node %s", templateName, nodeName)
	}

	return ns.VMID, nil
}

func (ws *WebServer) handleListJobs(w http.ResponseWriter, r *http.Request) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	type jobEntry struct {
		ID        string    `json:"id"`
		Status    string    `json:"status"`
		StartedAt time.Time `json:"startedAt"`
		VMCount   int       `json:"vmCount"`
	}

	jobs := make([]jobEntry, 0, len(ws.jobs))
	for _, j := range ws.jobs {
		jobs = append(jobs, jobEntry{
			ID:        j.ID,
			Status:    j.Status,
			StartedAt: j.StartedAt,
			VMCount:   len(j.Specs),
		})
	}
	jsonOK(w, jobs)
}

func (ws *WebServer) handleJobEvents(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")

	ws.mu.Lock()
	job, ok := ws.jobs[jobID]
	ws.mu.Unlock()

	if !ok {
		jsonError(w, "job not found", 404)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, "streaming not supported", 500)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Subscribe before replaying so we don't miss events.
	ch := make(chan ProvisionEvent, 100)

	job.mu.Lock()

	// Replay all past events.
	for _, e := range job.Events {
		data, _ := json.Marshal(e)
		fmt.Fprintf(w, "data: %s\n\n", data)
	}
	flusher.Flush()

	// If already done, close immediately.
	select {
	case <-job.done:
		job.mu.Unlock()
		return
	default:
	}

	job.listeners = append(job.listeners, ch)
	job.mu.Unlock()

	// Clean up listener on disconnect.
	defer func() {
		job.mu.Lock()
		for i, l := range job.listeners {
			if l == ch {
				job.listeners = append(job.listeners[:i], job.listeners[i+1:]...)
				break
			}
		}
		job.mu.Unlock()
	}()

	// Stream events until job completes or client disconnects.
	for {
		select {
		case event := <-ch:
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
			if event.Step == "job_complete" {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

func (ws *WebServer) handleTemplateState(w http.ResponseWriter, r *http.Request) {
	selected := strings.TrimSpace(r.URL.Query().Get("template"))
	if selected == "" {
		selected = defaultTemplateName
	}

	nodes, err := ws.pve.listNodes()
	if err != nil {
		jsonError(w, "failed to list nodes: "+err.Error(), 500)
		return
	}

	usedSet, err := ws.pve.existingVMIDs()
	if err != nil {
		jsonError(w, "failed to list cluster VMIDs: "+err.Error(), 500)
		return
	}

	used := make([]int, 0, len(usedSet))
	for vmid := range usedSet {
		used = append(used, vmid)
	}
	sort.Ints(used)

	ws.templateMu.Lock()
	ws.ensureTemplateLocked(selected, nodes)

	templateNames := make([]string, 0, len(ws.templates))
	for name := range ws.templates {
		templateNames = append(templateNames, name)
	}
	sort.Strings(templateNames)

	templates := make([]map[string]interface{}, 0, len(templateNames))
	for _, name := range templateNames {
		t := ws.templates[name]
		ws.ensureTemplateLocked(name, nodes)

		nodeStates := make([]map[string]interface{}, 0, len(t.NodeStates))
		readyCount := 0
		vmidsByNode := make(map[string]int, len(t.NodeStates))
		for _, st := range t.NodeStates {
			if st.Status == "Ready" {
				readyCount++
			}
			if st.VMID > 0 {
				vmidsByNode[st.Node] = st.VMID
			}
			nodeStates = append(nodeStates, map[string]interface{}{
				"node":        st.Node,
				"vmid":        st.VMID,
				"storageId":   st.StorageID,
				"volumeId":    st.VolumeID,
				"status":      st.Status,
				"reachable":   st.Reachable,
				"lastMessage": st.LastMessage,
				"lastError":   st.LastError,
				"updatedAt":   st.UpdatedAt,
			})
		}
		sort.Slice(nodeStates, func(i, j int) bool {
			a, _ := nodeStates[i]["node"].(string)
			b, _ := nodeStates[j]["node"].(string)
			return a < b
		})

		templates = append(templates, map[string]interface{}{
			"name":        t.Name,
			"vmidsByNode": vmidsByNode,
			"readyCount":  readyCount,
			"outOfSync":   len(t.NodeStates) - readyCount,
			"totalNodes":  len(t.NodeStates),
			"nodeStates":  nodeStates,
		})
	}

	logsCopy := make(map[string][]TemplateLogEntry, len(ws.templateLogs))
	for node, logs := range ws.templateLogs {
		copyLogs := make([]TemplateLogEntry, len(logs))
		copy(copyLogs, logs)
		logsCopy[node] = copyLogs
	}
	ws.templateMu.Unlock()

	suggestedVMIDs := make(map[string]int, len(nodes))
	for _, n := range nodes {
		nodeName, _ := n["node"].(string)
		if strings.TrimSpace(nodeName) == "" {
			continue
		}
		suggestedVMID, vmidErr := ws.nextTemplateVMID(9000, selected, nodeName)
		if vmidErr != nil {
			jsonError(w, "failed to compute suggested VMID: "+vmidErr.Error(), 500)
			return
		}
		suggestedVMIDs[nodeName] = suggestedVMID
	}

	nodeConfig := ws.collectTemplateNodeConfig(nodes, selected)

	jsonOK(w, map[string]interface{}{
		"selectedTemplate": selected,
		"templates":        templates,
		"nodes":            nodeConfig,
		"clusterUsedVMIDs": used,
		"suggestedVmids":   suggestedVMIDs,
		"logsByNode":       logsCopy,
	})
}

func (ws *WebServer) handleAssignTemplateStorage(w http.ResponseWriter, r *http.Request) {
	templateName := strings.TrimSpace(r.PathValue("name"))
	nodeName := strings.TrimSpace(r.PathValue("node"))
	if templateName == "" || nodeName == "" {
		jsonError(w, "template and node are required", 400)
		return
	}

	var req templateStorageAssignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), 400)
		return
	}
	req.StorageID = strings.TrimSpace(req.StorageID)
	if req.StorageID == "" {
		jsonError(w, "storageId is required", 400)
		return
	}

	storages, err := ws.pve.listNodeStorages(nodeName)
	if err != nil {
		jsonError(w, "failed to list node storages: "+err.Error(), 500)
		return
	}

	storageOK := false
	for _, st := range storages {
		id, _ := st["storage"].(string)
		if id == req.StorageID && storageIsNodeEligible(nodeName, st) {
			storageOK = true
			break
		}
	}
	if !storageOK {
		jsonError(w, "storage not available on selected node", 400)
		return
	}

	nodes, err := ws.pve.listNodes()
	if err != nil {
		jsonError(w, "failed to list nodes: "+err.Error(), 500)
		return
	}

	ws.templateMu.Lock()
	t := ws.ensureTemplateLocked(templateName, nodes)
	state := t.NodeStates[nodeName]
	if state == nil {
		state = &TemplateNodeState{Node: nodeName, Status: "Missing", UpdatedAt: time.Now()}
		t.NodeStates[nodeName] = state
	}
	state.StorageID = req.StorageID
	state.LastError = ""
	state.LastMessage = "Target storage assigned"
	state.UpdatedAt = time.Now()
	ws.templateMu.Unlock()
	if err := ws.saveTemplateSoT(); err != nil {
		jsonError(w, "failed to persist template source of truth: "+err.Error(), 500)
		return
	}

	jsonOK(w, map[string]string{"status": "ok"})
}

func (ws *WebServer) handleBuildTemplate(w http.ResponseWriter, r *http.Request) {
	templateName := strings.TrimSpace(r.PathValue("name"))
	if templateName == "" {
		jsonError(w, "template name is required", 400)
		return
	}

	var req templateBuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), 400)
		return
	}
	req.Node = strings.TrimSpace(req.Node)
	if req.Node == "" {
		jsonError(w, "node is required", 400)
		return
	}
	if req.VMID <= 0 {
		next, err := ws.nextTemplateVMID(9000, templateName, req.Node)
		if err != nil {
			jsonError(w, "failed to compute next free VMID: "+err.Error(), 500)
			return
		}
		req.VMID = next
	}
	if req.VMID < 9000 {
		next, err := ws.nextTemplateVMID(9000, templateName, req.Node)
		if err != nil {
			jsonError(w, "failed to compute next free VMID: "+err.Error(), 500)
			return
		}
		req.VMID = next
	}
	if req.Image == "" {
		req.Image = "debian-12-generic-amd64.qcow2"
	}

	nodes, err := ws.pve.listNodes()
	if err != nil {
		jsonError(w, "failed to list nodes: "+err.Error(), 500)
		return
	}

	isAvailable, err := ws.isTemplateVMIDAvailable(templateName, req.Node, req.VMID)
	if err != nil {
		jsonError(w, "failed to validate VMID: "+err.Error(), 500)
		return
	}
	if !isAvailable {
		jsonError(w, "vmid is already used in the cluster or reserved by another template/node", 409)
		return
	}

	key := templateName + "::" + req.Node

	ws.templateMu.Lock()
	t := ws.ensureTemplateLocked(templateName, nodes)
	ns := t.NodeStates[req.Node]
	if ns == nil {
		ns = &TemplateNodeState{Node: req.Node, Status: "Missing", UpdatedAt: time.Now()}
		t.NodeStates[req.Node] = ns
	}
	if ns.StorageID == "" {
		ws.templateMu.Unlock()
		jsonError(w, "target storage is not configured for node", 400)
		return
	}
	if ws.activeTplBuilds[key] {
		ws.templateMu.Unlock()
		jsonError(w, "a template build is already running for this node", 409)
		return
	}
	ns.VMID = req.VMID
	ws.activeTplBuilds[key] = true
	ns.Status = "Downloading"
	ns.LastError = ""
	ns.LastMessage = "Template build started"
	ns.UpdatedAt = time.Now()
	ws.appendTemplateLogLocked(req.Node, TemplateLogEntry{
		Timestamp: time.Now(),
		Template:  templateName,
		Node:      req.Node,
		Stage:     "start",
		Message:   fmt.Sprintf("Build started for %s (VMID %d)", templateName, req.VMID),
	})
	ws.templateMu.Unlock()
	if err := ws.saveTemplateSoT(); err != nil {
		jsonError(w, "failed to persist template source of truth: "+err.Error(), 500)
		return
	}

	go ws.runTemplateBuild(templateName, req.Node, req.VMID, req.Image)

	jsonOK(w, map[string]interface{}{
		"status":   "started",
		"template": templateName,
		"node":     req.Node,
		"vmid":     req.VMID,
	})
}

func (ws *WebServer) handleTemplateNodeLogs(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.PathValue("node"))
	if node == "" {
		jsonError(w, "node is required", 400)
		return
	}

	ws.templateMu.Lock()
	logs := ws.templateLogs[node]
	copyLogs := make([]TemplateLogEntry, len(logs))
	copy(copyLogs, logs)
	ws.templateMu.Unlock()

	jsonOK(w, copyLogs)
}

func (ws *WebServer) runTemplateBuild(templateName, node string, vmid int, image string) {
	key := templateName + "::" + node
	imageURL := "https://cloud.debian.org/images/cloud/bookworm/latest/" + image
	volumeID := ""

	finish := func(finalStatus string, volumeID string, err error) {
		ws.templateMu.Lock()
		t := ws.templates[templateName]
		if t == nil {
			delete(ws.activeTplBuilds, key)
			ws.templateMu.Unlock()
			return
		}
		ns := t.NodeStates[node]
		if ns == nil {
			ns = &TemplateNodeState{Node: node}
			t.NodeStates[node] = ns
		}

		ns.Status = finalStatus
		ns.UpdatedAt = time.Now()
		if volumeID != "" {
			ns.VolumeID = volumeID
		}
		if err != nil {
			ns.LastError = err.Error()
			ns.LastMessage = "Build failed"
			ws.appendTemplateLogLocked(node, TemplateLogEntry{
				Timestamp: time.Now(),
				Template:  templateName,
				Node:      node,
				Stage:     "failed",
				Message:   err.Error(),
			})
		} else {
			ns.LastError = ""
			ns.LastMessage = "Template ready"
			ws.appendTemplateLogLocked(node, TemplateLogEntry{
				Timestamp: time.Now(),
				Template:  templateName,
				Node:      node,
				Stage:     "ready",
				Message:   fmt.Sprintf("Template %s is ready on %s", templateName, node),
			})
		}

		delete(ws.activeTplBuilds, key)
		ws.templateMu.Unlock()
		_ = ws.saveTemplateSoT()
	}

	updateStage := func(status, stage, message string) {
		ws.templateMu.Lock()
		t := ws.templates[templateName]
		if t == nil {
			ws.templateMu.Unlock()
			return
		}
		ns := t.NodeStates[node]
		if ns == nil {
			ns = &TemplateNodeState{Node: node, Status: "Missing", UpdatedAt: time.Now()}
			t.NodeStates[node] = ns
		}
		ns.Status = status
		ns.LastMessage = message
		ns.LastError = ""
		ns.UpdatedAt = time.Now()

		ws.appendTemplateLogLocked(node, TemplateLogEntry{
			Timestamp: time.Now(),
			Template:  templateName,
			Node:      node,
			Stage:     stage,
			Message:   message,
		})
		ws.templateMu.Unlock()
		_ = ws.saveTemplateSoT()
	}

	ws.templateMu.Lock()
	t := ws.templates[templateName]
	storageID := ""
	if t != nil {
		if ns := t.NodeStates[node]; ns != nil {
			storageID = ns.StorageID
			if ns.VMID > 0 {
				vmid = ns.VMID
			}
		}
	}
	ws.templateMu.Unlock()

	if storageID == "" {
		finish("Failed", "", fmt.Errorf("no storage configured for node %s", node))
		return
	}

	appendLine := func(stage, line string) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		ws.templateMu.Lock()
		ws.appendTemplateLogLocked(node, TemplateLogEntry{
			Timestamp: time.Now(),
			Template:  templateName,
			Node:      node,
			Stage:     stage,
			Message:   line,
		})
		ws.templateMu.Unlock()
	}

	host := ws.sshHostForNode(node)
	runCmd := func(status, stage, message, command string) error {
		updateStage(status, stage, message)
		appendLine(stage, "$ "+command)
		return ws.execSSHCommand(host, command, func(out string) {
			appendLine(stage, out)
		})
	}

	downloadCmd := fmt.Sprintf("cd /var/lib/vz/template/iso && if [ ! -f %s ]; then wget -nv -O %s %s; else echo 'Image already present: %s'; fi",
		shellQuote(image), shellQuote(image), shellQuote(imageURL), image)
	if err := runCmd("Downloading", "download", "Downloading Debian 12 cloud image", downloadCmd); err != nil {
		finish("Failed", volumeID, err)
		return
	}

	createCmd := fmt.Sprintf("qm create %d --name %s --memory 2048 --cores 2 --net0 virtio,bridge=vmbr0,tag=10", vmid, shellQuote(templateName))
	if err := runCmd("Importing", "import", "Creating VM shell", createCmd); err != nil {
		finish("Failed", volumeID, err)
		return
	}

	importCmd := fmt.Sprintf("cd /var/lib/vz/template/iso && qm importdisk %d %s %s", vmid, shellQuote(image), shellQuote(storageID))
	if err := runCmd("Importing", "import", "Importing disk into node-local storage", importCmd); err != nil {
		finish("Failed", volumeID, err)
		return
	}
	volumeID = fmt.Sprintf("%s:vm-%d-disk-0", storageID, vmid)

	provisionCmds := []string{
		fmt.Sprintf("qm set %d --scsihw virtio-scsi-pci --scsi0 %s", vmid, shellQuote(volumeID)),
		fmt.Sprintf("qm set %d --ide2 %s", vmid, shellQuote(storageID+":cloudinit")),
		fmt.Sprintf("qm set %d --boot c --bootdisk scsi0", vmid),
		fmt.Sprintf("qm set %d --serial0 socket --vga serial0", vmid),
		fmt.Sprintf("qm set %d --agent enabled=1", vmid),
	}
	for _, cmd := range provisionCmds {
		if err := runCmd("Provisioning", "hardware", "Applying hardware and Cloud-Init settings", cmd); err != nil {
			finish("Failed", volumeID, err)
			return
		}
	}

	if err := runCmd("Converting", "convert", "Converting VM to template", fmt.Sprintf("qm template %d", vmid)); err != nil {
		finish("Failed", volumeID, err)
		return
	}

	finish("Ready", volumeID, nil)
}

func (ws *WebServer) ensureTemplateLocked(name string, nodes []map[string]interface{}) *TemplateState {
	t, ok := ws.templates[name]
	if !ok {
		t = &TemplateState{
			Name:       name,
			NodeStates: make(map[string]*TemplateNodeState),
		}
		ws.templates[name] = t
	}

	seen := make(map[string]bool)
	for _, n := range nodes {
		nodeName, _ := n["node"].(string)
		if nodeName == "" {
			continue
		}
		seen[nodeName] = true
		reachable := n["status"] == "online"
		ns, ok := t.NodeStates[nodeName]
		if !ok {
			ns = &TemplateNodeState{
				Node:      nodeName,
				Status:    "Missing",
				Reachable: reachable,
				UpdatedAt: time.Now(),
			}
			t.NodeStates[nodeName] = ns
		} else {
			ns.Reachable = reachable
		}
	}

	for nodeName := range t.NodeStates {
		if !seen[nodeName] {
			delete(t.NodeStates, nodeName)
		}
	}

	return t
}

type templateSoTPayload struct {
	Version   int                           `json:"version"`
	Templates map[string]*templateSoTRecord `json:"templates"`
}

type templateSoTRecord struct {
	Name       string                        `json:"name"`
	GlobalVMID int                           `json:"globalVmid,omitempty"`
	NodeStates map[string]*TemplateNodeState `json:"nodeStates"`
}

func (ws *WebServer) loadTemplateSoT() error {
	data, err := os.ReadFile(ws.templateSoTPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var payload templateSoTPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("decode %s: %w", ws.templateSoTPath, err)
	}

	if payload.Templates == nil {
		payload.Templates = make(map[string]*templateSoTRecord)
	}

	ws.templateMu.Lock()
	for name, rec := range payload.Templates {
		if rec == nil {
			continue
		}

		t := &TemplateState{
			Name:       rec.Name,
			NodeStates: rec.NodeStates,
		}
		if t.Name == "" {
			t.Name = name
		}
		if t.NodeStates == nil {
			t.NodeStates = make(map[string]*TemplateNodeState)
		}
		for nodeName, nodeState := range t.NodeStates {
			if nodeState == nil {
				t.NodeStates[nodeName] = &TemplateNodeState{Node: nodeName, Status: "Missing", UpdatedAt: time.Now()}
				continue
			}
			if nodeState.Node == "" {
				nodeState.Node = nodeName
			}
			if nodeState.Status == "" {
				nodeState.Status = "Missing"
			}
			if nodeState.VMID <= 0 && rec.GlobalVMID > 0 {
				nodeState.VMID = rec.GlobalVMID
			}
		}
		ws.templates[name] = t
	}
	if _, ok := ws.templates[defaultTemplateName]; !ok {
		ws.templates[defaultTemplateName] = &TemplateState{
			Name:       defaultTemplateName,
			NodeStates: make(map[string]*TemplateNodeState),
		}
	}
	ws.templateMu.Unlock()

	return nil
}

func (ws *WebServer) saveTemplateSoT() error {
	ws.templateMu.Lock()
	templates := make(map[string]*templateSoTRecord, len(ws.templates))
	for name, t := range ws.templates {
		if t == nil {
			continue
		}
		clone := &templateSoTRecord{
			Name:       t.Name,
			NodeStates: make(map[string]*TemplateNodeState, len(t.NodeStates)),
		}
		for nodeName, nodeState := range t.NodeStates {
			if nodeState == nil {
				continue
			}
			copyState := *nodeState
			clone.NodeStates[nodeName] = &copyState
		}
		templates[name] = clone
	}
	ws.templateMu.Unlock()

	payload := templateSoTPayload{
		Version:   1,
		Templates: templates,
	}

	jsonBytes, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}

	tmp := ws.templateSoTPath + ".tmp"
	if err := os.WriteFile(tmp, jsonBytes, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, ws.templateSoTPath); err != nil {
		return err
	}

	return nil
}

func (ws *WebServer) appendTemplateLogLocked(node string, entry TemplateLogEntry) {
	logs := append(ws.templateLogs[node], entry)
	if len(logs) > 500 {
		logs = logs[len(logs)-500:]
	}
	ws.templateLogs[node] = logs
}

func (ws *WebServer) collectTemplateNodeConfig(nodes []map[string]interface{}, templateName string) []map[string]interface{} {
	ws.templateMu.Lock()
	t := ws.templates[templateName]
	if t == nil {
		t = ws.ensureTemplateLocked(templateName, nodes)
	}

	assignedByNode := make(map[string]string, len(t.NodeStates))
	for node, ns := range t.NodeStates {
		assignedByNode[node] = ns.StorageID
	}
	ws.templateMu.Unlock()

	response := make([]map[string]interface{}, 0, len(nodes))
	for _, n := range nodes {
		nodeName, _ := n["node"].(string)
		if nodeName == "" {
			continue
		}
		reachable := n["status"] == "online"
		assignedStorage := assignedByNode[nodeName]

		storages, _ := ws.pve.listNodeStorages(nodeName)
		storageRows := make([]map[string]interface{}, 0, len(storages))
		for _, st := range storages {
			if !storageIsNodeEligible(nodeName, st) {
				continue
			}
			storageRows = append(storageRows, map[string]interface{}{
				"id":      st["storage"],
				"type":    st["type"],
				"content": st["content"],
				"active":  st["active"],
				"enabled": st["enabled"],
			})
		}

		configured := reachable && assignedStorage != ""

		response = append(response, map[string]interface{}{
			"node":            nodeName,
			"status":          n["status"],
			"reachable":       reachable,
			"assignedStorage": assignedStorage,
			"configured":      configured,
			"storages":        storageRows,
		})
	}

	sort.Slice(response, func(i, j int) bool {
		a, _ := response[i]["node"].(string)
		b, _ := response[j]["node"].(string)
		return a < b
	})

	return response
}

func storageIsNodeEligible(node string, storage map[string]interface{}) bool {
	if !storageBelongsToNode(node, storage) {
		return false
	}

	if shared, ok := boolish(storage["shared"]); ok && shared {
		return false
	}
	if enabled, ok := boolish(storage["enabled"]); ok && !enabled {
		return false
	}
	if active, ok := boolish(storage["active"]); ok && !active {
		return false
	}

	return true
}

func storageBelongsToNode(node string, storage map[string]interface{}) bool {
	if node == "" {
		return false
	}

	if nodesCSV, ok := storage["nodes"].(string); ok {
		nodesCSV = strings.TrimSpace(nodesCSV)
		if nodesCSV != "" {
			for _, part := range strings.Split(nodesCSV, ",") {
				if strings.TrimSpace(part) == node {
					return true
				}
			}
			return false
		}
	}

	if nodeField, ok := storage["node"].(string); ok {
		nodeField = strings.TrimSpace(nodeField)
		if nodeField != "" && nodeField != node {
			return false
		}
	}

	return true
}

func boolish(v interface{}) (bool, bool) {
	switch value := v.(type) {
	case bool:
		return value, true
	case float64:
		return value != 0, true
	case int:
		return value != 0, true
	case int64:
		return value != 0, true
	case string:
		s := strings.TrimSpace(strings.ToLower(value))
		switch s {
		case "1", "true", "yes", "on":
			return true, true
		case "0", "false", "no", "off", "":
			return false, true
		default:
			if n, err := strconv.Atoi(s); err == nil {
				return n != 0, true
			}
		}
	}

	return false, false
}

func (ws *WebServer) isTemplateVMIDAvailable(templateName, nodeName string, vmid int) (bool, error) {
	used, err := ws.pve.existingVMIDs()
	if err != nil {
		return false, err
	}
	if used[vmid] {
		return false, nil
	}

	ws.templateMu.Lock()
	defer ws.templateMu.Unlock()
	for name, t := range ws.templates {
		if t == nil {
			continue
		}
		for node, ns := range t.NodeStates {
			if ns == nil || ns.VMID <= 0 {
				continue
			}
			if name == templateName && node == nodeName {
				continue
			}
			if ns.VMID == vmid {
				return false, nil
			}
		}
	}
	return true, nil
}

func (ws *WebServer) nextTemplateVMID(start int, templateName, nodeName string) (int, error) {
	used, err := ws.pve.existingVMIDs()
	if err != nil {
		return 0, err
	}

	reserved := map[int]bool{}
	ws.templateMu.Lock()
	for name, t := range ws.templates {
		if t == nil {
			continue
		}
		for node, ns := range t.NodeStates {
			if ns == nil || ns.VMID <= 0 {
				continue
			}
			if name == templateName && node == nodeName {
				continue
			}
			reserved[ns.VMID] = true
		}
	}
	if current, ok := ws.templates[templateName]; ok && current != nil {
		if ns := current.NodeStates[nodeName]; ns != nil && ns.VMID > 0 {
			ws.templateMu.Unlock()
			return ns.VMID, nil
		}
	}
	ws.templateMu.Unlock()

	candidate := start
	for {
		if candidate > 999999999 {
			return 0, fmt.Errorf("VMID space exhausted")
		}
		if !used[candidate] && !reserved[candidate] {
			return candidate, nil
		}
		candidate++
	}
}

func (ws *WebServer) sshHostForNode(node string) string {
	if node == "" {
		return ws.pveHost
	}
	if node == ws.cfg.Node && ws.pveHost != "" {
		return ws.pveHost
	}
	return node
}

func (ws *WebServer) execSSHCommand(host, command string, onLine func(string)) error {
	if host == "" {
		return fmt.Errorf("empty SSH host")
	}

	keyBytes, err := os.ReadFile(ws.cfg.PVESSHKey)
	if err != nil {
		return fmt.Errorf("read SSH key %s: %w", ws.cfg.PVESSHKey, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("parse SSH key: %w", err)
	}

	clientCfg := &ssh.ClientConfig{
		User:            ws.cfg.PVESSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	client, err := ssh.Dial("tcp", host+":"+ws.cfg.PVESSHPort, clientCfg)
	if err != nil {
		return fmt.Errorf("ssh dial %s: %w", host, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := session.Start(command); err != nil {
		return fmt.Errorf("ssh start: %w", err)
	}

	var wg sync.WaitGroup
	readPipe := func(scanner *bufio.Scanner) {
		defer wg.Done()
		for scanner.Scan() {
			if onLine != nil {
				onLine(scanner.Text())
			}
		}
	}

	stdoutScanner := bufio.NewScanner(stdout)
	stderrScanner := bufio.NewScanner(stderr)
	stdoutScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	stderrScanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	wg.Add(2)
	go readPipe(stdoutScanner)
	go readPipe(stderrScanner)

	err = session.Wait()
	wg.Wait()
	if err != nil {
		return fmt.Errorf("ssh command failed: %w", err)
	}

	return nil
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

// ── Job Runner ───────────────────────────────────────────────────────────

func (ws *WebServer) runJob(job *Job, cfg Config, specs []VMSpec) {
	var wg sync.WaitGroup
	pveClient := newProxmoxClient(cfg)
	pveHost := ws.sshHostForNode(cfg.Node)

	for i, spec := range specs {
		wg.Add(1)
		go func(idx int, s VMSpec) {
			defer wg.Done()
			job.Results[idx] = provisionVM(cfg, pveClient, pveHost, s, func(e ProvisionEvent) {
				job.mu.Lock()
				job.Events = append(job.Events, e)
				// Copy listeners slice to avoid holding lock during send.
				listeners := make([]chan ProvisionEvent, len(job.listeners))
				copy(listeners, job.listeners)
				job.mu.Unlock()

				for _, ch := range listeners {
					select {
					case ch <- e:
					default: // slow listener, skip
					}
				}
			})
		}(i, spec)
	}

	wg.Wait()

	// Compute summary.
	job.mu.Lock()
	var success, failed int
	for _, r := range job.Results {
		if r.Err != nil {
			failed++
		} else {
			success++
		}
	}
	if failed > 0 && success == 0 {
		job.Status = "failed"
	} else if failed > 0 {
		job.Status = "failed"
	} else {
		job.Status = "completed"
	}

	completeEvent := ProvisionEvent{
		Step:    "job_complete",
		Message: fmt.Sprintf("%d succeeded, %d failed", success, failed),
	}
	job.Events = append(job.Events, completeEvent)
	listeners := make([]chan ProvisionEvent, len(job.listeners))
	copy(listeners, job.listeners)
	job.mu.Unlock()

	for _, ch := range listeners {
		select {
		case ch <- completeEvent:
		default:
		}
	}

	close(job.done)
}

// ── Naming Helper ─────────────────────────────────────────────────────────

// vmName returns the name for VM at index i out of total count.
// If baseName is empty, a random name is generated.
// If count == 1, baseName is used as-is.
// If count > 1, names are formatted as "<baseName>-01", "<baseName>-02", etc.
func vmName(baseName string, i, count int) string {
	if baseName == "" {
		return randomVMName()
	}
	if count == 1 {
		return baseName
	}
	return fmt.Sprintf("%s-%02d", baseName, i+1)
}

// ── JSON Helpers ─────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// generateJobID returns a random 16-char hex string for job identification.
func generateJobID() string {
	return randomHex(8)
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
