package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

//go:embed web/index.html
var indexHTML []byte

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
	TemplateID int    `json:"templateId"`
	Cores      int    `json:"cores"`
	Memory     int    `json:"memory"`
	DiskSize   string `json:"diskSize"`
	DiskDevice string `json:"diskDevice"`
	User       string `json:"user"`
	VMStartID  int    `json:"vmStartId"`
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
// Web Server
// ════════════════════════════════════════════════════════════════════════════

// WebServer holds the shared state for the HTTP handlers.
type WebServer struct {
	cfg     Config
	pve     *ProxmoxClient
	pveHost string

	mu   sync.Mutex
	jobs map[string]*Job
}

func startWebServer(cfg Config, port string) {
	pve := newProxmoxClient(cfg)
	pveHost, err := proxmoxHost(cfg.ProxmoxURL)
	if err != nil {
		fatalf("Cannot determine Proxmox host: %v", err)
	}

	ws := &WebServer{
		cfg:     cfg,
		pve:     pve,
		pveHost: pveHost,
		jobs:    make(map[string]*Job),
	}

	mux := http.NewServeMux()

	// Frontend
	mux.HandleFunc("GET /", ws.handleIndex)

	// API — Config
	mux.HandleFunc("GET /api/config", ws.handleGetConfig)

	// API — VMs
	mux.HandleFunc("GET /api/vms", ws.handleListVMs)
	mux.HandleFunc("POST /api/vms/{id}/start", ws.handleStartVM)
	mux.HandleFunc("POST /api/vms/{id}/stop", ws.handleStopVM)
	mux.HandleFunc("POST /api/vms/{id}/restart", ws.handleRestartVM)
	mux.HandleFunc("DELETE /api/vms/{id}", ws.handleDeleteVM)

	// API — Keys (download provisioned SSH keys)
	mux.HandleFunc("GET /api/keys/{filename}", ws.handleDownloadKey)

	// API — Provisioning
	mux.HandleFunc("POST /api/provision", ws.handleProvision)
	mux.HandleFunc("GET /api/jobs", ws.handleListJobs)
	mux.HandleFunc("GET /api/jobs/{id}/events", ws.handleJobEvents)

	fmt.Printf("\n✦  Atlas Plane — Web UI\n")
	fmt.Printf("   http://localhost:%s\n", port)
	fmt.Printf("   Proxmox: %s (node: %s)\n\n", cfg.ProxmoxURL, cfg.Node)

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

func (ws *WebServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"proxmoxUrl": ws.cfg.ProxmoxURL,
		"node":       ws.cfg.Node,
		"templateId": ws.cfg.TemplateID,
		"cores":      ws.cfg.Cores,
		"memory":     ws.cfg.Memory,
		"diskSize":   ws.cfg.DiskSize,
		"diskDevice": ws.cfg.DiskDevice,
		"user":       ws.cfg.User,
		"vmStartId":  ws.cfg.VMStartID,
	})
}

func (ws *WebServer) handleListVMs(w http.ResponseWriter, r *http.Request) {
	vms, err := ws.pve.listVMs()
	if err != nil {
		jsonError(w, "failed to list VMs: "+err.Error(), 500)
		return
	}
	jsonOK(w, vms)
}

func (ws *WebServer) handleStartVM(w http.ResponseWriter, r *http.Request) {
	vmid, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		jsonError(w, "invalid VMID", 400)
		return
	}
	if err := ws.pve.startVM(vmid); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	jsonOK(w, map[string]string{"status": "started"})
}

func (ws *WebServer) handleStopVM(w http.ResponseWriter, r *http.Request) {
	vmid, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		jsonError(w, "invalid VMID", 400)
		return
	}
	if err := ws.pve.stopVM(vmid); err != nil {
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
	if err := ws.pve.rebootVM(vmid); err != nil {
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
	if err := ws.pve.deleteVM(vmid); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	jsonOK(w, map[string]string{"status": "deleted"})
}

// ── Key Download ─────────────────────────────────────────────────────────

// validKeyName allows only the filenames produced by generateSSHCert:
//
//	vmname_key  or  vmname_key-cert.pub
//
// This prevents path traversal and limits exposure to only Atlas-generated files.
var validKeyName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*_key(-cert\.pub)?$`)

func (ws *WebServer) handleDownloadKey(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(r.PathValue("filename"))
	if !validKeyName.MatchString(filename) {
		jsonError(w, "invalid filename", 400)
		return
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		jsonError(w, "key not found", 404)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
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
	if params.TemplateID > 0 {
		cfg.TemplateID = params.TemplateID
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

	// Allocate VMIDs.
	ids, err := ws.pve.allocateVMIDs(cfg.VMStartID, cfg.VMCount)
	if err != nil {
		jsonError(w, "VMID allocation failed: "+err.Error(), 500)
		return
	}

	specs := make([]VMSpec, cfg.VMCount)
	for i, id := range ids {
		specs[i] = VMSpec{VMID: id, Name: randomVMName()}
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

// ── Job Runner ───────────────────────────────────────────────────────────

func (ws *WebServer) runJob(job *Job, cfg Config, specs []VMSpec) {
	var wg sync.WaitGroup

	for i, spec := range specs {
		wg.Add(1)
		go func(idx int, s VMSpec) {
			defer wg.Done()
			job.Results[idx] = provisionVM(cfg, ws.pve, ws.pveHost, s, func(e ProvisionEvent) {
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
