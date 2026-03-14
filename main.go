// Package main implements atlas-plane, a CLI tool that fully automates the
// provisioning of virtual machines on a Proxmox homelab. It clones a golden
// image template, configures hardware, injects Cloud-Init data with an SSH
// Certificate Authority for zero-trust access, boots the VM, and polls for
// the guest IP address.
//
// Supports provisioning multiple VMs in parallel via the VM_COUNT env var.
//
// Before running:
//  1. Generate a CA key pair:   ssh-keygen -t ed25519 -f ca_ed25519 -N "" -C "atlas-ca"
//  2. Prepare a Debian 12 Cloud-Init template VM in Proxmox (with qemu-guest-agent).
//  3. Enable "snippets" content type on your Proxmox storage (e.g. "local").
//  4. Create a Proxmox API token with sufficient privileges.
//  5. Export the required environment variables (see README.md).
//
// Run:
//
// go run main.go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// ════════════════════════════════════════════════════════════════════════════
// Configuration
// ════════════════════════════════════════════════════════════════════════════

// Config holds every tuneable knob for a provisioning run. Values are sourced
// from environment variables with sensible defaults.
type Config struct {
	ProxmoxURL   string        // e.g. https://192.168.1.100:8006
	Node         string        // Proxmox node name (default "pve")
	APIToken     string        // USER@REALM!TOKENID=SECRET
	TemplateID   int           // VMID of the Debian 12 Cloud-Init template
	VMCount      int           // Number of VMs to provision in parallel
	VMStartID    int           // Lowest VMID to consider (default 500)
	Cores        int           // vCPU count
	Memory       int           // RAM in MiB
	CAKeyPath    string        // Path to the CA private key (ed25519)
	SnippetStore string        // Proxmox storage that has "snippets" enabled
	SnippetDir   string        // Filesystem path on Proxmox node for snippets
	CertValidity time.Duration // How long the SSH cert remains valid
	User         string        // Cloud-Init user (default "debian")
	DiskDevice   string        // Proxmox disk identifier to resize (e.g. scsi0)
	DiskSize     string        // Target disk size after clone (e.g. 5G)
	VMName       string        // Optional base name for provisioned VMs

	// SSH access to the Proxmox host (for writing snippet files).
	PVESSHUser string
	PVESSHKey  string
	PVESSHPort string
}

func loadConfig() Config {
	home, _ := os.UserHomeDir()
	defaultSSHKey := filepath.Join(home, ".ssh", "id_rsa")

	return Config{
		ProxmoxURL:   envOr("PROXMOX_URL", "https://192.168.1.100:8006"),
		Node:         envOr("PROXMOX_NODE", "pve"),
		APIToken:     os.Getenv("PROXMOX_API_TOKEN"),
		TemplateID:   envIntOr("TEMPLATE_VMID", 9000),
		VMCount:      envIntOr("VM_COUNT", 1),
		VMStartID:    envIntOr("VM_START_ID", 500),
		Cores:        envIntOr("VM_CORES", 1),
		Memory:       envIntOr("VM_MEMORY", 1024),
		CAKeyPath:    envOr("CA_KEY_PATH", "./ca_ed25519"),
		SnippetStore: envOr("SNIPPET_STORAGE", "local"),
		SnippetDir:   envOr("SNIPPET_DIR", "/var/lib/vz/snippets"),
		CertValidity: 4 * time.Hour,
		User:         envOr("VM_USER", "debian"),
		DiskDevice:   envOr("VM_DISK_DEVICE", "scsi0"),
		DiskSize:     envOr("VM_DISK_SIZE", "5G"),
		VMName:       os.Getenv("VM_NAME"),
		PVESSHUser:   envOr("PVE_SSH_USER", "root"),
		PVESSHKey:    envOr("PVE_SSH_KEY", defaultSSHKey),
		PVESSHPort:   envOr("PVE_SSH_PORT", "22"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// ════════════════════════════════════════════════════════════════════════════
// Random VM Naming
// ════════════════════════════════════════════════════════════════════════════

// Docker-style adjective-noun generator. Collisions are astronomically
// unlikely with these list sizes + hex suffix, but the VMID is the real
// identity anyway.

var adjectives = []string{
	"agile", "bold", "brave", "calm", "cool", "crisp", "deft", "eager",
	"fast", "fleet", "grand", "keen", "lucid", "noble", "prime", "quick",
	"rapid", "sharp", "sleek", "smart", "solid", "stark", "stoic", "swift",
	"vivid", "witty", "able", "epic", "firm", "pure",
}

var nouns = []string{
	"atlas", "beacon", "cipher", "delta", "ember", "falcon", "gate",
	"helix", "ion", "jade", "kite", "lumen", "matrix", "nexus", "orbit",
	"pulse", "quasar", "relay", "spark", "tide", "unit", "vault", "wave",
	"apex", "bolt", "comet", "drone", "flux", "grid", "node",
}

func randomVMName() string {
	adj := adjectives[cryptoRandInt(len(adjectives))]
	noun := nouns[cryptoRandInt(len(nouns))]
	// 3-byte hex suffix for uniqueness: e.g. "swift-nexus-a3f1b2"
	var buf [3]byte
	_, _ = rand.Read(buf[:])
	return fmt.Sprintf("%s-%s-%s", adj, noun, hex.EncodeToString(buf[:]))
}

func cryptoRandInt(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

// ════════════════════════════════════════════════════════════════════════════
// Proxmox API Client
// ════════════════════════════════════════════════════════════════════════════

// ProxmoxClient wraps an *http.Client configured for the Proxmox REST API.
type ProxmoxClient struct {
	http     *http.Client
	baseURL  string
	apiToken string
	node     string
}

func newProxmoxClient(cfg Config) *ProxmoxClient {
	return &ProxmoxClient{
		http: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 120 * time.Second,
		},
		baseURL:  strings.TrimRight(cfg.ProxmoxURL, "/"),
		apiToken: cfg.APIToken,
		node:     cfg.Node,
	}
}

// apiDo performs a raw HTTP request and returns the JSON "data" field from the
// Proxmox envelope { "data": ... }.
func (c *ProxmoxClient) apiDo(method, path string, body io.Reader, contentType string) (interface{}, error) {
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "PVEAPIToken="+c.apiToken)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API %s %s → %d: %s", method, path, resp.StatusCode, string(raw))
	}

	var envelope map[string]interface{}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("json decode: %w (body: %s)", err, string(raw))
	}
	return envelope["data"], nil
}

func (c *ProxmoxClient) postForm(path string, vals url.Values) (interface{}, error) {
	return c.apiDo("POST", path, strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded")
}

func (c *ProxmoxClient) putForm(path string, vals url.Values) (interface{}, error) {
	return c.apiDo("PUT", path, strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded")
}

func (c *ProxmoxClient) get(path string) (interface{}, error) {
	return c.apiDo("GET", path, nil, "")
}

// ════════════════════════════════════════════════════════════════════════════
// VMID Allocation
// ════════════════════════════════════════════════════════════════════════════

// existingVMIDs queries /cluster/resources?type=vm and returns a set of all
// VMIDs currently in use across the cluster.
func (c *ProxmoxClient) existingVMIDs() (map[int]bool, error) {
	data, err := c.get("/api2/json/cluster/resources?type=vm")
	if err != nil {
		return nil, fmt.Errorf("list VMs: %w", err)
	}

	used := make(map[int]bool)
	if arr, ok := data.([]interface{}); ok {
		for _, item := range arr {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if vmid, ok := m["vmid"].(float64); ok {
				used[int(vmid)] = true
			}
		}
	}
	return used, nil
}

// allocateVMIDs finds `count` free VMIDs >= startID. It queries the cluster
// once and then scans locally — no per-ID API calls that might 400.
func (c *ProxmoxClient) allocateVMIDs(startID, count int) ([]int, error) {
	used, err := c.existingVMIDs()
	if err != nil {
		return nil, err
	}

	var ids []int
	candidate := startID
	for len(ids) < count {
		if candidate > 999999999 {
			return nil, fmt.Errorf("VMID space exhausted")
		}
		if !used[candidate] {
			ids = append(ids, candidate)
		}
		candidate++
	}
	return ids, nil
}

// ════════════════════════════════════════════════════════════════════════════
// Clone + Task Wait
// ════════════════════════════════════════════════════════════════════════════

func (c *ProxmoxClient) cloneVM(templateID, newVMID int, name string) (string, error) {
	path := fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/clone", c.node, templateID)
	data, err := c.postForm(path, url.Values{
		"newid": {strconv.Itoa(newVMID)},
		"name":  {name},
		"full":  {"1"},
	})
	if err != nil {
		return "", fmt.Errorf("clone API: %w", err)
	}
	upid, ok := data.(string)
	if !ok {
		return "", fmt.Errorf("expected UPID string, got %T: %v", data, data)
	}
	return upid, nil
}

func (c *ProxmoxClient) waitForTask(upid string) error {
	path := fmt.Sprintf("/api2/json/nodes/%s/tasks/%s/status", c.node, url.PathEscape(upid))
	for {
		data, err := c.get(path)
		if err != nil {
			return fmt.Errorf("polling task: %w", err)
		}
		m, ok := data.(map[string]interface{})
		if !ok {
			return fmt.Errorf("unexpected task payload: %v", data)
		}
		status, _ := m["status"].(string)
		if status == "stopped" {
			exitStatus, _ := m["exitstatus"].(string)
			if exitStatus == "OK" {
				return nil
			}
			return fmt.Errorf("task exited with: %s", exitStatus)
		}
		time.Sleep(3 * time.Second)
	}
}

// ════════════════════════════════════════════════════════════════════════════
// Hardware Configuration
// ════════════════════════════════════════════════════════════════════════════

func (c *ProxmoxClient) configureHardware(vmID, cores, memory int) error {
	path := fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/config", c.node, vmID)
	_, err := c.putForm(path, url.Values{
		"cores":  {strconv.Itoa(cores)},
		"memory": {strconv.Itoa(memory)},
		"agent":  {"1"},
	})
	return err
}

func (c *ProxmoxClient) resizeDisk(vmID int, disk, size string) error {
	path := fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/resize", c.node, vmID)
	_, err := c.putForm(path, url.Values{
		"disk": {disk},
		"size": {size},
	})
	return err
}

// ════════════════════════════════════════════════════════════════════════════
// SSH Certificate Authority
// ════════════════════════════════════════════════════════════════════════════

type SSHCertResult struct {
	CAPubKey    string
	UserPubKey  string
	PrivKeyFile string
	CertFile    string
}

// generateSSHCert creates a fresh Ed25519 key pair, signs it with the CA, and
// writes the private key and certificate to disk. Each VM gets its own key
// pair under a unique filename derived from the VM name.
func generateSSHCert(caKeyPath, vmName string, principals []string, validity time.Duration) (*SSHCertResult, error) {
	caRaw, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key %s: %w", caKeyPath, err)
	}
	caSigner, err := ssh.ParsePrivateKey(caRaw)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	caPubKeyStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(caSigner.PublicKey())))

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ssh public key: %w", err)
	}
	userPubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	var serialBuf [8]byte
	if _, err := rand.Read(serialBuf[:]); err != nil {
		return nil, fmt.Errorf("random serial: %w", err)
	}

	now := time.Now()
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             sshPub,
		KeyId:           "atlas-" + vmName,
		Serial:          binary.BigEndian.Uint64(serialBuf[:]),
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Add(-1 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(validity).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-user-rc":          "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		return nil, fmt.Errorf("sign cert: %w", err)
	}

	privBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}

	// Each VM gets its own key file so parallel provisioning doesn't clobber.
	privPath := fmt.Sprintf("./%s_key", vmName)
	certPath := fmt.Sprintf("./%s_key-cert.pub", vmName)

	if err := os.WriteFile(privPath, pem.EncodeToMemory(privBlock), 0600); err != nil {
		return nil, fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0644); err != nil {
		return nil, fmt.Errorf("write cert: %w", err)
	}

	return &SSHCertResult{
		CAPubKey:    caPubKeyStr,
		UserPubKey:  userPubStr,
		PrivKeyFile: privPath,
		CertFile:    certPath,
	}, nil
}

// ════════════════════════════════════════════════════════════════════════════
// Cloud-Init
// ════════════════════════════════════════════════════════════════════════════

func buildCloudInitUserData(user, caPubKey, userPubKey string) string {
	return fmt.Sprintf(`#cloud-config
users:
  - name: %s
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - %s

package_update: true
packages:
  - qemu-guest-agent

write_files:
  - path: /etc/ssh/ca.pub
    content: |
      %s
    owner: root:root
    permissions: '0644'
  - path: /etc/ssh/sshd_config.d/trusted_ca.conf
    content: |
      TrustedUserCAKeys /etc/ssh/ca.pub
    owner: root:root
    permissions: '0644'

runcmd:
  - systemctl enable --now qemu-guest-agent
  - systemctl restart sshd
`, user, userPubKey, caPubKey)
}

func writeSnippetViaSSH(host, port, user, keyPath, snippetDir, filename, content string) error {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read SSH key %s: %w", keyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("parse SSH key: %w", err)
	}

	clientCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := host + ":" + port
	client, err := ssh.Dial("tcp", addr, clientCfg)
	if err != nil {
		return fmt.Errorf("SSH dial %s: %w", addr, err)
	}
	defer client.Close()

	mkdirSess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session (mkdir): %w", err)
	}
	_ = mkdirSess.Run(fmt.Sprintf("mkdir -p '%s'", snippetDir))
	mkdirSess.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session (write): %w", err)
	}
	defer session.Close()

	filePath := snippetDir + "/" + filename
	session.Stdin = strings.NewReader(content)
	if err := session.Run(fmt.Sprintf("cat > '%s'", filePath)); err != nil {
		return fmt.Errorf("write %s: %w", filePath, err)
	}
	return nil
}

func proxmoxHost(proxmoxURL string) (string, error) {
	u, err := url.Parse(proxmoxURL)
	if err != nil {
		return "", fmt.Errorf("parse URL %q: %w", proxmoxURL, err)
	}
	h := u.Hostname()
	if h == "" {
		return "", fmt.Errorf("no host in URL %q", proxmoxURL)
	}
	return h, nil
}

func (c *ProxmoxClient) injectCloudInit(vmID int, storage, snippetFilename string) error {
	path := fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/config", c.node, vmID)
	cicustom := fmt.Sprintf("user=%s:snippets/%s", storage, snippetFilename)
	_, err := c.putForm(path, url.Values{
		"cicustom":  {cicustom},
		"ipconfig0": {"ip=dhcp"},
	})
	return err
}

// ════════════════════════════════════════════════════════════════════════════
// Boot + IP Discovery
// ════════════════════════════════════════════════════════════════════════════

func (c *ProxmoxClient) startVM(vmID int) error {
	path := fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/status/start", c.node, vmID)
	_, err := c.postForm(path, url.Values{})
	return err
}

func (c *ProxmoxClient) stopVM(vmID int) error {
	path := fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/status/stop", c.node, vmID)
	_, err := c.postForm(path, url.Values{})
	return err
}

func (c *ProxmoxClient) rebootVM(vmID int) error {
	path := fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/status/reboot", c.node, vmID)
	_, err := c.postForm(path, url.Values{})
	return err
}

func (c *ProxmoxClient) deleteVM(vmID int) error {
	path := fmt.Sprintf("/api2/json/nodes/%s/qemu/%d", c.node, vmID)
	_, err := c.apiDo("DELETE", path, nil, "")
	return err
}

// listVMs returns all VMs from the Proxmox cluster with their details.
func (c *ProxmoxClient) listVMs() ([]map[string]interface{}, error) {
	data, err := c.get("/api2/json/cluster/resources?type=vm")
	if err != nil {
		return nil, fmt.Errorf("list VMs: %w", err)
	}

	var vms []map[string]interface{}
	if arr, ok := data.([]interface{}); ok {
		for _, item := range arr {
			if m, ok := item.(map[string]interface{}); ok {
				vms = append(vms, m)
			}
		}
	}
	return vms, nil
}

func (c *ProxmoxClient) waitForIP(vmID int, maxAttempts int, interval time.Duration) (string, error) {
	path := fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/agent/network-get-interfaces", c.node, vmID)
	for i := 1; i <= maxAttempts; i++ {
		data, err := c.get(path)
		if err != nil {
			time.Sleep(interval)
			continue
		}
		if ip := extractIPv4(data); ip != "" {
			return ip, nil
		}
		time.Sleep(interval)
	}
	return "", fmt.Errorf("timed out after %d attempts", maxAttempts)
}

func extractIPv4(data interface{}) string {
	var ifaces []interface{}
	switch v := data.(type) {
	case map[string]interface{}:
		if arr, ok := v["result"].([]interface{}); ok {
			ifaces = arr
		}
	case []interface{}:
		ifaces = v
	}
	for _, raw := range ifaces {
		iface, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if name, _ := iface["name"].(string); name == "lo" {
			continue
		}
		addrs, _ := iface["ip-addresses"].([]interface{})
		for _, a := range addrs {
			entry, ok := a.(map[string]interface{})
			if !ok {
				continue
			}
			ipType, _ := entry["ip-address-type"].(string)
			ipAddr, _ := entry["ip-address"].(string)
			if ipType == "ipv4" && ipAddr != "" && ipAddr != "127.0.0.1" {
				return ipAddr
			}
		}
	}
	return ""
}

// ════════════════════════════════════════════════════════════════════════════
// Per-VM Provisioning Pipeline
// ════════════════════════════════════════════════════════════════════════════

// VMSpec is the resolved identity for a single VM before provisioning.
type VMSpec struct {
	VMID int
	Name string
}

// VMResult is returned by each provisioning goroutine.
type VMResult struct {
	Spec        VMSpec
	IP          string
	PrivKeyFile string
	Err         error
}

// provisionVM runs the full 6-step pipeline for a single VM. It is safe to
// call concurrently — each invocation uses its own VMID, name, and key files.
//
// If emit is non-nil, structured ProvisionEvent updates are sent for each step,
// enabling real-time progress in the web UI.  When emit is nil, only stdout
// logging is performed (CLI mode).
func provisionVM(cfg Config, pve *ProxmoxClient, pveHost string, spec VMSpec, emit func(ProvisionEvent)) VMResult {
	// send pushes a structured event (web UI) and logs to stdout.
	send := func(step, message string) {
		fmt.Printf("[vm %d / %s] %s\n", spec.VMID, spec.Name, message)
		if emit != nil {
			emit(ProvisionEvent{VMID: spec.VMID, VMName: spec.Name, Step: step, Message: message})
		}
	}

	result := VMResult{Spec: spec}
	fail := func(format string, a ...interface{}) VMResult {
		result.Err = fmt.Errorf(format, a...)
		fmt.Printf("[vm %d / %s] FAILED: %v\n", spec.VMID, spec.Name, result.Err)
		if emit != nil {
			emit(ProvisionEvent{VMID: spec.VMID, VMName: spec.Name, Step: "failed", Message: result.Err.Error(), Error: result.Err.Error()})
		}
		return result
	}

	// 1. Clone
	send("cloning", fmt.Sprintf("Cloning template %d…", cfg.TemplateID))
	upid, err := pve.cloneVM(cfg.TemplateID, spec.VMID, spec.Name)
	if err != nil {
		return fail("clone: %v", err)
	}

	// 2. Wait for clone
	send("clone_wait", "Waiting for clone…")
	if err := pve.waitForTask(upid); err != nil {
		return fail("clone task: %v", err)
	}
	send("clone_done", "✓ Clone complete")

	// 3. Hardware + disk
	send("configuring", fmt.Sprintf("Configuring hardware (cores=%d mem=%dMiB disk=%s)…", cfg.Cores, cfg.Memory, cfg.DiskSize))
	if err := pve.configureHardware(spec.VMID, cfg.Cores, cfg.Memory); err != nil {
		return fail("hardware: %v", err)
	}
	if err := pve.resizeDisk(spec.VMID, cfg.DiskDevice, cfg.DiskSize); err != nil {
		return fail("resize: %v", err)
	}

	// 4. SSH cert + Cloud-Init
	send("generating_cert", "Generating SSH certificate…")
	certResult, err := generateSSHCert(cfg.CAKeyPath, spec.Name, []string{cfg.User}, cfg.CertValidity)
	if err != nil {
		return fail("ssh cert: %v", err)
	}
	result.PrivKeyFile = certResult.PrivKeyFile

	userData := buildCloudInitUserData(cfg.User, certResult.CAPubKey, certResult.UserPubKey)
	snippetName := fmt.Sprintf("vm-%d-user-data.yml", spec.VMID)

	send("writing_snippet", "Writing Cloud-Init snippet…")
	if err := writeSnippetViaSSH(pveHost, cfg.PVESSHPort, cfg.PVESSHUser, cfg.PVESSHKey, cfg.SnippetDir, snippetName, userData); err != nil {
		return fail("snippet write: %v", err)
	}
	if err := pve.injectCloudInit(spec.VMID, cfg.SnippetStore, snippetName); err != nil {
		return fail("cloud-init inject: %v", err)
	}

	// 5. Boot
	send("booting", "Starting VM…")
	if err := pve.startVM(spec.VMID); err != nil {
		return fail("start: %v", err)
	}

	// 6. IP discovery
	send("waiting_ip", "Waiting for IP (guest agent)…")
	ip, err := pve.waitForIP(spec.VMID, 90, 5*time.Second)
	if err != nil {
		return fail("ip discovery: %v", err)
	}
	result.IP = ip

	// Final "ready" event with IP and key file.
	fmt.Printf("[vm %d / %s] ✓ Ready at %s\n", spec.VMID, spec.Name, ip)
	if emit != nil {
		emit(ProvisionEvent{
			VMID: spec.VMID, VMName: spec.Name,
			Step: "ready", Message: fmt.Sprintf("Ready at %s", ip),
			IP: ip, KeyFile: result.PrivKeyFile,
		})
	}

	return result
}

// ════════════════════════════════════════════════════════════════════════════
// Orchestrator
// ════════════════════════════════════════════════════════════════════════════

func main() {
	cfg := loadConfig()

	if cfg.APIToken == "" {
		fatalf("PROXMOX_API_TOKEN is required.\n  Format: USER@REALM!TOKENID=SECRET\n  Example: root@pam!atlas=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
	}

	// Subcommand: "serve" starts the web UI.
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		port := envOr("ATLAS_WEB_PORT", "8080")
		startWebServer(cfg, port)
		return
	}

	// CLI mode — provision VMs from the command line.
	if cfg.VMCount < 1 {
		fatalf("VM_COUNT must be >= 1 (got %d)", cfg.VMCount)
	}

	pve := newProxmoxClient(cfg)

	pveHost, err := proxmoxHost(cfg.ProxmoxURL)
	if err != nil {
		fatalf("Cannot determine Proxmox host: %v", err)
	}

	// ── Allocate VMIDs ───────────────────────────────────────────────────
	ids, err := pve.allocateVMIDs(cfg.VMStartID, cfg.VMCount)
	if err != nil {
		fatalf("VMID allocation failed: %v", err)
	}

	// Build specs — use VM_NAME if set, otherwise random names.
	specs := make([]VMSpec, cfg.VMCount)
	for i, id := range ids {
		specs[i] = VMSpec{VMID: id, Name: vmName(cfg.VMName, i, cfg.VMCount)}
	}

	// ── Banner ───────────────────────────────────────────────────────────
	fmt.Printf("\n════════════════════════════════════════\n   Atlas Plane — VM Provisioner\n════════════════════════════════════════\n")
	fmt.Printf("  Proxmox  : %s (node: %s)\n", cfg.ProxmoxURL, cfg.Node)
	fmt.Printf("  Template : %d\n", cfg.TemplateID)
	fmt.Printf("  Specs    : %d vCPU, %d MiB RAM, %s disk\n", cfg.Cores, cfg.Memory, cfg.DiskSize)
	fmt.Printf("  VMs      : %d\n", cfg.VMCount)
	for _, s := range specs {
		fmt.Printf("             → %d  %s\n", s.VMID, s.Name)
	}
	fmt.Println()

	// ── Provision in parallel ────────────────────────────────────────────
	results := make([]VMResult, cfg.VMCount)
	var wg sync.WaitGroup

	for i, spec := range specs {
		wg.Add(1)
		go func(idx int, s VMSpec) {
			defer wg.Done()
			results[idx] = provisionVM(cfg, pve, pveHost, s, nil)
		}(i, spec)
	}

	wg.Wait()

	// ── Summary ──────────────────────────────────────────────────────────
	fmt.Printf("\n════════════════════════════════════════\n   Results\n════════════════════════════════════════\n")

	var success, failed int
	sort.Slice(results, func(i, j int) bool {
		return results[i].Spec.VMID < results[j].Spec.VMID
	})

	for _, r := range results {
		if r.Err != nil {
			fmt.Printf("  ❌  VM %d (%s): %v\n", r.Spec.VMID, r.Spec.Name, r.Err)
			failed++
		} else {
			fmt.Printf("  ✅  VM %d (%s) — %s\n", r.Spec.VMID, r.Spec.Name, r.IP)
			fmt.Printf("      ssh -i %s %s@%s\n", r.PrivKeyFile, cfg.User, r.IP)
			success++
		}
	}

	fmt.Printf("\n  %d succeeded, %d failed\n", success, failed)
	fmt.Println("════════════════════════════════════════")

	if failed > 0 {
		os.Exit(1)
	}
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\nFATAL: "+format+"\n", args...)
	os.Exit(1)
}
