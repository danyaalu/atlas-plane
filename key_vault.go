package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type sshKeyRecord struct {
	VMID         int       `json:"vmid"`
	VMName       string    `json:"vmName"`
	DownloadName string    `json:"downloadName"`
	CipherFile   string    `json:"cipherFile"`
	CreatedAt    time.Time `json:"createdAt"`
}

type sshKeyVaultState struct {
	Records []sshKeyRecord `json:"records"`
}

type SSHKeyVault struct {
	dir       string
	indexPath string
	aead      cipher.AEAD

	mu         sync.Mutex
	records    map[int]sshKeyRecord
	nameToVMID map[string]int
}

var vmKeyNameSanitizer = regexp.MustCompile(`[^a-z0-9-]`)

func newSSHKeyVault(dir string) (*SSHKeyVault, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("key vault directory is required")
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create key vault dir: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("secure key vault dir permissions: %w", err)
	}

	masterKey, err := loadMasterKeyFromEnv()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}

	v := &SSHKeyVault{
		dir:        dir,
		indexPath:  filepath.Join(dir, "index.json"),
		aead:       aead,
		records:    make(map[int]sshKeyRecord),
		nameToVMID: make(map[string]int),
	}
	if err := v.loadIndex(); err != nil {
		return nil, err
	}

	return v, nil
}

func loadMasterKeyFromEnv() ([]byte, error) {
	v := strings.TrimSpace(os.Getenv("MASTER_ENCRYPTION_KEY"))
	if v == "" {
		return nil, fmt.Errorf("MASTER_ENCRYPTION_KEY is required")
	}

	if len(v) == 64 {
		if decoded, err := hex.DecodeString(v); err == nil {
			if len(decoded) == 32 {
				return decoded, nil
			}
		}
	}

	if decoded, err := base64.StdEncoding.DecodeString(v); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(v); err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	if len(v) == 32 {
		return []byte(v), nil
	}

	return nil, fmt.Errorf("MASTER_ENCRYPTION_KEY must decode to exactly 32 bytes (accepted: 64-char hex, base64, or raw 32-byte string)")
}

func (v *SSHKeyVault) loadIndex() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	b, err := os.ReadFile(v.indexPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read key vault index: %w", err)
	}

	var state sshKeyVaultState
	if err := json.Unmarshal(b, &state); err != nil {
		return fmt.Errorf("parse key vault index: %w", err)
	}

	for _, rec := range state.Records {
		v.records[rec.VMID] = rec
		v.nameToVMID[rec.DownloadName] = rec.VMID
	}
	return nil
}

func (v *SSHKeyVault) saveIndexLocked() error {
	records := make([]sshKeyRecord, 0, len(v.records))
	for _, rec := range v.records {
		records = append(records, rec)
	}

	state := sshKeyVaultState{Records: records}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal key vault index: %w", err)
	}

	tmp := v.indexPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return fmt.Errorf("write key vault index: %w", err)
	}
	if err := os.Rename(tmp, v.indexPath); err != nil {
		return fmt.Errorf("replace key vault index: %w", err)
	}
	return nil
}

func sanitizeKeyName(vmName string, vmID int) string {
	name := strings.ToLower(strings.TrimSpace(vmName))
	name = vmKeyNameSanitizer.ReplaceAllString(name, "-")
	name = strings.Trim(name, "-")
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	if name == "" {
		name = fmt.Sprintf("vm-%d", vmID)
	}
	return name + "_key"
}

func randomHexString(byteLen int) string {
	b := make([]byte, byteLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (v *SSHKeyVault) StorePrivateKey(vmid int, vmName string, privateKeyPEM []byte) (string, error) {
	if vmid <= 0 {
		return "", fmt.Errorf("invalid vmid %d", vmid)
	}
	if len(privateKeyPEM) == 0 {
		return "", fmt.Errorf("private key is empty")
	}

	downloadName := sanitizeKeyName(vmName, vmid)
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	aad := []byte(fmt.Sprintf("%d:%s", vmid, downloadName))
	ciphertext := v.aead.Seal(nil, nonce, privateKeyPEM, aad)

	cipherFile := randomHexString(12) + ".enc"
	fullPath := filepath.Join(v.dir, cipherFile)
	blob := append(nonce, ciphertext...)
	if err := os.WriteFile(fullPath, blob, 0600); err != nil {
		return "", fmt.Errorf("write encrypted key: %w", err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if prev, ok := v.records[vmid]; ok {
		_ = os.Remove(filepath.Join(v.dir, prev.CipherFile))
		delete(v.nameToVMID, prev.DownloadName)
	}

	rec := sshKeyRecord{
		VMID:         vmid,
		VMName:       vmName,
		DownloadName: downloadName,
		CipherFile:   cipherFile,
		CreatedAt:    time.Now(),
	}
	v.records[vmid] = rec
	v.nameToVMID[downloadName] = vmid

	if err := v.saveIndexLocked(); err != nil {
		return "", err
	}
	return downloadName, nil
}

func (v *SSHKeyVault) HasKeyForVM(vmid int) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.records[vmid]
	return ok
}

func (v *SSHKeyVault) KeyFileNameForVM(vmid int) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	rec, ok := v.records[vmid]
	if !ok {
		return ""
	}
	return rec.DownloadName
}

func (v *SSHKeyVault) GetPrivateKeyByVMID(vmid int) (string, []byte, error) {
	v.mu.Lock()
	rec, ok := v.records[vmid]
	v.mu.Unlock()
	if !ok {
		return "", nil, os.ErrNotExist
	}
	return v.decryptRecord(rec)
}

func (v *SSHKeyVault) GetPrivateKeyByFilename(filename string) (string, []byte, error) {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return "", nil, os.ErrNotExist
	}

	v.mu.Lock()
	vmid, ok := v.nameToVMID[filename]
	rec := v.records[vmid]
	v.mu.Unlock()
	if !ok {
		return "", nil, os.ErrNotExist
	}
	return v.decryptRecord(rec)
}

func (v *SSHKeyVault) decryptRecord(rec sshKeyRecord) (string, []byte, error) {
	b, err := os.ReadFile(filepath.Join(v.dir, rec.CipherFile))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil, os.ErrNotExist
		}
		return "", nil, fmt.Errorf("read encrypted key: %w", err)
	}

	nonceSize := v.aead.NonceSize()
	if len(b) <= nonceSize {
		return "", nil, fmt.Errorf("encrypted key file is invalid")
	}

	nonce := b[:nonceSize]
	ciphertext := b[nonceSize:]
	aad := []byte(fmt.Sprintf("%d:%s", rec.VMID, rec.DownloadName))
	plain, err := v.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return "", nil, fmt.Errorf("decrypt key: %w", err)
	}

	return rec.DownloadName, plain, nil
}
