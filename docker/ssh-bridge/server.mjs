import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { Client as SSHClient } from 'ssh2';
import { Server as SocketIOServer } from 'socket.io';

const PORT = Number.parseInt(process.env.PORT || '3002', 10);
const KEY_DIR = process.env.KEY_VAULT_DIR || '/keys';
const INDEX_PATH = path.join(KEY_DIR, 'index.json');
const BACKEND_URL = (process.env.ATLAS_BACKEND_URL || 'http://backend:8080').replace(/\/+$/, '');
const SSH_PORT = Number.parseInt(process.env.SSH_PORT || '22', 10);
const DEFAULT_SSH_USER = process.env.SSH_USER || 'debian';
const FRONTEND_ORIGIN = process.env.ATLAS_FRONTEND_ORIGIN || '*';

const MASTER_KEY = decodeMasterKey(process.env.MASTER_ENCRYPTION_KEY || '');

const httpServer = createServer((req, res) => {
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ status: 'ok', service: 'atlas-ssh-bridge' }));
});

const io = new SocketIOServer(httpServer, {
  cors: {
    origin: FRONTEND_ORIGIN,
    methods: ['GET', 'POST'],
  },
  transports: ['websocket', 'polling'],
});

io.on('connection', (socket) => {
  let sshClient = null;
  let sshStream = null;
  let closed = false;

  const cleanup = () => {
    if (closed) return;
    closed = true;
    try {
      if (sshStream) {
        sshStream.removeAllListeners();
        sshStream.end();
        sshStream = null;
      }
    } catch {
      // no-op
    }
    try {
      if (sshClient) {
        sshClient.removeAllListeners();
        sshClient.end();
        sshClient = null;
      }
    } catch {
      // no-op
    }
  };

  socket.on('ssh:connect', async (payload = {}) => {
    if (sshClient || sshStream) {
      socket.emit('ssh:error', { message: 'SSH session already active on this socket.' });
      return;
    }

    const vmId = Number.parseInt(String(payload.vmId || ''), 10);
    if (!Number.isInteger(vmId) || vmId <= 0) {
      socket.emit('ssh:error', { message: 'Invalid vmId.' });
      return;
    }

    const cols = sanitizeDimension(payload.cols, 120);
    const rows = sanitizeDimension(payload.rows, 32);

    try {
      const connectInfo = await fetchConnectInfo(vmId);
      const privateKey = await loadPrivateKeyForVM(connectInfo.vmid);

      sshClient = new SSHClient();

      sshClient.on('ready', () => {
        sshClient.shell(
          {
            term: 'xterm-256color',
            cols,
            rows,
          },
          (shellErr, stream) => {
            if (shellErr) {
              socket.emit('ssh:error', { message: `Failed to start shell: ${shellErr.message}` });
              cleanup();
              return;
            }

            sshStream = stream;
            socket.emit('ssh:ready', {
              vmid: connectInfo.vmid,
              vmName: connectInfo.vmName,
              user: connectInfo.user,
              host: connectInfo.host,
            });

            stream.on('data', (chunk) => socket.emit('ssh:data', chunk.toString('utf8')));
            stream.stderr?.on('data', (chunk) => socket.emit('ssh:data', chunk.toString('utf8')));

            stream.on('close', () => {
              socket.emit('ssh:closed');
              cleanup();
            });
          }
        );
      });

      sshClient.on('error', (err) => {
        socket.emit('ssh:error', { message: `SSH error: ${err.message}` });
        cleanup();
      });

      sshClient.on('close', () => {
        socket.emit('ssh:closed');
        cleanup();
      });

      sshClient.connect({
        host: connectInfo.host,
        port: SSH_PORT,
        username: connectInfo.user || DEFAULT_SSH_USER,
        privateKey,
        readyTimeout: 20000,
      });

      privateKey.fill(0);
    } catch (err) {
      socket.emit('ssh:error', { message: err.message || 'Failed to start SSH session.' });
      cleanup();
    }
  });

  socket.on('ssh:input', (data) => {
    if (!sshStream) return;
    if (typeof data !== 'string' || data.length === 0) return;
    sshStream.write(data);
  });

  socket.on('ssh:resize', ({ cols, rows } = {}) => {
    if (!sshStream) return;
    const nextCols = sanitizeDimension(cols, 120);
    const nextRows = sanitizeDimension(rows, 32);
    try {
      sshStream.setWindow(nextRows, nextCols, 0, 0);
    } catch {
      // ignore transient resize errors
    }
  });

  socket.on('ssh:disconnect', cleanup);
  socket.on('disconnect', cleanup);
});

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`atlas-ssh-bridge listening on :${PORT}`);
});

function sanitizeDimension(value, fallback) {
  const n = Number.parseInt(String(value || ''), 10);
  if (!Number.isFinite(n) || n < 1) return fallback;
  return Math.min(Math.max(n, 1), 1000);
}

async function fetchConnectInfo(vmId) {
  const response = await fetch(`${BACKEND_URL}/api/vms/${vmId}/ssh-connect`);
  let payload = {};
  try {
    payload = await response.json();
  } catch {
    payload = {};
  }
  if (!response.ok) {
    throw new Error(payload.error || `Failed to fetch connect info for VM ${vmId}.`);
  }

  if (!payload.host) {
    throw new Error(`No reachable IP found for VM ${vmId}.`);
  }

  return {
    vmid: Number(payload.vmid),
    vmName: String(payload.vmName || `vm-${vmId}`),
    host: String(payload.host),
    user: String(payload.user || DEFAULT_SSH_USER),
  };
}

function decodeMasterKey(value) {
  const raw = String(value || '').trim();
  if (!raw) {
    throw new Error('MASTER_ENCRYPTION_KEY is required');
  }

  if (raw.length === 64 && /^[0-9a-fA-F]+$/.test(raw)) {
    const hex = Buffer.from(raw, 'hex');
    if (hex.length === 32) return hex;
  }

  for (const encoding of ['base64', 'base64url']) {
    try {
      const decoded = Buffer.from(raw, encoding);
      if (decoded.length === 32) return decoded;
    } catch {
      // ignore
    }
  }

  const utf8 = Buffer.from(raw, 'utf8');
  if (utf8.length === 32) return utf8;

  throw new Error(
    'MASTER_ENCRYPTION_KEY must decode to exactly 32 bytes (accepted: 64-char hex, base64, or raw 32-byte string)'
  );
}

async function readVaultIndex() {
  const contents = await readFile(INDEX_PATH, 'utf8');
  const parsed = JSON.parse(contents);
  const records = Array.isArray(parsed.records) ? parsed.records : [];
  return records;
}

async function loadPrivateKeyForVM(vmid) {
  const records = await readVaultIndex();
  const record = records.find((entry) => Number(entry.vmid) === vmid);
  if (!record) {
    throw new Error(`Encrypted key record not found for VM ${vmid}.`);
  }

  const blobPath = path.join(KEY_DIR, String(record.cipherFile || ''));
  if (!record.cipherFile) {
    throw new Error(`Encrypted key file is missing for VM ${vmid}.`);
  }

  const blob = await readFile(blobPath);
  const nonceLength = 12;
  const tagLength = 16;
  if (blob.length <= nonceLength + tagLength) {
    throw new Error('Encrypted key blob is invalid.');
  }

  const nonce = blob.subarray(0, nonceLength);
  const bodyAndTag = blob.subarray(nonceLength);
  const ciphertext = bodyAndTag.subarray(0, bodyAndTag.length - tagLength);
  const tag = bodyAndTag.subarray(bodyAndTag.length - tagLength);

  const aad = Buffer.from(`${record.vmid}:${record.downloadName}`, 'utf8');
  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  return plain;
}