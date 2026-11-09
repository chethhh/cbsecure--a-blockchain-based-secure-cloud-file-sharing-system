export type User = {
  id: string;
  name: string;
  email: string;
  role: "Admin" | "Editor" | "Reader";
  walletAddress: string | null;
  walletVerified?: boolean;
};

export type FileRecord = {
  id: string;
  originalName: string;
  size: number;
  mimeType: string;
  ipfsCid: string;
  sha256Hash: string;
  iv: string;
  wrappedKey: string;
  wrapIv: string;
  salt: string;
  storage: "local" | "ipfs" | "blob" | "gcs";
  ownerId: string;
  ownerEmail: string;
  ownerWallet: string | null;
  blockchainFileId: string | null;
  transactionHash: string | null;
  createdAt: string;
};

export type SharedFile = {
  grantId: string;
  permissionLevel: number;
  wrappedKey: string;
  timestamp: string;
  file: FileRecord;
};

export type SharedFilesResponse = { items: SharedFile[]; count: number };
export type FileSummary = { totalCount: number; ownCount: number; sharedCount: number };

const API_ROOT = import.meta.env.VITE_API_URL || "/api";
let sessionToken = "";

export function setToken(token: string) {
  sessionToken = token;
}

export function getToken() {
  return sessionToken;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (sessionToken) headers.set("Authorization", "Bearer " + sessionToken);
  if (init.body && !(init.body instanceof FormData)) headers.set("Content-Type", "application/json");
  const response = await fetch(API_ROOT + path, { ...init, headers });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || "Request failed (" + response.status + ").");
  }
  return response.json() as Promise<T>;
}

export const api = {
  login: (email: string, password: string) =>
    request<{ challengeId: string }>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  register: (name: string, email: string, password: string) =>
    request<{ challengeId: string }>("/auth/register", { method: "POST", body: JSON.stringify({ name, email, password }) }),
  verifyOtp: (challengeId: string, code: string) =>
    request<{ token: string; user: User }>("/auth/verify-otp", { method: "POST", body: JSON.stringify({ challengeId, code }) }),
  walletNonce: () => request<{ nonce: string }>("/auth/wallet-nonce"),
  bindWallet: (address: string, signature: string) =>
    request<{ user: User }>("/auth/verify-wallet", { method: "POST", body: JSON.stringify({ address, signature }) }),
  publishPublicKey: (publicKey: JsonWebKey) =>
    request<{ saved: boolean }>("/auth/public-key", { method: "PUT", body: JSON.stringify({ publicKey }) }),
  files: () => request<FileRecord[]>("/files"),
  fileSummary: () => request<FileSummary>("/files/summary"),
  shared: () => request<SharedFilesResponse>("/files/shared"),
  activity: () => request<ActivityItem[]>("/activity"),
  verifyActivity: () => request<{ valid: boolean; checkedEvents: number; checkedAt: string }>("/activity/verify"),
  logActivity: (action: "FILE_DECRYPTED" | "INTEGRITY_VERIFIED", details: string) =>
    request<{ recorded: boolean }>("/activity/record", { method: "POST", body: JSON.stringify({ action, details }) }),
  directory: () => request<Array<User & { publicKey: JsonWebKey | null }>>("/users/directory"),
  grants: (id: string) => request<GrantRecord[]>("/files/" + encodeURIComponent(id) + "/grants"),
  upload: async (file: File, encrypted: Uint8Array, metadata: {
    iv: string; wrappedKey: string; wrapIv: string; salt: string; sha256Hash: string;
  }) => {
    const form = new FormData();
    form.append("ciphertext", new Blob([encrypted.slice().buffer as ArrayBuffer]), "ciphertext.bin");
    form.append("originalName", file.name);
    form.append("mimeType", file.type || "application/octet-stream");
    form.append("size", String(file.size));
    Object.entries(metadata).forEach(([key, value]) => form.append(key, value));
    return request<{ file: FileRecord; message: string }>("/files/upload", { method: "POST", body: form });
  },
  replaceFile: async (id: string, file: File, encrypted: Uint8Array, metadata: { iv: string; sha256Hash: string }) => {
    const form = new FormData();
    form.append("ciphertext", new Blob([encrypted.slice().buffer as ArrayBuffer]), "ciphertext.bin");
    form.append("originalName", file.name);
    form.append("mimeType", file.type || "application/octet-stream");
    form.append("size", String(file.size));
    form.append("iv", metadata.iv);
    form.append("sha256Hash", metadata.sha256Hash);
    return request<{ file: FileRecord }>("/files/" + encodeURIComponent(id) + "/replace", { method: "PUT", body: form });
  },
  renameFile: (id: string, originalName: string) =>
    request<{ file: FileRecord }>("/files/" + encodeURIComponent(id), { method: "PUT", body: JSON.stringify({ originalName }) }),
  download: (id: string) =>
    fetch(API_ROOT + "/files/" + encodeURIComponent(id) + "/download", { headers: { Authorization: "Bearer " + sessionToken } })
      .then(async (response) => {
        if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || "Could not download encrypted file.");
        return response.arrayBuffer();
      }),
  share: (id: string, recipientAddress: string, permissionLevel: number, wrappedKey: string, transactionHash?: string) =>
    request<{ message: string }>("/files/" + encodeURIComponent(id) + "/share", { method: "POST", body: JSON.stringify({ recipientAddress, permissionLevel, wrappedKey, transactionHash }) }),
  revoke: (id: string, recipientAddress: string) =>
    request<{ message: string }>("/files/" + encodeURIComponent(id) + "/revoke", { method: "POST", body: JSON.stringify({ recipientAddress }) }),
  revokeWithTx: (id: string, recipientAddress: string, transactionHash: string) =>
    request<{ message: string }>("/files/" + encodeURIComponent(id) + "/revoke", { method: "POST", body: JSON.stringify({ recipientAddress, transactionHash }) }),
  registerOnChain: (id: string, blockchainFileId: string, transactionHash: string) =>
    request<{ file: FileRecord }>("/files/" + encodeURIComponent(id) + "/chain", { method: "POST", body: JSON.stringify({ blockchainFileId, transactionHash }) }),
  users: () => request<User[]>("/users"),
  updateRole: (id: string, role: User["role"]) =>
    request<{ user: User }>("/users/" + encodeURIComponent(id) + "/role", { method: "PUT", body: JSON.stringify({ role }) }),
};

export type GrantRecord = { grantId: string; fileId: string; recipientAddress: string; recipientEmail: string; permissionLevel: number; active: boolean; timestamp: string; transactionHash: string | null };

export type ActivityItem = {
  id: string;
  userEmail: string;
  action: string;
  details: string;
  timestamp: string;
  walletAddress: string | null;
};
