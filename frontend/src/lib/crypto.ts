const encoder = new TextEncoder();
const KDF_ITERATIONS = 310_000;

function asBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export async function sha256Hex(bytes: BufferSource): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function deriveWrappingKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: asBuffer(salt), iterations: KDF_ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export type ClientIdentity = { privateKey: CryptoKey; publicKey: JsonWebKey };
export type EnvelopeMetadata = {
  iv: string;
  wrappedKey: string;
  wrapIv: string;
  salt: string;
  sha256Hash: string;
};

const identityCache = new Map<string, ClientIdentity>();

export async function ensureIdentity(email: string, password: string): Promise<ClientIdentity> {
  const cached = identityCache.get(email);
  if (cached) return cached;
  const storageKey = "cbsecure.identity.v1." + email.toLowerCase();
  const stored = localStorage.getItem(storageKey);
  let identity: ClientIdentity;
  if (stored) {
    const record = JSON.parse(stored) as { salt: string; iv: string; encryptedPrivate: string; publicKey: JsonWebKey };
    const key = await deriveWrappingKey(password, fromBase64(record.salt));
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: asBuffer(fromBase64(record.iv)) },
      key,
      asBuffer(fromBase64(record.encryptedPrivate)),
    );
    const privateJwk = JSON.parse(new TextDecoder().decode(plaintext)) as JsonWebKey;
    identity = {
      privateKey: await crypto.subtle.importKey("jwk", privateJwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey"]),
      publicKey: record.publicKey,
    };
  } else {
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
    const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
    const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveWrappingKey(password, salt);
    const encryptedPrivate = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: asBuffer(iv) },
      key,
      asBuffer(encoder.encode(JSON.stringify(privateJwk))),
    ));
    localStorage.setItem(storageKey, JSON.stringify({
      salt: toBase64(salt),
      iv: toBase64(iv),
      encryptedPrivate: toBase64(encryptedPrivate),
      publicKey,
    }));
    identity = { privateKey: pair.privateKey, publicKey };
  }
  identityCache.set(email, identity);
  return identity;
}

async function getRawDek(metadata: EnvelopeMetadata, password: string): Promise<Uint8Array> {
  const wrappingKey = await deriveWrappingKey(password, fromBase64(metadata.salt));
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asBuffer(fromBase64(metadata.wrapIv)) },
    wrappingKey,
    asBuffer(fromBase64(metadata.wrappedKey)),
  ));
}

async function decryptPayload(ciphertext: ArrayBuffer, metadata: EnvelopeMetadata, rawDek: Uint8Array): Promise<Blob> {
  const dek = await crypto.subtle.importKey("raw", asBuffer(rawDek), { name: "AES-GCM" }, false, ["decrypt"]);
  rawDek.fill(0);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: asBuffer(fromBase64(metadata.iv)) }, dek, ciphertext);
  const actualHash = await sha256Hex(plaintext);
  if (actualHash !== metadata.sha256Hash.toLowerCase()) {
    throw new Error("Integrity check failed: the decrypted file does not match its SHA-256 digest.");
  }
  return new Blob([plaintext]);
}

export async function wrapDekForRecipient(metadata: EnvelopeMetadata, password: string, recipientPublicKey: JsonWebKey): Promise<string> {
  const rawDek = await getRawDek(metadata, password);
  try {
    const recipientKey = await crypto.subtle.importKey(
      "jwk",
      recipientPublicKey,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const ephemeral = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
    const sharedWrappingKey = await crypto.subtle.deriveKey(
      { name: "ECDH", public: recipientKey },
      ephemeral.privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"],
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrappedDek = await crypto.subtle.encrypt({ name: "AES-GCM", iv: asBuffer(iv) }, sharedWrappingKey, asBuffer(rawDek));
    const ephemeralPublicKey = await crypto.subtle.exportKey("jwk", ephemeral.publicKey);
    return JSON.stringify({ version: 1, ephemeralPublicKey, iv: toBase64(iv), wrappedDek: toBase64(new Uint8Array(wrappedDek)) });
  } finally {
    rawDek.fill(0);
  }
}

async function unwrapDekForRecipient(wrappedKey: string, identity: ClientIdentity): Promise<Uint8Array> {
  const bundle = JSON.parse(wrappedKey) as { version: number; ephemeralPublicKey: JsonWebKey; iv: string; wrappedDek: string };
  if (bundle.version !== 1) throw new Error("Unsupported recipient key package.");
  const ephemeralPublicKey = await crypto.subtle.importKey(
    "jwk",
    bundle.ephemeralPublicKey,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const sharedWrappingKey = await crypto.subtle.deriveKey(
    { name: "ECDH", public: ephemeralPublicKey },
    identity.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asBuffer(fromBase64(bundle.iv)) },
    sharedWrappingKey,
    asBuffer(fromBase64(bundle.wrappedDek)),
  ));
}

async function encryptReplacementContent(file: File, rawDek: Uint8Array): Promise<{ ciphertext: Uint8Array; iv: string; sha256Hash: string }> {
  try {
    const plaintext = await file.arrayBuffer();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const dek = await crypto.subtle.importKey("raw", asBuffer(rawDek), { name: "AES-GCM" }, false, ["encrypt"]);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: asBuffer(iv) }, dek, plaintext));
    return { ciphertext, iv: toBase64(iv), sha256Hash: await sha256Hex(plaintext) };
  } finally {
    rawDek.fill(0);
  }
}

export async function replaceOwnedFileContent(file: File, current: EnvelopeMetadata, password: string) {
  return encryptReplacementContent(file, await getRawDek(current, password));
}

export async function replaceSharedFileContent(file: File, wrappedKey: string, identity: ClientIdentity) {
  return encryptReplacementContent(file, await unwrapDekForRecipient(wrappedKey, identity));
}

export async function decryptSharedFile(
  ciphertext: ArrayBuffer,
  metadata: EnvelopeMetadata,
  wrappedKey: string,
  identity: ClientIdentity,
): Promise<Blob> {
  return decryptPayload(ciphertext, metadata, await unwrapDekForRecipient(wrappedKey, identity));
}

export async function encryptFile(file: File, password: string): Promise<{ ciphertext: Uint8Array; metadata: EnvelopeMetadata }> {
  const plaintext = await file.arrayBuffer();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const rawDek = crypto.getRandomValues(new Uint8Array(32));
  const dek = await crypto.subtle.importKey("raw", asBuffer(rawDek), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const wrappingKey = await deriveWrappingKey(password, salt);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: asBuffer(iv) }, dek, plaintext));
  const wrappedKey = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: asBuffer(wrapIv) }, wrappingKey, asBuffer(rawDek)));
  rawDek.fill(0);
  return {
    ciphertext,
    metadata: {
      iv: toBase64(iv),
      wrappedKey: toBase64(wrappedKey),
      wrapIv: toBase64(wrapIv),
      salt: toBase64(salt),
      sha256Hash: await sha256Hex(plaintext),
    },
  };
}

export async function decryptFile(ciphertext: ArrayBuffer, metadata: EnvelopeMetadata, password: string): Promise<Blob> {
  return decryptPayload(ciphertext, metadata, await getRawDek(metadata, password));
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return (bytes / 1024 ** exponent).toFixed(exponent === 0 ? 0 : 1) + " " + units[exponent];
}

