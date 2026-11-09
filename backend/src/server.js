import "dotenv/config";
import { AsyncLocalStorage } from "node:async_hooks";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import multer from "multer";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import { OAuth2Client } from "google-auth-library";
import { Pool } from "@neondatabase/serverless";
import { del as deleteBlob, head as headBlob, issueSignedToken, presignUrl } from "@vercel/blob";
import { handleUploadPresigned } from "@vercel/blob/client";
import { randomInt, createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyMessage, getAddress } from "ethers";

const here = path.dirname(fileURLToPath(import.meta.url));
const isVercel = Boolean(process.env.VERCEL || process.env.VERCEL_ENV);
const isRender = Boolean(process.env.RENDER || process.env.RENDER_SERVICE_ID);
const isNetlify = Boolean(process.env.NETLIFY);
const isServerless = isVercel || isNetlify;
const privateBlobConfigured = Boolean(process.env.BLOB_STORE_ID && process.env.BLOB_READ_WRITE_TOKEN);
const dataDir = process.env.CB_SECURE_DATA_DIR
  ? path.resolve(process.env.CB_SECURE_DATA_DIR)
  : isServerless ? path.join(tmpdir(), "cb-secure-runtime") : path.resolve(here, "../data");
const storageDir = path.join(dataDir, "storage");
const incomingDir = path.join(dataDir, "incoming");
const dbPath = path.join(dataDir, "db.json");
const app = express();
const port = Number(process.env.PORT || 3000);
const jwtSecret = process.env.JWT_SECRET || "";
const initialAdminEmail = String(process.env.INITIAL_ADMIN_EMAIL || "").trim().toLowerCase();
const googleClientId = String(process.env.GOOGLE_CLIENT_ID || "").trim();
const googleClient = googleClientId ? new OAuth2Client(googleClientId) : null;
const smtpConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
const databaseUrl = process.env.NETLIFY_DB_URL || process.env.DATABASE_URL || process.env.POSTGRES_URL || "";

if (!isServerless && jwtSecret.length < 32) throw new Error("Set JWT_SECRET to a random value with at least 32 characters.");
await mkdir(storageDir, { recursive: true });
await mkdir(incomingDir, { recursive: true });

const emptyDb = { users: [], files: [], grants: [], activity: [], challenges: [], walletNonces: [], pendingUploads: [] };
const dbContext = new AsyncLocalStorage();
let processDb;
let databasePool = null;
let databaseStartupError = "";
async function readDb() {
  try {
    return { ...emptyDb, ...JSON.parse(await readFile(dbPath, "utf8")) };
  } catch {
    return structuredClone(emptyDb);
  }
}
function currentDb() {
  return dbContext.getStore()?.db || processDb;
}
const db = new Proxy(Object.create(null), {
  get: (_target, property) => currentDb()?.[property],
  set: (_target, property, value) => { currentDb()[property] = value; return true; },
});
processDb = isServerless ? structuredClone(emptyDb) : await readDb();

function migrateDbState(state) {
  let changed = false;
  state.pendingUploads ||= [];
  for (const user of state.users) {
    if (user.role === "Viewer") { user.role = "Reader"; changed = true; }
    if (restoreLocalFiles(user, state)) changed = true;
  }
  if (initialAdminEmail && !state.users.some((user) => user.role === "Admin")) {
    const bootstrapAdmin = state.users.find((user) => user.email === initialAdminEmail);
    if (bootstrapAdmin) { bootstrapAdmin.role = "Admin"; changed = true; }
  }
  return changed;
}

if (isServerless && databaseUrl) {
  try {
    databasePool = new Pool({ connectionString: databaseUrl, max: 3, connectionTimeoutMillis: 8000, idleTimeoutMillis: 10000 });
    await initializePersistentDatabase();
  } catch (error) {
    databaseStartupError = "Persistent database connection failed.";
    console.error(databaseStartupError, error instanceof Error ? error.message : "Unknown database error");
    await databasePool?.end().catch(() => {});
    databasePool = null;
  }
}

if (!isServerless && migrateDbState(processDb)) await saveDb();

async function initializePersistentDatabase() {
  const client = await databasePool.connect();
  try {
    await client.query("CREATE TABLE IF NOT EXISTS cb_secure_app_state (id smallint PRIMARY KEY CHECK (id = 1), state jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())");
    await client.query("INSERT INTO cb_secure_app_state (id, state) VALUES (1, $1::jsonb) ON CONFLICT (id) DO NOTHING", [JSON.stringify(emptyDb)]);
    await client.query("BEGIN");
    const result = await client.query("SELECT state FROM cb_secure_app_state WHERE id = 1 FOR UPDATE");
    processDb = { ...emptyDb, ...(result.rows[0]?.state || {}) };
    if (migrateDbState(processDb)) {
      await client.query("UPDATE cb_secure_app_state SET state = $1::jsonb, updated_at = now() WHERE id = 1", [JSON.stringify(processDb)]);
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function deployedConfigurationIssues() {
  if (!isServerless && !isRender) return [];
  return [
    isServerless && !databasePool && (databaseStartupError || "NETLIFY_DB_URL / DATABASE_URL"),
    jwtSecret.length < 32 && "JWT_SECRET",
    !initialAdminEmail && "INITIAL_ADMIN_EMAIL",
    isServerless && !smtpConfigured && "SMTP_HOST / SMTP_USER / SMTP_PASS",
    isServerless && !privateBlobConfigured && "Private Blob storage connection",
  ].filter(Boolean);
}

function persistentDatabaseMiddleware(req, res, next) {
  if (!isServerless) return next();
  if (!databasePool) return res.status(503).json({ error: "The hosted backend needs a persistent database connection.", missing: [databaseStartupError || "DATABASE_URL"] });
  databasePool.connect().then(async (client) => {
    try {
      await client.query("BEGIN");
      const result = await client.query("SELECT state FROM cb_secure_app_state WHERE id = 1 FOR UPDATE");
      const requestDb = { ...emptyDb, ...(result.rows[0]?.state || {}) };
      requestDb.pendingUploads ||= [];
      const context = { db: requestDb, client, finishPromise: null, afterCommit: [] };
      const finish = (commit) => {
        if (!context.finishPromise) {
          context.finishPromise = (async () => {
            try {
              await client.query(commit ? "COMMIT" : "ROLLBACK");
              if (commit) {
                for (const task of context.afterCommit) {
                  try { await task(); }
                  catch (error) { console.error("Post-commit storage cleanup failed.", error instanceof Error ? error.message : "Unknown error"); }
                }
              }
            }
            finally { client.release(); }
          })();
        }
        return context.finishPromise;
      };
      res.locals.finishDatabaseTransaction = finish;
      res.locals.afterDatabaseCommit = (task) => context.afterCommit.push(task);
      const originalEnd = res.end.bind(res);
      res.end = (...args) => {
        void finish(res.statusCode < 500).then(
          () => originalEnd(...args),
          () => {
            if (!res.headersSent) {
              res.statusCode = 503;
              res.setHeader("Content-Type", "application/json; charset=utf-8");
              originalEnd(JSON.stringify({ error: "The hosted database could not save this request." }));
            } else originalEnd(...args);
          },
        );
        return res;
      };
      req.on("aborted", () => { void finish(false); });
      res.on("close", () => { if (!res.writableFinished) void finish(false); });
      dbContext.run(context, next);
    } catch (error) {
      client.release();
      next(error);
    }
  }).catch(next);
}

async function saveDb() {
  const context = dbContext.getStore();
  if (context?.client) {
    await context.client.query("UPDATE cb_secure_app_state SET state = $1::jsonb, updated_at = now() WHERE id = 1", [JSON.stringify(context.db)]);
    return;
  }
  if (isServerless) throw new Error("The hosted backend cannot save data without its persistent database.");
  await writeFile(dbPath, JSON.stringify(processDb, null, 2), "utf8");
}

function restoreLocalFiles(user, state = currentDb()) {
  let restored = 0;
  for (const file of state.files) {
    if (file.ownerId !== user.id && file.ownerEmail?.toLowerCase() === user.email.toLowerCase() && file.storage === "local" && !file.blockchainFileId) {
      file.ownerId = user.id;
      restored += 1;
    }
  }
  return restored;
}

function audit(action, user, details, req, walletAddress = user?.walletAddress || null) {
  const entry = {
    id: randomUUID(),
    userEmail: user?.email || "anonymous",
    action,
    details,
    ipAddress: req.ip,
    userAgent: req.get("user-agent") || "",
    walletAddress,
    timestamp: new Date().toISOString(),
    previousHash: db.activity[0]?.eventHash || "0".repeat(64),
  };
  entry.eventHash = createHash("sha256").update(JSON.stringify(entry)).digest("hex");
  db.activity.unshift(entry);
}

function verifyActivityChain() {
  for (let index = 0; index < db.activity.length; index += 1) {
    const { eventHash, ...entry } = db.activity[index];
    const calculatedHash = createHash("sha256").update(JSON.stringify(entry)).digest("hex");
    if (eventHash !== calculatedHash) return false;
    const nextOlderEvent = db.activity[index + 1];
    if (nextOlderEvent && entry.previousHash !== nextOlderEvent.eventHash) return false;
  }
  return true;
}

function issueToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, role: user.role }, jwtSecret, { expiresIn: "8h" });
}

function createOtp() {
  return String(randomInt(0, 1_000_000)).padStart(6, "0");
}

async function deliverOtp(email, code) {
  if (!smtpConfigured) throw new Error("Email verification is unavailable. Configure SMTP_HOST, SMTP_USER, and SMTP_PASS.");
  const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT || 587) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  await transport.sendMail({
    from: process.env.SMTP_FROM || { name: "CB SECURE", address: process.env.SMTP_USER || "cbsecure@gmail.com" },
    to: email,
    subject: "Your CB SECURE verification code",
    text: "Your one-time verification code is " + code + ". It expires in five minutes.",
  });
}

async function issueChallenge(user, req, res, status = 200) {
  const code = createOtp();
  const challenge = {
    id: randomUUID(),
    userId: user.id,
    purpose: status === 201 ? "register" : "login",
    codeHash: createHash("sha256").update(code).digest("hex"),
    expiresAt: Date.now() + 5 * 60 * 1000,
    attempts: 0,
  };
  db.challenges = db.challenges.filter((item) => item.expiresAt > Date.now() && item.userId !== user.id);
  db.challenges.push(challenge);
  audit("OTP_SENT", user, "A one-time verification code was issued.", req);
  await saveDb();
  try {
    await deliverOtp(user.email, code);
  } catch {
    audit("OTP_SEND_FAILED", user, "Verification email delivery failed for " + user.email + ".", req);
    await saveDb();
    return res.status(503).json({ error: "Could not send the verification email. Check the SMTP settings." });
  }
  res.status(status).json({
    challengeId: challenge.id,
    message: "Enter the six-digit code to continue.",
  });
}

function authenticate(req, res, next) {
  const token = req.get("authorization")?.replace(/^Bearer\s+/i, "");
  if (!token) return res.status(401).json({ error: "Authentication required." });
  try {
    const claims = jwt.verify(token, jwtSecret);
    const user = db.users.find((item) => item.id === claims.sub);
    if (!user) return res.status(401).json({ error: "Session user no longer exists." });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired session." });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: "Insufficient role." });
    next();
  };
}

const upload = multer({
  dest: incomingDir,
  limits: { fileSize: 100 * 1024 * 1024, files: 1, fields: 8, parts: 9, fieldSize: 4096 },
});

app.disable("x-powered-by");
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
const allowedOrigins = new Set([
  process.env.CORS_ORIGIN,
  process.env.URL,
  process.env.DEPLOY_PRIME_URL,
  process.env.NETLIFY_URL,
  "http://localhost:5173",
].filter(Boolean).flatMap((value) => value.split(",")).map((value) => value.trim()));
app.use(cors({ origin: (origin, callback) => callback(null, !origin || allowedOrigins.includes(origin)) }));
app.use(express.json({ limit: "1mb" }));
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));
app.use("/api", (req, res, next) => {
  if (req.path === "/health") return next();
  const missing = deployedConfigurationIssues();
  if (missing.length) {
    return res.status(503).json({ error: "The hosted backend is deployed but needs its production resources configured.", missing });
  }
  return persistentDatabaseMiddleware(req, res, next);
});

for (const method of ["get", "post", "put", "patch", "delete"]) {
  const register = app[method].bind(app);
  app[method] = (routePath, ...handlers) => register(routePath, ...handlers.map((handler) => {
    if (typeof handler !== "function" || handler.length === 4) return handler;
    return (req, res, next) => {
      try { Promise.resolve(handler(req, res, next)).catch(next); }
      catch (error) { next(error); }
    };
  }));
}

app.get("/api/health", (_req, res) => {
  const missing = [...deployedConfigurationIssues(), ...(!smtpConfigured && isRender ? ["Email delivery provider (SMTP)"] : [])];
  res.json({
    status: missing.length ? "setup_required" : "ok",
    missing,
    capabilities: {
      webCrypto: true,
      aes256gcm: true,
      sha256: true,
      database: Boolean(databasePool),
      durableMetadata: Boolean(databasePool),
      emailOtp: smtpConfigured,
      privateBlobStorage: privateBlobConfigured,
      directUploads: privateBlobConfigured,
      durableFileStorage: Boolean(process.env.PINATA_JWT || privateBlobConfigured),
      ipfs: Boolean(process.env.PINATA_JWT),
      ethereum: "configure contract address in client",
    },
    timestamp: new Date().toISOString(),
  });
});
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password } = req.body || {};
  const normalizedEmail = String(email || "").trim().toLowerCase();
  if (!name?.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) || !password || password.length < 10) {
    return res.status(400).json({ error: "Provide a name, valid email, and password of at least 10 characters." });
  }
  if (!smtpConfigured) return res.status(503).json({ error: "Email verification is not configured on this deployment yet." });
  if (db.users.some((user) => user.email === normalizedEmail)) return res.status(409).json({ error: "An account with that email already exists." });
  const passwordHash = await bcrypt.hash(password, 12);
  const hasAdmin = db.users.some((item) => item.role === "Admin");
  const isConfiguredAdmin = initialAdminEmail && normalizedEmail === initialAdminEmail;
  const role = !hasAdmin && isConfiguredAdmin ? "Admin" : "Reader";
  const user = { id: randomUUID(), name: name.trim(), email: normalizedEmail, passwordHash, role, walletAddress: null, walletVerified: false, publicKey: null, createdAt: new Date().toISOString() };
  db.users.push(user);
  await saveDb();
  return issueChallenge(user, req, res, 201);
});

app.post("/api/auth/login", async (req, res) => {
  const email = String(req.body?.email || "").toLowerCase();
  const user = db.users.find((item) => item.email === email);
  const valid = user?.passwordHash && await bcrypt.compare(String(req.body?.password || ""), user.passwordHash);
  if (!valid) {
    audit("LOGIN_FAILED", user, "Invalid email or password.", req);
    await saveDb();
    return res.status(401).json({ error: "Email or password is incorrect." });
  }
  if (!smtpConfigured) return res.status(503).json({ error: "Email verification is not configured on this deployment yet." });
  return issueChallenge(user, req, res);
});

app.post("/api/auth/google", async (req, res) => {
  if (!googleClient) return res.status(503).json({ error: "Google sign-in is temporarily unavailable." });
  const credential = req.body?.credential;
  if (typeof credential !== "string" || credential.length > 10_000) return res.status(400).json({ error: "A valid Google credential is required." });
  let payload;
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: googleClientId });
    payload = ticket.getPayload();
  } catch {
    return res.status(401).json({ error: "Google could not verify this sign-in. Try again." });
  }
  const normalizedEmail = String(payload?.email || "").trim().toLowerCase();
  if (!payload?.sub || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) || payload.email_verified !== true) {
    return res.status(401).json({ error: "Use a Google account with a verified email address." });
  }

  let user = db.users.find((item) => item.googleSub === payload.sub);
  let isNewUser = false;
  if (!user) {
    user = db.users.find((item) => item.email === normalizedEmail);
    if (user?.googleSub && user.googleSub !== payload.sub) return res.status(409).json({ error: "This email is linked to a different Google account." });
    if (user) {
      user.googleSub = payload.sub;
      user.authProvider = user.passwordHash ? "email+google" : "google";
    } else {
      const hasAdmin = db.users.some((item) => item.role === "Admin");
      const isConfiguredAdmin = initialAdminEmail && normalizedEmail === initialAdminEmail;
      user = {
        id: randomUUID(),
        name: String(payload.name || normalizedEmail.split("@")[0]).slice(0, 120),
        email: normalizedEmail,
        passwordHash: null,
        googleSub: payload.sub,
        authProvider: "google",
        role: !hasAdmin && isConfiguredAdmin ? "Admin" : "Reader",
        walletAddress: null,
        walletVerified: false,
        publicKey: null,
        createdAt: new Date().toISOString(),
      };
      db.users.push(user);
      isNewUser = true;
    }
  }

  user.mfaVerified = true;
  audit(isNewUser ? "ACCOUNT_REGISTERED" : "GOOGLE_SIGN_IN", user,
    isNewUser ? "Account registered with a verified Google identity." : "Successful Google sign-in for " + user.email + ".", req);
  await saveDb();
  res.json({ token: issueToken(user), user: publicUser(user), isNewUser });
});

app.post("/api/auth/verify-otp", async (req, res) => {
  const { challengeId, code } = req.body || {};
  const challenge = db.challenges.find((item) => item.id === challengeId);
  if (!challenge || challenge.expiresAt < Date.now() || challenge.attempts >= 5) return res.status(400).json({ error: "Code expired. Start again." });
  const suppliedHash = createHash("sha256").update(String(code || "")).digest("hex");
  if (suppliedHash !== challenge.codeHash) {
    challenge.attempts += 1;
    const user = db.users.find((item) => item.id === challenge.userId);
    audit("LOGIN_FAILED", user, "Invalid or expired OTP code.", req);
    await saveDb();
    return res.status(401).json({ error: "That code is incorrect." });
  }
  db.challenges = db.challenges.filter((item) => item.id !== challengeId);
  const user = db.users.find((item) => item.id === challenge.userId);
  user.mfaVerified = true;
  audit("OTP_VERIFIED", user, "Email verification completed.", req);
  const restoredFiles = challenge.purpose === "register" ? restoreLocalFiles(user) : 0;
  audit(challenge.purpose === "register" ? "ACCOUNT_REGISTERED" : "LOGIN_SUCCESS", user,
    challenge.purpose === "register" ? "Account registration completed for " + user.email + "." : "Successful sign-in for " + user.email + ".", req);
  if (restoredFiles) audit("FILES_RESTORED", user, "Restored access to " + restoredFiles + " local file(s) registered under this verified email.", req);
  await saveDb();
  res.json({ token: issueToken(user), user: publicUser(user) });
});

app.get("/api/auth/wallet-nonce", authenticate, async (req, res) => {
  const nonce = "Sign this message to authenticate your wallet with CB SECURE: Nonce " + randomUUID() + " Timestamp " + Date.now();
  const record = { userId: req.user.id, nonce, expiresAt: Date.now() + 5 * 60 * 1000 };
  db.walletNonces = db.walletNonces.filter((item) => item.userId !== req.user.id);
  db.walletNonces.push(record);
  await saveDb();
  res.json({ nonce, expiresAt: record.expiresAt });
});

app.post("/api/auth/verify-wallet", authenticate, async (req, res) => {
  const { address, signature } = req.body || {};
  const record = db.walletNonces.find((item) => item.userId === req.user.id);
  if (!record || record.expiresAt < Date.now()) return res.status(400).json({ error: "Request a fresh wallet challenge." });
  try {
    const recovered = getAddress(verifyMessage(record.nonce, signature));
    if (recovered !== getAddress(address)) return res.status(401).json({ error: "Signature does not match the wallet address." });
    if (db.users.some((user) => user.id !== req.user.id && user.walletAddress?.toLowerCase() === recovered.toLowerCase() && user.walletVerified)) {
      return res.status(409).json({ error: "This wallet is already linked to another account." });
    }
    req.user.walletAddress = recovered;
    req.user.walletVerified = true;
    db.walletNonces = db.walletNonces.filter((item) => item.userId !== req.user.id);
    audit("WALLET_BOUND", req.user, "Wallet signature verified and address bound.", req, recovered);
    await saveDb();
    res.json({ user: publicUser(req.user) });
  } catch {
    res.status(400).json({ error: "Invalid wallet address or signature." });
  }
});

function publicUser(user) {
  const { passwordHash: _passwordHash, googleSub: _googleSub, ...safe } = user;
  return safe;
}

app.get("/api/users", authenticate, requireRole("Admin"), (_req, res) => res.json(db.users.map(publicUser)));
app.get("/api/users/directory", authenticate, (_req, res) => {
  res.json(db.users.map(({ id, name, email, role, walletAddress, walletVerified, publicKey }) => ({ id, name, email, role, walletAddress, walletVerified: Boolean(walletVerified), publicKey })));
});
app.put("/api/auth/public-key", authenticate, async (req, res) => {
  const { publicKey } = req.body || {};
  if (!publicKey || publicKey.kty !== "EC" || publicKey.crv !== "P-256" || !publicKey.x || !publicKey.y) {
    return res.status(400).json({ error: "A P-256 public key is required." });
  }
  req.user.publicKey = publicKey;
  await saveDb();
  res.json({ saved: true });
});
app.put("/api/users/:id/role", authenticate, requireRole("Admin"), async (req, res) => {
  const user = db.users.find((item) => item.id === req.params.id);
  const { role } = req.body || {};
  if (!user) return res.status(404).json({ error: "User not found." });
  if (!["Admin", "Editor", "Reader"].includes(role)) return res.status(400).json({ error: "Invalid role." });
  if (user.role === "Admin" && role !== "Admin" && db.users.filter((item) => item.role === "Admin").length === 1) {
    return res.status(409).json({ error: "At least one Admin must remain. Promote another account before changing this role." });
  }
  user.role = role;
  audit("ROLE_UPDATED", req.user, "Role updated for " + user.email + " to " + role + ".", req);
  await saveDb();
  res.json({ user: publicUser(user) });
});

const maximumFileSize = 100 * 1024 * 1024;
const validIv = (value) => /^[A-Za-z0-9+/]{16}$/.test(value || "");
const validSalt = (value) => /^[A-Za-z0-9+/]{22}==$/.test(value || "");
const validWrappedKey = (value) => /^[A-Za-z0-9+/]{64}$/.test(value || "");

function validateUploadMetadata(body, mode) {
  const originalName = path.basename(String(body.originalName || "").trim()).slice(0, 255);
  const originalSize = Number(body.size);
  const encryptedSize = Number(body.encryptedSize);
  if (!originalName || !Number.isSafeInteger(originalSize) || originalSize < 0 || originalSize > maximumFileSize
    || !Number.isSafeInteger(encryptedSize) || encryptedSize < 16 || encryptedSize > maximumFileSize + 16
    || encryptedSize !== originalSize + 16 || !/^[a-fA-F0-9]{64}$/.test(body.sha256Hash || "") || !validIv(body.iv)) {
    return null;
  }
  const metadata = {
    originalName,
    originalSize,
    encryptedSize,
    mimeType: String(body.mimeType || "application/octet-stream").slice(0, 255),
    sha256Hash: String(body.sha256Hash).toLowerCase(),
    iv: String(body.iv),
  };
  if (mode === "create") {
    if (!validWrappedKey(body.wrappedKey) || !validIv(body.wrapIv) || !validSalt(body.salt)) return null;
    metadata.wrappedKey = String(body.wrappedKey);
    metadata.wrapIv = String(body.wrapIv);
    metadata.salt = String(body.salt);
  }
  return metadata;
}

async function createBlobUploadTicket(user, metadata, mode, fileId = null) {
  const ticket = {
    id: randomUUID(),
    userId: user.id,
    mode,
    fileId,
    pathname: "cb-secure/" + user.id + "/" + randomUUID() + ".bin",
    metadata,
    createdAt: new Date().toISOString(),
    expiresAt: Date.now() + 15 * 60 * 1000,
  };
  db.pendingUploads = db.pendingUploads.filter((item) => item.expiresAt > Date.now());
  db.pendingUploads.push(ticket);
  await saveDb();
  return ticket;
}

app.post("/api/files/upload-ticket", authenticate, async (req, res) => {
  if (!privateBlobConfigured) return res.status(503).json({ error: "Private Blob storage is not connected to this deployment." });
  const metadata = validateUploadMetadata(req.body || {}, "create");
  if (!metadata) return res.status(400).json({ error: "Encrypted file metadata is incomplete or invalid." });
  const ticket = await createBlobUploadTicket(req.user, metadata, "create");
  res.status(201).json({ ticketId: ticket.id, pathname: ticket.pathname, mode: ticket.mode });
});

app.post("/api/files/:id/replace-ticket", authenticate, async (req, res) => {
  if (!privateBlobConfigured) return res.status(503).json({ error: "Private Blob storage is not connected to this deployment." });
  const file = db.files.find((item) => item.id === req.params.id);
  if (!file) return res.status(404).json({ error: "File not found." });
  const writeGrant = db.grants.find((item) => item.fileId === file.id && item.active && item.permissionLevel === 2 && item.recipientAddress?.toLowerCase() === req.user.walletAddress?.toLowerCase());
  const canReplace = file.ownerId === req.user.id || ((req.user.role === "Editor" || req.user.role === "Admin") && writeGrant);
  if (!canReplace) return res.status(403).json({ error: "Only the owner or an Editor with write access can replace this file." });
  const metadata = validateUploadMetadata(req.body || {}, "replace");
  if (!metadata) return res.status(400).json({ error: "Encrypted replacement metadata is incomplete or invalid." });
  const ticket = await createBlobUploadTicket(req.user, metadata, "replace", file.id);
  res.status(201).json({ ticketId: ticket.id, pathname: ticket.pathname, mode: ticket.mode });
});

app.post("/api/blob/upload", authenticate, async (req, res) => {
  if (!privateBlobConfigured) return res.status(503).json({ error: "Private Blob storage is not connected to this deployment." });
  try {
    const response = await handleUploadPresigned({
      request: req,
      body: req.body,
      getSignedToken: async (pathname, clientPayload) => {
        let ticketId;
        try { ticketId = JSON.parse(clientPayload || "{}").ticketId; } catch { throw new Error("A valid upload ticket is required."); }
        const ticket = db.pendingUploads.find((item) => item.id === ticketId && item.userId === req.user.id && item.pathname === pathname);
        if (!ticket || ticket.expiresAt <= Date.now()) throw new Error("The upload ticket is invalid or expired.");
        const validUntil = Math.min(ticket.expiresAt, Date.now() + 15 * 60 * 1000);
        const token = await issueSignedToken({
          pathname: ticket.pathname,
          operations: ["put"],
          validUntil,
          allowedContentTypes: ["application/octet-stream"],
          maximumSizeInBytes: ticket.metadata.encryptedSize,
        });
        return {
          token,
          urlOptions: {
            allowedContentTypes: ["application/octet-stream"],
            maximumSizeInBytes: ticket.metadata.encryptedSize,
            addRandomSuffix: false,
            allowOverwrite: false,
            validUntil,
          },
        };
      },
    });
    res.json(response);
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : "Could not authorize the private upload." });
  }
});

async function readCompletedBlob(ticket) {
  try {
    const metadata = await headBlob(ticket.pathname, { access: "private" });
    if (metadata.size !== ticket.metadata.encryptedSize || metadata.contentType !== "application/octet-stream") return null;
    return metadata;
  } catch {
    return null;
  }
}

app.post("/api/files/upload-finalize", authenticate, async (req, res) => {
  const ticket = db.pendingUploads.find((item) => item.id === req.body?.ticketId && item.userId === req.user.id && item.mode === "create");
  if (!ticket || ticket.expiresAt <= Date.now()) return res.status(404).json({ error: "The upload ticket is invalid or expired." });
  const blob = await readCompletedBlob(ticket);
  if (!blob) return res.status(409).json({ error: "Private encrypted bytes were not found or did not match the upload ticket." });
  const record = {
    id: randomUUID(),
    originalName: ticket.metadata.originalName,
    size: ticket.metadata.originalSize,
    mimeType: ticket.metadata.mimeType,
    ipfsCid: "",
    storagePath: ticket.pathname,
    sha256Hash: ticket.metadata.sha256Hash,
    iv: ticket.metadata.iv,
    wrappedKey: ticket.metadata.wrappedKey,
    wrapIv: ticket.metadata.wrapIv,
    salt: ticket.metadata.salt,
    storage: "blob",
    ownerId: req.user.id,
    ownerEmail: req.user.email,
    ownerWallet: req.user.walletAddress,
    blockchainFileId: null,
    transactionHash: null,
    createdAt: new Date().toISOString(),
  };
  db.pendingUploads = db.pendingUploads.filter((item) => item.id !== ticket.id);
  db.files.unshift(record);
  audit("FILE_UPLOADED", req.user, "Encrypted file stored in private object storage.", req);
  await saveDb();
  res.status(201).json({ file: record, message: "Encrypted bytes stored in private cloud storage." });
});

app.post("/api/files/:id/replace-finalize", authenticate, async (req, res) => {
  const ticket = db.pendingUploads.find((item) => item.id === req.body?.ticketId && item.userId === req.user.id && item.mode === "replace" && item.fileId === req.params.id);
  if (!ticket || ticket.expiresAt <= Date.now()) return res.status(404).json({ error: "The replacement ticket is invalid or expired." });
  const file = db.files.find((item) => item.id === ticket.fileId);
  if (!file) return res.status(404).json({ error: "File not found." });
  const writeGrant = db.grants.find((item) => item.fileId === file.id && item.active && item.permissionLevel === 2 && item.recipientAddress?.toLowerCase() === req.user.walletAddress?.toLowerCase());
  const canReplace = file.ownerId === req.user.id || ((req.user.role === "Editor" || req.user.role === "Admin") && writeGrant);
  if (!canReplace) return res.status(403).json({ error: "Write access was revoked before the replacement completed." });
  const blob = await readCompletedBlob(ticket);
  if (!blob) return res.status(409).json({ error: "Private encrypted bytes were not found or did not match the upload ticket." });
  const oldPath = file.storage === "blob" ? file.storagePath : null;
  file.storage = "blob";
  file.storagePath = ticket.pathname;
  file.ipfsCid = "";
  file.originalName = ticket.metadata.originalName;
  file.size = ticket.metadata.originalSize;
  file.mimeType = ticket.metadata.mimeType;
  file.iv = ticket.metadata.iv;
  file.sha256Hash = ticket.metadata.sha256Hash;
  file.updatedAt = new Date().toISOString();
  db.pendingUploads = db.pendingUploads.filter((item) => item.id !== ticket.id);
  audit("FILE_CONTENT_REPLACED", req.user, "Replaced encrypted content for " + file.originalName + ".", req);
  await saveDb();
  if (oldPath && oldPath !== ticket.pathname && res.locals.afterDatabaseCommit) {
    res.locals.afterDatabaseCommit(() => deleteBlob(oldPath, { access: "private" }));
  }
  res.json({ file });
});

app.post("/api/files/upload", authenticate, upload.single("ciphertext"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Encrypted file payload is required." });
  const { originalName, mimeType, sha256Hash, iv, wrappedKey, wrapIv, salt } = req.body || {};
  const originalSize = Number(req.body.size);
  const validIv = (value) => /^[A-Za-z0-9+/]{16}$/.test(value || "");
  const validSalt = (value) => /^[A-Za-z0-9+/]{22}==$/.test(value || "");
  const validWrappedKey = (value) => /^[A-Za-z0-9+/]{64}$/.test(value || "");
  if (!originalName || !Number.isFinite(originalSize) || originalSize < 0 || !/^[a-fA-F0-9]{64}$/.test(sha256Hash || "") || !validIv(iv) || !validWrappedKey(wrappedKey) || !validIv(wrapIv) || !validSalt(salt)) {
    await unlink(req.file.path).catch(() => {});
    return res.status(400).json({ error: "Encryption metadata is incomplete." });
  }
  let cid;
  try {
    if (process.env.PINATA_JWT) {
      const form = new FormData();
      form.append("file", new Blob([await readFile(req.file.path)]), "ciphertext.bin");
      const pinResponse = await fetch("https://api.pinata.cloud/pinning/pinFileToIPFS", {
        method: "POST",
        headers: { Authorization: "Bearer " + process.env.PINATA_JWT },
        body: form,
      });
      if (!pinResponse.ok) throw new Error("IPFS pin request failed.");
      cid = (await pinResponse.json()).IpfsHash;
      await unlink(req.file.path);
    } else {
      const digest = createHash("sha256").update(await readFile(req.file.path)).digest("hex");
      cid = "local-" + digest;
      const target = path.join(storageDir, digest + ".bin");
      await writeFile(target, await readFile(req.file.path));
      await unlink(req.file.path);
    }
  } catch {
    await unlink(req.file.path).catch(() => {});
    return res.status(502).json({ error: "Ciphertext storage failed." });
  }

  const record = {
    id: randomUUID(),
    originalName: path.basename(String(originalName)).slice(0, 255),
    size: originalSize,
    mimeType: String(mimeType || "application/octet-stream").slice(0, 255),
    ipfsCid: cid,
    sha256Hash: String(sha256Hash).toLowerCase(),
    iv: String(iv),
    wrappedKey: String(wrappedKey),
    wrapIv: String(wrapIv),
    salt: String(salt),
    storage: process.env.PINATA_JWT ? "ipfs" : "local",
    ownerId: req.user.id,
    ownerEmail: req.user.email,
    ownerWallet: req.user.walletAddress,
    blockchainFileId: null,
    transactionHash: null,
    createdAt: new Date().toISOString(),
  };
  db.files.unshift(record);
  audit("FILE_UPLOADED", req.user, "Encrypted file stored with CID " + cid + ".", req);
  await saveDb();
  res.status(201).json({ file: record, message: record.storage === "ipfs" ? "Encrypted bytes pinned to IPFS." : "Encrypted bytes stored by this server." });
});

app.get("/api/files", authenticate, (req, res) => {
  const visible = req.user.role === "Admin" ? db.files : db.files.filter((file) => file.ownerId === req.user.id);
  res.json(visible);
});
app.get("/api/files/summary", authenticate, (req, res) => {
  const sharedFileIds = new Set(db.grants.filter((grant) => grant.active && grant.recipientAddress?.toLowerCase() === req.user.walletAddress?.toLowerCase()).map((grant) => grant.fileId));
  res.json({
    totalCount: db.files.length,
    ownCount: db.files.filter((file) => file.ownerId === req.user.id).length,
    sharedCount: [...sharedFileIds].filter((id) => db.files.some((file) => file.id === id)).length,
  });
});
app.post("/api/files/:id/chain", authenticate, async (req, res) => {
  const file = db.files.find((item) => item.id === req.params.id);
  const writeGrant = db.grants.find((item) => item.fileId === req.params.id && item.active && item.permissionLevel === 2 && item.recipientAddress?.toLowerCase() === req.user.walletAddress?.toLowerCase());
  const { blockchainFileId, transactionHash } = req.body || {};
  const canUpdate = file && (file.ownerId === req.user.id || ((req.user.role === "Editor" || req.user.role === "Admin") && writeGrant));
  if (!canUpdate) return res.status(404).json({ error: "File not found or unavailable." });
  if (!/^(0x[a-fA-F0-9]{64})$/.test(transactionHash || "") || !/^\d+$/.test(String(blockchainFileId || ""))) {
    return res.status(400).json({ error: "A transaction hash and numeric chain record ID are required." });
  }
  file.blockchainFileId = String(blockchainFileId);
  file.transactionHash = transactionHash;
  await saveDb();
  res.json({ file });
});
app.put("/api/files/:id/replace", authenticate, upload.single("ciphertext"), async (req, res) => {
  const file = db.files.find((item) => item.id === req.params.id);
  if (!file) {
    if (req.file) await unlink(req.file.path).catch(() => {});
    return res.status(404).json({ error: "File not found." });
  }
  const writeGrant = db.grants.find((item) => item.fileId === file.id && item.active && item.permissionLevel === 2 && item.recipientAddress?.toLowerCase() === req.user.walletAddress?.toLowerCase());
  const canReplace = file.ownerId === req.user.id || ((req.user.role === "Editor" || req.user.role === "Admin") && writeGrant);
  if (!canReplace) {
    if (req.file) await unlink(req.file.path).catch(() => {});
    return res.status(403).json({ error: "Only the owner or an Editor with write access can replace this file." });
  }
  if (!req.file) return res.status(400).json({ error: "Encrypted replacement file payload is required." });
  const originalName = path.basename(String(req.body.originalName || "")).slice(0, 255);
  const originalSize = Number(req.body.size);
  const validIv = (value) => /^[A-Za-z0-9+/]{16}$/.test(value || "");
  if (!originalName || !Number.isFinite(originalSize) || originalSize < 0 || !validIv(req.body.iv) || !/^[a-fA-F0-9]{64}$/.test(req.body.sha256Hash || "")) {
    await unlink(req.file.path).catch(() => {});
    return res.status(400).json({ error: "Encrypted replacement metadata is incomplete." });
  }

  let cid;
  const storage = process.env.PINATA_JWT ? "ipfs" : "local";
  try {
    if (process.env.PINATA_JWT) {
      const form = new FormData();
      form.append("file", new Blob([await readFile(req.file.path)]), "ciphertext.bin");
      const pinResponse = await fetch("https://api.pinata.cloud/pinning/pinFileToIPFS", { method: "POST", headers: { Authorization: "Bearer " + process.env.PINATA_JWT }, body: form });
      if (!pinResponse.ok) throw new Error("IPFS pin request failed.");
      cid = (await pinResponse.json()).IpfsHash;
      await unlink(req.file.path);
    } else {
      const digest = createHash("sha256").update(await readFile(req.file.path)).digest("hex");
      cid = "local-" + digest;
      await writeFile(path.join(storageDir, digest + ".bin"), await readFile(req.file.path));
      await unlink(req.file.path);
    }
  } catch {
    await unlink(req.file.path).catch(() => {});
    return res.status(502).json({ error: "Ciphertext storage failed." });
  }

  const oldCid = file.ipfsCid;
  file.ipfsCid = cid;
  file.storage = storage;
  file.originalName = originalName;
  file.size = originalSize;
  file.mimeType = String(req.body.mimeType || "application/octet-stream").slice(0, 255);
  file.iv = String(req.body.iv);
  file.sha256Hash = String(req.body.sha256Hash).toLowerCase();
  file.updatedAt = new Date().toISOString();
  if (oldCid !== cid && oldCid.startsWith("local-") && !db.files.some((item) => item.id !== file.id && item.ipfsCid === oldCid)) {
    await unlink(path.join(storageDir, oldCid.slice("local-".length) + ".bin")).catch(() => {});
  }
  audit("FILE_CONTENT_REPLACED", req.user, "Updated encrypted content for " + file.originalName + ".", req);
  await saveDb();
  res.json({ file });
});
app.get("/api/files/shared", authenticate, (req, res) => {
  const grants = db.grants.filter((grant) => grant.recipientAddress?.toLowerCase() === req.user.walletAddress?.toLowerCase() && grant.active && db.files.some((file) => file.id === grant.fileId));
  const count = new Set(grants.map((grant) => grant.fileId)).size;
  if (req.user.role === "Reader") return res.json({ items: [], count });
  const items = grants.map((grant) => ({ ...grant, file: db.files.find((file) => file.id === grant.fileId) })).filter((item) => item.file);
  res.json({ items, count });
});
app.get("/api/files/:id/grants", authenticate, (req, res) => {
  const file = db.files.find((item) => item.id === req.params.id && (item.ownerId === req.user.id || req.user.role === "Admin"));
  if (!file) return res.status(404).json({ error: "File not found or unavailable." });
  res.json(db.grants.filter((grant) => grant.fileId === file.id));
});
app.get("/api/files/:id/download", authenticate, async (req, res) => {
  const file = db.files.find((item) => item.id === req.params.id);
  if (!file) return res.status(404).json({ error: "File not found." });
  const grant = db.grants.find((item) => item.fileId === file.id && item.active && item.recipientAddress?.toLowerCase() === req.user.walletAddress?.toLowerCase());
  const isOwner = file.ownerId === req.user.id;
  if (!isOwner && (!(["Editor", "Admin"].includes(req.user.role)) || !grant || grant.permissionLevel < 1)) {
    audit("ACCESS_DENIED", req.user, "Denied download request for file " + file.id + ".", req);
    await saveDb();
    return res.status(403).json({ error: "This wallet is not authorized for the file." });
  }
  if (file.storage === "blob" && file.storagePath) {
    const validUntil = Date.now() + 5 * 60 * 1000;
    const signedToken = await issueSignedToken({ pathname: file.storagePath, operations: ["get"], validUntil });
    const { presignedUrl } = await presignUrl(signedToken, {
      operation: "get",
      pathname: file.storagePath,
      access: "private",
      validUntil,
      useCache: false,
    });
    return res.json({ downloadUrl: presignedUrl });
  }
  if (file.storage === "ipfs") {
    return res.redirect("https://gateway.pinata.cloud/ipfs/" + encodeURIComponent(file.ipfsCid));
  }
  const digest = file.ipfsCid.replace(/^local-/, "");
  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Content-Disposition", "attachment; filename=ciphertext.bin");
  res.sendFile(path.join(storageDir, digest + ".bin"));
});
app.put("/api/files/:id", authenticate, async (req, res) => {
  const file = db.files.find((item) => item.id === req.params.id);
  if (!file) return res.status(404).json({ error: "File not found." });
  const writeGrant = db.grants.find((item) => item.fileId === file.id && item.active && item.permissionLevel === 2 && item.recipientAddress?.toLowerCase() === req.user.walletAddress?.toLowerCase());
  if (file.ownerId !== req.user.id && req.user.role !== "Admin" && !(req.user.role === "Editor" && writeGrant)) {
    return res.status(403).json({ error: "Only the owner, an Editor with write access, or an Admin can rename this file." });
  }
  const originalName = typeof req.body?.originalName === "string" ? path.basename(req.body.originalName.trim()).slice(0, 255) : "";
  if (!originalName) return res.status(400).json({ error: "A valid file name is required." });
  const previousName = file.originalName;
  file.originalName = originalName;
  file.updatedAt = new Date().toISOString();
  audit("FILE_RENAMED", req.user, "Renamed " + previousName + " to " + originalName + ".", req);
  await saveDb();
  res.json({ file });
});
app.post("/api/files/:id/share", authenticate, async (req, res) => {
  const file = db.files.find((item) => item.id === req.params.id && item.ownerId === req.user.id);
  const { recipientAddress, permissionLevel, wrappedKey, transactionHash } = req.body || {};
  if (!file) return res.status(404).json({ error: "File not found or not owned by you." });
  if (!/^0x[a-fA-F0-9]{40}$/.test(recipientAddress || "") || ![1, 2].includes(Number(permissionLevel)) || typeof wrappedKey !== "string") return res.status(400).json({ error: "A valid wallet address, permission level (1 read, 2 write), and encrypted DEK package are required." });
  const recipient = db.users.find((user) => user.walletAddress?.toLowerCase() === recipientAddress.toLowerCase());
  if (!recipient?.publicKey || !recipient.walletVerified) return res.status(400).json({ error: "Recipient must sign in, register an encryption key, and verify wallet ownership first." });
  if (recipient.role === "Reader") return res.status(403).json({ error: "Viewer accounts can see file counts only. Assign Editor or Admin before granting file access." });
  const grant = { grantId: randomUUID(), fileId: file.id, recipientAddress: getAddress(recipientAddress), recipientEmail: recipient.email, permissionLevel: Number(permissionLevel), wrappedKey, active: true, transactionHash: transactionHash || null, timestamp: new Date().toISOString(), adapter: transactionHash ? "evm" : "api" };
  db.grants = db.grants.filter((item) => !(item.fileId === file.id && item.recipientAddress.toLowerCase() === grant.recipientAddress.toLowerCase()));
  db.grants.push(grant);
  audit("ACCESS_GRANTED", req.user, "Access granted to " + grant.recipientAddress + ".", req);
  await saveDb();
  res.status(201).json({ grant, message: transactionHash ? "On-chain and API access grant saved." : "Access grant saved by the API." });
});
app.post("/api/files/:id/revoke", authenticate, async (req, res) => {
  const file = db.files.find((item) => item.id === req.params.id && (item.ownerId === req.user.id || req.user.role === "Admin"));
  if (!file) return res.status(404).json({ error: "File not found or unavailable." });
  const { recipientAddress, transactionHash } = req.body || {};
  const grant = db.grants.find((item) => item.fileId === file.id && item.recipientAddress.toLowerCase() === String(recipientAddress || "").toLowerCase());
  if (!grant) return res.status(404).json({ error: "Access grant not found." });
  grant.active = false;
  grant.revocationTransactionHash = transactionHash || null;
  audit("ACCESS_REVOKED", req.user, "Access grant revoked for " + grant.recipientAddress + ".", req);
  await saveDb();
  res.json({ grant, message: transactionHash ? "On-chain and API access grant revoked." : "Access grant revoked by the API." });
});
app.get("/api/activity", authenticate, (req, res) => {
  const visible = req.user.role === "Admin" ? db.activity : db.activity.filter((item) => item.userEmail === req.user.email);
  res.json(visible);
});
app.get("/api/activity/verify", authenticate, requireRole("Admin"), (_req, res) => {
  res.json({ valid: verifyActivityChain(), checkedEvents: db.activity.length, checkedAt: new Date().toISOString() });
});
app.post("/api/activity/record", authenticate, async (req, res) => {
  const { action, details } = req.body || {};
  if (!["FILE_DECRYPTED", "INTEGRITY_VERIFIED"].includes(action) || typeof details !== "string") {
    return res.status(400).json({ error: "Unsupported client verification event." });
  }
  audit(action, req.user, details.slice(0, 240), req);
  await saveDb();
  res.status(201).json({ recorded: true, eventHash: db.activity[0].eventHash });
});
app.get("/api/notifications", authenticate, (req, res) => {
  res.json(db.activity.filter((item) => item.userEmail === req.user.email).slice(0, 20));
});
if (process.env.NODE_ENV === "production" && !isServerless) {
  const frontendDist = path.resolve(here, "../../frontend/dist");
  app.use(express.static(frontendDist, { index: false, maxAge: "1h" }));
  app.get("*", (req, res, next) => {
    if (req.path === "/api" || req.path.startsWith("/api/")) return next();
    res.sendFile(path.join(frontendDist, "index.html"));
  });
}
app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError) return res.status(413).json({ error: "Upload exceeds the 100 MB file limit." });
  console.error("CB SECURE request failed.", error instanceof Error ? error.message : "Unknown error");
  res.status(500).json({ error: "Unexpected server error." });
});

if (!isServerless) app.listen(port, "0.0.0.0", () => console.log("CB SECURE service listening on port " + port));

export default app;
