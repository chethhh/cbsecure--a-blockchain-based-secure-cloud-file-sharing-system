import { AsyncLocalStorage } from "node:async_hooks";
import { Readable } from "node:stream";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import multer from "multer";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import { randomInt, createHash, randomUUID, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyMessage, getAddress } from "ethers";

const here = path.dirname(fileURLToPath(import.meta.url));
const isCloudflare = process.env.CF_WORKERS === "true";
if (!isCloudflare) await import("dotenv/config");
const rateLimit = isCloudflare ? null : (await import("express-rate-limit")).default;
const isVercel = Boolean(process.env.VERCEL || process.env.VERCEL_ENV);
const isRender = Boolean(process.env.RENDER || process.env.RENDER_SERVICE_ID);
const isNetlify = Boolean(process.env.NETLIFY);
const isCloudRun = Boolean(process.env.K_SERVICE || process.env.CLOUD_RUN);
const isFunctionPlatform = isVercel || isNetlify;
const isServerless = isFunctionPlatform || isCloudRun || isCloudflare;
const privateBlobConfigured = Boolean(process.env.BLOB_STORE_ID && process.env.BLOB_READ_WRITE_TOKEN);
const storageBucketName = String(process.env.GCS_BUCKET || "").trim();
const googleCloud = isCloudRun ? await import("@google-cloud/firestore") : null;
const googleStorage = isCloudRun ? await import("@google-cloud/storage") : null;
const firestore = isCloudRun ? new googleCloud.Firestore({ projectId: process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT }) : null;
const firestoreStateRef = firestore?.collection("cb_secure").doc("app_state") || null;
const cloudStorage = isCloudRun && storageBucketName ? new googleStorage.Storage({ projectId: process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT }) : null;
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
const cloudflareAuthPepper = String(process.env.CF_AUTH_PEPPER || "");
const cloudflarePasswordHashIterations = 100_000;
const cloudflarePasswordHashPrefix = "cf-pbkdf2-sha256";
const googleClientId = String(process.env.GOOGLE_CLIENT_ID || "").trim();
const googleAuth = googleClientId ? await import("google-auth-library") : null;
const googleClient = googleClientId ? new googleAuth.OAuth2Client(googleClientId) : null;
const resendApiKey = String(process.env.RESEND_API_KEY || "").trim();
const resendFromEmail = String(process.env.RESEND_FROM_EMAIL || "").trim();
const resendSenderConfigured = /^(?:[^<>\r\n]*<[^<>\s@]+@[^<>\s@]+\.[^<>\s@]+>|[^<>\s@]+@[^<>\s@]+\.[^<>\s@]+)$/.test(resendFromEmail)
  && !/(?:your-verified-domain\.com|@example\.(?:com|net|org)|@[^<>\s@]+\.(?:example|invalid|test)(?:>|$))/i.test(resendFromEmail);
const emailDeliveryConfigured = resendApiKey.length >= 20 && resendSenderConfigured;
const databaseUrl = process.env.NETLIFY_DB_URL || process.env.DATABASE_URL || process.env.POSTGRES_URL || "";
const blobModule = isVercel ? await import("@vercel/blob") : null;
const blobClientModule = isVercel ? await import("@vercel/blob/client") : null;
const deleteBlob = blobModule?.del;
const headBlob = blobModule?.head;
const issueSignedToken = blobModule?.issueSignedToken;
const presignUrl = blobModule?.presignUrl;
const handleUploadPresigned = blobClientModule?.handleUploadPresigned;

if (!isServerless && jwtSecret.length < 32) throw new Error("Set JWT_SECRET to a random value with at least 32 characters.");
if (!isCloudflare) {
  await mkdir(storageDir, { recursive: true });
  await mkdir(incomingDir, { recursive: true });
}

const emptyDb = { users: [], files: [], grants: [], activity: [], challenges: [], walletNonces: [], pendingUploads: [] };
const dbContext = new AsyncLocalStorage();
let processDb;
let databasePool = null;
let databaseStartupError = "";
let firestoreStartupError = "";
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

if (isFunctionPlatform && databaseUrl) {
  try {
    const { Pool } = await import("@neondatabase/serverless");
    databasePool = new Pool({ connectionString: databaseUrl, max: 3, connectionTimeoutMillis: 8000, idleTimeoutMillis: 10000 });
    await initializePersistentDatabase();
  } catch (error) {
    databaseStartupError = "Persistent database connection failed.";
    console.error(databaseStartupError, error instanceof Error ? error.message : "Unknown database error");
    await databasePool?.end().catch(() => {});
    databasePool = null;
  }
}

if (isCloudRun) {
  try {
    const snapshot = await firestoreStateRef.get();
    if (snapshot.exists) processDb = { ...emptyDb, ...(snapshot.data()?.state || {}) };
    else await firestoreStateRef.create({ state: emptyDb, updatedAt: new Date().toISOString() });
    if (migrateDbState(processDb)) await firestoreStateRef.set({ state: processDb, updatedAt: new Date().toISOString() });
  } catch (error) {
    firestoreStartupError = "Firestore connection failed.";
    console.error(firestoreStartupError, error instanceof Error ? error.message : "Unknown database error");
  }
} else if (!isServerless && migrateDbState(processDb)) await saveDb();

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
    isFunctionPlatform && !databasePool && (databaseStartupError || "NETLIFY_DB_URL / DATABASE_URL"),
    isCloudRun && firestoreStartupError,
    isCloudRun && !firestoreStateRef && "Firestore database",
    isCloudflare && process.env.CF_D1_ACTIVE !== "true" && "Cloudflare D1 binding",
    isCloudflare && cloudflareAuthPepper.length < 32 && "CF_AUTH_PEPPER",
    jwtSecret.length < 32 && "JWT_SECRET",
    !initialAdminEmail && "INITIAL_ADMIN_EMAIL",
    (isServerless || isRender) && resendApiKey.length < 20 && "RESEND_API_KEY (Cloudflare Worker secret)",
    (isServerless || isRender) && !resendSenderConfigured && "RESEND_FROM_EMAIL (address on a verified Resend domain)",
    isFunctionPlatform && !privateBlobConfigured && "Private Blob storage connection",
    isCloudRun && !cloudStorage && "GCS_BUCKET",
  ].filter(Boolean);
}

let firestoreRequestQueue = Promise.resolve();
const recordKeys = {
  users: "id",
  files: "id",
  grants: "grantId",
  activity: "id",
  challenges: "id",
  walletNonces: "userId",
  pendingUploads: "id",
};

function cloudflareEnvironment() {
  return dbContext.getStore()?.env || null;
}

function privateStorageConfigured() {
  return isCloudflare ? process.env.CF_D1_ACTIVE === "true" : privateBlobConfigured;
}

const cloudflareFileChunkBytes = 1_800_000;
const cloudflareFileChunkBatchSize = 8;
const authRateLimitState = new Map();
const otpRateWindowMs = 60 * 60 * 1000;
const otpRateLimitPerEmail = 5;
const otpTtlMs = 5 * 60 * 1000;

function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}

function decodeBase64Url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function hashPassword(password) {
  if (!isCloudflare) return bcrypt.hash(password, 12);
  if (cloudflareAuthPepper.length < 32) throw new Error("CF_AUTH_PEPPER is not configured.");
  const salt = randomBytes(16);
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(password) + "\0" + cloudflareAuthPepper),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const derived = new Uint8Array(await crypto.subtle.deriveBits({
    name: "PBKDF2",
    hash: "SHA-256",
    salt,
    iterations: cloudflarePasswordHashIterations,
  }, material, 256));
  return [cloudflarePasswordHashPrefix, cloudflarePasswordHashIterations, encodeBase64Url(salt), encodeBase64Url(derived)].join("$");
}

async function verifyPassword(password, storedHash) {
  if (typeof storedHash !== "string") return false;
  if (isCloudflare && storedHash.startsWith(cloudflarePasswordHashPrefix + "$")) {
    if (cloudflareAuthPepper.length < 32) throw new Error("CF_AUTH_PEPPER is not configured.");
    const [, iterationsValue, saltValue, expectedValue] = storedHash.split("$");
    const iterations = Number(iterationsValue);
    if (!Number.isSafeInteger(iterations) || iterations < 10_000 || iterations > cloudflarePasswordHashIterations) return false;
    let salt;
    let expected;
    try {
      salt = decodeBase64Url(saltValue);
      expected = decodeBase64Url(expectedValue);
    } catch {
      return false;
    }
    if (salt.length !== 16 || expected.length !== 32) return false;
    const material = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(String(password) + "\0" + cloudflareAuthPepper),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const actual = new Uint8Array(await crypto.subtle.deriveBits({
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations,
    }, material, 256));
    return crypto.subtle.timingSafeEqual(actual, expected);
  }
  return bcrypt.compare(String(password), storedHash);
}

function cloudflareAuthRateLimit(req, res, next) {
  const now = Date.now();
  const address = req.get("cf-connecting-ip") || req.ip || "unknown";
  let window = authRateLimitState.get(address);
  if (!window || now - window.startedAt >= 15 * 60 * 1000) {
    window = { startedAt: now, count: 0 };
    authRateLimitState.set(address, window);
  }
  if (window.count >= 30) {
    res.setHeader("Retry-After", String(Math.ceil((15 * 60 * 1000 - (now - window.startedAt)) / 1000)));
    return res.status(429).json({ error: "Too many authentication attempts. Try again later." });
  }
  window.count += 1;
  if (authRateLimitState.size > 1000) {
    for (const [key, value] of authRateLimitState) {
      if (now - value.startedAt >= 15 * 60 * 1000) authRateLimitState.delete(key);
    }
  }
  next();
}

export function runWithCloudflareEnvironment(env, handler) {
  return dbContext.run({ env }, handler);
}

async function deleteCloudflareFileChunks(storageKey) {
  const d1 = dbContext.getStore()?.d1;
  if (d1 && storageKey) await d1.prepare("DELETE FROM cb_secure_file_chunks WHERE storage_key = ?").bind(storageKey).run();
}

function collectRecords(state) {
  const records = new Map();
  for (const [collection, keyName] of Object.entries(recordKeys)) {
    for (const item of state[collection] || []) {
      const key = item?.[keyName];
      if (key !== undefined && key !== null) records.set(collection + "\u0000" + String(key), JSON.stringify(item));
    }
  }
  return records;
}

async function cloudflareDatabaseMiddleware(req, res, next) {
  const inherited = dbContext.getStore() || {};
  const env = inherited.env;
  const d1 = env?.DB;
  if (!d1 || process.env.CF_D1_ACTIVE !== "true") {
    return res.status(503).json({ error: "The hosted backend needs a persistent database connection.", missing: ["Cloudflare D1 binding"] });
  }
  try {
    const result = await d1.prepare("SELECT collection, record_key, payload FROM cb_secure_records").all();
    const requestDb = structuredClone(emptyDb);
    const originalRecords = new Map();
    for (const row of result.results || []) {
      const collection = String(row.collection);
      const item = JSON.parse(String(row.payload));
      if (!Object.hasOwn(recordKeys, collection)) continue;
      requestDb[collection].push(item);
      originalRecords.set(collection + "\u0000" + String(row.record_key), String(row.payload));
    }
    requestDb.activity.sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
    requestDb.files.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
    const context = { ...inherited, db: requestDb, d1, originalRecords, dirty: false, finishPromise: null, afterCommit: [] };
    const finish = (commit) => {
      if (!context.finishPromise) {
        context.finishPromise = (async () => {
          try {
            if (commit && context.dirty) {
              const currentRecords = collectRecords(context.db);
              const statements = [];
              for (const compoundKey of originalRecords.keys()) {
                if (currentRecords.has(compoundKey)) continue;
                const splitAt = compoundKey.indexOf("\u0000");
                const collection = compoundKey.slice(0, splitAt);
                const recordKey = compoundKey.slice(splitAt + 1);
                statements.push(d1.prepare("DELETE FROM cb_secure_records WHERE collection = ? AND record_key = ?").bind(collection, recordKey));
              }
              for (const [compoundKey, payload] of currentRecords) {
                if (originalRecords.get(compoundKey) === payload) continue;
                const splitAt = compoundKey.indexOf("\u0000");
                const collection = compoundKey.slice(0, splitAt);
                const recordKey = compoundKey.slice(splitAt + 1);
                statements.push(d1.prepare("INSERT INTO cb_secure_records (collection, record_key, payload) VALUES (?, ?, ?) ON CONFLICT(collection, record_key) DO UPDATE SET payload = excluded.payload").bind(collection, recordKey, payload));
              }
              if (statements.length) await d1.batch(statements);
              processDb = context.db;
              for (const task of context.afterCommit) {
                try { await task(); }
                catch (error) { console.error("Post-commit storage cleanup failed.", error instanceof Error ? error.message : "Unknown error"); }
              }
            }
          } finally { }
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
    console.error("Cloudflare D1 request failed.", error instanceof Error ? error.message : "Unknown error");
    next(error);
  }
}

async function firestoreRequestMiddleware(req, res, next) {
  let release;
  const previous = firestoreRequestQueue;
  firestoreRequestQueue = new Promise((resolve) => { release = resolve; });
  await previous;
  try {
    const snapshot = await firestoreStateRef.get();
    const requestDb = { ...emptyDb, ...(snapshot.data()?.state || {}) };
    const context = { db: requestDb, firestore: true, dirty: false, finishPromise: null, afterCommit: [] };
    const finish = (commit) => {
      if (!context.finishPromise) {
        context.finishPromise = (async () => {
          try {
            if (commit && context.dirty) {
              await firestoreStateRef.set({ state: context.db, updatedAt: new Date().toISOString() });
              processDb = context.db;
              for (const task of context.afterCommit) {
                try { await task(); }
                catch (error) { console.error("Post-commit storage cleanup failed.", error instanceof Error ? error.message : "Unknown error"); }
              }
            }
          } finally { release(); }
        })();
      }
      return context.finishPromise;
    };
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
    release();
    next(error);
  }
}

function persistentDatabaseMiddleware(req, res, next) {
  if (isCloudRun) return firestoreStartupError ? res.status(503).json({ error: "The hosted backend needs a persistent database connection.", missing: [firestoreStartupError] }) : firestoreRequestMiddleware(req, res, next);
  if (isCloudflare) return cloudflareDatabaseMiddleware(req, res, next);
  if (!isFunctionPlatform) return next();
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
  if (context?.d1) {
    context.dirty = true;
    return;
  }
  if (context?.firestore) {
    context.dirty = true;
    return;
  }
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

async function deliverOtp(email, code, expiresAt, challengeId) {
  if (!emailDeliveryConfigured) throw new Error("Email verification is unavailable. Configure RESEND_API_KEY and RESEND_FROM_EMAIL.");

  const expirationLabel = new Date(expiresAt).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
  const subject = "Your CB SECURE verification code";
  const text = [
    "CB SECURE email verification",
    "Your one-time verification code is " + code + ".",
    "This code expires at " + expirationLabel + " (in five minutes) and can only be used once.",
    "If you did not request this code, you can ignore this email.",
  ].join("\n\n");
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;background:#f3f6fa;font-family:Arial,Helvetica,sans-serif;color:#152238">
  <div style="max-width:560px;margin:32px auto;padding:0 16px">
    <div style="background:#ffffff;border:1px solid #e5eaf1;border-radius:18px;overflow:hidden">
      <div style="padding:28px 32px;background:#101b2d;color:#ffffff">
        <div style="font-size:12px;font-weight:700;letter-spacing:2px;color:#a8c8ff">CB SECURE</div>
        <h1 style="font-size:24px;line-height:1.25;margin:18px 0 0">Verify your email</h1>
      </div>
      <div style="padding:32px">
        <p style="margin:0 0 20px;font-size:15px;line-height:1.6;color:#42516a">Use this one-time code to continue securely:</p>
        <div style="padding:18px 16px;background:#f3f6fa;border:1px solid #e5eaf1;border-radius:12px;text-align:center;font-size:34px;font-weight:700;letter-spacing:10px;color:#13233b">${code}</div>
        <p style="margin:20px 0 0;font-size:14px;line-height:1.6;color:#42516a">Expires at <strong>${expirationLabel}</strong>. This code can only be used once.</p>
        <p style="margin:20px 0 0;font-size:13px;line-height:1.6;color:#718096">If you did not request this code, you can safely ignore this message.</p>
      </div>
    </div>
    <p style="margin:18px 0 0;text-align:center;font-size:12px;color:#8995a6">CB SECURE · Private file access, verified.</p>
  </div>
</body></html>`;

  let response;
  try {
    response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + resendApiKey,
        "Content-Type": "application/json",
        "Idempotency-Key": "cb-secure-otp/" + challengeId,
      },
      body: JSON.stringify({ from: resendFromEmail, to: [email], subject, text, html }),
      signal: AbortSignal.timeout(15_000),
    });
  } catch (error) {
    const deliveryError = new Error("Resend API request failed.");
    deliveryError.provider = "resend";
    deliveryError.providerCode = ["AbortError", "TimeoutError"].includes(error?.name) ? "TIMEOUT" : "NETWORK_ERROR";
    throw deliveryError;
  }

  if (!response.ok) {
    const responseBody = await response.json().catch(() => ({}));
    const deliveryError = new Error("Resend rejected the email request.");
    deliveryError.provider = "resend";
    deliveryError.responseStatus = response.status;
    deliveryError.providerCode = typeof responseBody?.name === "string" ? responseBody.name.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 60) : "API_ERROR";
    throw deliveryError;
  }

  const result = await response.json().catch(() => ({}));
  if (typeof result?.id !== "string" || !result.id) {
    const deliveryError = new Error("Resend response did not include an email id.");
    deliveryError.provider = "resend";
    deliveryError.responseStatus = response.status;
    deliveryError.providerCode = "INVALID_RESPONSE";
    throw deliveryError;
  }
  return result.id;
}

function otpRateLimitRetryAfter(email, now = Date.now()) {
  const sentAttempts = db.activity
    .filter((entry) => String(entry.userEmail || "").toLowerCase() === email.toLowerCase() && ["OTP_SENT", "OTP_SEND_FAILED"].includes(entry.action))
    .map((entry) => Date.parse(entry.timestamp))
    .filter((timestamp) => Number.isFinite(timestamp) && timestamp > now - otpRateWindowMs)
    .sort((a, b) => a - b);
  if (sentAttempts.length < otpRateLimitPerEmail) return 0;
  return Math.max(1, Math.ceil((sentAttempts[sentAttempts.length - otpRateLimitPerEmail] + otpRateWindowMs - now) / 1000));
}

async function issueChallenge(user, req, res, status = 200) {
  const retryAfter = otpRateLimitRetryAfter(user.email);
  if (retryAfter) {
    audit("OTP_RATE_LIMITED", user, "OTP request rate limit reached for this email address.", req);
    await saveDb();
    res.setHeader("Retry-After", String(retryAfter));
    return res.status(429).json({ error: "Too many verification emails requested. Try again later." });
  }

  const code = createOtp();
  const challenge = {
    id: randomUUID(),
    userId: user.id,
    purpose: status === 201 ? "register" : "login",
    codeHash: createHash("sha256").update(code).digest("hex"),
    expiresAt: Date.now() + otpTtlMs,
    attempts: 0,
  };
  db.challenges = db.challenges.filter((item) => item.expiresAt > Date.now() && item.userId !== user.id);
  db.challenges.push(challenge);
  await saveDb();
  try {
    await deliverOtp(user.email, code, challenge.expiresAt, challenge.id);
  } catch (error) {
    console.error("OTP email delivery failed.", {
      provider: error?.provider || "resend",
      providerCode: error?.providerCode || "UNKNOWN",
      responseStatus: Number.isInteger(error?.responseStatus) ? error.responseStatus : undefined,
    });
    db.challenges = db.challenges.filter((item) => item.id !== challenge.id);
    if (status === 201) db.users = db.users.filter((item) => item.id !== user.id);
    audit("OTP_SEND_FAILED", user, "Verification email delivery failed for " + user.email + ".", req);
    await saveDb();
    return res.status(503).json({ error: "Could not send the verification email. Check the email delivery configuration." });
  }
  audit("OTP_SENT", user, "A one-time verification code was issued.", req);
  await saveDb();
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

const upload = isCloudflare
  ? { single: () => (_req, res) => res.status(410).json({ error: "Use the secure upload ticket flow for Cloudflare storage." }) }
  : multer({
    dest: incomingDir,
    limits: { fileSize: isCloudRun ? 30 * 1024 * 1024 : 100 * 1024 * 1024, files: 1, fields: 8, parts: 9, fieldSize: 4096 },
  });

async function saveCloudStorageObject(ownerId, bytes, digest) {
  const objectName = "cb-secure/" + ownerId + "/" + digest + ".bin";
  await cloudStorage.bucket(storageBucketName).file(objectName).save(bytes, {
    resumable: false,
    contentType: "application/octet-stream",
    metadata: { metadata: { ownerId, sha256: digest } },
  });
  return "gcs:" + objectName;
}

async function deleteCloudStorageObject(storageReference) {
  if (!cloudStorage || !storageReference?.startsWith("gcs:")) return;
  await cloudStorage.bucket(storageBucketName).file(storageReference.slice("gcs:".length)).delete({ ignoreNotFound: true });
}

app.disable("x-powered-by");
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
const allowedOrigins = new Set([
  process.env.CORS_ORIGIN,
  process.env.URL,
  process.env.DEPLOY_PRIME_URL,
  process.env.NETLIFY_URL,
  "http://localhost:5173",
].filter(Boolean).flatMap((value) => value.split(",")).map((value) => value.trim()));
app.use(cors({ origin: (origin, callback) => callback(null, !origin || allowedOrigins.has(origin)) }));
app.use(express.json({ limit: "1mb" }));
app.use("/api/auth", isCloudflare ? cloudflareAuthRateLimit : rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));
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
  const missing = deployedConfigurationIssues();
  res.json({
    status: missing.length ? "setup_required" : "ok",
    missing,
    capabilities: {
      webCrypto: true,
      aes256gcm: true,
      sha256: true,
      database: Boolean(databasePool) || (isCloudflare && process.env.CF_D1_ACTIVE === "true"),
      durableMetadata: Boolean(databasePool) || (isCloudflare && process.env.CF_D1_ACTIVE === "true"),
      emailOtp: emailDeliveryConfigured,
      privateBlobStorage: privateBlobConfigured,
      cloudflareD1FileStorage: isCloudflare && process.env.CF_D1_ACTIVE === "true",
      directUploads: privateBlobConfigured || (isCloudflare && process.env.CF_D1_ACTIVE === "true"),
      durableFileStorage: Boolean(process.env.PINATA_JWT || privateBlobConfigured || (isCloudflare && process.env.CF_D1_ACTIVE === "true")),
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
  if (!emailDeliveryConfigured) return res.status(503).json({ error: "Email verification is not configured on this deployment yet." });
  const existingUser = db.users.find((user) => user.email === normalizedEmail);
  if (existingUser?.mfaVerified) return res.status(409).json({ error: "An account with that email already exists." });
  if (existingUser) {
    db.challenges = db.challenges.filter((item) => item.userId !== existingUser.id);
    db.users = db.users.filter((item) => item.id !== existingUser.id);
    await saveDb();
  }
  const passwordHash = await hashPassword(password);
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
  const valid = user?.passwordHash && await verifyPassword(String(req.body?.password || ""), user.passwordHash);
  if (!valid) {
    audit("LOGIN_FAILED", user, "Invalid email or password.", req);
    await saveDb();
    return res.status(401).json({ error: "Email or password is incorrect." });
  }
  if (!emailDeliveryConfigured) return res.status(503).json({ error: "Email verification is not configured on this deployment yet." });
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

const maximumFileSize = isCloudflare ? 20 * 1024 * 1024 : 100 * 1024 * 1024;
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
  if (!privateStorageConfigured()) return res.status(503).json({ error: "Private object storage is not connected to this deployment." });
  const metadata = validateUploadMetadata(req.body || {}, "create");
  if (!metadata) return res.status(400).json({ error: "Encrypted file metadata is incomplete or invalid." });
  const ticket = await createBlobUploadTicket(req.user, metadata, "create");
  res.status(201).json({ ticketId: ticket.id, pathname: ticket.pathname, mode: ticket.mode });
});

app.post("/api/files/:id/replace-ticket", authenticate, async (req, res) => {
  if (!privateStorageConfigured()) return res.status(503).json({ error: "Private object storage is not connected to this deployment." });
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
  if (!privateStorageConfigured()) return res.status(503).json({ error: "Private object storage is not connected to this deployment." });
  if (isCloudflare) {
    const d1 = dbContext.getStore()?.d1;
    const ticketId = String(req.get("x-upload-ticket") || "");
    const ticket = db.pendingUploads.find((item) => item.id === ticketId && item.userId === req.user.id);
    const removePartialUpload = async () => {
      if (ticket && d1) await d1.prepare("DELETE FROM cb_secure_file_chunks WHERE storage_key = ?").bind(ticket.pathname).run();
    };
    let reader;
    try {
      if (!ticket || ticket.expiresAt <= Date.now()) return res.status(404).json({ error: "The upload ticket is invalid or expired." });
      if (!d1) return res.status(503).json({ error: "Cloudflare D1 storage is unavailable." });
      if (req.get("content-type")?.split(";")[0].trim().toLowerCase() !== "application/octet-stream") {
        return res.status(400).json({ error: "The upload must contain encrypted application/octet-stream bytes." });
      }
      await removePartialUpload();
      reader = Readable.toWeb(req).getReader();
      let received = 0;
      let chunkIndex = 0;
      let pendingSize = 0;
      let pendingParts = [];
      let statements = [];
      const queueChunk = async (size) => {
        const payload = new Uint8Array(size);
        let offset = 0;
        for (const part of pendingParts) { payload.set(part, offset); offset += part.byteLength; }
        statements.push(d1.prepare("INSERT INTO cb_secure_file_chunks (storage_key, chunk_index, payload) VALUES (?, ?, ?)").bind(ticket.pathname, chunkIndex++, payload));
        pendingParts = [];
        pendingSize = 0;
        if (statements.length >= cloudflareFileChunkBatchSize) {
          await d1.batch(statements);
          statements = [];
        }
      };
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
        received += bytes.byteLength;
        if (received > ticket.metadata.encryptedSize) throw new Error("The encrypted upload is larger than its ticket allows.");
        let offset = 0;
        while (offset < bytes.byteLength) {
          const take = Math.min(cloudflareFileChunkBytes - pendingSize, bytes.byteLength - offset);
          pendingParts.push(bytes.subarray(offset, offset + take));
          pendingSize += take;
          offset += take;
          if (pendingSize === cloudflareFileChunkBytes) await queueChunk(pendingSize);
        }
      }
      if (received !== ticket.metadata.encryptedSize) throw new Error("The encrypted upload size did not match its ticket.");
      if (pendingSize) await queueChunk(pendingSize);
      if (statements.length) await d1.batch(statements);
      return res.status(201).json({ uploaded: true });
    } catch (error) {
      await reader?.cancel().catch(() => {});
      await removePartialUpload().catch(() => {});
      console.error("Cloudflare D1 file upload failed.", error instanceof Error ? error.message : "Unknown error");
      return res.status(502).json({ error: "Ciphertext storage failed." });
    }
  }
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
    if (isCloudflare) {
      const d1 = dbContext.getStore()?.d1;
      if (!d1) return null;
      const summary = await d1.prepare("SELECT COUNT(*) AS chunks, COALESCE(SUM(length(payload)), 0) AS byte_length FROM cb_secure_file_chunks WHERE storage_key = ?").bind(ticket.pathname).first();
      const expectedChunks = Math.ceil(ticket.metadata.encryptedSize / cloudflareFileChunkBytes);
      if (Number(summary?.chunks) !== expectedChunks || Number(summary?.byte_length) !== ticket.metadata.encryptedSize) return null;
      return summary;
    }
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
    storage: isCloudflare ? "d1" : "blob",
    encryptedSize: ticket.metadata.encryptedSize,
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
  const oldPath = ["blob", "d1"].includes(file.storage) ? file.storagePath : null;
  file.storage = isCloudflare ? "d1" : "blob";
  file.storagePath = ticket.pathname;
  file.encryptedSize = ticket.metadata.encryptedSize;
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
    res.locals.afterDatabaseCommit(() => isCloudflare ? deleteCloudflareFileChunks(oldPath) : deleteBlob(oldPath, { access: "private" }));
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
    } else if (isCloudRun && cloudStorage) {
      const bytes = await readFile(req.file.path);
      const digest = createHash("sha256").update(bytes).digest("hex");
      cid = await saveCloudStorageObject(req.user.id, bytes, digest);
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
    storage: process.env.PINATA_JWT ? "ipfs" : isCloudRun && cloudStorage ? "gcs" : "local",
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
  const storage = process.env.PINATA_JWT ? "ipfs" : isCloudRun && cloudStorage ? "gcs" : "local";
  try {
    if (process.env.PINATA_JWT) {
      const form = new FormData();
      form.append("file", new Blob([await readFile(req.file.path)]), "ciphertext.bin");
      const pinResponse = await fetch("https://api.pinata.cloud/pinning/pinFileToIPFS", { method: "POST", headers: { Authorization: "Bearer " + process.env.PINATA_JWT }, body: form });
      if (!pinResponse.ok) throw new Error("IPFS pin request failed.");
      cid = (await pinResponse.json()).IpfsHash;
      await unlink(req.file.path);
    } else if (storage === "gcs") {
      const bytes = await readFile(req.file.path);
      const digest = createHash("sha256").update(bytes).digest("hex");
      cid = await saveCloudStorageObject(req.user.id, bytes, digest);
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
  const oldStorage = file.storage;
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
  if (oldStorage === "gcs" && oldCid !== cid && !db.files.some((item) => item.id !== file.id && item.storage === "gcs" && item.ipfsCid === oldCid)) {
    if (res.locals.afterDatabaseCommit) res.locals.afterDatabaseCommit(() => deleteCloudStorageObject(oldCid));
    else await deleteCloudStorageObject(oldCid).catch(() => {});
  }
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
  if (file.storage === "d1" && file.storagePath) {
    const d1 = dbContext.getStore()?.d1;
    const encryptedSize = Number(file.encryptedSize);
    if (!d1 || !Number.isSafeInteger(encryptedSize) || encryptedSize < 16 || encryptedSize > maximumFileSize + 16) {
      return res.status(404).json({ error: "Encrypted file bytes were not found." });
    }
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Length", String(encryptedSize));
    res.setHeader("Content-Disposition", "attachment; filename=\"ciphertext.bin\"");
    const encryptedChunks = async function* () {
      const chunkCount = Math.ceil(encryptedSize / cloudflareFileChunkBytes);
      for (let index = 0; index < chunkCount; index += 1) {
        const row = await d1.prepare("SELECT payload FROM cb_secure_file_chunks WHERE storage_key = ? AND chunk_index = ?").bind(file.storagePath, index).first();
        if (!row?.payload) throw new Error("Encrypted file chunk is missing.");
        yield Buffer.from(row.payload);
      }
    };
    const stream = Readable.from(encryptedChunks());
    stream.on("error", () => {
      if (!res.headersSent) res.status(404).json({ error: "Encrypted file bytes were not found." });
      else res.destroy();
    });
    return stream.pipe(res);
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
  if (file.storage === "gcs" && file.ipfsCid?.startsWith("gcs:")) {
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", "attachment; filename=\"ciphertext.bin\"");
    const stream = cloudStorage.bucket(storageBucketName).file(file.ipfsCid.slice("gcs:".length)).createReadStream();
    stream.on("error", () => {
      if (!res.headersSent) res.status(404).json({ error: "Encrypted file bytes were not found." });
      else res.destroy();
    });
    return stream.pipe(res);
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
  if (process.env.NODE_ENV === "production" && !isFunctionPlatform && !isCloudflare) {
  const frontendDist = path.resolve(here, "../../frontend/dist");
  app.use(express.static(frontendDist, { index: false, maxAge: "1h" }));
  app.get("*", (req, res, next) => {
    if (req.path === "/api" || req.path.startsWith("/api/")) return next();
    res.sendFile(path.join(frontendDist, "index.html"));
  });
}
app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError) return res.status(413).json({ error: isCloudRun ? "Upload exceeds the 30 MB Cloud Run file limit." : "Upload exceeds the 100 MB file limit." });
  console.error("CB SECURE request failed.", error instanceof Error ? error.message : "Unknown error");
  res.status(500).json({ error: "Unexpected server error." });
});

if (!isCloudflare && !isFunctionPlatform) app.listen(port, "0.0.0.0", () => console.log("CB SECURE service listening on port " + port));

export default app;
