import { useMemo, useRef, useState } from "react";
import type { FormEvent, PointerEvent as ReactPointerEvent, ReactNode } from "react";
import {
  Activity, ArrowDownToLine, ArrowLeft, ArrowRight, ArrowUpRight, Bell, Check, CheckCircle2,
  ChevronDown, Clock3, Cloud, Copy, File, FileArchive, FileImage, FileKey2, FileText,
  Fingerprint, FolderLock, Globe2, HardDrive, KeyRound, LayoutDashboard, LockKeyhole,
  LogOut, Menu, Pencil, Plus, ScanLine, Search, Shield, ShieldAlert,
  ShieldCheck, Share2, Sparkles, Users, WalletCards, X,
} from "lucide-react";
import { BrowserProvider, Contract, getAddress } from "ethers";
import { api, type ActivityItem, type FileRecord, type GrantRecord, type SharedFile, type User, setToken } from "./lib/api";
import { decryptFile, decryptSharedFile, ensureIdentity, encryptFile, formatBytes, replaceOwnedFileContent, replaceSharedFileContent, wrapDekForRecipient } from "./lib/crypto";
import metamaskFox from "./assets/metamask-fox.svg";
import type { ClientIdentity } from "./lib/crypto";

type View = "overview" | "files" | "integrity" | "activity" | "governance";
type AuthMode = "login" | "register";
type FileCategory = "all" | "images" | "documents" | "other";
type Toast = { text: string; tone: "success" | "error" | "info" };
const contractAddress = import.meta.env.VITE_CONTRACT_ADDRESS as string | undefined;
const contractAbi = [
  "function uploadFile(string ipfsCid, string sha256Hash) returns (uint256)",
  "function updateFile(uint256 fileId, string ipfsCid, string sha256Hash)",
  "function grantAccess(uint256 fileId, address targetUser, uint8 permissionLevel)",
  "function revokeAccess(uint256 fileId, address targetUser)",
  "function hasAccess(uint256 fileId, address user) view returns (bool)",
];

declare global {
  interface Window {
    ethereum?: { request: (args: { method: string; params?: unknown[] }) => Promise<unknown> };
  }
}

function initials(value: string) {
  return value.split(/[ .@_-]/).filter(Boolean).slice(0, 2).map((part) => part[0].toUpperCase()).join("");
}

function roleLabel(role: User["role"]) {
  return role === "Reader" ? "Viewer" : role;
}

function dateLabel(value: string) {
  return new Intl.DateTimeFormat("en", { month: "short", day: "numeric", year: "numeric" }).format(new Date(value));
}

function shortAddress(value: string | null | undefined) {
  return value ? value.slice(0, 6) + "…" + value.slice(-4) : "Not connected";
}

function fileIcon(name: string) {
  const ext = name.split(".").pop()?.toLowerCase();
  if (["png", "jpg", "jpeg", "gif", "webp", "svg"].includes(ext || "")) return <FileImage size={18} />;
  if (["zip", "rar", "7z", "tar"].includes(ext || "")) return <FileArchive size={18} />;
  if (["pdf", "doc", "docx", "txt", "md"].includes(ext || "")) return <FileText size={18} />;
  return <File size={18} />;
}

function categoryForFile(file: FileRecord): Exclude<FileCategory, "all"> {
  const extension = file.originalName.split(".").pop()?.toLowerCase() || "";
  if (file.mimeType.startsWith("image/") || ["png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "tif", "tiff", "heic"].includes(extension)) return "images";
  if (file.mimeType.startsWith("text/") || ["pdf", "doc", "docx", "odt", "rtf", "txt", "md", "xls", "xlsx", "csv", "ppt", "pptx"].includes(extension)) return "documents";
  return "other";
}

function AmbientBackdrop() {
  return <div className="ambient-scene" aria-hidden="true">
    <div className="ambient-glow ambient-glow-one" />
    <div className="ambient-glow ambient-glow-two" />
    <div className="ambient-glow ambient-glow-three" />
    <div className="ambient-ring ambient-ring-one" />
    <div className="ambient-ring ambient-ring-two" />
    <svg className="ambient-flow" viewBox="0 0 1600 900" preserveAspectRatio="none">
      <path className="ambient-flow-line flow-line-one" d="M-120 650 C 190 430 240 140 590 220 S 1040 820 1710 270" />
      <path className="ambient-flow-line flow-line-two" d="M-100 310 C 240 590 460 760 770 540 S 1230 120 1700 500" />
      <path className="ambient-flow-line flow-line-three" d="M-100 820 C 300 720 450 330 810 350 S 1280 760 1700 130" />
    </svg>
    <div className="ambient-star star-one" />
    <div className="ambient-star star-two" />
    <div className="ambient-star star-three" />
    <div className="ambient-star star-four" />
    <div className="ambient-star star-five" />
  </div>;
}

function useToast() {
  const [toast, setToast] = useState<Toast | null>(null);
  const timer = useRef<number | undefined>(undefined);
  const showToast = (text: string, tone: Toast["tone"] = "info") => {
    setToast({ text, tone });
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setToast(null), 4200);
  };
  return { toast, showToast, dismissToast: () => setToast(null) };
}

function AuthScreen({ onAuthenticated, initialMode, onBack }: { onAuthenticated: (user: User, password: string) => void; initialMode: AuthMode; onBack: () => void }) {
  const [mode, setMode] = useState<AuthMode>(initialMode);
  const [step, setStep] = useState<"credentials" | "otp">("credentials");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");
  const [visible, setVisible] = useState(false);
  async function requestCode(event: FormEvent) {
    event.preventDefault();
    setError("");
    setWorking(true);
    try {
      const result = mode === "login"
        ? await api.login(email, password)
        : await api.register(name, email, password);
      setChallengeId(result.challengeId);
      setOtp("");
      setStep("otp");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not start sign in.");
    } finally {
      setWorking(false);
    }
  }

  async function verifyCode(event: FormEvent) {
    event.preventDefault();
    setError("");
    setWorking(true);
    try {
      const result = await api.verifyOtp(challengeId, otp);
      setToken(result.token);
      try {
        const identity: ClientIdentity = await ensureIdentity(result.user.email, password);
        await api.publishPublicKey(identity.publicKey);
      } catch {
        setToken("");
        throw new Error("Your encryption identity could not be unlocked with this password. Check the password or clear this browser’s saved CB SECURE identity.");
      }
      onAuthenticated(result.user, password);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The code could not be verified.");
    } finally {
      setWorking(false);
    }
  }

  return (
    <div className="auth-page">
      <AmbientBackdrop />
      <div className="auth-glow auth-glow-one" />
      <div className="auth-glow auth-glow-two" />
      <div className="auth-frame">
        <section className="auth-intro">
          <Brand />
          <AuthMascot />
          <div className="auth-copy">
            <div className="eyebrow"><span className="status-dot" /> ZERO-TRUST FILE VAULT</div>
            <h1>Meet your<br /><span>private vault.</span></h1>
            <p>Keep your files protected in your browser, then decide who can access them and what they can do.</p>
            <div className="auth-proof">
              <div className="proof-line"><span className="proof-icon"><LockKeyhole size={15} /></span><span>Encrypted before upload</span><Check size={15} /></div>
              <div className="proof-line"><span className="proof-icon cyan"><Users size={15} /></span><span>Access by role and permission</span><Check size={15} /></div>
              <div className="proof-line"><span className="proof-icon green"><ShieldCheck size={15} /></span><span>Integrity checked on open</span><Check size={15} /></div>
            </div>
          </div>
          <div className="auth-footnote"><span className="pulse-ring" /> Encrypted in this browser before upload</div>
        </section>

        <section className="auth-panel">
          <div className="auth-panel-top">
            <button className="auth-back-home" onClick={onBack}><ArrowLeft size={14} /> Website</button>
            <div className="mobile-brand"><Brand /><AuthMascot compact /></div>
            <span className="env-pill"><span /> SECURE ACCESS</span>
          </div>
          {step === "credentials" ? (
            <>
          <div className="auth-heading">
                <div className="eyebrow">WELCOME TO YOUR PRIVATE VAULT</div>
                <h2>{mode === "login" ? "Sign in securely" : "Create your account"}</h2>
            <p>Verify your email and unlock your encryption identity.</p>
              </div>
              <form className="auth-form" onSubmit={requestCode}>
                {mode === "register" && <label>Full name<input required value={name} onChange={(event) => setName(event.target.value)} placeholder="Your name" autoComplete="name" /></label>}
                <label>Email address<div className="input-with-icon"><span>@</span><input required type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" autoComplete="email" /></div></label>
                <label>Password<div className="password-wrap"><input required minLength={mode === "register" ? 10 : 1} type={visible ? "text" : "password"} value={password} onChange={(event) => setPassword(event.target.value)} autoComplete={mode === "login" ? "current-password" : "new-password"} /><button className="input-action" type="button" aria-label={visible ? "Hide password" : "Show password"} onClick={() => setVisible(!visible)}>{visible ? <EyeOffIcon /> : <EyeIcon />}</button></div></label>
                {error && <div className="inline-error"><ShieldAlert size={15} />{error}</div>}
                <button className="button button-primary auth-submit" disabled={working}>{working ? <span className="spinner" /> : <Fingerprint size={17} />}{working ? "Securing session…" : "Continue with email"}</button>
              </form>
              <div className="auth-switch"><span>{mode === "login" ? "New to CB SECURE?" : "Already have an account?"}</span><button onClick={() => { setMode(mode === "login" ? "register" : "login"); setError(""); }}> {mode === "login" ? "Create account" : "Sign in"}</button></div>
            </>
          ) : (
            <>
              <button className="back-link" onClick={() => setStep("credentials")}>← Back to sign in</button>
              <div className="otp-visual"><div className="otp-orbit"><Fingerprint size={30} /></div><span className="otp-check"><Check size={13} /></span></div>
              <div className="auth-heading centered">
                <div className="eyebrow">MULTI-FACTOR VERIFICATION</div>
                <h2>Check your inbox</h2>
                <p>Enter the six-digit verification code sent to <strong>{email}</strong>.</p>
              </div>
              <form className="auth-form" onSubmit={verifyCode}>
                <label>Verification code<input className="otp-input" value={otp} onChange={(event) => setOtp(event.target.value.replace(/\D/g, "").slice(0, 6))} inputMode="numeric" maxLength={6} placeholder="000000" autoComplete="one-time-code" /></label>
                {error && <div className="inline-error"><ShieldAlert size={15} />{error}</div>}
                <button className="button button-primary auth-submit" disabled={working || otp.length !== 6}>{working ? <span className="spinner" /> : <ArrowRight size={17} />}{working ? "Verifying…" : "Verify and open vault"}</button>
              </form>
              <div className="auth-caption">Codes expire after 5 minutes and can only be used once.</div>
            </>
          )}
          <div className="auth-legal"><span>CB SECURE <i>·</i> PRIVATE BY DESIGN</span><span>Client-side encrypted storage</span></div>
        </section>
      </div>
    </div>
  );
}

function AuthMascot({ compact = false }: { compact?: boolean }) {
  function followPointer(event: ReactPointerEvent<HTMLDivElement>) {
    const bounds = event.currentTarget.getBoundingClientRect();
    const dx = (event.clientX - bounds.left - bounds.width / 2) / bounds.width;
    const dy = (event.clientY - bounds.top - bounds.height / 2) / bounds.height;
    event.currentTarget.style.setProperty("--mascot-x", Math.max(-6, Math.min(6, dx * 17)) + "px");
    event.currentTarget.style.setProperty("--mascot-y", Math.max(-5, Math.min(5, dy * 14)) + "px");
  }
  function resetPointer(event: ReactPointerEvent<HTMLDivElement>) {
    event.currentTarget.style.setProperty("--mascot-x", "0px");
    event.currentTarget.style.setProperty("--mascot-y", "0px");
  }
  return <div className={"auth-mascot-stage" + (compact ? " compact" : "")} onPointerMove={followPointer} onPointerLeave={resetPointer} aria-hidden="true">
    <div className="metamask-fox-follow"><img className="metamask-fox" src={metamaskFox} alt="" /></div>
    {!compact && <span className="mascot-caption"><i /> PROTECTING YOUR PRIVACY</span>}
  </div>;
}

function LandingScreen({ onLogin, onRegister }: { onLogin: () => void; onRegister: () => void }) {
  return <div className="marketing-page">
    <AmbientBackdrop />
    <header className="marketing-nav">
      <Brand />
      <nav aria-label="Main navigation" className="marketing-links"><a href="#features">Features</a><a href="#how-it-works">How it works</a><a href="#security">Security</a></nav>
      <div className="marketing-nav-actions"><button className="marketing-signin" onClick={onLogin}>Sign in</button><button className="button button-primary marketing-start" onClick={onRegister}>Create account <ArrowRight size={15} /></button></div>
    </header>
    <main>
      <section className="marketing-hero">
        <div className="marketing-copy">
          <div className="marketing-kicker"><span className="status-dot" /> PRIVATE FILE VAULT</div>
          <h1>Your files.<br /><span>Your control.</span></h1>
          <p>Store, protect, and share files with encryption that starts in your browser. You decide who can open each file and what they can do with it.</p>
          <div className="marketing-cta"><button className="button button-primary" onClick={onRegister}>Create your vault <ArrowRight size={16} /></button><button className="marketing-secondary" onClick={onLogin}>I already have an account</button></div>
          <div className="marketing-promise"><span><CheckCircle2 size={14} /> Encrypted before upload</span><span><CheckCircle2 size={14} /> Access by permission</span></div>
        </div>
        <div className="marketing-art" aria-label="Illustration of browser encryption and protected file sharing">
          <div className="marketing-orbit marketing-orbit-a" /><div className="marketing-orbit marketing-orbit-b" /><div className="marketing-orbit marketing-orbit-c" />
          <div className="marketing-shield-card"><div className="marketing-card-top"><span>CB SECURE VAULT</span><span className="marketing-card-live"><i /> PROTECTED</span></div><div className="marketing-lock-mark"><ShieldCheck size={42} strokeWidth={1.4} /><span /></div><h2>Private by design</h2><p>Your browser encrypts file contents before they leave your device.</p><div className="marketing-encryption-tag"><LockKeyhole size={13} /> AES-256-GCM <span /> SHA-256 integrity</div></div>
          <div className="marketing-float-chip chip-browser"><Fingerprint size={15} /><span><strong>YOUR BROWSER</strong><small>Encryption happens here</small></span></div>
          <div className="marketing-float-chip chip-access"><KeyRound size={15} /><span><strong>YOUR PERMISSIONS</strong><small>Share only what you choose</small></span></div>
        </div>
      </section>
      <section className="marketing-features" id="features">
        <div className="marketing-section-head"><span className="eyebrow">A SAFER WAY TO SHARE</span><h2>Built around your privacy.</h2><p>Keep file protection understandable, from the first upload to every access change.</p></div>
        <div className="marketing-feature-grid">
          <article className="marketing-feature-card"><span className="marketing-feature-icon mint"><LockKeyhole size={19} /></span><h3>Encrypt in your browser</h3><p>Files are encrypted before upload, so the storage service receives protected content.</p><span className="marketing-feature-note">AES-256-GCM</span></article>
          <article className="marketing-feature-card"><span className="marketing-feature-icon blue"><Share2 size={19} /></span><h3>Choose who gets access</h3><p>Assign Viewer, Editor, or Admin roles and grant file access to the right people.</p><span className="marketing-feature-note">Role-based permissions</span></article>
          <article className="marketing-feature-card"><span className="marketing-feature-icon purple"><Fingerprint size={19} /></span><h3>Verify files when opened</h3><p>Check the decrypted file against its saved SHA-256 digest after each successful open.</p><span className="marketing-feature-note">Integrity checks</span></article>
        </div>
      </section>
      <section className="marketing-how" id="how-it-works">
        <div className="marketing-section-head"><span className="eyebrow">SIMPLE, CLEAR, CONTROLLED</span><h2>From upload to access.</h2></div>
        <div className="marketing-steps"><article><span>01</span><div><h3>Sign in securely</h3><p>Verify your account with an email code to enter your private workspace.</p></div></article><article><span>02</span><div><h3>Upload and protect</h3><p>Select a file and encrypt it in your browser before it is stored.</p></div></article><article><span>03</span><div><h3>Share by permission</h3><p>Choose an eligible account and decide whether they can read or edit.</p></div></article></div>
      </section>
      <section className="marketing-security" id="security"><div><span className="eyebrow">SECURITY THAT STAYS VISIBLE</span><h2>Know what is protected<br />and who can access it.</h2><p>Review activity, manage account roles, and revoke access from one workspace.</p></div><button className="button button-primary" onClick={onRegister}>Get started <ArrowRight size={15} /></button></section>
    </main>
    <footer className="marketing-footer"><Brand /><span>© 2026 CB SECURE <i>·</i> PRIVATE BY DESIGN</span><button onClick={onLogin}>Sign in</button></footer>
  </div>;
}

function EyeIcon() { return <span className="eye-glyph">◉</span>; }
function EyeOffIcon() { return <span className="eye-glyph">⊘</span>; }

function Brand() {
  return <div className="brand-lockup"><div className="brand-mark"><ShieldCheck size={20} strokeWidth={1.8} /><span /></div><div><strong>CB <b>SECURE</b></strong><small>PRIVATE CLOUD VAULT</small></div></div>;
}

function MetaMaskMark() {
  return <svg className="metamask-mark" viewBox="0 0 32 32" aria-hidden="true">
    <path fill="#E27625" d="M3.4 4.2 14.2 11l-2 4.4-6.5-2.1-4.1-5.1L3.4 4.2Z" />
    <path fill="#E27625" d="M28.6 4.2 17.8 11l2 4.4 6.5-2.1 4.1-5.1-1.8-4Z" />
    <path fill="#F6851B" d="m5.7 14.1 6.7 2.2 2.1 4.1-4.9 5-5.2-2.9-1.1-5.2 2.4-3.2Z" />
    <path fill="#F6851B" d="m26.3 14.1-6.7 2.2-2.1 4.1 4.9 5 5.2-2.9 1.1-5.2-2.4-3.2Z" />
    <path fill="#E27625" d="m12.4 16.1 3.6-1.8 3.6 1.8-1.1 6.4-2.5 2-2.5-2-1.1-6.4Z" />
    <path fill="#CD6116" d="m10 25.4 2.4-2.4 3.6 1.7 3.6-1.7 2.4 2.4-3.2 3H13l-3-3Z" />
    <path fill="#763D16" d="m12.6 17.8 2.1-.5 1.3 1.1-1.3 1.1-2.1-1.7Zm6.8 0-2.1-.5-1.3 1.1 1.3 1.1 2.1-1.7Z" />
  </svg>;
}

function FileTable({ files, busyId, currentUserId, role, onDownload, onShare, onRename, onReplace, onCopy, allowShare = true, grants = [] }: {
  files: FileRecord[];
  busyId: string;
  currentUserId: string;
  role: User["role"];
  onDownload: (file: FileRecord, grant?: SharedFile) => void;
  onShare?: (file: FileRecord) => void;
  onRename: (file: FileRecord) => void;
  onReplace: (file: FileRecord, grant?: SharedFile) => void;
  onCopy: (value: string) => void;
  allowShare?: boolean;
  grants?: SharedFile[];
}) {
  if (!files.length) return <div className="empty-state"><div className="empty-icon"><FolderLock size={22} /></div><strong>No encrypted files yet</strong><span>Your vault will appear here once you add a file.</span></div>;
  return (
    <div className="file-table-wrap">
      <table className="file-table">
        <thead><tr><th>FILE NAME</th><th>SIZE</th><th>STORAGE</th><th>ADDED</th><th>INTEGRITY</th><th aria-label="Actions" /></tr></thead>
        <tbody>{files.map((file) => {
          const isBusy = busyId === file.id;
          const grant = grants.find((item) => item.file.id === file.id);
          const isOwner = file.ownerId === currentUserId;
          const canDownload = isOwner || ((role === "Editor" || role === "Admin") && Boolean(grant));
          const canEdit = isOwner || role === "Admin" || (role === "Editor" && grant?.permissionLevel === 2);
          const canReplace = isOwner || ((role === "Editor" || role === "Admin") && grant?.permissionLevel === 2);
          return <tr key={file.id}>
            <td><div className="file-name-cell"><span className="file-type-icon">{fileIcon(file.originalName)}</span><span><strong>{file.originalName}</strong><small>{role === "Admin" && !isOwner ? file.ownerEmail : file.ipfsCid.slice(0, 13) + "…"}</small></span></div></td>
            <td className="muted-cell">{formatBytes(file.size)}</td>
            <td><span className={"storage-pill " + (file.storage === "ipfs" ? "ipfs" : file.storage === "gcs" || file.storage === "blob" ? "gcs" : "local")}><span />{file.storage === "ipfs" ? "IPFS" : file.storage === "gcs" || file.storage === "blob" ? "Cloud" : "Local"}</span></td>
            <td className="muted-cell">{dateLabel(file.createdAt)}</td>
            <td><span className="integrity-pill"><CheckCircle2 size={13} /> SHA-256</span></td>
            <td><div className="row-actions">
              <button className="icon-button" title="Copy content ID" onClick={() => onCopy(file.ipfsCid)}><Copy size={15} /></button>
              {allowShare && onShare && (isOwner || role === "Admin") && <button className="icon-button" title={isOwner ? "Share file" : "Review file access"} onClick={() => onShare(file)}><Share2 size={15} /></button>}
              {canEdit && <button className="icon-button" title="Rename file" onClick={() => onRename(file)}><Pencil size={14} /></button>}
              {canReplace && <button className="icon-button" title="Replace encrypted file contents" onClick={() => onReplace(file, grant)}><Cloud size={15} /></button>}
              {canDownload && <button className="icon-button download-action" title="Decrypt and download" disabled={isBusy} onClick={() => onDownload(file, grant)}>{isBusy ? <span className="spinner dark" /> : <ArrowDownToLine size={15} />}</button>}
              {grant && <span className="permission-mini">{grant.permissionLevel === 2 ? "WRITE" : "READ"}</span>}
            </div></td>
          </tr>;
        })}</tbody>
      </table>
    </div>
  );
}

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [entryPage, setEntryPage] = useState<"landing" | "auth">("landing");
  const [authMode, setAuthMode] = useState<AuthMode>("login");
  const [password, setPassword] = useState("");
  const [identity, setIdentity] = useState<ClientIdentity | null>(null);
  const [view, setView] = useState<View>("overview");
  const [files, setFiles] = useState<FileRecord[]>([]);
  const [shared, setShared] = useState<SharedFile[]>([]);
  const [sharedCount, setSharedCount] = useState(0);
  const [fileSummary, setFileSummary] = useState({ totalCount: 0, ownCount: 0, sharedCount: 0 });
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [auditStatus, setAuditStatus] = useState<{ valid: boolean; checkedEvents: number } | null>(null);
  const [directory, setDirectory] = useState<Array<User & { publicKey: JsonWebKey | null }>>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [query, setQuery] = useState("");
  const [fileCategory, setFileCategory] = useState<FileCategory>("all");
  const [uploading, setUploading] = useState(false);
  const [uploadStep, setUploadStep] = useState("");
  const [busyId, setBusyId] = useState("");
  const [selectedUpload, setSelectedUpload] = useState<File | null>(null);
  const [replaceContext, setReplaceContext] = useState<{ file: FileRecord; grant?: SharedFile } | null>(null);
  const [shareTarget, setShareTarget] = useState<FileRecord | null>(null);
  const [recipientEmail, setRecipientEmail] = useState("");
  const [permissionLevel, setPermissionLevel] = useState(1);
  const [grants, setGrants] = useState<GrantRecord[]>([]);
  const [shareWorking, setShareWorking] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [walletAddress, setWalletAddress] = useState<string | null>(null);
  const [provider, setProvider] = useState<BrowserProvider | null>(null);
  const [mobileNav, setMobileNav] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const replaceInputRef = useRef<HTMLInputElement>(null);
  const { toast, showToast, dismissToast } = useToast();

  const refreshData = async (currentUser: User) => {
    try {
      const results = await Promise.all([
        api.files(), api.shared(), api.fileSummary(), api.activity(), api.directory(),
        currentUser.role === "Admin" ? api.users() : Promise.resolve([] as User[]),
        currentUser.role === "Admin" ? api.verifyActivity() : Promise.resolve(null),
      ]);
      setFiles(results[0]);
      setShared(results[1].items);
      setSharedCount(results[1].count);
      setFileSummary(results[2]);
      setActivity(results[3]);
      setDirectory(results[4]);
      setUsers(results[5]);
      setAuditStatus(results[6]);
    } catch (error) {
      showToast(error instanceof Error ? error.message : "Could not load vault data.", "error");
    }
  };

  const authenticate = async (nextUser: User, nextPassword: string) => {
    try {
      const nextIdentity = await ensureIdentity(nextUser.email, nextPassword);
      setIdentity(nextIdentity);
      setUser(nextUser);
      setPassword(nextPassword);
      await refreshData(nextUser);
    } catch (error) {
      showToast(error instanceof Error ? error.message : "Could not unlock encryption identity.", "error");
      setToken("");
    }
  };

  const signOut = () => {
    setToken("");
    setUser(null);
    setPassword("");
    setIdentity(null);
    setFiles([]);
    setShared([]);
    setSharedCount(0);
    setFileSummary({ totalCount: 0, ownCount: 0, sharedCount: 0 });
    setReplaceContext(null);
    setUsers([]);
    setFileCategory("all");
    setWalletAddress(null);
    setProvider(null);
    setView("overview");
    setEntryPage("landing");
    setAuthMode("login");
  };

  async function connectWallet() {
    if (!window.ethereum) {
      showToast("Install MetaMask to bind an Ethereum wallet.", "error");
      return;
    }
    try {
      const web3 = new BrowserProvider(window.ethereum as never);
      await web3.send("eth_requestAccounts", []);
      const signer = await web3.getSigner();
      const address = await signer.getAddress();
      const challenge = await api.walletNonce();
      const signature = await signer.signMessage(challenge.nonce);
      const bound = await api.bindWallet(address, signature);
      setProvider(web3);
      setWalletAddress(address);
      setUser(bound.user);
      showToast("Wallet signature verified and address linked.", "success");
      await refreshData(bound.user);
    } catch (error) {
      showToast(error instanceof Error ? error.message : "Wallet verification failed.", "error");
    }
  }

  async function uploadSelected() {
    if (!selectedUpload || !user) return;
    setUploading(true);
    setUploadStep("Encrypting in browser");
    try {
      const encrypted = await encryptFile(selectedUpload, password);
      setUploadStep("Sending ciphertext");
      const saved = await api.upload(selectedUpload, encrypted.ciphertext, encrypted.metadata);
      let file = saved.file;
      if (contractAddress && provider && file.storage === "ipfs") {
        try {
          setUploadStep("Registering on EVM");
          const signer = await provider.getSigner();
          const contract = new Contract(contractAddress, contractAbi, signer);
          const transaction = await contract.uploadFile(file.ipfsCid, file.sha256Hash);
          const receipt = await transaction.wait();
          const event = receipt.logs.map((log: { topics: string[]; data: string }) => {
            try { return contract.interface.parseLog(log); } catch { return null; }
          }).find((item: { name?: string } | null) => item?.name === "FileUploaded");
          if (event) {
            const chainFileId = String(event.args.fileId);
            const updated = await api.registerOnChain(file.id, chainFileId, transaction.hash);
            file = updated.file;
            showToast("Encrypted file stored and EVM record confirmed.", "success");
          } else {
            showToast("Encrypted file stored; transaction confirmed without a parsed event.", "info");
          }
        } catch (error) {
          showToast("Encrypted file stored. EVM registration needs attention: " + (error instanceof Error ? error.message : "transaction failed"), "info");
        }
      } else {
        showToast(saved.message, "success");
      }
      setFiles((current) => [file, ...current]);
      setFileSummary((current) => ({ ...current, totalCount: current.totalCount + 1, ownCount: current.ownCount + 1 }));
      setSelectedUpload(null);
      if (inputRef.current) inputRef.current.value = "";
      setUploadStep("Secured");
      window.setTimeout(() => setUploadStep(""), 2400);
    } catch (error) {
      showToast(error instanceof Error ? error.message : "The file could not be secured.", "error");
      setUploadStep("");
    } finally {
      setUploading(false);
    }
  }

  async function renameFile(file: FileRecord) {
    const originalName = window.prompt("New file name", file.originalName)?.trim();
    if (!originalName || originalName === file.originalName) return;
    try {
      const updated = (await api.renameFile(file.id, originalName)).file;
      setFiles((current) => current.map((item) => item.id === updated.id ? updated : item));
      setShared((current) => current.map((item) => item.file.id === updated.id ? { ...item, file: updated } : item));
      showToast("File name updated.", "success");
    } catch (error) {
      showToast(error instanceof Error ? error.message : "Could not rename the file.", "error");
    }
  }

  function chooseReplacement(file: FileRecord, grant?: SharedFile) {
    setReplaceContext({ file, grant });
    replaceInputRef.current?.click();
  }

  async function replaceSelectedFile(replacementFile: File) {
    if (!replaceContext || !user || !password) return;
    const { file: currentFile, grant } = replaceContext;
    const isOwner = currentFile.ownerId === user.id;
    if (!isOwner && (!grant || grant.permissionLevel !== 2)) {
      showToast("This file requires Editor write access before it can be replaced.", "error");
      return;
    }
    if (contractAddress && currentFile.blockchainFileId && (!provider || !walletAddress)) {
      showToast("Connect the wallet with write access before replacing this on-chain file.", "error");
      return;
    }
    setUploading(true);
    setBusyId(currentFile.id);
    setUploadStep("Encrypting replacement");
    try {
      const metadata = {
        iv: currentFile.iv,
        wrappedKey: currentFile.wrappedKey,
        wrapIv: currentFile.wrapIv,
        salt: currentFile.salt,
        sha256Hash: currentFile.sha256Hash,
      };
      const encrypted = isOwner
        ? await replaceOwnedFileContent(replacementFile, metadata, password)
        : await replaceSharedFileContent(replacementFile, grant!.wrappedKey, identity || await ensureIdentity(user.email, password));
      setUploadStep("Saving encrypted replacement");
      let updated = (await api.replaceFile(currentFile.id, replacementFile, encrypted.ciphertext, encrypted)).file;
      if (contractAddress && currentFile.blockchainFileId && provider) {
        try {
          const contract = new Contract(contractAddress, contractAbi, await provider.getSigner());
          const transaction = await contract.updateFile(BigInt(currentFile.blockchainFileId), updated.ipfsCid, updated.sha256Hash);
          await transaction.wait();
          updated = (await api.registerOnChain(updated.id, currentFile.blockchainFileId, transaction.hash)).file;
        } catch (error) {
          showToast("Encrypted file was replaced. The on-chain update needs attention: " + (error instanceof Error ? error.message : "transaction failed"), "info");
        }
      }
      setFiles((current) => current.map((item) => item.id === updated.id ? updated : item));
      setShared((current) => current.map((item) => item.file.id === updated.id ? { ...item, file: updated } : item));
      setReplaceContext(null);
      if (replaceInputRef.current) replaceInputRef.current.value = "";
      if (!(contractAddress && currentFile.blockchainFileId)) showToast("Encrypted file content replaced.", "success");
      await refreshData(user);
    } catch (error) {
      showToast(error instanceof Error ? error.message : "Could not replace the file contents.", "error");
    } finally {
      setUploading(false);
      setBusyId("");
      setUploadStep("");
    }
  }

  async function downloadFile(file: FileRecord, grant?: SharedFile) {
    if (!password) {
      showToast("Sign in again to unlock your file key.", "error");
      return;
    }
    setBusyId(file.id);
    try {
      if (contractAddress && file.blockchainFileId) {
        if (!provider || !walletAddress || walletAddress.toLowerCase() !== user?.walletAddress?.toLowerCase()) {
          throw new Error("Connect the wallet linked to this account to verify on-chain access.");
        }
        const contract = new Contract(contractAddress, contractAbi, provider);
        const allowed = await contract.hasAccess(BigInt(file.blockchainFileId), getAddress(walletAddress));
        if (!allowed) throw new Error("The contract does not authorize this wallet for the file.");
      }
      const ciphertext = await api.download(file.id);
      const metadata = {
        iv: file.iv, wrappedKey: grant?.wrappedKey || file.wrappedKey, wrapIv: file.wrapIv, salt: file.salt, sha256Hash: file.sha256Hash,
      };
      const plain = grant
        ? await decryptSharedFile(ciphertext, metadata, grant.wrappedKey, identity || await ensureIdentity(user!.email, password))
        : await decryptFile(ciphertext, metadata, password);
      const url = URL.createObjectURL(new Blob([plain], { type: file.mimeType }));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = file.originalName;
      anchor.click();
      URL.revokeObjectURL(url);
      await api.logActivity("INTEGRITY_VERIFIED", "SHA-256 matched for file " + file.id + ": " + file.originalName + ".");
      await api.logActivity("FILE_DECRYPTED", "Client-side AES-GCM decryption completed for " + file.originalName + ".");
      if (user) {
        const events = await api.activity();
        setActivity(events);
      }
      showToast("Integrity verified. Decrypted file downloaded.", "success");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Could not decrypt the file.";
      showToast(message, "error");
    } finally {
      setBusyId("");
    }
  }

  async function openShare(file: FileRecord) {
    setShareTarget(file);
    setRecipientEmail("");
    try {
      setGrants(await api.grants(file.id));
    } catch { setGrants([]); }
  }

  async function shareFile(event: FormEvent) {
    event.preventDefault();
    if (!shareTarget || !password || !provider && contractAddress && shareTarget.blockchainFileId) {
      if (contractAddress && shareTarget?.blockchainFileId && !provider) showToast("Connect the owner wallet to update on-chain permissions.", "error");
      return;
    }
    const recipient = directory.find((person) => person.email.toLowerCase() === recipientEmail.toLowerCase());
    if (!recipient) return showToast("Choose a registered CB SECURE account.", "error");
    if (!recipient.walletAddress || !recipient.walletVerified || !recipient.publicKey) return showToast("This user needs to sign in and verify wallet ownership before receiving a share.", "error");
    if (recipient.id === user?.id) return showToast("You already own this file.", "error");
    setShareWorking(true);
    try {
      const wrappedKey = await wrapDekForRecipient(shareTarget, password, recipient.publicKey);
      let transactionHash: string | undefined;
    if (contractAddress && provider && shareTarget.blockchainFileId && shareTarget.ownerId === user?.id) {
        const contract = new Contract(contractAddress, contractAbi, await provider.getSigner());
        const transaction = await contract.grantAccess(BigInt(shareTarget.blockchainFileId), getAddress(recipient.walletAddress), permissionLevel);
        await transaction.wait();
        transactionHash = transaction.hash;
      }
      const result = await api.share(shareTarget.id, recipient.walletAddress, permissionLevel, wrappedKey, transactionHash);
      setGrants(await api.grants(shareTarget.id));
      showToast(result.message, "success");
      setRecipientEmail("");
      await refreshData(user!);
    } catch (error) {
      showToast(error instanceof Error ? error.message : "Could not share this file.", "error");
    } finally {
      setShareWorking(false);
    }
  }

  async function revokeGrant(grant: GrantRecord) {
    if (!shareTarget) return;
    try {
      if (contractAddress && provider && shareTarget.blockchainFileId && shareTarget.ownerId === user?.id) {
        const contract = new Contract(contractAddress, contractAbi, await provider.getSigner());
        const transaction = await contract.revokeAccess(BigInt(shareTarget.blockchainFileId), getAddress(grant.recipientAddress));
        await transaction.wait();
        await api.revokeWithTx(shareTarget.id, grant.recipientAddress, transaction.hash);
      } else {
        await api.revoke(shareTarget.id, grant.recipientAddress);
      }
      setGrants((current) => current.filter((item) => item.grantId !== grant.grantId));
      showToast("Access revoked for " + grant.recipientEmail + ".", "success");
      await refreshData(user!);
    } catch (error) {
      showToast(error instanceof Error ? error.message : "Could not revoke access.", "error");
    }
  }

  async function copyValue(value: string) {
    try { await navigator.clipboard.writeText(value); showToast("Copied to clipboard.", "success"); }
    catch { showToast("Clipboard access is unavailable.", "error"); }
  }

  const visibleFiles = useMemo(() => {
    const search = query.trim().toLowerCase();
    return files.filter((file) => file.originalName.toLowerCase().includes(search) && (fileCategory === "all" || categoryForFile(file) === fileCategory))
      .sort((first, second) => Date.parse(second.createdAt) - Date.parse(first.createdAt));
  }, [files, query, fileCategory]);
  const visibleShared = useMemo(() => {
    const search = query.trim().toLowerCase();
    return shared.filter((grant) => grant.file.originalName.toLowerCase().includes(search) && (fileCategory === "all" || categoryForFile(grant.file) === fileCategory));
  }, [shared, query, fileCategory]);
  const visibleVaultFiles = useMemo(() => {
    const grantedFiles = user?.role === "Reader" ? [] : visibleShared.map((grant) => grant.file);
    const ownedIds = new Set(visibleFiles.map((file) => file.id));
    return [...visibleFiles, ...grantedFiles.filter((file) => !ownedIds.has(file.id))]
      .sort((first, second) => Date.parse(second.createdAt) - Date.parse(first.createdAt));
  }, [visibleFiles, visibleShared, user?.role]);
  const titleMap: Record<View, string> = { overview: "Overview", files: "My vault", integrity: "Integrity center", activity: "Activity log", governance: "Governance" };
  const navItems = [
    { id: "overview" as const, label: "Overview", icon: <LayoutDashboard size={17} /> },
    { id: "files" as const, label: "My vault", icon: <FolderLock size={17} />, count: files.length },
    { id: "integrity" as const, label: "Integrity center", icon: <ScanLine size={17} /> },
    { id: "activity" as const, label: "Activity log", icon: <Activity size={17} /> },
  ];

  if (!user) {
    if (entryPage === "landing") return <LandingScreen onLogin={() => { setAuthMode("login"); setEntryPage("auth"); }} onRegister={() => { setAuthMode("register"); setEntryPage("auth"); }} />;
    return <AuthScreen onAuthenticated={authenticate} initialMode={authMode} onBack={() => setEntryPage("landing")} />;
  }

  const selectView = (nextView: View) => { setView(nextView); setMobileNav(false); };
  const mostRecent = files[0];
  const mostRecentVerified = Boolean(mostRecent && activity.some((item) => item.action === "INTEGRITY_VERIFIED" && item.details.includes("file " + mostRecent.id + ":")));
  const savedBytes = files.reduce((total, file) => total + file.size, 0);
  const verifiedCount = activity.filter((item) => item.action === "INTEGRITY_VERIFIED").length;
  const activityIcon = (action: string) => action.includes("ACCESS") ? <Users size={15} /> : action.includes("FILE") ? <FileKey2 size={15} /> : <ShieldCheck size={15} />;

  return (
    <div className="app-shell">
      <AmbientBackdrop />
      <input ref={inputRef} type="file" hidden onChange={(event) => { setSelectedUpload(event.currentTarget.files?.[0] || null); event.currentTarget.value = ""; }} />
      <input ref={replaceInputRef} type="file" hidden onChange={(event) => { const replacement = event.currentTarget.files?.[0]; event.currentTarget.value = ""; if (replacement) void replaceSelectedFile(replacement); }} />
      {mobileNav && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNav(false)} />}
      <aside className={"sidebar " + (mobileNav ? "sidebar-open" : "")}>
        <div className="sidebar-brand"><Brand /><button className="mobile-close" onClick={() => setMobileNav(false)} aria-label="Close menu"><X size={18} /></button></div>
        <div className="workspace-switcher"><span className="workspace-avatar">{initials(user.name)}</span><span><strong>Personal vault</strong><small>Private workspace</small></span><ChevronDown size={15} /></div>
        <div className="nav-label">WORKSPACE</div>
        <nav className="side-nav">
          {navItems.map((item) => <button key={item.id} className={"nav-item " + (view === item.id ? "active" : "")} onClick={() => selectView(item.id)}>
            <span className="nav-icon">{item.icon}</span><span>{item.label}</span>{item.count ? <small>{item.count}</small> : null}
          </button>)}
        </nav>
        {user.role === "Admin" && <><div className="nav-label nav-label-spaced">ADMINISTRATION</div><button className={"nav-item " + (view === "governance" ? "active" : "")} onClick={() => selectView("governance")}><span className="nav-icon"><Users size={17} /></span><span>Governance</span><span className="admin-badge">ADMIN</span></button></>}
        <div className="sidebar-spacer" />
        <div className="storage-card">
          <div className="storage-card-head"><span><HardDrive size={15} /> VAULT CAPACITY</span><span>SECURE</span></div>
          <div className="capacity-bar"><span style={{ width: files.length ? "22%" : "4%" }} /></div>
          <div className="storage-caption"><strong>{formatBytes(savedBytes)}</strong><span>encrypted</span></div>
          <p>Each encrypted file can be up to 100 MB.</p>
        </div>
        <button className="help-card" onClick={() => selectView("integrity")}><span className="help-icon"><Sparkles size={15} /></span><span><strong>Integrity tools</strong><small>Explore security checks</small></span><ArrowUpRight size={14} /></button>
        <div className="sidebar-user">
          <span className={"user-avatar " + user.role.toLowerCase()}>{initials(user.name)}</span>
          <span className="sidebar-user-info"><strong>{user.name}</strong><small>{roleLabel(user.role)} · verified</small></span>
          <button className="icon-button logout-button" title="Sign out" onClick={signOut}><LogOut size={15} /></button>
        </div>
      </aside>

      <main className="main-column">
        <header className="topbar">
          <div className="topbar-left">
            <button className="mobile-menu" onClick={() => setMobileNav(true)} aria-label="Open menu"><Menu size={19} /></button>
            <span className="crumb-root">Workspace</span><span className="crumb-sep">/</span><strong>{titleMap[view]}</strong>
          </div>
          <div className="topbar-actions">
            <div className={"search-box " + (searchOpen ? "search-open" : "")}><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} onFocus={() => setSearchOpen(true)} onBlur={() => setSearchOpen(false)} placeholder="Search files…" /><kbd>⌘ K</kbd></div>
            <div className="notification-wrap"><button className="icon-button top-icon" aria-label="Notifications" title="Notifications" onClick={() => setNotificationsOpen(!notificationsOpen)}><Bell size={17} />{activity.length > 0 && <i />}</button>
              {notificationsOpen && <div className="notifications-popover"><div className="section-heading"><strong>Recent activity</strong><button className="text-button" onClick={() => { selectView("activity"); setNotificationsOpen(false); }}>View all</button></div>{activity.slice(0, 5).map((item) => <div className="notification-row" key={item.id}><span className="notification-mark">{activityIcon(item.action)}</span><span><strong>{item.action.replaceAll("_", " ")}</strong><small>{item.details}</small></span></div>)}{!activity.length && <div className="notification-empty">No security events yet.</div>}</div>}
            </div>
            <button className={"wallet-button " + (walletAddress ? "wallet-connected" : "")} onClick={connectWallet}><MetaMaskMark /><span>{walletAddress ? shortAddress(walletAddress) : "Connect MetaMask"}</span><span className="wallet-indicator" /></button>
            <div className="topbar-divider" />
            <button className="top-user" onClick={signOut}><span className={"user-avatar small " + user.role.toLowerCase()}>{initials(user.name)}</span><ChevronDown size={14} /></button>
          </div>
        </header>

        <div className="page-content">
          {view === "overview" && <section className="page-enter">
            <div className="page-title-row">
              <div><div className="eyebrow page-eyebrow">{new Intl.DateTimeFormat("en", { weekday: "long", month: "long", day: "numeric" }).format(new Date()).toUpperCase()}</div><h1>Good to see you, {user.name.split(" ")[0]} <span className="wave">✦</span></h1><p>Your secure workspace is ready. Every file is encrypted before it leaves this device.</p></div>
              <button className="button button-primary" onClick={() => inputRef.current?.click()}><Plus size={16} /> Add files</button>
            </div>
            <section className="hero-banner">
              <div className="hero-content"><div className="hero-kicker"><span className="secure-spark"><ShieldCheck size={15} /></span> YOUR PRIVATE CLOUD, REIMAGINED</div><h2>Security that starts<br /><em>with you.</em></h2><p>End-to-end encryption keeps your files private at every step, from upload to sharing.</p><button className="hero-link" onClick={() => selectView("integrity")}>Explore the security model <ArrowRight size={15} /></button></div>
              <div className="hero-art" aria-hidden="true">
                <div className="art-orbit orbit-a" /><div className="art-orbit orbit-b" /><div className="art-orbit orbit-c" />
                <div className="art-center"><ShieldCheck size={48} strokeWidth={1.3} /><span>256-BIT<br />ENCRYPTED</span></div>
                <div className="art-node node-one"><LockKeyhole size={15} /><span>AES-GCM</span></div>
                <div className="art-node node-two"><Globe2 size={15} /><span>IPFS</span></div>
                <div className="art-node node-three"><FileKey2 size={15} /><span>ON-CHAIN</span></div>
                <div className="art-particle particle-one" /><div className="art-particle particle-two" /><div className="art-particle particle-three" />
              </div>
              <div className="hero-foot"><span><span className="live-dot" /> SYSTEM OPERATIONAL</span><span>ZERO-KNOWLEDGE STORAGE</span><span className="hero-foot-mark">CB<span>.</span></span></div>
            </section>

            <div className="stats-grid">
              <MetricCard icon={<FolderLock size={16} />} label={user.role === "Reader" ? "Workspace files" : user.role === "Admin" ? "Workspace files" : "Encrypted files"} value={String(user.role === "Reader" ? fileSummary.totalCount : files.length).padStart(2, "0")} detail={user.role === "Reader" ? "Count only · file details restricted" : user.role === "Admin" ? "All workspace records" : "In your private vault"} tone="purple" />
              <MetricCard icon={<HardDrive size={16} />} label="Vault storage" value={formatBytes(savedBytes)} detail="Ciphertext only" tone="blue" />
              <MetricCard icon={<Share2 size={16} />} label="Active shares" value={String(sharedCount).padStart(2, "0")} detail={user.role === "Reader" ? "Count only" : "Shared with your identity"} tone="green" />
              <MetricCard icon={<ShieldCheck size={16} />} label="Integrity checks" value={String(verifiedCount).padStart(2, "0")} detail={verifiedCount ? "Successful file opens" : "No verified opens yet"} tone="mint" />
            </div>

            <div className="overview-grid">
              <div className="panel upload-panel">
                <div className="section-heading"><div><div className="eyebrow">SECURE PIPELINE</div><h3>Add a file to your vault</h3></div><span className="pipeline-badge"><span /> ENCRYPTION ACTIVE</span></div>
                <div className={"drop-zone " + (selectedUpload ? "has-file" : "") + (uploading ? " is-uploading" : "")} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); const dropped = event.dataTransfer.files?.[0]; if (dropped) setSelectedUpload(dropped); }}>
                  {selectedUpload ? <><div className="drop-icon selected-file">{fileIcon(selectedUpload.name)}</div><strong>{selectedUpload.name}</strong><span>{formatBytes(selectedUpload.size)} · Ready to encrypt</span><button className="clear-file" onClick={() => setSelectedUpload(null)} aria-label="Clear selected file"><X size={14} /></button></> : <><div className="drop-icon"><Cloud size={23} /></div><strong>Drop a file here to get started</strong><span>Files are encrypted locally before upload</span><button className="button button-secondary browse-button" onClick={() => inputRef.current?.click()}><Plus size={15} /> Browse files</button></>}
                </div>
                <div className="pipeline-steps">
                  <PipelineStep number="01" title="AES-256 encrypt" active={uploadStep.includes("Encrypt")} done={Boolean(uploadStep && !uploadStep.includes("Encrypt"))} />
                  <span className="pipeline-connector" />
                  <PipelineStep number="02" title="Pin ciphertext" active={uploadStep.includes("Sending")} done={uploadStep.includes("EVM") || uploadStep === "Secured"} />
                  <span className="pipeline-connector" />
                  <PipelineStep number="03" title="Register digest" active={uploadStep.includes("EVM")} done={uploadStep === "Secured"} />
                </div>
                {uploadStep && <div className="upload-progress"><span className="spinner dark" />{uploadStep}…</div>}
                <div className="upload-footer"><span><LockKeyhole size={13} /> Only encrypted bytes leave your browser</span><button className="button button-primary small-button" onClick={uploadSelected} disabled={!selectedUpload || uploading}>{uploading ? "Securing…" : "Secure file"} <ArrowRight size={14} /></button></div>
              </div>

              <div className="panel security-panel">
                <div className="section-heading"><div><div className="eyebrow">SECURITY POSTURE</div><h3>Vault protection</h3></div><span className="mini-status"><i /> ACTIVE</span></div>
                <div className="security-score"><div className="score-ring security-shield"><ShieldCheck size={23} /></div><div><strong>{roleLabel(user.role)} access</strong><span>Permissions are enforced by the CB SECURE API.</span><small>{user.walletAddress ? "Wallet linked · " + shortAddress(user.walletAddress) : "Wallet not linked"}</small></div></div>
                <div className="security-list">
                  <SecurityRow icon={<LockKeyhole size={15} />} label="Client-side encryption" value="AES-256-GCM" tone="blue" />
                  <SecurityRow icon={<Fingerprint size={15} />} label="Identity verification" value="Email OTP" tone="purple" />
                  <SecurityRow icon={<ShieldCheck size={15} />} label="Integrity monitoring" value="SHA-256" tone="green" />
                </div>
                <button className="text-button full-width" onClick={() => selectView("integrity")}>Run integrity scan <ArrowRight size={14} /></button>
              </div>
            </div>

            <section className="panel recent-panel">
              <div className="section-heading recent-heading"><div><div className="eyebrow">PRIVATE STORAGE</div><h3>Recently added</h3></div><button className="text-button" onClick={() => selectView("files")}>View all files <ArrowRight size={14} /></button></div>
              {files.length ? <FileTable files={files.slice(0, 5)} busyId={busyId} currentUserId={user.id} role={user.role} onDownload={downloadFile} onShare={openShare} onRename={renameFile} onReplace={chooseReplacement} onCopy={copyValue} /> : <div className="recent-empty"><span className="recent-empty-icon"><FileKey2 size={18} /></span><span><strong>Your vault is waiting</strong><small>Add a file to see its encrypted record here.</small></span><button className="text-button" onClick={() => inputRef.current?.click()}>Add first file <ArrowRight size={14} /></button></div>}
            </section>
          </section>}

          {view === "files" && <section className="page-enter">
            <PageHeading eyebrow={user.role === "Admin" ? "WORKSPACE STORAGE" : "YOUR PRIVATE STORAGE"} title={user.role === "Admin" ? "All files" : "My vault"} description={user.role === "Admin" ? "Workspace records, ownership and access controls. File contents remain encrypted to their owners." : user.role === "Reader" ? "Your encrypted files. Restricted file details stay hidden for viewers." : "Your encrypted files and files your role allows you to access."} action={<button className="button button-primary" onClick={() => inputRef.current?.click()}><Plus size={16} /> Add files</button>} />
            <div className="vault-toolbar"><div className="vault-filter" role="tablist" aria-label="Filter files by type">
              <button type="button" role="tab" aria-selected={fileCategory === "all"} className={fileCategory === "all" ? "filter-on" : "filter-muted"} onClick={() => setFileCategory("all")}>All files <b>{files.length}</b></button>
              <button type="button" role="tab" aria-selected={fileCategory === "images"} className={fileCategory === "images" ? "filter-on" : "filter-muted"} onClick={() => setFileCategory("images")}>Images <b>{files.filter((file) => categoryForFile(file) === "images").length}</b></button>
              <button type="button" role="tab" aria-selected={fileCategory === "documents"} className={fileCategory === "documents" ? "filter-on" : "filter-muted"} onClick={() => setFileCategory("documents")}>Documents <b>{files.filter((file) => categoryForFile(file) === "documents").length}</b></button>
              <button type="button" role="tab" aria-selected={fileCategory === "other"} className={fileCategory === "other" ? "filter-on" : "filter-muted"} onClick={() => setFileCategory("other")}>Other <b>{files.filter((file) => categoryForFile(file) === "other").length}</b></button>
            </div><span className="vault-summary"><LockKeyhole size={13} /> {visibleFiles.length} shown · {formatBytes(savedBytes)} total</span></div>
            <section className="panel table-panel">{visibleVaultFiles.length ? <FileTable files={visibleVaultFiles} grants={visibleShared} busyId={busyId} currentUserId={user.id} role={user.role} onDownload={downloadFile} onShare={openShare} onRename={renameFile} onReplace={chooseReplacement} onCopy={copyValue} /> : <div className="empty-state"><FolderLock size={22} /><strong>{files.length || (user.role !== "Reader" && shared.length) ? "No files match this filter" : "No encrypted files yet"}</strong><span>{files.length || (user.role !== "Reader" && shared.length) ? "Try another category or clear your search." : "Files you add to this account will appear here."}</span>{(files.length || (user.role !== "Reader" && shared.length)) && (fileCategory !== "all" || query) && <button className="text-button" onClick={() => { setFileCategory("all"); setQuery(""); }}>Clear filters</button>}</div>}</section>
            <div className="footnote-line"><ShieldCheck size={14} /><span>Files are encrypted in your browser before ciphertext is sent to the configured storage service.</span></div>
          </section>}

          {view === "integrity" && <section className="page-enter">
            <PageHeading eyebrow="CRYPTOGRAPHIC VERIFICATION" title="Integrity center" description="Verify the file you decrypt against its original SHA-256 digest." action={<span className="scan-status"><span /> ALL SYSTEMS NOMINAL</span>} />
            <div className="integrity-hero panel">
              <div className="integrity-emblem"><div className="emblem-ring"><ShieldCheck size={34} /></div><span className="emblem-orbit orbit-x" /><span className="emblem-orbit orbit-y" /><span className="emblem-dot" /></div>
              <div className="integrity-copy"><div className="eyebrow">INTEGRITY ENGINE</div><h2>Every bit has a witness.</h2><p>After decryption, CB SECURE calculates SHA-256 again and compares it with the digest recorded when the file was uploaded.</p><div className="integrity-points"><span><CheckCircle2 size={14} /> AES-GCM authentication tag</span><span><CheckCircle2 size={14} /> SHA-256 plaintext digest</span><span><CheckCircle2 size={14} /> Recipient key wrapping</span></div></div>
            </div>
            <div className="integrity-grid">
              <section className="panel digest-panel"><div className="section-heading"><div><div className="eyebrow">DIGEST COMPARISON</div><h3>Latest registered file</h3></div><span className="verified-tag"><CheckCircle2 size={13} /> VERIFIED</span></div>
                {mostRecent ? <>
                  <div className="digest-file"><span className="file-type-icon">{fileIcon(mostRecent.originalName)}</span><span><strong>{mostRecent.originalName}</strong><small>{formatBytes(mostRecent.size)} · {dateLabel(mostRecent.createdAt)}</small></span></div>
                  <div className="hash-card"><div><span>REGISTERED SHA-256</span><button onClick={() => copyValue(mostRecent.sha256Hash)} aria-label="Copy digest"><Copy size={13} /></button></div><code>{mostRecent.sha256Hash}</code><small>{mostRecent.blockchainFileId ? "Anchored in EVM record #" + mostRecent.blockchainFileId : "Stored in the configured API metadata"}</small></div>
                  <div className="hash-card current-hash"><div><span>LAST DECRYPTION CHECK</span><span className={mostRecentVerified ? "hash-check" : "hash-pending"}>{mostRecentVerified ? <><Check size={12} /> VERIFIED</> : "NOT CHECKED"}</span></div><small>{mostRecentVerified ? "AES-GCM and SHA-256 checks passed during the last successful open." : "Decrypt this file to verify it against the registered SHA-256 digest."}</small></div>
                </> : <div className="digest-empty"><ScanLine size={22} /><strong>No digest to compare yet</strong><span>Secure a file to generate its first fingerprint.</span></div>}
              </section>
              <section className="panel integrity-method-panel"><div className="section-heading"><div><div className="eyebrow">VERIFICATION FLOW</div><h3>Checks performed on open</h3></div><span className="verified-tag"><ShieldCheck size={13} /> ACTIVE</span></div><div className="integrity-method-list"><div><span>01</span><strong>AES-GCM authentication</strong><small>Rejects modified ciphertext during decryption.</small></div><div><span>02</span><strong>SHA-256 comparison</strong><small>Compares decrypted bytes with the registered digest.</small></div><div><span>03</span><strong>Activity record</strong><small>Records a verification event after a successful open.</small></div></div></section>
            </div>
            <div className="integrity-note"><Shield size={15} /><span><strong>Digest storage.</strong> The digest is stored in API metadata and can also be anchored on-chain when a FileSharing contract is configured.</span></div>
          </section>}

          {view === "activity" && <section className="page-enter">
            <PageHeading eyebrow="AUTHENTICATION & ACCESS EVENTS" title="Activity log" description="Account registrations, successful sign-ins, and security events with the associated email and time." action={<span className="log-count"><Activity size={14} /> {activity.length} EVENTS</span>} />
            <section className="panel activity-panel"><div className="activity-table-head"><span aria-hidden="true" /><span>EVENT</span><span>DETAILS</span><span>TIME</span><span>EMAIL</span></div>
              {activity.length ? activity.map((item) => <div className="activity-row" key={item.id}><span className={"activity-event-icon " + (item.action.includes("FAILED") ? "failed" : "")}>{activityIcon(item.action)}</span><strong>{item.action.replaceAll("_", " ")}</strong><span className="activity-detail">{item.details}</span><span className="activity-time"><Clock3 size={13} />{dateLabel(item.timestamp)} · {new Date(item.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span><span className="activity-identity"><strong>{item.userEmail || "Unknown email"}</strong>{item.walletAddress && <small>{shortAddress(item.walletAddress)}</small>}</span></div>) : <div className="empty-state"><Activity size={22} /><strong>No events yet</strong><span>Security events will appear as you use the vault.</span></div>}
            </section>
            <div className="footnote-line"><ShieldCheck size={14} /><span>Authentication events are recorded by the CB SECURE API. On-chain events are immutable after contract deployment.</span></div>
          </section>}

          {view === "governance" && user.role === "Admin" && <section className="page-enter">
            <PageHeading eyebrow="ADMIN CONSOLE" title="Governance" description="Assign Admin, Editor, or Viewer access. Viewers can upload their own files and see counts for files shared by others." action={<span className="admin-console-tag"><ShieldCheck size={14} /> ADMIN</span>} />
            <div className="governance-summary"><MetricCard icon={<Users size={16} />} label="Registered identities" value={String(users.length).padStart(2, "0")} detail="Email verified accounts" tone="purple" /><MetricCard icon={<WalletCards size={16} />} label="Wallet bindings" value={String(users.filter((item) => item.walletAddress).length).padStart(2, "0")} detail="EIP-191 verified" tone="blue" /><MetricCard icon={<Activity size={16} />} label="Audit events" value={String(activity.length).padStart(2, "0")} detail="All retained history" tone="green" /></div>
            <section className="panel governance-panel"><div className="section-heading"><div><div className="eyebrow">IDENTITY DIRECTORY</div><h3>Users and role access</h3></div><span className="directory-count">{users.length} identities</span></div>
              <div className="directory-head"><span>USER</span><span>WALLET ADDRESS</span><span>ROLE</span><span>ACCESS</span></div>
              {users.map((item) => <div className="directory-row" key={item.id}><span className="directory-person"><span className={"user-avatar small " + item.role.toLowerCase()}>{initials(item.name)}</span><span><strong>{item.name}</strong><small>{item.email}</small></span></span><code>{shortAddress(item.walletAddress)}</code><span className={"directory-role " + item.role.toLowerCase()}>{roleLabel(item.role)}</span><select aria-label={"Set role for " + item.email} value={item.role} onChange={async (event) => { try { await api.updateRole(item.id, event.target.value as User["role"]); await refreshData(user); showToast("Role updated for " + item.email + ".", "success"); } catch (error) { showToast(error instanceof Error ? error.message : "Role update failed.", "error"); } }}><option value="Admin">Admin</option><option value="Editor">Editor</option><option value="Reader">Viewer · count only</option></select></div>)}
            </section>
            <div className="integrity-note"><ShieldAlert size={15} /><span><strong>Audit hash chain: {auditStatus?.valid ? "valid for " + auditStatus.checkedEvents + " retained events" : "check failed"}.</strong> The chain detects partial edits; a local administrator can still rewrite the complete database. Production deployments need external audit checkpoints.</span></div>
          </section>}
        </div>

        <footer className="app-footer"><span>© 2026 CB SECURE <i>·</i> PRIVATE BY DESIGN</span><span><span className="footer-live" /> ALL SYSTEMS NOMINAL</span><span>SECURE STORAGE <b>v0.1.0</b></span></footer>
      </main>

      {selectedUpload && view !== "overview" && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget && !uploading) setSelectedUpload(null); }}>
        <section className="share-modal" role="dialog" aria-modal="true" aria-labelledby="upload-dialog-title">
          <div className="modal-top"><span className="modal-icon"><Cloud size={18} /></span><button className="icon-button" onClick={() => setSelectedUpload(null)} aria-label="Cancel upload" disabled={uploading}><X size={17} /></button></div>
          <div className="eyebrow">SECURE FILE UPLOAD</div><h2 id="upload-dialog-title">Ready to secure</h2><p>The file is encrypted in this browser before its ciphertext is sent to storage.</p>
          <div className="share-file-chip"><span className="file-type-icon">{fileIcon(selectedUpload.name)}</span><span><strong>{selectedUpload.name}</strong><small>{formatBytes(selectedUpload.size)}</small></span><LockKeyhole size={15} /></div>
          {uploadStep && <div className="upload-progress"><span className="spinner dark" />{uploadStep}…</div>}
          <button className="button button-primary modal-submit" onClick={uploadSelected} disabled={uploading}>{uploading ? <span className="spinner" /> : <LockKeyhole size={15} />}{uploading ? "Securing file…" : "Encrypt and upload"}</button>
          <div className="modal-foot"><ShieldCheck size={13} /> AES-GCM encryption and SHA-256 verification protect your file.</div>
        </section>
      </div>}

      {shareTarget && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setShareTarget(null); }}>
        <section className="share-modal" role="dialog" aria-modal="true" aria-labelledby="share-title">
          <div className="modal-top"><span className="modal-icon"><Share2 size={18} /></span><button className="icon-button" onClick={() => setShareTarget(null)} aria-label="Close share dialog"><X size={17} /></button></div>
          <div className="eyebrow">ENCRYPTED DELEGATION</div><h2 id="share-title">{shareTarget.ownerId === user?.id ? "Share this file" : "Manage file access"}</h2><p>{shareTarget.ownerId === user?.id ? "We re-wrap the file’s key to the recipient’s public identity. Your password and the plaintext never leave this browser." : "Review and revoke active access grants for this workspace file."}</p>
          <div className="share-file-chip"><span className="file-type-icon">{fileIcon(shareTarget.originalName)}</span><span><strong>{shareTarget.originalName}</strong><small>{formatBytes(shareTarget.size)}</small></span><LockKeyhole size={15} /></div>
          {shareTarget.ownerId === user?.id && <form onSubmit={shareFile}>
            <label>Recipient<select required value={recipientEmail} onChange={(event) => setRecipientEmail(event.target.value)}><option value="">Choose an Editor or Admin</option>{directory.filter((person) => person.id !== user.id && person.role !== "Reader").map((person) => <option value={person.email} key={person.id}>{person.name} · {person.email}{person.publicKey && person.walletVerified ? "" : " · wallet verification required"}</option>)}</select></label>
            <label>Permission<select value={permissionLevel} onChange={(event) => setPermissionLevel(Number(event.target.value))}><option value={1}>Read and download</option><option value={2}>Read, rename and replace</option></select></label>
            <div className="share-security-note"><KeyRound size={14} /><span>Viewer accounts can only see file counts. Editors and Admins need a verified wallet and registered encryption key to receive file access.</span></div>
            <button className="button button-primary modal-submit" disabled={shareWorking || !recipientEmail}>{shareWorking ? <span className="spinner" /> : <Share2 size={15} />}{shareWorking ? "Wrapping key…" : "Encrypt key for recipient"}</button>
          </form>}
          {grants.filter((grant) => grant.active).length > 0 && <div className="active-grants"><div className="eyebrow">ACTIVE SHARES</div>{grants.filter((grant) => grant.active).map((grant) => <div className="grant-row" key={grant.grantId}><span className="grant-avatar">{initials(grant.recipientEmail)}</span><span><strong>{grant.recipientEmail}</strong><small>{grant.permissionLevel === 2 ? "Read and edit" : "Read and download"} · {grant.transactionHash ? "on-chain" : "API managed"}</small></span><button className="revoke-button" onClick={() => revokeGrant(grant)}>Revoke</button></div>)}</div>}
          <div className="modal-foot"><ShieldCheck size={13} /> Access is enforced by the CB SECURE API and optional smart contract.</div>
        </section>
      </div>}
      {toast && <div className={"toast toast-" + toast.tone}><span>{toast.tone === "success" ? <CheckCircle2 size={17} /> : toast.tone === "error" ? <ShieldAlert size={17} /> : <Shield size={17} />}</span><p>{toast.text}</p><button onClick={dismissToast} aria-label="Dismiss notification"><X size={15} /></button></div>}
    </div>
  );
}

function MetricCard({ icon, label, value, detail, tone }: { icon: ReactNode; label: string; value: string; detail: string; tone: string }) {
  return <div className="metric-card"><span className={"metric-icon " + tone}>{icon}</span><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-detail"><span className={"metric-trend " + tone}><ArrowUpRight size={12} /></span>{detail}</div></div>;
}

function PipelineStep({ number, title, active, done }: { number: string; title: string; active: boolean; done: boolean }) {
  return <div className={"pipeline-step " + (active ? "active" : "") + (done ? "done" : "")}><span>{done ? <Check size={12} /> : number}</span><small>{title}</small></div>;
}

function SecurityRow({ icon, label, value, tone }: { icon: ReactNode; label: string; value: string; tone: string }) {
  return <div className="security-row"><span className={"security-row-icon " + tone}>{icon}</span><span>{label}</span><strong>{value}</strong></div>;
}

function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="page-title-row inner-page-heading"><div><div className="eyebrow page-eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{action}</div>;
}

export default App;
