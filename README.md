# CB SECURE

CB SECURE is a client-encrypted file vault with account verification, file sharing, activity logging, and optional IPFS/EVM integration. Files are encrypted in the browser before upload. The JSON database and local ciphertext adapter can run as a small, single-instance deployment when their directory is on persistent storage. For higher traffic or multiple instances, move metadata to a managed database and ciphertext to object storage.

## Run the application

Run these commands from the CB SECURE project folder (the folder containing this README and the root `package.json`):

```powershell
npm install
Copy-Item .env.example backend/.env
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). Before the first registration, edit `backend/.env`: set a random `JWT_SECRET` with at least 32 characters, set `INITIAL_ADMIN_EMAIL` to your account email, and configure SMTP as described below. The verified account matching `INITIAL_ADMIN_EMAIL` becomes the first Admin. Other new accounts start as Viewers.

## Real email verification codes

Email/password registration and sign-in send a random, single-use code that expires after five minutes. There is no fixed OTP or in-app OTP bypass. Configure a Gmail App Password for `cbsecure@gmail.com` in `backend/.env` (`SMTP_USER`, `SMTP_PASS`) and set `SMTP_FROM=CB SECURE <cbsecure@gmail.com>`. Gmail requires 2-Step Verification before you can create an App Password ([Google instructions](https://support.google.com/accounts/answer/185833)). Use the authenticated Gmail address as the sender or a verified Gmail alias.

## Access roles

- **Viewer** can upload and open their own files. For files shared by others, Viewer accounts see counts only.
- **Editor** can upload and open their own files, and can read or edit files when an owner grants access. Write access allows rename and encrypted content replacement.
- **Admin** can assign roles, see workspace file records and the full activity log, rename workspace records, and review or revoke grants. Opening file contents still requires a cryptographic share grant.
- Only Admins can change account roles. File owners share keys to Editor/Admin recipients; viewers cannot receive content grants.

The activity log records registration, successful sign-ins, email OTP, and file/access events with email and timestamp. Admins see the workspace log; other accounts see their own events.

## Storage and optional chain setup

With no `PINATA_JWT`, encrypted bytes are stored in `backend/data/storage` and metadata in `backend/data/db.json`. Set `CB_SECURE_DATA_DIR` to move that data directory, as the Render setup does with its persistent disk. Set `PINATA_JWT` in `backend/.env` to pin ciphertext to Pinata IPFS. Never store plaintext files in the storage adapter.

## Cloudflare deployment

The current hosted app uses Cloudflare Pages for the React frontend, a Cloudflare Worker for the Express API, and D1 for both metadata and encrypted file chunks. `functions/api/[[path]].js` sends same-origin Pages API calls to the Worker. Apply `cloudflare/migrations/0001_create_records.sql` to the `cb-secure-db` D1 database before deploying the Worker.

Set these Worker secrets with Wrangler (never commit their values): `JWT_SECRET` (32+ random characters), `CF_AUTH_PEPPER` (32+ random characters), `INITIAL_ADMIN_EMAIL`, `SMTP_USER`, and `SMTP_PASS`. Set `SMTP_HOST=smtp.gmail.com` and `SMTP_PORT=587` as Worker variables. Deploy the API with `npx wrangler deploy --config cloudflare/wrangler.jsonc`, then build and publish Pages with `npm run build` and `npx wrangler pages deploy frontend/dist --project-name cb-secure --branch cloudflare-pages`.

The free D1 tier allows 500 MB per database and each encrypted file is limited to 20 MiB by the app. Files are stored as encrypted 1.8 MB chunks to stay within D1's 2 MB row limit. Cloudflare Workers Free also has a 100,000 request/day limit and a 10 ms CPU limit per request. The app uses Web Crypto PBKDF2-SHA-256 (100,000 iterations) with a Worker-only pepper for password hashes on this plan; other hosting platforms keep bcrypt. For larger storage or traffic, move file chunks to private object storage and review Cloudflare plan limits.

## Render deployment

The root-level `render.yaml` deploys the frontend and Express API together as one free Node web service. Render generates `JWT_SECRET` for the service. Set `INITIAL_ADMIN_EMAIL` in the Render service environment before registering the first account; that verified account becomes the first Admin. The site and API use the same Render URL.

Render Free is suitable for a temporary preview, not durable vault storage. Its web service filesystem is ephemeral and is cleared when the service spins down, restarts, or redeploys. Free web services also cannot send outbound SMTP over ports 25, 465, or 587, so Gmail SMTP OTP delivery will not work there. Until an email provider reachable over HTTPS or an allowed port is configured, email/password registration and sign-in return a setup error. Free Render Postgres expires 30 days after creation. See [Render Free instance limits](https://render.com/docs/free).

Do not store real user files or accounts on this temporary Free deployment. It stores local metadata and ciphertext on the service filesystem, which can be lost. For durable use, move metadata to a persistent database and encrypted file bytes to durable object storage, then configure an email delivery provider.

To use the optional Hardhat contract, install dependencies with `npm install --prefix contracts`, start a local node with `npm run contracts:node`, deploy with `npm run contracts:deploy`, and set the deployed address as `VITE_CONTRACT_ADDRESS` in `frontend/.env`. Connect MetaMask to the same network. A local-chain record still requires an IPFS CID, so configure Pinata for that path.

## Project layout

- `frontend/` — React, TypeScript, responsive workspace, and browser cryptography
- `backend/` — Express API, account and OTP verification, roles, activity, and storage adapters
- `contracts/` — Solidity access registry and Hardhat scripts
- `docs/` — architecture and security boundaries

The optional on-chain digest is a raw SHA-256 value and can reveal whether a guessed file matches. Consider a commitment or keyed digest before anchoring sensitive file hashes.

