# CB SECURE architecture

## Request and storage flow

```mermaid
sequenceDiagram
    actor Owner
    participant Browser
    participant API
    participant IPFS as Pinata / local ciphertext adapter
    participant EVM as FileSharing.sol
    actor Recipient

    Owner->>Browser: Select plaintext file
    Browser->>Browser: SHA-256 plaintext; generate random 256-bit DEK and 96-bit IV
    Browser->>Browser: AES-256-GCM encrypt; PBKDF2-wrap DEK
    Browser->>API: Multipart ciphertext + IV, wrapped DEK, salt, digest
    API->>IPFS: Pin encrypted bytes only
    IPFS-->>API: CID
    API-->>Browser: File metadata + CID
    opt Contract configured and connected
        Browser->>EVM: uploadFile(CID, SHA-256)
        EVM-->>Browser: FileUploaded and file ID
    end
    Owner->>Browser: Select recipient and permission
    Browser->>Browser: ECDH ephemeral key; wrap DEK to recipient P-256 public key
    Browser->>EVM: grantAccess (optional)
    Browser->>API: Store recipient, permission, wrapped DEK
    Recipient->>API: Request encrypted file
    API->>EVM: Client checks hasAccess for anchored records
    API-->>Recipient: Ciphertext + metadata + recipient DEK package
    Recipient->>Browser: Decrypt via private identity key
    Browser->>Browser: Verify AES-GCM tag and SHA-256 digest
```

## Trust boundaries

| Component | Receives | Does not receive |
| --- | --- | --- |
| Browser | Plaintext, account password, DEK, recipient private key | — |
| API | OTP password hash, ciphertext, public keys, wrapped DEKs, file metadata | Plaintext files, plaintext DEKs |
| Storage adapter | Encrypted file bytes | Plaintext files or keys |
| EVM contract | CID, raw SHA-256 digest, wallet addresses, access decisions | File bytes, filenames, decryption keys |

The JSON database and disk directory are development adapters. Browser encryption does not make an API administrator's database immutable or protect the app from XSS, compromised dependencies, malicious browser extensions, or endpoint malware.

## Cryptographic envelope

For each file, the browser generates a random 32-byte DEK and a fresh 12-byte AES-GCM nonce. AES-GCM ciphertext includes its 128-bit authentication tag. The original file's SHA-256 digest is stored in file metadata and optionally recorded on-chain.

The owner wrapping key is derived from the account password using PBKDF2-HMAC-SHA-256 with a random 16-byte salt and 310,000 iterations. A separate random 12-byte nonce encrypts the DEK. For a recipient share, the browser uses ephemeral P-256 ECDH and AES-GCM to wrap the DEK to the recipient's P-256 public key. The recipient private key is saved in local storage only as AES-GCM ciphertext protected by a password-derived key.

## Authorization model

- New accounts receive the Reader role. The verified account matching `INITIAL_ADMIN_EMAIL` receives the first Admin role.
- Admins may promote registered accounts to Admin, Editor, or Reader.
- Every role can upload and open its own files. Reader accounts can see counts only for other users' files.
- Owners can grant READ (`1`) or WRITE (`2`) access to Editor/Admin recipients. READ permits opening and downloading; WRITE also permits rename and encrypted content replacement.
- Admins can manage roles, inspect workspace records and the full activity log, rename records, and review or revoke access grants. File content still requires a cryptographic key grant.
- Wallet binding is a short-lived EIP-191 message challenge; the API stores the recovered checksum address.
- In configured EVM mode, the client checks `hasAccess(fileId, address)` before decrypting anchored records. The Solidity contract emits grant and revoke events.

The API remains the authority for its local storage adapter. Contract events do not automatically make local metadata, API logs, or file availability decentralized.

## Data and event handling

The API persists users, file metadata, access grants, challenges, and up to 1,000 activity events in `backend/data/db.json`. Local ciphertext is stored in `backend/data/storage/`. OTP challenges expire in five minutes and allow up to five attempts. JWT sessions expire in eight hours.

Each activity event includes the preceding event hash and a SHA-256 hash of its own fields. This linked sequence detects partial edits, but because the anchor is also local, an administrator can rewrite all events and recompute the chain. External immutable checkpoints are required for stronger tamper evidence.

## Solidity record

`FileSharing.sol` stores the IPFS CID and SHA-256 digest, owner address, upload timestamp, and wallet permission mappings. It validates permission values, rejects the zero address, protects owner-only grant/revoke calls, and emits indexed access events. It deliberately stores no names, bytes, keys, or password material.

