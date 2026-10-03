# SecureVault — Product Requirements Document

- Status: Draft
- Version: 0.1
- Target Platform: Windows 10/11 x64
- Primary Language: Rust
- Initial Delivery: CLI-based encrypted local vault
- Future Delivery: Windows virtual secure drive + pluggable authenticators

## 1. Product Vision

SecureVault is a local-first secure storage system for Windows that separates:

1. Authentication — proving who is requesting access.
2. Identity — determining which user was authenticated.
3. Authorization — deciding whether that identity may unlock a vault.
4. Session management — determining how long access remains valid.
5. Key management — releasing cryptographic capability only to an authorized session.
6. Storage — encrypting and retrieving protected data.

Facial recognition is not the product itself. It is one implementation of a pluggable authentication mechanism.

The architecture must allow additional authenticators such as password, PIN, WebAuthn/passkeys, hardware security keys, TPM-backed credentials, or future mechanisms without modifying the vault or cryptographic layers.

## 2. Problem Statement

Windows users may want a local encrypted workspace whose access can be controlled by authentication methods that are independent of the underlying storage.

A conventional application often couples authentication directly to application logic:

```text
password -> decrypt data
```

SecureVault instead establishes explicit security boundaries:

```text
Authenticator
      |
      v
Identity
      |
      v
Authorization Policy
      |
      v
Session
      |
      v
Key Lease
      |
      v
Encrypted Vault
```

This separation enables:

- multiple authentication methods;
- configurable authentication policies;
- short-lived sessions;
- explicit key-release control;
- future Windows integration;
- future virtual-drive support;
- replacement of individual components without redesigning the system.

## 3. Product Goals

### 3.1 Primary Goals

- G1 — Build a secure local encrypted vault
  Users must be able to create a vault and store encrypted files locally.
- G2 — Create a pluggable authentication framework
  Authentication must be represented by an interface/trait rather than hard-coded into the vault.
- G3 — Separate authentication from encryption
  Successful authentication must produce an identity/session, not directly expose or derive the vault key.
- G4 — Implement short-lived sessions
  The MVP must support a five-minute session TTL and explicit session expiration.
- G5 — Control cryptographic key release
  Vault keys must only become available to an authorized active session.
- G6 — Keep biometric functionality optional
  Facial recognition must be implementable as a separate authenticator without changing the vault architecture.
- G7 — Build a foundation for a Windows secure drive
  The initial MVP will be user-space and CLI-based. A future milestone may expose the vault as a virtual Windows drive.

## 4. Non-Goals

The following are explicitly outside the first MVP:

- Windows logon replacement.
- Windows Credential Provider.
- Reimplementing BitLocker.
- Kernel filesystem driver.
- Cloud synchronization.
- Remote authentication servers.
- Cloud biometric processing.
- Facial recognition in the initial vault implementation.
- GUI in the initial milestone.
- Enterprise identity management.
- Multi-device synchronization.

These may be considered after the core security architecture is validated.

## 5. Core Design Principles

### 5.1 Local First

Protected data and authentication data must remain local by default. No cloud service is required for core operation.

### 5.2 Authentication Is Pluggable

The vault must not depend on a particular authentication mechanism.

```text
                 Authenticator
                      |
        +-------------+-------------+
        |             |             |
      Password       Face        WebAuthn
```

### 5.3 Authentication Is Not Authorization

Authentication establishes identity. Authorization determines whether that identity can unlock a particular vault.

### 5.4 Authentication Is Not Key Derivation

The authentication result must not itself be treated as an encryption key.

### 5.5 Keys Are Capabilities

Possession of an active vault key represents cryptographic capability. Key release must therefore be controlled and short-lived.

### 5.6 Minimize Sensitive Data Lifetime

Secrets and cryptographic keys should remain in memory only as long as required. Sensitive memory should be explicitly zeroized where practical.

### 5.7 Fail Closed

Unexpected errors must result in denial of access rather than accidental access.

## 6. Terminology

| Term | Meaning |
| --- | --- |
| Authenticator | Component that verifies a user's credential |
| Credential | Input supplied to an authenticator |
| Identity | Logical user identity established after authentication |
| Authentication Result | Result of credential verification |
| Authorization Policy | Rules determining whether an identity may access a vault |
| Session | Time-bounded authenticated context |
| Key Lease | Temporary capability allowing access to a vault key |
| Vault | Logical protected storage container |
| Object | Individual encrypted data object/file |
| Metadata | Non-content information required to locate and manage objects |
| Vault Key | Cryptographic key used to protect vault data |
| Lock | Revocation of active access and key leases |
| Expiration | Automatic invalidation of a session after TTL |

## 7. High-Level Architecture

```text
                         SecureVault CLI
                               |
                               v
                  +-------------------------+
                  | Authentication Engine   |
                  +-----------+-------------+
                              |
                +-------------+-------------+
                |             |             |
                v             v             v
           Password         Face        WebAuthn
          Authenticator  Authenticator  Authenticator
                |             |             |
                +-------------+-------------+
                              |
                              v
                         +---------+
                         | Identity|
                         +----+----+
                              |
                              v
                    +-------------------+
                    | Authorization     |
                    | Policy            |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Session Manager   |
                    | TTL = 5 minutes   |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Key Manager       |
                    | Key Lease         |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Crypto Engine     |
                    | AES-256-GCM       |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Encrypted Object  |
                    | Store              |
                    +-------------------+
```

## 8. Component Architecture

### 8.1 Authentication Engine

The Authentication Engine provides a common abstraction over authentication providers.

Responsibilities:

- register authenticators;
- select an authenticator;
- execute authentication;
- return an authenticated identity;
- normalize authentication errors;
- avoid exposing provider-specific secrets to unrelated layers.

Non-responsibilities:

The Authentication Engine must not:

- decrypt vault data;
- directly manipulate vault keys;
- store plaintext passwords;
- make storage decisions.

## 9. Authenticator Interface

The core abstraction should be represented by a Rust trait.

Conceptually:

```rust
trait Authenticator {
    fn authenticate(
        &self,
        request: AuthRequest,
    ) -> Result<AuthenticationResult, AuthError>;
}
```

The exact API may evolve during implementation.

### 9.1 Initial Implementations

- `PasswordAuthenticator` — initial MVP authenticator.
- `MockAuthenticator` — used for deterministic tests of the entire authentication/session/key pipeline.

### 9.2 Future Implementations

- `FaceAuthenticator`
- `PINAuthenticator`
- `WebAuthnAuthenticator`
- `HardwareKeyAuthenticator`
- `TPMAuthenticator`
- `RecoveryAuthenticator`

The addition of a new authenticator must not require changes to:

- encrypted object format;
- crypto engine;
- vault storage;
- session implementation.

## 10. Identity

Authentication produces an identity.

Conceptually:

```text
Identity
---------
user_id
username
```

Multiple authenticators may map to the same identity.

Example:

```text
Face      -> User 123
Password  -> User 123
WebAuthn  -> User 123
```

The identity is the stable security principal.

## 11. Authorization Policy

Authentication alone must not automatically unlock every vault.

Authorization evaluates:

```text
Identity + Vault + Policy
```

Example:

```text
User: 123
Vault: Personal
Policy: face OR password
Result: ALLOW
```

Future policies may support:

```yaml
authentication:
  mode: any
  providers:
    - face
    - password
```

or:

```yaml
authentication:
  mode: all
  providers:
    - face
    - hardware_key
```

Authorization policy is a future extensibility boundary but should be represented in the architecture from the beginning.

## 12. Session Manager

A successful authorization creates a session.

Conceptually:

```text
Session
-------
session_id
identity
created_at
expires_at
state
```

### 12.1 Initial TTL

Default: 5 minutes.

### 12.2 Session States

```text
CREATED
   |
   v
AUTHENTICATED
   |
   v
ACTIVE
   |
   +----------+
   |          |
   v          v
EXPIRED     REVOKED
```

### 12.3 Expiration Behavior

When a session expires:

1. the session becomes invalid;
2. associated key leases are revoked;
3. sensitive key material is zeroized where possible;
4. vault operations are rejected;
5. the user must authenticate again.

Session expiration must not depend solely on a UI state.

## 13. Key Manager

The Key Manager is responsible for controlling access to vault cryptographic keys. It must not derive a vault key directly from a password or face embedding.

Conceptually:

```text
Authentication
      |
      v
Identity
      |
      v
Authorization
      |
      v
Session
      |
      v
Key Manager
      |
      v
Key Lease
```

### 13.1 Key Lease

A key lease is a temporary cryptographic capability associated with an active session.

A lease should:

- belong to a specific session;
- be invalidated when the session expires;
- be revocable;
- hold key material only while required;
- zeroize sensitive material on destruction where practical.

## 14. Cryptographic Design

### 14.1 Data Encryption

Initial algorithm:

- AES-256-GCM

Requirements:

- unique nonce per encryption operation;
- authenticated encryption;
- integrity verification before plaintext is released;
- no nonce reuse under the same key.

### 14.2 Key Generation

Vault keys must be generated using a cryptographically secure random number generator.

The vault key must not be:

```text
SHA256(password)
```

or any equivalent direct password hash.

### 14.3 Password Protection

Passwords should use a memory-hard password hashing/KDF mechanism such as Argon2id where password-derived protection is required.

Password authentication and vault encryption keys must remain conceptually separate.

### 14.4 Key Hierarchy

The final key hierarchy is subject to implementation review, but should follow the principle:

```text
Root / Vault Key
       |
       +---- wrapped/protected key material
       |
       +---- encrypted data objects
```

Authentication controls release of the key rather than becoming the key itself.

## 15. Sensitive Memory

Sensitive values include:

- passwords;
- PINs;
- encryption keys;
- decrypted key material;
- authentication secrets.

Rust crates such as `zeroize` and `secrecy` should be evaluated for handling these values.

The implementation must avoid unnecessary copies of secrets.

## 16. Encrypted Object Store

The MVP should use individual encrypted objects rather than one giant encrypted vault blob.

Example:

```text
SecureVault/
|
+-- vault.db
|
+-- objects/
    |
    +-- 01/
    |   +-- object-a
    |   +-- object-b
    |
    +-- 02/
        +-- object-c
```

The object store separates:

- metadata;
- encrypted content.

This allows:

- independent file reads/writes;
- corruption isolation;
- future deduplication;
- future filesystem integration;
- incremental storage operations.

## 17. Object Format

The exact binary format will be finalized during implementation.

Conceptually:

```text
+--------------------------------+
| Object Header                  |
+--------------------------------+
| Version                        |
| Algorithm                      |
| Object ID                      |
| Nonce                          |
| Metadata / flags               |
+--------------------------------+
| Ciphertext                     |
+--------------------------------+
| Authentication Tag             |
+--------------------------------+
```

The format must support versioning so cryptographic algorithms or metadata structures can evolve without invalidating existing vaults.

## 18. Metadata Storage

Initial metadata storage:

- SQLite

Metadata may include:

```text
objects
-------
object_id
name
size
created_at
modified_at
storage_path
content_metadata
```

SQLite is used for metadata management, not as a substitute for authenticated encrypted object storage.

## 19. CLI MVP

The first user-facing interface should be a CLI.

Example:

```bash
securevault init myvault
securevault user create dip
securevault unlock myvault
securevault put secret.txt
securevault list
securevault get secret.txt
securevault lock
```

The CLI should expose the security lifecycle explicitly.

## 20. Example MVP Flow

### Create

```bash
securevault init personal
```

System:

- Generate vault key
- Initialize metadata database
- Initialize object store
- Configure authorization policy

### Authenticate

```bash
securevault unlock personal
```

Flow:

```text
Credential
    |
    v
Authenticator
    |
    v
Identity
    |
    v
Authorization
    |
    v
Session
    |
    v
Key Lease
```

### Access

```bash
securevault put secret.txt
```

Flow:

```text
Session validation
       |
       v
Key lease validation
       |
       v
Encrypt object
       |
       v
Write object
       |
       v
Update metadata
```

### Expiration

After five minutes:

```text
Session expires
      |
      v
Key lease revoked
      |
      v
Key material zeroized
      |
      v
Vault access denied
```

## 21. Technology Stack

### Core

- Rust
- Cargo workspace
- Rust 2021/2024 edition as appropriate at implementation time

### Cryptography

Evaluate:

- RustCrypto
- aes-gcm
- argon2
- hkdf
- rand / OS CSPRNG
- zeroize
- secrecy

Only well-maintained cryptographic libraries should be used. Do not implement cryptographic primitives ourselves.

### Storage

- SQLite
- rusqlite or another mature Rust SQLite library

### CLI

- clap

### Windows

- windows Rust crate
- Windows CNG/DPAPI APIs where justified
- Windows security APIs in later milestones

### Future Face Engine

Potential isolated process:

```text
face-engine.exe
```

Technology candidates:

- Python
- OpenCV
- ONNX Runtime
- face embedding model
- liveness model

The face engine should communicate with SecureVault through a defined IPC boundary rather than embedding Python into the security core.

## 22. Repository Structure

Proposed workspace:

```text
securevault/
|
+-- Cargo.toml
+-- Cargo.lock
|
+-- crates/
|   |
|   +-- securevault-core/
|   +-- securevault-auth/
|   +-- securevault-session/
|   +-- securevault-crypto/
|   +-- securevault-storage/
|   +-- securevault-cli/
|
+-- tests/
|
+-- docs/
|   +-- architecture.md
|   +-- threat-model.md
|   +-- vault-format.md
|   +-- authentication.md
|
+-- README.md
```

Suggested responsibilities:

- `securevault-core`
  - Identity
  - Authentication contracts
  - Authorization contracts
  - Core errors
- `securevault-auth`
  - Authenticator implementations
- `securevault-session`
  - Session lifecycle
  - TTL
  - Revocation
- `securevault-crypto`
  - Encryption
  - Key management
  - Zeroization
- `securevault-storage`
  - SQLite metadata
  - Object store
  - Vault lifecycle
- `securevault-cli`
  - User interface
  - Command routing

## 23. Security Requirements

- SR-01 — No plaintext protected files
  Protected vault objects must never be persisted as plaintext.
- SR-02 — Authenticated encryption
  Every encrypted object must provide confidentiality and integrity.
- SR-03 — Random nonces
  Encryption must use unique nonces according to the selected AEAD scheme's requirements.
- SR-04 — No password-as-key shortcut
  Passwords must not directly become vault encryption keys.
- SR-05 — Key lifetime control
  Vault keys must only be available to authorized active sessions.
- SR-06 — Session expiration
  Expired sessions must not be able to access vault data.
- SR-07 — Fail closed
  Authentication, authorization, key, and storage errors must deny access.
- SR-08 — No biometric dependency
  The core vault must work without facial recognition.
- SR-09 — Local processing
  The MVP must not require sending protected data or biometric data to a remote service.
- SR-10 — Tamper detection
  Modified ciphertext must be detected and rejected.

## 24. Threat Model

The initial threat model should consider:

### T1 — Stolen vault files

Attacker obtains the encrypted vault directory.

Expected result: No plaintext access.

### T2 — Incorrect credentials

Repeated invalid authentication attempts must not release the key.

### T3 — Modified ciphertext

Attacker modifies encrypted object bytes.

Expected result: Authentication tag verification fails.

### T4 — Expired session

Attacker attempts to use a previously valid session after expiration.

Expected result: Access denied.

### T5 — Process crash

The application crashes while a vault is unlocked.

Expected behavior must be defined and tested, with no assumption that volatile memory is always perfectly scrubbed by the OS.

### T6 — Local privileged attacker

A local administrator or kernel-level attacker may be able to inspect process memory or intercept operations.

This is outside the initial protection boundary and must be explicitly documented.

### T7 — Compromised face authenticator

The face engine is treated as an authentication provider, not as a trusted cryptographic authority.

A compromised provider must not gain arbitrary access to vault internals beyond the authentication interface.

## 25. Logging and Audit

Logs must never contain:

- passwords;
- PINs;
- encryption keys;
- face embeddings;
- raw biometric images;
- decrypted protected file contents.

Useful events:

- `vault_created`
- `authentication_attempt`
- `authentication_success`
- `authentication_failure`
- `authorization_denied`
- `session_created`
- `session_expired`
- `session_revoked`
- `key_lease_created`
- `key_lease_revoked`
- `vault_locked`
- `object_read`
- `object_write`
- `integrity_failure`

Sensitive identifiers should be minimized.

## 26. Error Handling

Errors should be categorized.

Example categories:

- `AuthenticationError`
- `AuthorizationError`
- `SessionError`
- `KeyError`
- `CryptoError`
- `StorageError`
- `VaultError`

Security-sensitive failures should not expose unnecessary information. For example, avoid revealing whether the username exists unless explicitly required by the product behavior.

## 27. Testing Strategy

### Unit Tests

Test independently:

- identity handling;
- authenticator contracts;
- password verification;
- session TTL;
- session revocation;
- authorization policy;
- encryption/decryption;
- nonce generation;
- tamper detection;
- key lifecycle;
- object storage.

### Integration Tests

Test:

```text
Authentication
      ↓
Identity
      ↓
Authorization
      ↓
Session
      ↓
Key Lease
      ↓
Encryption
      ↓
Storage
```

### Security Tests

At minimum:

- wrong password;
- corrupted ciphertext;
- corrupted authentication tag;
- expired session;
- revoked session;
- missing key;
- malformed vault;
- malformed object;
- interrupted write;
- duplicate object IDs;
- concurrent access;
- application restart;
- vault copied to another machine.

### Property / Fuzz Testing

Eventually fuzz:

- vault metadata;
- encrypted object parser;
- object headers;
- authentication request parsing;
- vault recovery logic.

## 28. Milestone Roadmap

### M0 — Architecture and Threat Model

Deliverables:

- PRD
- architecture document
- threat model
- vault format proposal
- key hierarchy proposal
- Rust workspace skeleton

Acceptance:

- security boundaries documented;
- trust assumptions documented;
- interfaces defined.

### M1 — Secure Vault MVP

Deliver:

- vault initialization;
- password authentication;
- identity;
- authorization;
- five-minute sessions;
- key manager;
- AES-256-GCM encryption;
- encrypted object store;
- SQLite metadata;
- lock/unlock;
- CLI.

Acceptance:

1. Create vault.
2. Register user.
3. Authenticate.
4. Establish session.
5. Release key lease.
6. Write encrypted object.
7. Read/decrypt object.
8. Lock vault.
9. Expire session.
10. Reject access after expiration.
11. Detect tampered ciphertext.

### M2 — Authentication Framework

Deliver:

- Authenticator trait;
- password provider;
- mock provider;
- authentication registry;
- provider-specific credential handling.

Acceptance:

A new authenticator can be introduced without modifying crypto or storage modules.

### M3 — Face Authentication

Deliver:

- camera capture;
- face detection;
- face enrollment;
- face embedding;
- verification;
- liveness/presentation-attack protection;
- isolated face-engine process;
- `FaceAuthenticator`.

Acceptance:

Face authentication returns an identity through the same authentication interface used by password authentication.

### M4 — Windows Security Integration

Deliver:

- Windows-specific secure storage integrations where appropriate;
- Windows lock awareness;
- suspend/resume behavior;
- stronger key protection;
- OS credential integration where justified.

### M5 — Virtual Secure Drive

Deliver:

```text
S:\
or another mounted drive representation.
```

User experience:

```text
Explorer
   |
   v
SecureVault Drive
   |
   v
Encrypted Object Store
```

The filesystem layer must not bypass the existing authentication/session/key architecture.

### M6 — Advanced Authentication Policies

Potential features:

- multi-factor authentication;
- face + hardware key;
- face OR password;
- WebAuthn/passkeys;
- TPM-backed credentials;
- configurable session policies;
- reauthentication policies;
- per-vault policies.

## 29. MVP Acceptance Criteria

The first release is considered successful when all of the following work:

### Vault

- [ ] Vault can be initialized.
- [ ] Vault metadata is created.
- [ ] Vault objects are encrypted.
- [ ] Plaintext objects are not persisted.

### Authentication

- [ ] Password authenticator works.
- [ ] Authentication produces an identity.
- [ ] Authentication failure never releases the vault key.
- [ ] Authentication provider is abstracted behind an interface.

### Authorization

- [ ] Identity is checked against vault access policy.
- [ ] Unauthorized identities are rejected.

### Session

- [ ] Successful authorization creates a session.
- [ ] Default TTL is five minutes.
- [ ] Expired sessions cannot access vault data.
- [ ] Sessions can be explicitly revoked.

### Keys

- [ ] Vault key is generated securely.
- [ ] Vault key is not derived directly from the password.
- [ ] Key access is controlled through a key lease.
- [ ] Sensitive key material is zeroized where practical.

### Encryption

- [ ] AES-256-GCM or an equivalent approved AEAD is used.
- [ ] Nonces are unique.
- [ ] Tampered ciphertext is rejected.

### Storage

- [ ] Encrypted objects can be written.
- [ ] Encrypted objects can be read.
- [ ] Metadata is stored separately.
- [ ] Corrupted objects do not silently produce plaintext.

### CLI

- [ ] `init`
- [ ] `user create`
- [ ] `unlock`
- [ ] `lock`
- [ ] `put`
- [ ] `get`
- [ ] `list`

## 30. Future Architecture

The long-term system should converge toward:

```text
                         Windows
                            |
                      +-----+------+
                      |            |
                  SecureVault   Explorer
                      |            |
                      +-----+------+
                            |
                    Authentication
                       Engine
                            |
             +--------------+--------------+
             |              |              |
           Face          WebAuthn       Hardware
             |              |              |
             +--------------+--------------+
                            |
                         Identity
                            |
                     Authorization
                            |
                         Session
                            |
                        Key Lease
                            |
                     Crypto Engine
                            |
                     Virtual FS
                            |
                    Encrypted Store
```

This allows SecureVault to become a general-purpose local authentication and protected-storage platform, rather than a single-purpose biometric application.

## 31. Risks and Tradeoffs

### Rust Complexity

Rust increases implementation complexity compared with Go or Python but provides strong guarantees for security-sensitive memory and concurrency.

Decision: Use Rust for the core.

### Python Face Engine

Python provides access to a much stronger ML ecosystem.

Decision: Isolate it as a separate process rather than embedding it into the security core.

### SQLite

SQLite is sufficient for local metadata in the MVP.

Decision: Use SQLite initially.

### Filesystem Driver Complexity

A real Windows filesystem integration introduces substantial complexity and potentially kernel-level risk.

Decision: Defer until the user-space vault is proven.

### Facial Recognition Security

Face recognition is vulnerable to presentation attacks if implemented as simple image similarity.

Decision: Require liveness/presentation-attack protection before treating face authentication as a serious security mechanism.

## 32. Open Questions

The following decisions should be resolved before later milestones:

1. Should each vault have one master key or a hierarchy of data-encryption keys?
2. Should vault keys be wrapped using Windows DPAPI?
3. Should TPM-backed protection be mandatory or optional?
4. How should vault recovery work?
5. What happens if the user loses every configured authenticator?
6. Should metadata itself be encrypted?
7. Should filenames be encrypted?
8. How should concurrent access be handled?
9. How should atomic writes and crash recovery work?
10. Which virtual filesystem mechanism should be used for the Windows drive?
11. What exact face model and liveness architecture will be used?
12. What attacks are considered within the product's security boundary?

These decisions should be made based on the threat model rather than convenience.

## 33. Immediate Next Steps

The implementation order should be:

1. Create Rust workspace
2. Define core domain types
3. Define `Authenticator` trait
4. Implement `Identity`
5. Implement `Authorization`
6. Implement `Session Manager`
7. Implement `Key Manager`
8. Implement crypto abstraction
9. Implement encrypted object format
10. Implement SQLite metadata
11. Build Vault service
12. Build CLI
13. Write integration tests
14. Attack the implementation
15. Only then begin `FaceAuthenticator`

The first implementation target is therefore:

```text
Rust
  |
  +-- Authentication
  |
  +-- Identity
  |
  +-- Authorization
  |
  +-- Session
  |
  +-- Key Manager
  |
  +-- Crypto
  |
  +-- Object Store
  |
  +-- SQLite
  |
  +-- CLI
```

No GUI, no facial recognition, no Windows driver.

The goal of M1 is to prove that the security architecture works independently of the authentication method.
