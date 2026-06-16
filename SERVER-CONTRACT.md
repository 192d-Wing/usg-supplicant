# usg-radius ↔ usg-supplicant Contract: TEAP, Machine→User Chaining, Key Schedule

**Status:** DRAFT v1 for review. Defines what **usg-radius** must implement so the supplicant's two-session EAP chaining and TLS 1.3 TEAP work. Because **both ends are ours**, this is a **private profile** (`usg-TEAP/1.3`) — it intentionally does not need to interop with stock TEAP servers, which lets us pin the TLS 1.3 key schedule cleanly.

---

## 0. Why a private profile

RFC 7170 (TEAP) predates TLS 1.3 and defines its key schedule in terms of the **TLS 1.2 PRF + master secret**. We require **TLS 1.3** (no 1.2). There is no finalized standard for TEAP-over-TLS-1.3, so §3 below **defines** the derivation both ends MUST implement byte-for-byte. Treat §3 as normative; deviation on either side breaks crypto-binding and the session fails closed.

---

## 1. Chaining mechanism (chosen): **Machine Authorization Ticket (MAT)**

We chose a **server-issued, server-encrypted, client-opaque ticket** — the cleanest, strongest option of those considered (vs. TLS resumption, which reuses the machine identity, or MAC/device tracking, which is spoofable). It is a focused PAC analog scoped to exactly the machine→user correlation we need.

### 1.1 Flow
```
BOOT (machine context)
  supplicant --TEAP-> usg-radius : inner EAP-TLS with machine cert (CNG)
  usg-radius validates machine cert chain + policy
  usg-radius --issues--> MAT TLV (opaque blob + lifetime)   [inside the TLS tunnel]
  supplicant stores MAT in machine-scope secure storage (DPAPI machine key)
  usg-radius authorizes port at MACHINE access level (Access-Accept + machine policy)

USER LOGON (user context)
  supplicant --TEAP-> usg-radius : presents stored MAT TLV, then inner EAP-TLS with smartcard cert
  usg-radius decrypts+validates MAT, then validates user cert chain + policy
  usg-radius binds {machine identity from MAT} + {user identity} -> FULL access decision
  usg-radius --issues--> refreshed MAT (optional) ; Access-Accept + full policy
```

### 1.2 MAT contents (server-defined, **opaque to the client**)
The client never parses it; it stores and replays it verbatim. usg-radius MUST:

- **Encrypt + authenticate** the ticket with a server-held master key using **AES-256-GCM** (FIPS). Format:
  `MAT = version(1) || key_id(4) || nonce(12) || AES-256-GCM-Ciphertext || tag(16)`
- Plaintext payload (CBOR or fixed struct) MUST contain:
  - `machine_id` — stable machine identity = SHA-256 of the machine cert's SubjectPublicKeyInfo (SKI-equivalent) **and** the cert serial+issuer.
  - `machine_auth_time` (unix seconds), `not_after` (issue + configurable lifetime, default 18h to cover a shift).
  - `nonce_id` — unique per issue, for optional server-side single-use / replay tracking.
  - `assurance` — machine auth method + policy tags applied at boot.
- **Rotate** the master key via `key_id`; keep N previous keys for the MAT lifetime window.

### 1.3 MAT validation at user logon — usg-radius MUST fail closed unless ALL hold
1. GCM tag verifies under a known `key_id` (else reject).
2. `now < not_after` (else reject — stale; client must re-run machine auth).
3. `machine_id`'s cert is **still valid / not revoked** (OCSP/CRL per policy).
4. (Optional, recommended) the user TEAP session arrives on the **same NAS / Calling-Station-ID** as the machine session that issued the MAT, if your topology guarantees it.
5. Crypto-binding for the **user** session validates independently (§3).

On success, usg-radius applies the **combined** policy ("user U on managed machine M") and returns full-access authorization. On any failure, return machine-only (or deny) per your policy — never silently upgrade.

### 1.4 TLV carriage
Use a **vendor TEAP TLV** (private, since both ends are ours):

- **MAT TLV** (server→client at issue; client→server at present). Type from the TEAP vendor-TLV space; `M`(mandatory) bit set. Value = the opaque MAT bytes of §1.2.
- The MAT TLV travels **inside the TLS 1.3 tunnel only** (Phase 2), never in cleartext.
- At user logon the client sends the MAT TLV **before** the user Intermediate-Result, so the server has machine context when it binds the result.

---

## 2. Per-session TEAP requirements (usg-radius)

- **Outer:** EAP-TEAP (type 55) over **TLS 1.3 only**. Server cert chain must be issued from a CA the supplicant trusts; server name/SAN must match the supplicant's configured `expected_server`.
- **Cipher suites:** `TLS_AES_256_GCM_SHA384` (preferred) or `TLS_AES_128_GCM_SHA256`. Curves P-256/P-384. No others.
- **Inner method:** **EAP-TLS (13) only**, one per session (machine OR user). Reject any other inner type.
- **Identity-Type TLV:** server SHOULD send `Identity-Type=Machine` for the boot session and `Identity-Type=User` for the logon session; the supplicant also infers context from EAPHost. The server determines required identity from the NAS/port + presence of a MAT.
- **TLVs server must support:** Authority-ID, Identity-Type, EAP-Payload, Intermediate-Result, **Crypto-Binding** (mandatory each inner method), Result, **MAT (vendor)**, Error, NAK, Request-Action.
- **Crypto-Binding:** server MUST send and verify a Crypto-Binding TLV per inner method (§3.4) and only emit `Result=Success` when it verifies.

---

## 3. `usg-TEAP/1.3` key schedule (NORMATIVE — implement identically both ends)

Let `H` = the hash of the negotiated suite (SHA-384 for AES-256-GCM-SHA384, SHA-256 for AES-128-GCM-SHA256). `HKDF-Expand` / `HMAC` use `H`. All lengths in octets.

### 3.1 Tunnel seed (replaces RFC 7170 §5.2 TLS 1.2 PRF step)
Use the **RFC 8446 §7.5 exporter**:
```
session_key_seed = TLS-Exporter("EXPORTER: teap session key seed", "" /*empty context*/, 40)
```

### 3.2 Inner IMSK (from inner EAP-TLS, itself TLS 1.3 per draft-ietf-emu-eap-tls13)
```
inner_MSK = inner EAP-TLS exporter "EXPORTER_EAP_TLS_Key_Material" (first 64 octets)
IMSK      = inner_MSK[0..31]            // first 32 octets
```

### 3.3 Compound key chain (replaces RFC 7170 §5.2 PRF with HKDF)
```
S-IMCK[0] = session_key_seed
for each completed inner method j = 1..n:
    IMCK[j]   = HKDF-Expand(S-IMCK[j-1], "Inner Methods Compound Keys" || IMSK[j], 60)
    S-IMCK[j] = IMCK[j][0..39]          // 40 octets
    CMK[j]    = IMCK[j][40..59]         // 20 octets
```
(In our two-session model each session has exactly one inner method, so `n = 1` per session; the chain construct is kept for fidelity and future multi-inner sessions.)

### 3.4 Crypto-Binding Compound MAC (RFC 7170 §4.2.13, hash = `H`)
```
Compound-MAC = HMAC-H(CMK[j], Crypto-Binding-TLV-with-MAC-field-zeroed)
```
Each side computes over its own and verifies the peer's; mismatch ⇒ fail closed.

### 3.5 Exported MSK to dot3svc (port keys)
```
MSK  = HKDF-Expand(S-IMCK[n], "Session Key Generating Function", 64)
EMSK = HKDF-Expand(S-IMCK[n], "Extended Session Key Generating Function", 64)   // if needed
```

> **Pin point:** §3.1–3.5 constants/labels are the contract. usg-radius and usg-supplicant MUST ship identical implementations; we'll lock them with shared **known-answer test vectors** generated once and checked into both repos.

---

## 4. What usg-radius needs to add (checklist)

- [ ] TEAP outer over TLS 1.3 only, suite allow-list, EAP-TLS inner only.
- [ ] Per-session Crypto-Binding using the §3 `usg-TEAP/1.3` schedule.
- [ ] Vendor **MAT TLV** issue (machine session) + validate/consume (user session).
- [ ] AES-256-GCM MAT seal/unseal with rotating master key (`key_id`).
- [ ] Machine-only authorization on boot; combined machine+user authorization on logon when a valid MAT is presented.
- [ ] Machine-cert revocation check at MAT validation time.
- [ ] Shared KAT vectors for §3, committed to both repos.

---

## 5. Open items to confirm with usg-radius team

- **Lifetime/refresh:** default MAT `not_after` = 18h, refresh on each successful machine re-auth — OK?
- **Single-use:** track `nonce_id` server-side for strict replay protection, or rely on short lifetime + NAS binding?
- **NAS binding (1.3 step 4):** can we assume machine and user sessions share Calling-Station-ID / NAS-Port? If yes, enforce it.
- **Master-key custody:** where does the MAT master key live in usg-radius (HSM/KMS)? Must be FIPS-validated storage.
```
