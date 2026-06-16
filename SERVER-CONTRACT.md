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

### 2.1 Inner EAP-TLS client-certificate signature algorithms — **NEW** (usg-radius to implement)

> **NEW / for the usg-radius agent.** Added because the supplicant now signs the inner EAP-TLS `CertificateVerify` with the **machine/user certificate's own key**, which on real DoD PKI is **RSA-2048** (CAC/PIV), not only ECDSA. The server's inner EAP-TLS `CertificateRequest` and its CertificateVerify-verification must accept what the supplicant sends. Validated on hardware against live CAC/machine certs.

**Client key types the supplicant presents** (machine cert via CNG, user cert via smartcard): **ECDSA P-256**, **ECDSA P-384**, or **RSA ≥ 2048** (DESIGN.md allow-list; RSA < 2048 is rejected by the supplicant and MUST be rejected by usg-radius).

**TLS 1.3 signature scheme per key (what the supplicant puts in CertificateVerify):**

| Client key | `signature_algorithms` codepoint | rustls / scheme name |
| --- | --- | --- |
| ECDSA P-256 | `0x0403` `ecdsa_secp256r1_sha256` | `ECDSA_NISTP256_SHA256` |
| ECDSA P-384 | `0x0503` `ecdsa_secp384r1_sha384` | `ECDSA_NISTP384_SHA384` |
| RSA (rsaEncryption) | `0x0804` `rsa_pss_rsae_sha256` | `RSA_PSS_SHA256` |

usg-radius MUST:

1. In the **inner EAP-TLS `CertificateRequest`**, offer **all three** schemes above in `signature_algorithms`. The supplicant advertises **exactly one** scheme (the one its selected key uses) and **declines to present** a cert if the server's offered set does not contain it — so a missing scheme silently drops to no-client-cert / auth failure rather than a clear error.
2. **Verify** the client `CertificateVerify` with a provider whose `signature_verification_algorithms` includes these. The shared `usg-fips-tls` provider already does (it keeps the aws-lc-rs default signature algorithms; only suites + KX are restricted) — no provider change needed on the server, just don't strip the defaults.
3. Reject client RSA keys `< 2048` bits, matching the supplicant.

**FIPS note (intentional):** RSA uses **SHA-256** PSS (`rsa_pss_rsae_sha256`, salt = 32) even on the SHA-384/AES-256 suite — the most widely supported `rsae` scheme, and FIPS-valid for RSA-2048. This is the one place the client-cert signature hash diverges from the tunnel's SHA-384 posture. See §5 to pin SHA-256 vs SHA-384 for RSA before this is load-bearing; whichever is chosen, **both ends must advertise/accept the same** scheme.

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

**HKDF-Expand definition (PIN):** `HKDF-Expand` here is RFC 5869 §2.3 built on
`HMAC-H`, used directly **without** the RFC 5869 "`PRK` length ≥ HashLen"
recommendation — `S-IMCK` is 40 octets and `HMAC` accepts any key length. The
`info` argument is the literal label octets (ASCII, no NUL terminator)
optionally followed by `IMSK`, exactly as written in §3.3/§3.5.

### 3.4 Crypto-Binding Compound MAC (single MSK-based path — PIN)

RFC 7170's dual EMSK/MSK compound-MAC chains are the main source of its errata.
Because **both ends are ours**, `usg-TEAP/1.3` collapses this to one
deterministic path:

- We maintain a **single** `S-IMCK`/`CMK` chain seeded per §3.1 using the
  **MSK-based** `IMSK` of §3.2.
- The Crypto-Binding TLV's **MSK Compound MAC** field is:
  ```
  MSK-Compound-MAC = HMAC-H(CMK[j], CB)
  ```
  where `CB` is the **entire encoded Crypto-Binding TLV** (4-octet header +
  value) with **both** MAC fields (EMSK and MSK) set to all-zero octets of
  their negotiated length (= HashLen of `H`).
- The **EMSK Compound MAC** field MUST be all zeros and is **not** used. The
  receiver MUST reject a Crypto-Binding whose EMSK Compound MAC is non-zero.
- Each side computes the MSK Compound MAC and verifies the peer's with a
  **constant-time** comparison; mismatch ⇒ fail closed.
- The peer additionally rejects a Crypto-Binding whose `sub_type` is not a
  Binding **Request** or whose `version`/`received_version` ≠ `TEAP_VERSION`
  (1), before trusting the MAC.

**Replay protection (PIN):** anti-replay rests on `session_key_seed` being
unique per TEAP session. The TLS 1.3 exporter (§3.1) MUST be keyed by the
specific handshake, so `S-IMCK[0]`, `CMK`, and every Compound MAC are unique
per session — a Crypto-Binding captured from one session cannot verify in
another. **The TLS backend MUST guarantee a fresh exporter per session** (no
resumption that would reuse exporter output for a distinct TEAP run). The
32-octet Crypto-Binding nonce is MAC-covered but is *not* relied on for
freshness; seed uniqueness is the guarantee.

### 3.5 Exported MSK to dot3svc (port keys)
```
MSK  = HKDF-Expand(S-IMCK[n], "Session Key Generating Function", 64)
EMSK = HKDF-Expand(S-IMCK[n], "Extended Session Key Generating Function", 64)
```

> **Pin point:** §3.1–3.5 constants/labels are the contract. usg-radius and
> usg-supplicant MUST ship identical implementations; they are locked with
> shared **known-answer test vectors** (see `crates/usg-kat`), committed to both
> repos and asserted by an independent HMAC/SHA reference in each.

---

## 4. What usg-radius needs to add (checklist)

- [ ] TEAP outer over TLS 1.3 only, suite allow-list, EAP-TLS inner only.
- [ ] **(NEW, §2.1)** Inner EAP-TLS `CertificateRequest` offers ECDSA P-256/P-384 **and** `rsa_pss_rsae_sha256`; verify client `CertificateVerify` for all three; reject RSA < 2048.
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
- **(NEW, §2.1) RSA client-cert PSS hash:** supplicant currently advertises `rsa_pss_rsae_sha256` (SHA-256) for all RSA keys, even on the SHA-384/AES-256 suite. Keep SHA-256 (most interoperable, FIPS-valid for RSA-2048), or switch both ends to `rsa_pss_rsae_sha384` (`0x0805`) for a uniform SHA-384 posture? Pick one; both ends MUST match.
