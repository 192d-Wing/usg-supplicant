# Design: FIPS 802.1X Supplicant — EAP-TEAP, EAP Chaining over Time (Rust / Windows EAPHost)

**Status:** DRAFT v2 for review. No implementation code yet. Stop-and-review gate.

**Locked decisions (from review):**
1. **FIPS boundary** = AWS-LC-rs (FIPS) for tunnel crypto + CNG/smartcard for private-key signing. ✅
2. **TLS 1.3 required** (no TLS 1.2 fallback). ✅
3. **No extra driver** ⇒ implement TEAP as a **Windows EAPHost peer EAP-method DLL**; Wired AutoConfig (`dot3svc`) owns EAPOL/L2. ✅
4. **Chaining over time** = **two separate TEAP sessions**: machine auth at boot grants network access; user (smartcard) auth at login; server correlates the two for full access. ✅

---

## 1. Scope & non-goals

**In scope:**
- IEEE 802.1X-2020 wired auth on Windows 10/11 + Server, delivered as an **EAPHost peer EAP method** (type TEAP / RFC 7170) driven by Wired AutoConfig (`dot3svc`).
- **Two-phase timing (item 4):**
  - **Boot / pre-logon:** `dot3svc` invokes our method in **machine context** → TEAP session #1 → inner EAP-TLS with **machine cert (CNG)** → port authorized for machine/limited access.
  - **User logon:** `dot3svc` invokes our method in **user context** → TEAP session #2 → inner EAP-TLS with **smartcard user cert** → server correlates with the prior machine auth → full user access.
- **Chaining correlation** carried across the two sessions via persisted authorization state (PAC / authorization-data, machine-scope) and/or server-side device tracking — exact mechanism pinned to the target RADIUS server (see §10 Q-A).
- All security-path crypto via **FIPS 140-3 validated** modules; fail closed otherwise.

**Out of scope now:** Linux, wireless, password/MSCHAPv2 inner methods, GUI beyond required EAPHost config/identity UI, single-tunnel back-to-back chaining (explicitly replaced by the two-session model).

---

## 2. Workspace layout

`eap-core` / `teap` are pure and fully unit-testable with no OS or network. Windows coupling is isolated in `eaphost`, `creds`, `pac`, and the config/UI DLL.

```
usg-supplicant/
├─ Cargo.toml                 # workspace
├─ DESIGN.md
├─ crates/
│  ├─ eap-core/              # EAP packet types + inner dispatch (EAP-TLS only). No I/O.
│  ├─ teap/                  # TEAP TLV codec, per-session state machine,
│  │                         #   crypto-binding, key schedule. No I/O.
│  │   └─ src/{tlv/*, session.rs, cryptobind.rs, keyschedule.rs, identity.rs}
│  ├─ fips-tls/             # TLS 1.3-only backend trait + aws-lc-rs(FIPS) impl; exporter access
│  │   └─ src/{backend.rs, awslc.rs, exporter.rs, suites.rs}
│  ├─ creds/               # CNG machine + smartcard user cert/key providers behind a trait
│  │   └─ src/{provider.rs, cng_machine.rs, smartcard_user.rs}
│  ├─ pac/                 # authorization-data / PAC persistence (machine-scope, DPAPI) behind trait
│  ├─ eaphost/             # cdylib: EAPHost peer-method C-ABI shim → drives teap; identity context
│  │   └─ src/{exports.rs, session_glue.rs, registration.rs}
│  ├─ eaphost-config/      # cdylib: EAPHost peer config/UI DLL (XML<->blob, identity/cred UI)
│  └─ cli/                # diagnostics: fips-check, register/unregister method, decode captures
└─ tests/                  # recorded TEAP exchanges, KAT vectors, state-machine scripts
```

> **No `eapol`/`netif` crates.** With EAPHost, `dot3svc` owns the EAPOL frame layer, port state machine, and L2 transport. We never touch raw L2 — that's what satisfies "no extra driver."

---

## 3. FIPS strategy & crypto boundary (locked)

| Crypto operation | Module | Validated |
|---|---|---|
| TLS 1.3 records, key schedule, exporters, Crypto-Binding HMAC | **aws-lc-rs FIPS** (AWS-LC FIPS module) via rustls | ✅ |
| Machine cert signature (inner EAP-TLS #1) | **Windows CNG** (FIPS mode), key non-exportable | ✅ |
| User cert signature (inner EAP-TLS #2) | **Smartcard** via CNG KSP / PKCS#11, key on card | ✅ |

- rustls uses a **custom `SigningKey`** delegating CertVerify to CNG/smartcard so private keys never leave their store; the validated symmetric/KDF crypto stays in aws-lc-rs. FIPS boundary = AWS-LC-FIPS (tunnel) **+** platform/card validated module (signing). Documented as such in the FIPS deployment guide.
- **Hosting note:** our DLL runs inside the EAPHost service (`svchost`/`eaphost`). aws-lc-rs FIPS is statically linked into the DLL; the FIPS power-on self-test runs at DLL load. PAC/key access respects the machine-vs-user context EAPHost provides.
- **Fail-closed self-check** (`cli fips-check`, plus at DLL init + each `BeginSession`): assert rustls `CryptoProvider.fips() == true`; assert Windows `FipsAlgorithmPolicy` enabled; enforce the TLS 1.3 suite allow-list. Any failure ⇒ method returns auth failure to `dot3svc`. No fallback path exists.

---

## 4. TLS backend trait (`fips-tls`) — TLS 1.3 only

```rust
pub trait TlsBackend {
    type Conn: TlsTunnel;
    fn assert_fips(&self) -> Result<(), FipsError>;          // gate
    fn client(
        &self,
        trust: &TrustAnchors,                                 // configurable EAP-server CA(s)
        expected_server: &ServerIdentity,                     // name/SAN match, fail closed
        client_key: Option<Arc<dyn SigningKey>>,              // CNG / smartcard delegate
    ) -> Result<Self::Conn, TlsError>;
}

pub trait TlsTunnel {
    fn read_handshake(&mut self, buf: &[u8]) -> Result<HandshakeStep, TlsError>;
    fn write_handshake(&mut self) -> Result<Vec<u8>, TlsError>;
    fn is_established(&self) -> bool;
    fn negotiated_suite(&self) -> CipherSuite;                // must be in allow-list
    /// RFC 8446 §7.5 exporter — sole key-material source for TEAP key schedule.
    fn export_keying_material(&self, label: &str, context: Option<&[u8]>, len: usize)
        -> Result<Vec<u8>, TlsError>;
    fn protect(&mut self, pt: &[u8]) -> Result<Vec<u8>, TlsError>;     // Phase-2 app data
    fn unprotect(&mut self, ct: &[u8]) -> Result<Vec<u8>, TlsError>;
}
```

**Enforced allow-list:** TLS **1.3 only**; `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`; curves P-256/P-384; RSA ≥ 2048. Anything else ⇒ abort.

> ⚠️ **Interop caution (now a hard constraint):** Many RADIUS servers run TEAP over TLS **1.2**; TEAP-over-1.3 key derivation depends on the TLS 1.3 exporter path plus RFC 7170 errata. Requiring 1.3 narrows interoperable servers — confirm the target server negotiates TEAP over TLS 1.3 (see §10 Q-B).

---

## 5. Credential providers (`creds`)

```rust
pub trait CertCredential {
    fn certificate_chain(&self) -> Result<Vec<CertDer>, CredError>;
    fn signing_key(&self) -> Result<Arc<dyn SigningKey>, CredError>;  // never exposes raw key
    fn kind(&self) -> CredKind;                                       // Machine | User
}
```

- The active credential is chosen from the **EAPHost session identity context**: machine context ⇒ `cng_machine`; user context ⇒ `smartcard_user`. We do not pick both in one session.
- `cng_machine`: Local Machine\My, select by issuer/EKU/SAN/thumbprint; sign via `NCryptSignHash`.
- `smartcard_user`: PIV/CAC via CNG Smart Card KSP (preferred) or PKCS#11 fallback; PIN policy delegated to EAPHost credential UI / logon; key non-extractable.

---

## 6. EAPHost integration (`eaphost`, `eaphost-config`)

- Build a **peer EAP-method DLL** (`cdylib`) exporting the EAPHost peer C ABI: `EapPeerGetInfo`, `EapPeerInitialize`, `EapPeerBeginSession`, `EapPeerProcessRequestPacket`, `EapPeerGetResponsePacket`, `EapPeerGetResult`, `EapPeerGetIdentity`, `EapPeerGet/SetUIContext`, `EapPeerGet/SetResponseAttributes`, `EapPeerEndSession`, `EapPeerShutdown`.
- A second **peer config/UI DLL** (`eaphost-config`) exports `EapPeerConfigXml2Blob` / `EapPeerInvokeConfigUI` / `EapPeerInvokeIdentityUI` / `EapPeerQueryCredentialInputFields` etc. for `dot3svc` profile config (trust anchors, expected server name, cert-selection criteria).
- **Registration** under `HKLM\SYSTEM\CurrentControlSet\Services\EapHost\Methods\{AuthorId}\{TypeId}` with peer/config DLL paths. `cli register` writes these.
- The shim is thin: marshals EAPHost request packets into `teap`, pumps responses back; `teap` and below stay pure/testable. The shim maps EAPHost's machine-vs-user context onto the credential + PAC selection.

> ⚠️ **Method identity (open, §10 Q-C):** recent Windows ships a **built-in TEAP** (type 55, author 0). To supply our FIPS + smartcard-chaining behavior we register under a **distinct author ID** (or vendor-specific type) to avoid colliding with the in-box method, and the `dot3svc` profile must select ours.

---

## 7. EAP layer (`eap-core`)

- Typed `EapPacket`; inner dispatcher permits **EAP-TLS (13) only**. Any other inner type ⇒ NAK / fail closed. (The outer EAP type is owned by EAPHost = our registered TEAP method.)

---

## 8. TEAP per-session core (`teap`)

### 8.1 Per-session shape (single identity per session)
Each EAPHost session runs **one** TEAP tunnel with **one** inner EAP-TLS, selected by context:

1. **Phase 1** — TLS 1.3 handshake builds the tunnel; validate server chain vs configured trust anchor + expected name/SAN (fail closed).
2. **Phase 2** — TLVs carry: (optionally) presented machine authorization (user session), the inner EAP-TLS exchange, Intermediate-Result + Crypto-Binding, final Result.

### 8.2 TLVs (typed codec, no ad-hoc slicing)
Authority-ID, **Identity-Type**, **EAP-Payload**, **Intermediate-Result**, **Crypto-Binding**, **Result**, **PAC/authorization-data**, Request-Action, Error, NAK. Each gets encode/decode round-trip + KAT tests.

### 8.3 Two-session chaining (item 4)
- **Machine session (boot):** authenticate machine; on success, persist any server-issued authorization/PAC to **machine-scope secure storage** (`pac` crate, DPAPI machine key — readable pre-logon, before any user profile exists).
- **User session (logon):** present the stored machine authorization inside the tunnel (and/or rely on server device tracking) so the server grants the combined machine+user result. Smartcard inner EAP-TLS authenticates the user.
- Supplicant **accepts the user Result=Success only** when: server cert validated, Crypto-Binding verified, inner user EAP-TLS succeeded. Full-access *policy* is the server's; we provide correct credentials + correlation material.

### 8.4 Key schedule & Crypto-Binding (RFC 7170 §5, TLS 1.3 path)
- `session_key_seed` from the **TLS 1.3 exporter** (RFC 8446 §7.5) with the TEAP label.
- Inner EAP-TLS **IMSK** folded into the S-IMCK / IMCK chain → derive **CMK** → Compound MAC (HMAC, in aws-lc FIPS) over the Crypto-Binding TLV; verify server's, emit ours.
- All constants/labels isolated in `keyschedule.rs`, each with a cited source, validated by KAT vectors against a reference server.

> ⚠️ **Spec hazard (open, §10 Q-B):** RFC 7170 key-derivation has known **errata**, and the **EMSK/IMSK source under TLS 1.3** differs from 1.2. These constants will be pinned against the errata + a known-good TLS 1.3 TEAP server before trust; not guessed silently.

### 8.5 Per-session state machine

| State | Input | Action | Next |
|---|---|---|---|
| `Start` | EAPHost `BeginSession` (+ machine/user context) | select credential + PAC mode | `ExpectTeapStart` |
| `ExpectTeapStart` | TEAP Start (S-bit) | begin TLS 1.3, emit ClientHello | `TlsHandshake` |
| `TlsHandshake` | TLS records | advance; validate server cert+name | `TlsHandshake` / `TunnelUp` |
| `TlsHandshake` | cert/name invalid | Error TLV | `Failed` |
| `TunnelUp` (user) | tunnel ready | present machine authorization/PAC | `Inner` |
| `TunnelUp` (machine) | tunnel ready | — | `Inner` |
| `Inner` | inner EAP-TLS exchange | drive inner TLS via CNG/smartcard signer | `Inner` |
| `Inner` | inner Success + Intermediate-Result | verify+send Crypto-Binding; (machine) persist PAC | `AwaitResult` |
| `AwaitResult` | Result=Success ∧ CB ok ∧ inner ok | send Result=Success | `Authenticated` |
| any | CB mismatch / inner failure / trust failure / non-FIPS | Error/Result=Failure | `Failed` |

Fail-closed is the default edge.

---

## 9. Error handling & testing

- One `thiserror` enum per crate; **fail closed** on FIPS check, suite/version, server cert/name, crypto-binding, inner failure, missing/locked credential. No silent downgrade.
- **Pure unit tests:** TLV round-trip + KAT; crypto-binding/key-schedule KAT (TLS 1.3 path); per-session state machine via scripted inputs.
- **Recorded exchanges:** capture full TEAP+EAP-TLS byte streams from a lab server (TLS 1.3) for both machine and user sessions; replay through `teap`.
- **EAPHost integration (Windows):** register method, drive via `dot3svc` against a test RADIUS; validate boot machine-auth then logon smartcard-auth and server correlation. Smartcard tested with a PIV/virtual smartcard.

---

## 10. Open questions — RESOLVED

- **Q-A — Correlation mechanism: RESOLVED.** Server is **our own usg-radius**, so we define the cleanest mechanism: a server-issued, server-encrypted, client-opaque **Machine Authorization Ticket (MAT)** (PAC analog), stored machine-scope (DPAPI) at boot and replayed inside the user-session tunnel. Full server-side spec in [SERVER-CONTRACT.md](SERVER-CONTRACT.md) §1. The `pac` crate stores/replays the opaque MAT; it never parses it.
- **Q-B — TLS 1.3 TEAP key schedule: RESOLVED.** Both ends are ours ⇒ we define a private **`usg-TEAP/1.3`** profile that adapts RFC 7170's TLS-1.2 PRF schedule to the TLS 1.3 exporter + HKDF. Normative byte-level spec in [SERVER-CONTRACT.md](SERVER-CONTRACT.md) §3; locked with shared KAT vectors committed to both repos.
- **Q-C — Method identity: RESOLVED.** Register under a **distinct author ID / vendor type**, not the in-box Windows TEAP; `dot3svc` wired profile selects ours.
- **Q-D — Smartcard middleware: RESOLVED.** Support **ActivClient** and **90Meter** for **DoD CAC/PIV** and **SIPR hardware token**. Primary path = **CNG** via each product's registered smartcard **minidriver/KSP** (certs surface in the user MY store); **PKCS#11 fallback** wired to ActivClient (`acpkcs211.dll`) and 90Meter modules for the SIPR token where CNG is insufficient. Cert selection prefers the **PIV Authentication cert** (EKU `1.3.6.1.5.5.7.3.2` Client Authentication, with PIV policy OIDs); PIN handled via EAPHost/logon (cached smartcard-logon PIN when available, else credential UI).

---

## 11. Milestones (after sign-off)

1. `teap` TLV codec + tests.
2. `teap` per-session state machine + crypto-binding + key schedule (TLS 1.3, KAT) + tests.
3. `fips-tls` aws-lc-rs FIPS backend (TLS 1.3) + exporter + suite enforcement + fips self-check.
4. `creds`: CNG machine provider, then smartcard user provider.
5. `pac` authorization-data persistence (machine-scope) — pending Q-A.
6. `eaphost` peer-method DLL + `eaphost-config` + registration; wire to `teap`.
7. Integration: boot machine-auth → logon user-auth via `dot3svc` against test RADIUS.
```
