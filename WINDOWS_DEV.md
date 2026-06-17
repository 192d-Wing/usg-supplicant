# Windows Development Handoff

How to continue `usg-supplicant` on a Windows host. The entire authentication
**logic** is built and proven in-memory on non-Windows; what remains is
Windows-only packaging (the EAPHost DLL), on-hardware validation of the FFI
(CNG/smartcard), the OS FIPS gate, the real FIPS (`aws-lc-fips`) build, and live
integration with usg-radius.

Read alongside [DESIGN.md](DESIGN.md) (architecture) and
[SERVER-CONTRACT.md](SERVER-CONTRACT.md) (the wire/key-schedule contract with
usg-radius). Commit conventions in [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 1. Current state (what's done, as of `1a98ab0`)

Cargo workspace, **edition 2024 / Rust 1.95**, 98 tests, clippy-clean under a
hardened lint baseline (forbid unsafe in pure crates; deny
unwrap/expect/panic/indexing/cast-truncation/arithmetic-side-effects).

| Crate | Role | Status |
|---|---|---|
| `usg-kat` | Shared KAT vectors (also vendored into usg-radius) | done, pure |
| `teap` | TLV codec, `usg-TEAP/1.3` key schedule, crypto-binding, Phase-2 session state machine, EAP + TEAP outer framing/fragmentation | done, pure, tested |
| `fips-tls` | TLS 1.3 backend: restricted aws-lc-rs provider (AES-GCM, **ML-KEM-1024** kx), RFC 8446 exporter, `TeapTlsClient` tunnel, FIPS gate, `RemoteSigner` seam | done; FIPS path gated behind `--features fips` |
| `creds` | CNG machine-cert + smartcard user-cert providers as `RemoteSigner`s; ECDSA raw→DER; cert selection; rustls signing adapter | cross-platform parts done+tested; **`cng.rs` is `#[cfg(windows)]`, compile-checked only — never run** |
| `pac` | Machine Authorization Ticket persistence (record codec + `MatStore`); **DPAPI** machine-scope sealer | cross-platform done+tested; `dpapi.rs` fully compiles on windows-msvc, **never run** |
| `supplicant` | `TeapDriver` (orchestration) + `EapTlsInner` (real inner EAP-TLS auth) | done, proven end-to-end in-memory |
| `eaphost` | OS `FipsAlgorithmPolicy` gate; EAPHost DLL plan | os_fips done (windows-compiled); **DLL shim NOT written** |

**Proven in-memory** (`crates/supplicant/tests/full_session.rs`): a full machine
session — outer ML-KEM TLS 1.3 → Phase 2 → nested inner EAP-TLS machine-cert
auth → crypto-binding → Result → EAP-Success → `Outcome::Success` with MSK/EMSK,
against an independent rustls-based TEAP server harness.

---

## 2. Windows prerequisites

```
rustup toolchain install 1.95.0          # edition 2024
rustup default 1.95.0
rustup target add x86_64-pc-windows-msvc # native on a Windows box
```

Build tooling:
- **MSVC** (Visual Studio Build Tools, "Desktop development with C++") — linker + headers.
- **CMake** and **Go** and **NASM** (or clang) — required to build `aws-lc-fips-sys`
  (the FIPS module) when using `--features fips`. The non-FIPS dev build
  (`aws-lc-sys`) needs CMake + NASM only.
- **Perl** is also commonly required by AWS-LC builds.

No Npcap / WinPcap needed: we integrate via **EAPHost**, so Windows
(`dot3svc` / Wired AutoConfig) owns EAPOL and L2 — we never touch raw sockets.

For the EAPHost DLL: the **Windows SDK** (eaphost headers `eaptypes.h`,
`eapmethodpeerapis.h`, `eaphostpeertypes.h`).

---

## 3. Building

```
# Dev build (non-FIPS provider; compiles without the FIPS toolchain).
cargo build
cargo test                       # 98 tests
cargo clippy --all-targets
cargo fmt --check

# FIPS build — routes ALL crypto through the validated aws-lc-fips module.
cargo build  -p fips-tls --features fips
cargo test   -p fips-tls --features fips     # verifies ML-KEM-1024 under aws-lc-fips
```

**Release builds REQUIRE `--features fips`.** `fips-tls/src/lib.rs` has a
`compile_error!` that fails any non-test release build without the `fips`
feature, so a release can never ship non-validated crypto. (The runtime
`provider::assert_fips()` is the second gate.)

### Verifying the `#[cfg(windows)]` FFI without a Windows box (already used here)
- `pac` and `eaphost` have **no aws-lc dependency**, so they fully type-check +
  clippy-clean against the Windows target from any host:
  ```
  cargo clippy -p pac     --target x86_64-pc-windows-msvc
  cargo clippy -p eaphost --target x86_64-pc-windows-msvc
  ```
- `creds` **cannot** be windows-checked off-Windows (its `aws-lc-sys` C build
  can't cross-compile here). The `windows`-crate FFI calls in `crates/creds/src/cng.rs`
  were validated by extracting them into a scratch crate that depends only on
  `windows` and checking *that* against `x86_64-pc-windows-msvc`. On a real
  Windows host just `cargo build -p creds`.

---

## 4. Remaining work, in priority order

### 4.1 EAPHost peer-method DLL  (the big remaining piece — `eaphost` crate)
Build the DLL that Windows `dot3svc` loads. See `crates/eaphost/src/lib.rs` for
the full plan. Concretely:

1. Add a `cdylib` crate-type and the EAPHost peer C-ABI exports (all
   `#[no_mangle] pub extern "system"`):
   `EapPeerGetInfo`, `EapPeerInitialize`, `EapPeerBeginSession`,
   `EapPeerProcessRequestPacket`, `EapPeerGetResponsePacket`, `EapPeerGetResult`,
   `EapPeerGetIdentity`, `EapPeerGetUIContext`, `EapPeerSetUIContext`,
   `EapPeerGetResponseAttributes`, `EapPeerSetResponseAttributes`,
   `EapPeerEndSession`, `EapPeerShutdown`.
   The `windows` crate exposes the EAP types under
   `windows::Win32::Security::ExtensibleAuthenticationProtocol` and
   `windows::Win32::NetworkManagement::*` — confirm coverage; if a type is
   missing, hand-declare the small struct/`#[repr(C)]` it needs.
2. The shim is thin: marshal each call into the already-built orchestration.
   - `EapPeerBeginSession` receives the machine-vs-user context (and config blob)
     → build a `supplicant::driver::TeapDriver` with
     `DriverConfig { identity, server_name, mat_vendor_id, mat_to_present, max_fragment }`
     and an injected `supplicant::inner_tls::EapTlsInner`:
       - **machine** session: inner client config from
         `fips_tls::backend::client_config(roots, ClientAuth::Resolver(resolver))`
         where `resolver = creds::adapter::RemoteCertResolver::new(Arc::new(creds::cng::machine_signer(&selector)?))`.
       - **user** session: same, but `creds::cng::user_signer(&selector)?` and set
         `mat_to_present` from the stored MAT (see 4.3).
   - `EapPeerProcessRequestPacket(eap_bytes)` → `driver.step(eap_bytes)` →
     map `DriverStep::Respond` to the EAPHost response packet,
     `DriverStep::Finished{ outcome }` to `EapPeerGetResult` (success → hand the
     MSK to EAPHost for the port keys; failure → fail).
   - Recommended max_fragment ≈ **1024–1400** (real EAP MTU), not the 64 KiB used
     in tests — this exercises the fragmentation/ACK paths in
     `teap::outer` + the driver/inner out-queues.
3. **Registration** (run by `cli register`, or an installer): write
   `HKLM\SYSTEM\CurrentControlSet\Services\EapHost\Methods\{AuthorId}\{TypeId}`
   (`eaphost::EAPHOST_METHODS_KEY` = the path) with `PeerDllPath` /
   `PeerConfigDllPath`. **Use a distinct Author ID** so we don't collide with the
   in-box Windows TEAP (type 55) — the `dot3svc` wired profile must select ours.
4. A second **peer config/UI DLL** (`EapPeerConfigXml2Blob`,
   `EapPeerInvokeConfigUI`, `EapPeerInvokeIdentityUI`,
   `EapPeerQueryCredentialInputFields`) carries the profile: trust anchors,
   expected server name/SAN, cert-selection criteria, MAT vendor id.
5. **Wire the OS FIPS gate**: call `eaphost::os_fips::assert_fips_policy()` in
   `EapPeerInitialize`/`EapPeerBeginSession` and fail closed if it errors. This
   completes the FIPS boundary (provider `assert_fips()` + OS policy).

### 4.2 Validate the CNG / smartcard providers on hardware (`creds::cng`)
`crates/creds/src/cng.rs` is written and FFI-type-checked but **never executed**.
On Windows, validate:
- `machine_signer(&CertSelector)` opens `Local Machine\My`, selects by
  `require_client_auth_eku` / thumbprint / subject, acquires the **non-exportable**
  NCRYPT key, signs with `NCryptSignHash`, DER-encodes via `creds::ecdsa::raw_to_der`.
- `user_signer(&CertSelector)` does the same on `Current User\My` for the
  smartcard cert. Test with **ActivClient** and **90Meter** middleware for
  **DoD CAC/PIV** and the **SIPR token**; the PIV Authentication cert is selected
  by Client-Auth EKU. PIN handling comes via EAPHost/logon (cached smartcard PIN)
  or the credential UI.
- Two code-review findings were already fixed but only on-host can confirm:
  the matched `CERT_CONTEXT` is duplicated (no use-after-free) and the
  `caller_free` flag is honored before `NCryptFreeObject`.
- If a card only exposes PKCS#11 (not a CNG minidriver), add the PKCS#11 fallback
  (ActivClient `acpkcs211.dll` / 90Meter module) — noted as a TODO.

### 4.3 Implement the OS FIPS registry read for real
`crates/eaphost/src/os_fips.rs::fips_policy_enabled()` is written for windows
(`RegGetValueW` on
`HKLM\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy\Enabled`) and
compiles for windows-msvc; confirm the value read on a FIPS-mode box.

### 4.4 MAT correlation across boot→logon (`pac` + driver + usg-radius)
`pac` stores the opaque MAT (DPAPI `LOCAL_MACHINE` scope) at machine auth and the
user session presents it. End-to-end this needs:
- machine session: capture `Outcome::Success { issued_mat }` → `pac::store::FileMatStore`
  with `pac::dpapi::DpapiSealer` under `%ProgramData%`.
- user session: `pac::store::fresh_ticket(...)` → `DriverConfig.mat_to_present`.
- the **exact MAT mechanism is ours to define** (SERVER-CONTRACT §1) — finalize
  with the usg-radius team (lifetime/refresh, single-use vs NAS-binding, master
  key custody). Validate on the live server.

### 4.5 User-session end-to-end test (optional, cross-platform)
`full_session.rs` covers the **machine** session. A user-session variant
(smartcard inner cert + MAT present/capture) mirrors it; the logic already
exists. Worth adding before on-hardware work.

### 4.6 Production validation via `dot3svc` (wired 802.1X)
The manual `EapHostPeer*` harness (`tests/real_eaphost*.rs`) validates the method
end to end **up to the outer EAP identity**: it authenticates a full TEAP session
self-hosted, runs inside the real `EAPHost` service (load + `BeginSession` + FIPS
gate), and round-trips the connection profile through `EapHostPeerConfigXml2Blob`.
The one thing it can't drive is the EAP-Response/Identity: on-hardware testing
showed `EAPHost` never calls our `EapPeerGetIdentity` and a manual session aborts
the Identity round with `EAP_E_EAPHOST_IDENTITY_UNKNOWN`, because the production
supplicant — Windows' Wired `AutoConfig` (`dot3svc`) — performs the identity and
credential plumbing (machine context, profile, connection-id registration) that a
hand-rolled `EapHostPeer*` caller does not. So the remaining validation is to let
`dot3svc` drive the method on a real 802.1X link.

**Supplicant side (this repo provides):** the `usg-eaphost` CLI (`eaphost-cli`
crate) wraps `eaphost::{profile, register}`:

- `usg-eaphost emit-config …` / `emit-profile …` — print the `EapHostConfig` /
  `dot3svc` LAN profile XML for a given `--server-name` / `--cert-subject` (+
  `--root`, `--machine`/`--user`, `--max-fragment`, …).
- `usg-eaphost register --dll <path>` / `unregister` — the HKLM method registration.
- `usg-eaphost install-profile --interface <if> …` — emit the LAN profile and
  `netsh lan add profile` it in one step.

**Provisioning + run (elevated):**

1. `sc.exe config dot3svc start= auto && net start dot3svc` (Wired AutoConfig).
2. Deploy `eaphost.dll` to a stable path (**not** a `usg-eaphost-testN.dll` scratch
   name) and `usg-eaphost register --dll <that path>`.
3. `usg-eaphost install-profile --interface "<adapter>" --server-name <s> --cert-subject <subj> --root <ca.der>`.
4. Enable 802.1X on that interface; on link-up `dot3svc` initiates EAPOL and drives
   our method. Watch via `netsh lan show interfaces` and the EAPHost event log /
   `netsh trace start scenario=Wired ...`.

**Authenticator side (lab infrastructure, not in this repo):** an 802.1X
authenticator that relays EAPOL to a RADIUS server speaking the `usg-TEAP/1.3`
server contract — e.g. `hostapd` (`driver=wired`) or a managed switch in front of
`usg-radius`. Do **not** test on the host's primary corporate NIC (it may already
do 802.1X and you can disrupt connectivity) — use an isolated segment (a VM bridged
to a host-only/internal virtual switch).

---

## 5. Pinned facts the implementation depends on (don't drift)

- **TLS:** 1.3 only. Suites `TLS13_AES_256_GCM_SHA384` (primary, SHA-384 MAC) and
  `TLS13_AES_128_GCM_SHA256`. KX group **`MLKEM1024`** only (pure ML-KEM-1024,
  FIPS 203, NamedGroup `0x0202`) — `fips_tls::provider::fips_kx_groups()`. No
  X25519/secp hybrids, no classical fallback. (To add `SecP384r1MLKEM1024` later,
  it's one line in that function once rustls ships the `0x11ed` codepoint.)
- **Key schedule (`usg-TEAP/1.3`, SERVER-CONTRACT §3):** single MSK-based S-IMCK
  chain; HKDF-Expand built on HMAC-H; Crypto-Binding MSK Compound MAC =
  `HMAC-H(CMK, full-CB-TLV-with-MAC-fields-zeroed)`, EMSK MAC field all-zero.
  Exporter labels: TEAP seed = `"EXPORTER: teap session key seed"` (40 octets);
  inner EAP-TLS IMSK = `"EXPORTER_EAP_TLS_Key_Material"` (first 32 of 64).
  Frozen KAT vectors in `crates/usg-kat/src/lib.rs` — **must stay byte-identical
  with usg-radius.**
- **Two-session chaining:** machine at boot grants access; user at logon; server
  correlates via the MAT. Outer TEAP tunnel is server-authenticated only; the
  machine/user cert auth is the **inner** EAP-TLS (also ML-KEM, also FIPS-gated).

---

## 6. Gotchas learned here

- **Shared Cargo target dir.** This repo's target is shared with sibling repos
  (`usg-radius`, etc.). A same-named crate poisoned the build cache once — that's
  why the KAT crate is `usg-kat`, not `kat`. If you see "no `tlv_vectors` in the
  root" or similar, `cargo clean -p usg-kat -p teap`.
- **Commit signing.** Commits are signed via a 1Password agent; it intermittently
  errored here — just retry the commit.
- **`fips-tls::backend::feed_incoming`** must never call `read_tls` on an exhausted
  cursor: a 0-byte `read_tls` makes rustls believe the transport hit EOF and
  breaks `unprotect`. It now advances through the slice. Keep it that way.
- **Inner EAP-TLS completion** (`supplicant::inner_tls`): the IMSK is derived from
  the completed-handshake exporter; the server's post-handshake "commitment" is
  required to be non-empty but is intentionally **not** decrypted (the tunnel is
  already mutually authenticated). Confirm this matches what usg-radius sends.

---

## 7. Quick commands

```
cargo test                                   # all 98, non-FIPS dev
cargo test -p supplicant --test full_session # the machine-session capstone
cargo test -p fips-tls --features fips       # ML-KEM under the validated module
cargo clippy --all-targets                   # 0 warnings expected
cargo build -p creds                         # (on Windows) build the CNG FFI
```

Key entry points: `supplicant::driver::TeapDriver`,
`supplicant::inner_tls::EapTlsInner`, `creds::cng::{machine_signer,user_signer}`,
`creds::adapter::RemoteCertResolver`, `fips_tls::backend::client_config`,
`pac::store::{FileMatStore,fresh_ticket}`, `pac::dpapi::DpapiSealer`,
`eaphost::os_fips::assert_fips_policy`.
