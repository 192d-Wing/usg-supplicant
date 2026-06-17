# Roadmap

Tracks the remaining work to ship `usg-supplicant` (the FIPS-gated EAP-TEAP
Windows supplicant). For the day-to-day Windows build/runbook see
[`WINDOWS_DEV.md`](WINDOWS_DEV.md); for the protocol/crypto contract see
[`DESIGN.md`](DESIGN.md) and [`SERVER-CONTRACT.md`](SERVER-CONTRACT.md).

## Done (merged)

- **TEAP stack** — full machine-session authentication to `Outcome::Success`
  end-to-end (TLS 1.3 + ML-KEM-1024 outer & inner, key schedule, crypto-binding,
  inner EAP-TLS with the machine cert), incl. RSA-2048 client/server certs.
- **EAPHost peer-method DLL** — `eaphost.dll` implements the EAPHost peer C-ABI
  (`EapPeerGetInfo`/`Initialize`/`BeginSession`/`ProcessRequestPacket`/… +
  `GetIdentity` and the config-method exports), with the OS FIPS gate. Validated
  **inside the real EAPHost service**: registration enumerated, DLL loaded as
  Local System, `EapPeerInitialize`(FIPS) + `EapPeerBeginSession` (CNG machine
  cert) driven by the live service.
- **Config-profile pipeline (live)** — an `EapHostConfig` profile →
  `EapHostPeerConfigXml2Blob` drives our `EapPeerConfigXml2Blob` → EAPHost-format
  connection blob → `EapHostPeerBeginSession` begins a live session.
- **Provisioning tooling** — `eaphost::profile` (LAN/`EapHostConfig` XML builders)
  and the `usg-eaphost` CLI (`emit-config`/`emit-profile`/`register`/`unregister`/
  `install-profile`). See `WINDOWS_DEV.md` §4.6.
- **Status UI (tray + window)** — the peer method publishes a coarse `AuthStatus`
  (outer/inner state, identity, the machine **and** user cert subjects + their
  SHA-256 thumbprints, server) to `%ProgramData%\usg-supplicant\status` via the
  `usg-status` crate, preserving both credentials across the one-at-a-time
  machine/user sessions. The `usg-tray` app (raw Win32, no new deps) polls and shows
  a state-colored **lock-and-key** tray icon, a right-click status menu, and an
  animated **toast** (DoD seal + green/spinner/red indicator, auto-dismiss). A
  right-click **"Status window…"** launches `usg-status-window` — a modern **Slint**
  GUI (DoW logo header, seal title-bar icon, centered status) that shows the
  **computer and user certificates** together, each with a **"View…"** button that
  opens the *exact* cert (matched by SHA-256 thumbprint, subject-CN fallback) in the
  Windows certificate dialog. Validated end-to-end (a full session ends the file at
  `state=authenticated` with the cert subject).
- **CNG/smartcard credentials** and the **OS FIPS-policy gate**, validated on
  hardware.

## Open — the remaining gap

### Live `dot3svc` / 802.1X validation of the outer identity  *(blocked on lab infra)*

**The gap.** Everything validatable in software is done, but one step remains:
confirming the method authenticates end-to-end when driven by Windows' Wired
`AutoConfig` service (`dot3svc`) over a real 802.1X link.

**Why it's still open.** The manual `EapHostPeer*` test harness drives the method
all the way up to the outer EAP **identity** and there hits a wall: a hand-rolled
host-API session aborts the EAP-Request/Identity round with
`EAP_E_EAPHOST_IDENTITY_UNKNOWN`. On-hardware investigation (≈15 live runs + the
EAPHost docs) established this is a **harness limitation, not a method defect**:

- Per the MSDN *Supplicant API Call Sequence*, the supplicant flow is
  `BeginSession(config + user data)` → `ProcessReceivedPacket` loop → `GetResult`;
  EAPHost forms the EAP-Response/Identity from the **user data** passed to
  `BeginSession`.
- A certificate method pulls its cert from the store and passes no user data, so
  in production the **`dot3svc` supplicant** supplies the identity/credential
  plumbing (machine context, profile, connection-id registration) — a hand-rolled
  caller does not.
- Confirmed dead ends (don't re-try): EAPHost never calls our `EapPeerGetIdentity`
  on this path (marker-verified) across `PeerIdentityPath`/`PeerConfigUIPath`/
  `Properties`/dialog-flag registration, a fresh author id (rules out service
  caching), `EapHostPeerGetIdentity` (tunnel→inner API, `E_INVALIDARG`), skipping
  the Identity round, and `EAP_FLAG_MACHINE_AUTH`.

**What's needed (lab infrastructure, not in this repo).** An 802.1X authenticator
that relays EAPOL to a RADIUS server speaking the `usg-TEAP/1.3` server contract —
e.g. `hostapd` (`driver=wired`) or a managed switch in front of `usg-radius`. Run
on an **isolated** segment (a VM bridged to a host-only / internal virtual switch),
**never** the host's primary corporate NIC (it may already do 802.1X — you can
disrupt connectivity).

**Steps** (the supplicant side is ready — `WINDOWS_DEV.md` §4.6):

1. `sc.exe config dot3svc start= auto && net start dot3svc`.
2. Deploy `eaphost.dll` to a stable path; `usg-eaphost register --dll <path>`.
3. `usg-eaphost install-profile --interface "<isolated adapter>" --server-name <s>
   --cert-subject <subj> --root <ca.der>`.
4. Enable 802.1X on that interface; on link-up `dot3svc` drives the method.

**Acceptance criteria.** `dot3svc` authenticates the machine end-to-end (the switch
port authorizes / RADIUS Access-Accept), and the EAPHost event log / `netsh trace
scenario=Wired` shows the TEAP exchange completing — i.e. the identity round that
the manual harness couldn't drive is supplied by `dot3svc`.

**Cheap precursor** (optional, still needs an isolated interface): enable 802.1X on
an isolated adapter with no authenticator and confirm — via a marker in
`EapPeerGetIdentity` + EAPHost tracing — that `dot3svc`-driven EAPHost calls our
method's `GetIdentity`, which would directly confirm the harness-vs-production
hypothesis without a full RADIUS lab.

## Other open items

- **Outer EAP-TLS over RSA on real DoD PKI** — inner EAP-TLS RSA is done; revisit
  the outer tunnel's RSA path against real CAC/DoD certs (the "reattack outer"
  follow-up).
- **User-session end-to-end test** — `full_session.rs` covers the machine session;
  add the user-session variant (smartcard inner cert + MAT present/capture).
  See `WINDOWS_DEV.md` §4.5.
- **MAT correlation across boot→logon** — the two-session chaining (machine at
  boot → user at logon, correlated via the MAT) end-to-end with `usg-radius`.
  See `WINDOWS_DEV.md` §4.4.
