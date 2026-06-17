//! Provisioning CLI for the usg-supplicant `EAPHost` peer method.
//!
//! Builds a [`SessionConfigBlob`] from the command line, then either prints the
//! provisioning XML (the `EapHostConfig` or the `dot3svc` LAN profile) or, on
//! Windows, registers the method in HKLM / installs the LAN profile via `netsh`.
//! See `WINDOWS_DEV.md` §4.6 for the end-to-end runbook.

use std::process::ExitCode;

use eaphost::config::SessionConfigBlob;
use eaphost::profile::{eap_host_config_xml, lan_profile_xml};

const USAGE: &str = "\
usg-eaphost — provision the usg-TEAP EAPHost peer method

USAGE:
    usg-eaphost <command> [options]

COMMANDS:
    emit-config        Print the EapHostConfig XML (method + config blob)
    emit-profile       Print the dot3svc wired LAN profile XML
    register           [Windows] Register the method DLL in HKLM
    unregister         [Windows] Remove the method registration
    install-profile    [Windows] Install the LAN profile on an interface (netsh)
    help               Show this help

CONFIG OPTIONS (emit-config / emit-profile / install-profile):
    --server-name <name>     Expected EAP server name (required)
    --cert-subject <substr>  Client-cert subject substring to select (required)
    --machine                Machine session (default)
    --user                   User session
    --mat-vendor-id <hex>    MAT Vendor SMI PEN, hex digits, 0x optional (default 9999 = 0x9999)
    --max-fragment <n>       Max TLS fragment per TEAP message (default 1400)
    --root <file.der>        Server trust-anchor DER, repeatable
    --out <file>             Write XML here instead of stdout (emit-* only)

OTHER OPTIONS:
    --dll <path>             PeerDllPath to register (register)
    --interface <name>       Network interface name (install-profile)
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let cmd = args.first().map_or("help", String::as_str);
    let rest = if args.is_empty() { args } else { &args[1..] };
    match cmd {
        "emit-config" => write_out(rest, &eap_host_config_xml(&build_blob(rest)?.to_bytes())),
        "emit-profile" => write_out(rest, &lan_profile_xml(&build_blob(rest)?.to_bytes())),
        "register" => register_cmd(rest),
        "unregister" => unregister_cmd(),
        "install-profile" => install_profile_cmd(rest),
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    }
}

/// First value following `--name`, if present. A following token that is itself a
/// `--flag` is treated as a missing value (so `--server-name --cert-subject x`
/// reports a missing `--server-name` value rather than silently using
/// `--cert-subject` as the name).
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
        .filter(|v| !v.starts_with("--"))
}

/// All values following each occurrence of `--name` (repeatable flag); a
/// `--flag`-looking value is skipped (missing value).
fn repeated<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if let Some(v) = args.get(i + 1).filter(|v| !v.starts_with("--")) {
                out.push(v.as_str());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

fn present(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    flag(args, name).ok_or_else(|| format!("missing required option {name}"))
}

fn build_blob(args: &[String]) -> Result<SessionConfigBlob, String> {
    // Validate required flags first — before optional parsing or reading --root
    // files — so a missing flag is the reported error, not a downstream I/O failure.
    let server_name = required(args, "--server-name")?.to_string();
    let selector_subject = required(args, "--cert-subject")?.to_string();
    if present(args, "--machine") && present(args, "--user") {
        return Err("--machine and --user are mutually exclusive".to_string());
    }
    let mat_vendor_id = match flag(args, "--mat-vendor-id") {
        Some(s) => {
            let hex = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s);
            u32::from_str_radix(hex, 16)
                .map_err(|_| format!("invalid --mat-vendor-id '{s}' (expected hex digits)"))?
        }
        None => 0x9999,
    };
    let max_fragment = match flag(args, "--max-fragment") {
        Some(s) => s
            .parse::<u32>()
            .map_err(|_| format!("invalid --max-fragment '{s}' (expected a decimal integer)"))?,
        None => 1400,
    };
    let mut roots = Vec::new();
    for path in repeated(args, "--root") {
        roots.push(std::fs::read(path).map_err(|e| format!("read --root {path}: {e}"))?);
    }
    Ok(SessionConfigBlob {
        machine: !present(args, "--user"),
        server_name,
        mat_vendor_id,
        max_fragment,
        selector_subject,
        roots,
        // Provisioning carries no stored MAT; the user-session MAT is runtime state.
        mat: None,
    })
}

fn write_out(args: &[String], xml: &str) -> Result<(), String> {
    match flag(args, "--out") {
        Some(path) => std::fs::write(path, xml).map_err(|e| format!("write --out {path}: {e}")),
        None => {
            println!("{xml}");
            Ok(())
        }
    }
}

#[cfg(windows)]
fn register_cmd(args: &[String]) -> Result<(), String> {
    let dll = required(args, "--dll")?;
    // EAPHost runs as a service from its own working directory, so PeerDllPath must
    // be absolute — resolve a relative --dll against the current directory.
    let dll_abs = std::path::absolute(dll).map_err(|e| format!("resolve --dll {dll}: {e}"))?;
    let dll_str = dll_abs
        .to_str()
        .ok_or_else(|| format!("--dll path is not valid Unicode: {}", dll_abs.display()))?;
    eaphost::register::register(dll_str).map_err(|e| format!("register: {e}"))?;
    eprintln!("registered the usg-TEAP method (PeerDllPath = {dll_str})");
    Ok(())
}

#[cfg(windows)]
fn unregister_cmd() -> Result<(), String> {
    eaphost::register::unregister().map_err(|e| format!("unregister: {e}"))?;
    eprintln!("unregistered the usg-TEAP method");
    Ok(())
}

#[cfg(windows)]
fn install_profile_cmd(args: &[String]) -> Result<(), String> {
    let interface = required(args, "--interface")?;
    let xml = lan_profile_xml(&build_blob(args)?.to_bytes());
    // Per-process temp file so concurrent runs don't clobber each other.
    let path = std::env::temp_dir().join(format!("usg-teap-lanprofile-{}.xml", std::process::id()));
    std::fs::write(&path, xml).map_err(|e| format!("write profile: {e}"))?;
    let status = std::process::Command::new("netsh")
        .args([
            "lan",
            "add",
            "profile",
            &format!("filename={}", path.display()),
            &format!("interface={interface}"),
        ])
        .status()
        .map_err(|e| format!("run netsh: {e}"))?;
    if !status.success() {
        return Err(format!(
            "netsh lan add profile failed (exit {:?}); profile left at {}",
            status.code(),
            path.display()
        ));
    }
    let _ = std::fs::remove_file(&path);
    eprintln!("installed the LAN profile on '{interface}' (from a temp file)");
    Ok(())
}

#[cfg(not(windows))]
fn register_cmd(_args: &[String]) -> Result<(), String> {
    Err("register is only available on Windows".to_string())
}

#[cfg(not(windows))]
fn unregister_cmd() -> Result<(), String> {
    Err("unregister is only available on Windows".to_string())
}

#[cfg(not(windows))]
fn install_profile_cmd(_args: &[String]) -> Result<(), String> {
    Err("install-profile is only available on Windows".to_string())
}
