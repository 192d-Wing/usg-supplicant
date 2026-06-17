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
    --mat-vendor-id <hex>    MAT Vendor SMI PEN, hex (default 9999)
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

/// First value following `--name`, if present.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// All values following each occurrence of `--name` (repeatable flag).
fn repeated<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if let Some(v) = args.get(i + 1) {
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
    if present(args, "--machine") && present(args, "--user") {
        return Err("--machine and --user are mutually exclusive".to_string());
    }
    let mat_vendor_id = match flag(args, "--mat-vendor-id") {
        Some(s) => u32::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|_| format!("invalid --mat-vendor-id '{s}' (expected hex)"))?,
        None => 0x9999,
    };
    let max_fragment = match flag(args, "--max-fragment") {
        Some(s) => s
            .parse::<u32>()
            .map_err(|_| format!("invalid --max-fragment '{s}'"))?,
        None => 1400,
    };
    let mut roots = Vec::new();
    for path in repeated(args, "--root") {
        roots.push(std::fs::read(path).map_err(|e| format!("read --root {path}: {e}"))?);
    }
    Ok(SessionConfigBlob {
        machine: !present(args, "--user"),
        server_name: required(args, "--server-name")?.to_string(),
        mat_vendor_id,
        max_fragment,
        selector_subject: required(args, "--cert-subject")?.to_string(),
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
    eaphost::register::register(dll).map_err(|e| format!("register: {e}"))?;
    eprintln!("registered the usg-TEAP method (PeerDllPath = {dll})");
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
    let path = std::env::temp_dir().join("usg-teap-lanprofile.xml");
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
    eprintln!(
        "installed the LAN profile on '{interface}' (from {})",
        path.display()
    );
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
