"""Compile exact network/platform source in isolation from unavailable signing dependency."""
from pathlib import Path
import hashlib
import json
import shutil

out = Path("build/component")
(out / "src").mkdir(parents=True, exist_ok=True)
upstream = Path("build/pr241")
shutil.copytree(upstream / "crates/plume_utils/src/wireless", out / "src/wireless")
for name in ["pr226", "pr241"]:
    shutil.copyfile(Path("build") / name / "crates/plume_core/src/developer/platform.rs", out / f"src/platform_{name}.rs")
manifest = '''[package]
name = "network-component-probe"
version = "0.1.0"
edition = "2024"
license = "MIT AND MPL-2.0"
[dependencies]
idevice = { git = "https://github.com/jkcoxson/idevice", rev = "5171e34e3a236842af1160a84d955d037ddca3af", default-features = false, features = ["full", "ring"] }
plist = "=1.8.0"
tokio = { version = "1.43", features = ["rt-multi-thread", "macros"] }
mdns-sd = "0.21"
log = "0.4"
thiserror = "2.0"
uuid = { version = "1.3", features = ["v4"] }
'''
(out / "Cargo.toml").write_text(manifest, encoding="utf-8")
(out / "src/lib.rs").write_text('''pub mod wireless;
pub mod platform_pr226;
pub mod platform_pr241;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O: {0}")] Io(#[from] std::io::Error),
    #[error("plist: {0}")] Plist(#[from] plist::Error),
    #[error("idevice: {0}")] Idevice(#[from] idevice::IdeviceError),
    #[error("mDNS: {0}")] Mdns(#[from] mdns_sd::Error),
    #[error("Pairing rejected")] PairingNotAccepted,
    #[error("Pairing missing: {0}")] PairingNotFound(String),
    #[error("Unsafe device identifier: {0}")] PairingInvalidUdid(String),
}
''', encoding="utf-8")
(out / "src/main.rs").write_text('''use network_component_probe::wireless::discover;
use std::time::Duration;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|a| a == "--help") {
        println!("Discovery only. No Apple ID, PIN, pairing records, installation, or system changes. Optional timeout seconds (1-15). Default 5.");
        return Ok(());
    }
    let timeout = std::env::args().nth(1).and_then(|a| a.parse::<u64>().ok()).unwrap_or(5).clamp(1, 15);
    let devices = discover(Duration::from_secs(timeout)).await?;
    println!("devices_found={}", devices.len());
    for device in devices { println!("{device}"); }
    Ok(())
}
''', encoding="utf-8")
hashes = {p.relative_to(out).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in (out / "src").rglob("*.rs")}
Path("evidence/component-source-sha256.json").write_text(json.dumps(hashes, indent=2), encoding="utf-8")
print("Exact PR241 wireless source and PR226/241 platform code copied; test-only Error/CLI glue added. No signing dependency substitution.")
