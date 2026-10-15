use plume_utils::discovery::{DeviceDiscovery, PlatformDiscovery};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|a| a == "--help") {
        println!("Native Windows discovery only (DnsServiceBrowse/Resolve, with mDNS fallback). No account, PIN, pairing, filesystem writes, install, or configuration changes. Optional timeout seconds 1-15; default 5.");
        return Ok(());
    }
    let seconds = std::env::args().nth(1).and_then(|a| a.parse::<u64>().ok()).unwrap_or(5).clamp(1, 15);
    let devices = PlatformDiscovery::new().discover(Duration::from_secs(seconds)).await?;
    println!("devices_found={}", devices.len());
    for device in devices { println!("{device:?}"); }
    Ok(())
}
