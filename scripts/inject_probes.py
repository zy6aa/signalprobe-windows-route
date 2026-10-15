"""Add test-only probes to disposable CI source checkout; never alter implementation."""
from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1])
candidate = sys.argv[2]
(root / "crates/plume_utils/examples").mkdir(exist_ok=True)
shutil.copyfile(Path(__file__).with_name("route_probe.rs"), root / "crates/plume_utils/examples/route_probe.rs")
if candidate == "fork226":
    shutil.copyfile(Path(__file__).with_name("discovery_probe.rs"), root / "crates/plume_utils/examples/discovery_probe.rs")
if candidate == "pr241":
    path = root / "crates/plume_utils/src/device.rs"
    with path.open("a", encoding="utf-8") as stream:
        stream.write('''
#[cfg(test)]
mod independent_windows_route_probe {
    use super::*;
    #[tokio::test]
    async fn network_only_apple_tv_is_rejected_before_installation() {
        let device = Device { name: "Synthetic Apple TV".into(), udid: "SYNTHETIC".into(),
            product_type: Some("AppleTV14,1".into()), device_id: 0, usbmuxd_device: None, is_mac: false };
        assert!(device.is_tvos());
        assert_eq!(device.developer_platform(), DeveloperPlatform::TvOs);
        let error = device.install_app(&PathBuf::from("never-uploaded.app"), |_| async {}).await.unwrap_err();
        assert!(error.to_string().contains("not connected via USB"), "{error}");
    }
}
''')
print("Added independent probes only; production source unchanged except appended test module")
