"""Exercise actual upstream APIs using fake device services, never network devices."""
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pymobiledevice3.exceptions import AppInstallError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services import installation_proxy as module
from pymobiledevice3.services.installation_proxy import InstallationProxyService, ZipFileType, classify_zip_file


def test_real_unsigned_ipa_classification():
    assert classify_zip_file(Path(os.environ["PROBE_IPA"]).read_bytes()) == ZipFileType.IPA


def test_remote_installation_service_selection():
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 1))
    service = InstallationProxyService(rsd)
    assert service.service_name == "com.apple.mobile.installation_proxy.shim.remote"


@pytest.mark.asyncio
async def test_install_real_ipa_upload_dispatch_cleanup_without_hardware(monkeypatch):
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 1))
    service = InstallationProxyService(rsd)
    afc = SimpleNamespace(makedirs=AsyncMock(), set_file_contents=AsyncMock(), rm_single=AsyncMock())

    class FakeAfc:
        def __init__(self, provider): assert provider is rsd
        async def __aenter__(self): return afc
        async def __aexit__(self, *args): pass

    monkeypatch.setattr(module, "AfcService", FakeAfc)
    send = AsyncMock()
    monkeypatch.setattr(service, "send_package", send)
    ipa = Path(os.environ["PROBE_IPA"])
    await service.install_from_local(ipa, developer=True)
    remote_path, uploaded = afc.set_file_contents.call_args.args
    assert uploaded == ipa.read_bytes()
    assert remote_path.startswith("/PublicStaging/pymobiledevice3/") and remote_path.endswith(".ipa")
    assert send.call_args.args[:2] == ("Install", {"PackageType": "Developer"})
    afc.rm_single.assert_awaited_once_with(remote_path, force=True)


@pytest.mark.asyncio
async def test_installation_completion_and_error_propagation():
    rsd = RemoteServiceDiscoveryService(("127.0.0.1", 1))
    service = InstallationProxyService(rsd)
    service._service = SimpleNamespace(recv_plist=AsyncMock(side_effect=[{"PercentComplete": 30}, {"Status": "Complete"}]))
    await service._watch_completion()
    service._service = SimpleNamespace(recv_plist=AsyncMock(return_value={"Error": "ApplicationVerificationFailed", "ErrorDescription": "synthetic untrusted signature"}))
    with pytest.raises(AppInstallError, match="ApplicationVerificationFailed"):
        await service._watch_completion()
