"""Exercise actual upstream APIs using fake device services, never network devices."""
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from contextlib import asynccontextmanager
import network_probe

import pytest
from pymobiledevice3.exceptions import AppInstallError
from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services import installation_proxy as module
from pymobiledevice3.services.installation_proxy import InstallationProxyService, ZipFileType, classify_zip_file
from pymobiledevice3.remote import userspace_tunnel


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


@pytest.mark.asyncio
async def test_default_userspace_selector_does_not_reach_network_when_usbmux_is_absent(monkeypatch):
    usb = AsyncMock(side_effect=ConnectionFailedToUsbmuxdError())
    network = AsyncMock(return_value=[])
    monkeypatch.setattr(userspace_tunnel, "create_using_usbmux", usb)
    monkeypatch.setattr(userspace_tunnel.tunnel_service, "get_remote_pairing_tunnel_services", network)
    with pytest.raises(ConnectionFailedToUsbmuxdError):
        await userspace_tunnel._create_no_root_tunnel_provider("SYNTHETIC", False)
    network.assert_not_awaited()


@pytest.mark.asyncio
async def test_network_adapter_refuses_missing_existing_pairing(monkeypatch):
    monkeypatch.setattr(network_probe.tunnel_service, "get_remote_pairing_tunnel_services", AsyncMock(return_value=[]))
    with pytest.raises(RuntimeError, match="existing local pairing"):
        async with network_probe.network_only_rsd("SYNTHETIC"):
            pytest.fail("No device should be returned")


@pytest.mark.asyncio
@pytest.mark.parametrize("handshake_failure", [False, True])
async def test_network_adapter_selects_existing_peer_and_closes_resources(monkeypatch, handshake_failure):
    tun = SimpleNamespace(set_peer=Mock())
    result = SimpleNamespace(address="fd00::1", port=123, client=SimpleNamespace(tun=tun), auxiliary_metadata=None)
    events = []

    @asynccontextmanager
    async def fake_tunnel():
        assert network_probe.tunnel_service.USE_USERSPACE_TUNNEL is True
        try: yield result
        finally: events.append("tunnel-closed")

    provider = SimpleNamespace(close=AsyncMock(), start_tcp_tunnel=fake_tunnel)
    lookup = AsyncMock(return_value=[provider])
    monkeypatch.setattr(network_probe.tunnel_service, "get_remote_pairing_tunnel_services", lookup)
    monkeypatch.setattr(network_probe.tunnel_service, "USE_USERSPACE_TUNNEL", False)
    dialer = SimpleNamespace(dial=AsyncMock())

    @asynccontextmanager
    async def fake_dialer(*args):
        try: yield dialer
        finally: events.append("dialer-closed")

    monkeypatch.setattr(network_probe, "UserspaceDialPlane", fake_dialer)
    rsd = SimpleNamespace(connect=AsyncMock(side_effect=RuntimeError("handshake failed") if handshake_failure else None), close=AsyncMock(), peer_info={"Services": {"synthetic": {}}})
    constructor = Mock(return_value=rsd)
    monkeypatch.setattr(network_probe, "RemoteServiceDiscoveryService", constructor)
    if handshake_failure:
        with pytest.raises(RuntimeError, match="handshake failed"):
            async with network_probe.network_only_rsd("SYNTHETIC"): pass
    else:
        async with network_probe.network_only_rsd("SYNTHETIC") as actual:
            assert actual is rsd
    lookup.assert_awaited_once_with(udid="SYNTHETIC")
    assert constructor.call_args.kwargs["open_connection"] is dialer.dial
    rsd.close.assert_awaited_once()
    provider.close.assert_awaited_once()
    assert events == ["dialer-closed", "tunnel-closed"]
    assert network_probe.tunnel_service.USE_USERSPACE_TUNNEL is False
