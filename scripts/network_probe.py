"""Prepared local experiment only: discover, or inspect an ALREADY paired device.

Never signs/installs, never prompts for a PIN, never falls back to USB/kernel tunnels.
Needs the pinned pymobiledevice3 wheel environment. Not executed on the user's PC.
"""
import argparse
import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
import json

from pymobiledevice3.bonjour import browse_remotepairing_manual_pairing
from pymobiledevice3.remote import tunnel_service
from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.userspace_tunnel import UserspaceDialPlane


@asynccontextmanager
async def network_only_rsd(identifier):
    # Select only an existing matching pairing; this function never pair-setups.
    providers = await tunnel_service.get_remote_pairing_tunnel_services(udid=identifier)
    if not providers:
        raise RuntimeError("No advertised device matches an existing local pairing record")
    async with AsyncExitStack() as stack:
        for provider in providers:
            stack.push_async_callback(provider.close)
        old_userspace = tunnel_service.USE_USERSPACE_TUNNEL
        tunnel_service.USE_USERSPACE_TUNNEL = True
        stack.callback(setattr, tunnel_service, "USE_USERSPACE_TUNNEL", old_userspace)
        tunnel = await stack.enter_async_context(providers[0].start_tcp_tunnel())
        tun = tunnel.client.tun
        tun.set_peer(tunnel.address)
        dialer = await stack.enter_async_context(UserspaceDialPlane(tun, tunnel.address))
        rsd = RemoteServiceDiscoveryService((tunnel.address, tunnel.port), open_connection=dialer.dial,
                                            auxiliary_metadata=tunnel.auxiliary_metadata)
        stack.push_async_callback(rsd.close)
        await rsd.connect()
        yield rsd


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["discover", "inspect-paired"])
    parser.add_argument("--identifier")
    args = parser.parse_args()
    if args.mode == "discover":
        answers = await browse_remotepairing_manual_pairing()
        print(json.dumps([{"addresses": [a.full_ip for a in answer.addresses], "port": answer.port,
                           "name": answer.properties.get("name")} for answer in answers], indent=2))
    else:
        if not args.identifier:
            parser.error("inspect-paired requires the exact existing pairing identifier")
        async with network_only_rsd(args.identifier) as rsd:
            # Listing service names is read-only; do not send an install request.
            print(json.dumps({"services": sorted(rsd.peer_info["Services"])}, indent=2))


if __name__ == "__main__": asyncio.run(main())
