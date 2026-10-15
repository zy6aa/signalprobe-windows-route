"""Offline Windows signing experiments on the existing IPA. Synthetic identity only."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import zipfile

from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

EXPECTED = "1e4706cf4d2d8ca14b5d05d3b631857047726482687887096f75d23f8b9e8212"
APP_ID = "dev.zy6aa.signalprobe.tvos"
TEAM = "SYNTHETIC1"


def signature_blob(data):
    magic, cpu = struct.unpack_from("<2I", data)
    assert magic == 0xFEEDFACF and cpu == 0x0100000C
    count = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    platform = None
    found = None
    for _ in range(count):
        cmd, size = struct.unpack_from("<2I", data, offset)
        assert size >= 8 and offset + size <= len(data)
        if cmd == 0x32: platform = struct.unpack_from("<I", data, offset + 8)[0]
        if cmd == 0x1D:
            start, length = struct.unpack_from("<2I", data, offset + 8)
            found = data[start:start + length]
        offset += size
    assert platform == 3, "Must remain physical tvOS"
    return found


def verify_signed(data, cert):
    blob = signature_blob(data)
    assert blob, "No code signature"
    magic, length, count = struct.unpack_from(">3I", blob)
    assert magic == 0xFADE0CC0 and length <= len(blob)
    slots = {}
    for i in range(count):
        slot, offset = struct.unpack_from(">2I", blob, 12 + 8 * i)
        size = struct.unpack_from(">I", blob, offset + 4)[0]
        slots[slot] = blob[offset:offset + size]
    cd = slots[0]
    _, _, version, flags, hash_offset, ident_offset, special, pages, code_limit = struct.unpack_from(">9I", cd)
    hash_size, hash_type, platform, page_power = struct.unpack_from("4B", cd, 36)
    digest = {1: hashlib.sha1, 2: hashlib.sha256, 3: hashlib.sha256, 4: hashlib.sha384}[hash_type]
    for i in range(pages):
        page = data[i * (1 << page_power):min((i + 1) * (1 << page_power), code_limit)]
        assert digest(page).digest()[:hash_size] == cd[hash_offset + i * hash_size:hash_offset + (i + 1) * hash_size], f"Invalid code page {i}"
    entitlements_blob = slots[5]
    assert digest(entitlements_blob).digest()[:hash_size] == cd[hash_offset - 5 * hash_size:hash_offset - 4 * hash_size]
    entitlements = plistlib.loads(entitlements_blob[8:])
    assert entitlements["application-identifier"] == TEAM + "." + APP_ID
    assert entitlements["com.apple.developer.team-identifier"] == TEAM
    assert entitlements["get-task-allow"] is True
    signed = cms.ContentInfo.load(slots[0x10000][8:])["content"]
    signer = signed["signer_infos"][0]
    algorithm = signer["digest_algorithm"]["algorithm"].native
    attributes = signer["signed_attrs"]
    message_digest = next(a["values"][0].native for a in attributes if a["type"].native == "message_digest")
    assert hashlib.new(algorithm, cd).digest() == message_digest, "CMS not bound to CodeDirectory"
    der = attributes.dump()
    cert.public_key().verify(signer["signature"].native, b"\x31" + der[1:], padding.PKCS1v15(), {"sha256": hashes.SHA256(), "sha1": hashes.SHA1()}[algorithm])
    expected_cert = cert.public_bytes(serialization.Encoding.DER)
    assert any(c.chosen.dump() == expected_cert for c in signed["certificates"]), "Unexpected certificate"
    return {"code_pages_verified": pages, "cms_signature_verified": True, "entitlements": entitlements, "apple_trusted": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--ipa", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    args.output.mkdir(parents=True, exist_ok=True)
    exe = str(args.exe.resolve())
    source = args.ipa.read_bytes()
    assert hashlib.sha256(source).hexdigest() == EXPECTED
    with zipfile.ZipFile(args.ipa) as archive:
        assert all(".." not in Path(n).parts and "\\" not in n and not n.startswith("/") for n in archive.namelist())
        archive.extractall(args.work / "extracted")
    app = args.work / "extracted/Payload/SignalProbe.app"
    assert signature_blob((app / "SignalProbe").read_bytes()) is None

    def run(label, command):
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", timeout=120)
        (args.output / (label + ".log")).write_text(result.stdout, encoding="utf-8")
        assert result.returncode == 0, f"{label} failed: {result.stdout[-2000:]}"

    cli_output = args.work / "cli-output.ipa"
    run("cli-ipa-adhoc", [exe, "sign", "--package", str(args.ipa), "--output", str(cli_output)])
    with zipfile.ZipFile(cli_output) as archive:
        cli_signed = signature_blob(archive.read("Payload/SignalProbe.app/SignalProbe")) is not None
    report = {"input_sha256": EXPECTED, "cli_ipa_output_signed": cli_signed,
              "cli_ipa_output_equals_original": cli_output.read_bytes() == source}

    now = datetime.datetime.now(datetime.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SYNTHETIC TEST ONLY - NOT APPLE"), x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, TEAM)])
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256())
    cert_path, key_path = args.work / "synthetic-cert.pem", args.work / "synthetic-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    profile = {"Name": "SYNTHETIC TEST ONLY", "UUID": "00000000-0000-0000-0000-000000000000", "Platform": ["tvOS"],
               "ApplicationIdentifierPrefix": [TEAM], "TeamIdentifier": [TEAM], "ProvisionedDevices": ["SYNTHETIC-DEVICE"],
               "ExpirationDate": (now + datetime.timedelta(days=1)).replace(tzinfo=None), "CreationDate": now.replace(tzinfo=None),
               "DeveloperCertificates": [cert.public_bytes(serialization.Encoding.DER)],
               "Entitlements": {"application-identifier": TEAM + "." + APP_ID, "com.apple.developer.team-identifier": TEAM, "get-task-allow": True}}
    profile_data = pkcs7.PKCS7SignatureBuilder().set_data(plistlib.dumps(profile)).add_signer(cert, key, hashes.SHA256()).sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    profile_path = args.work / "synthetic.mobileprovision"
    profile_path.write_bytes(profile_data)
    run("directory-pem-sign", [exe, "sign", "--package", str(app), "--pem", str(cert_path), str(key_path), "--provision", str(profile_path)])
    binary = (app / "SignalProbe").read_bytes()
    report["directory_pem_signature"] = verify_signed(binary, cert)
    assert (app / "embedded.mobileprovision").read_bytes() == profile_data
    tampered = bytearray(binary)
    tampered[4096] ^= 1
    try:
        verify_signed(tampered, cert)
    except AssertionError:
        report["tampered_code_rejected"] = True
    else:
        raise AssertionError("Tampered executable accepted")
    output = args.output / "SYNTHETIC-NOT-INSTALLABLE.ipa"
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(app.rglob("*")):
            if path.is_file():
                entry = zipfile.ZipInfo("Payload/SignalProbe.app/" + path.relative_to(app).as_posix())
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.create_system = 3
                entry.external_attr = (0o100755 if path.name == "SignalProbe" else 0o100644) << 16
                archive.writestr(entry, path.read_bytes())
    with zipfile.ZipFile(output) as archive:
        assert all("\\" not in name for name in archive.namelist())
        verify_signed(archive.read("Payload/SignalProbe.app/SignalProbe"), cert)
        assert (archive.getinfo("Payload/SignalProbe.app/SignalProbe").external_attr >> 16) & 0o111
    report["safe_packaging_verified"] = True
    report["synthetic_ipa_sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
    report["scope"] = "offline native Windows code signing and packaging; no Apple-issued provisioning, pairing, or installation"
    (args.output / "signing-results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    # Private synthetic key stays in ignored CI work directory, never in artifacts.


if __name__ == "__main__": main()
