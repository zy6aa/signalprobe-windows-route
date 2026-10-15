# SignalProbe native Windows route investigation

Credential-free research harness. Existing app commit and IPA SHA are frozen in `revisions.json`.
No app rebuild, real Apple credentials, pairing, device installation or local system changes.

Manual-only Actions runs on standard `windows-2025` runners in this public repository.
Three independent Rust source candidates and pinned pymobiledevice3 are compiled/tested.
Candidate sources are fetched by exact SHA and unmodified except for added independent test/example code.
No failed checks are suppressed. Known functional defects are recorded as findings rather than
misreported as successful signing or hardware operation. All physical-device behavior remains untested.

Synthetic signing artifacts are **NOT INSTALLABLE** and contain no real Apple-issued certificate/profile.
The independently generated key stays in temporary CI work, outside uploaded evidence.
Artifacts include source archives, upstream licenses, locked dependency metadata, toolchain versions,
CLI binaries, test logs, signatures and hashes. Inspect licenses before any redistribution:
Impactor is MIT, bundled apple-codesign is MPL-2.0, pymobiledevice3 is GPL-3.0-or-later;
transitive dependencies have their own licenses recorded in inventories/source archives.

Do not give credentials to an unmerged fork merely because it builds. Security and real-device
readiness are reported separately. Do not run these tools locally until the investigation's final
safe-test instructions have been reviewed and the specific local action is authorized.
