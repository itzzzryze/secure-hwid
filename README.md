# secure-hwid

simple hwid profiler for security purposes

Windows x64 hardware identity profiler with encrypted JSON reports. It combines
firmware identity, PCI GPU device IDs, NVIDIA GPU UUIDs, an optional TPM fingerprint,
and the storage serial for the disk backing C: into a SHA-256 HWID.

## Run the precompiled release

Download and extract `secure-hwid-v1.0.0-windows-x64.zip` from Releases.
Open PowerShell as administrator in the extracted folder, configure your own
Discord webhook URL for that terminal session, and start the profiler:

```powershell
$env:SECURE_HWID_WEBHOOK = Read-Host 'Discord webhook URL'
.\HWID.exe
```

Use an ordinary webhook URL starting with `https://discord.com/api/webhooks/`,
without query parameters. The program adds `wait=true` itself. The release and
source contain no configured webhook destination. A missing or invalid setting
shows `Set SECURE_HWID_WEBHOOK` and stops before collecting hardware information.
The release also includes `HWID-decrypt.exe`, which does not require a webhook
or administrator rights. These are unsigned Windows x64 executables.

Only run the profiler on computers you own or are authorized to profile. Running
it with a configured webhook sends the hardware report and decryption parameters
to that Discord destination.

Run `HWID.exe` as administrator. It gathers the identifiers, encrypts the JSON,
and sends the report to the configured Discord webhook. The UI shows
`gathering ...`, then `sending to Discord ...`, then `done` after Discord confirms
message creation. No new Desktop files, clipboard content, or local report logs
are created. Failed collection, encryption or delivery stays visible with a retry
control.

Run the new build to receive a fresh Discord report. Existing encrypted files
still decrypt to the snapshot collected by the build that created them.

## Discord delivery

The formatted message contains Base64 ciphertext and the actual 256-bit AES key
in hexadecimal, a 12-byte nonce, the authentication tag in both hexadecimal and
Base64, and the authenticated header (AAD). Use the AES key directly, without
hashing it again. Decrypting the
ciphertext with AES-256-GCM requires all four parameters. The plaintext encoding
is UTF-8. The webhook posts these details; it does not execute a decryption bot.
Anyone with access to the message has enough information to decrypt the report.

`encrypted.txt` is attached for compatibility with `HWID-decrypt.exe`. Larger
ciphertexts are attached as `ciphertext.txt` instead of exceeding Discord's embed
field limits. Attachments and message bodies are generated in memory; the app
does not write exported keys/nonces or reports to local files or print them.

Delivery uses HTTPS with certificate verification, disabled redirects, bounded
network timeouts, and `wait=true`. `done` requires HTTP 200 from Discord. There
are no automatic retries. After a timeout, Discord may already have received the
message; check the channel before using Try again. Closing cancels work before
the POST starts, but cannot retract a request already sent.

`webhook_config.h` reads `SECURE_HWID_WEBHOOK` at runtime and validates the host
and path. Never commit a real webhook URL, local credential file or a binary
compiled with a private destination. `test_delivery.bat` verifies the
message and decryption parameters locally without printing them or making a
network request. `test_delivery.bat --send-test` additionally posts one explicitly
labelled synthetic test report without hardware identifiers.

## Encrypted JSON

The block decrypts to indented UTF-8 JSON with these fields:

```json
{
  "hwid": "Base64 of the 32-byte combined SHA-256 digest",
  "nvram": "64-character hexadecimal NVRAM serial",
  "tpm_fingerprint": "64-character hexadecimal fingerprint, or null",
  "gpu_serial_source": "pci_device_instance_id",
  "gpu_serials": [
    "PCI\\VEN_10DE&DEV_1234&SUBSYS_12345678&REV_A1\\4&EXAMPLE&0&0019"
  ],
  "gpu_uuids": [
    "GPU-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  ],
  "c_drive": {
    "volume": "C:",
    "storage_query_property_serial": "driver-returned storage serial"
  }
}
```

`nvram` is the NVRAM serial derived from the firmware variables, as in the
previous app. `tpm_fingerprint` is JSON `null` when unavailable. `gpu_serials` now
contains PCI device-instance IDs, matching the "PCI Device" row in your spoofed
tool; `gpu_serial_source` identifies the type explicitly. These are Windows PnP
identifiers, not manufacturer board serials. Present PCI display devices from
NVIDIA, AMD and Intel are supported; an empty array means none were found.
`gpu_uuids` contains
the NVIDIA UUIDs, matching the GPU "GUID Serial" in your
[spoofed tool](https://github.com/itzzzryze/spoofed/blob/4ecfc3ec89aa9f5a28ebc190a0a236aefe615182/SystemInfoGatherer.cs).
That tool uses `nvidia-smi --query-gpu=uuid`; this C++ app obtains the same value
directly with `nvmlDeviceGetUUID`. UUID collection remains separate from PCI IDs.
`c_drive.storage_query_property_serial` is the serial returned by
`IOCTL_STORAGE_QUERY_PROPERTY / StorageDeviceProperty` for the disk backing C:.
It is required in production reports. Missing/invalid serials or ambiguous C:
disk mappings stop collection with `C: drive identity unavailable` instead of
substituting another drive. Replacing board serials with PCI IDs and adding the
C: serial changes the combined HWID from earlier builds. Old reports still decrypt.

Encryption uses AES-256-GCM, PBKDF2-HMAC-SHA256 with 600,000 iterations, a random
16-byte salt, a random 12-byte nonce, and a 16-byte authentication tag. A new
salt and nonce are generated for each report, so the encrypted text varies even when
the underlying identity is unchanged. Modified blocks fail authentication.

The text is standard Base64 of: `HWEN` + version byte `0x01` + salt (16 bytes) +
nonce (12 bytes) + tag (16 bytes) + ciphertext. The first 33 bytes are authenticated
as additional data. The ciphertext is the UTF-8 JSON, without a BOM.

Download `encrypted.txt` from the Discord message, then run
`HWID-decrypt.exe "C:\path\to\encrypted.txt"` to print the decrypted JSON.
Redirect its output to save a JSON file. It does not require administrator rights.
It reads the input without changing it, and rejects malformed or modified blocks.

## Composite identity, version 2

The required base is the existing firmware variable family:
`OfflineUniqueIDEKPub`, `OfflineUniqueIDEKPubCRC`, `OfflineUniqueIDRandomSeed`,
`OfflineUniqueIDRandomSeedCRC`, and `UnlockIDCopy`. At least one nonempty value
must exist. Only actual value bytes are included, excluding record padding.
Names are qualified with vendor GUID bytes, sorted, and hashed to a NVRAM digest.

The final SHA-256 combines that digest with available hardware sources:

- PCI GPU device-instance IDs are retrieved through SetupAPI from present devices
  in the display class. This is the same identity exposed by
  `Win32_VideoController.PNPDeviceID` in spoofed, without requiring a WMI query.
  Only `PCI\` devices are included. IDs are validated, uppercased, sorted and
  deduplicated. No manual registry reads are used.
- NVIDIA GPU UUIDs are queried through NVML, NVIDIA's management interface to its
  kernel-mode display driver. The elevated app loads `nvml.dll`
  only from an absolute Windows System32 path or NVIDIA's fixed Program Files
  installation path. It resolves both current and legacy NVML entry points,
  enumerates each driver-visible device and queries its UUID.
  Repeated successful reads must match. UUIDs must match NVIDIA's GPU
  UUID format and cannot be all zero. Valid values are sorted and deduplicated.
  The UUID is required for every enumerated NVIDIA GPU when NVML is available.
  AMD-only systems skip the NVIDIA UUID source, but still collect PCI IDs.
- C: is opened as `\\.\C:` and mapped with `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`.
  Only the resulting physical disk is opened. Multiple extents on one disk are
  supported; C: spanning distinct disks is rejected because there is no single
  main disk. The app never assumes disk 0 and never scans other physical drives.
  It sends `IOCTL_STORAGE_QUERY_PROPERTY` with `StorageDeviceProperty` and
  `PropertyStandardQuery`, then reads the descriptor's `SerialNumberOffset`, as
  in [spoofed's NativeDiskQuery](https://github.com/itzzzryze/spoofed/blob/4ecfc3ec89aa9f5a28ebc190a0a236aefe615182/NativeDiskQuery.cs).
  Buffer sizes, offsets and string termination are checked; surrounding whitespace
  is trimmed, and empty/zero/placeholder values are rejected. No byte swapping,
  fabricated serials, WMI fallback or registry fallback is used. A second serial
  query and C: mapping query must agree before the value is accepted. RAID or
  virtual storage may expose the controller's logical disk identity.
- SHA-256 of the TPM endorsement public key returned by the Microsoft Platform
  Crypto Provider. Missing, disabled or inaccessible TPM keys are skipped.

Each hash input starts with the five bytes `HWID` + `0x02`, followed by sorted
fields. Each field is a 32-bit little-endian name length, ASCII name, 32-bit
little-endian value length, and raw value. The final fields are `nvram/sha256`,
`gpu/pci/0` (and subsequent PCI indices), `gpu/uuid/0` (and subsequent UUID
indices), `tpm/ekpub-sha256`, and `storage/c/serial`. The C: serial and GPU PCI
IDs are hash inputs, not just additional JSON fields. The volume label and source
labels are descriptive metadata, not hash inputs.
Digests used as component values are raw 32-byte values. The final combined
digest is represented as Base64 inside the encrypted JSON.

On systems without PCI display hardware, the PCI component is omitted; without
NVIDIA/NVML, UUIDs are omitted. The TPM
component is omitted when the platform provider exposes no endorsement public
key. Production reports require NVRAM and C: storage, with PCI/UUID/TPM components
included when available. A change
in hardware, firmware identity values, or availability of a source can change
the HWID. SHA-256 is deterministic; it does not make source identifiers unique.
No software-readable HWID can be made unspoofable against an administrator or a
modified kernel/firmware. PCI instance IDs can change with topology or device
configuration and are not globally unique manufacturer serials. This implementation
uses the device, vendor and platform interfaces described above. Repeated
reads detect inconsistent results; they do not prove authenticity or defeat hooks.
Version 2 intentionally generates different IDs from the old NVRAM-only app.

## Memory protection

AES keys use dedicated, non-executable, `VirtualLock`-locked allocations. Idle
keys are encrypted with `CryptProtectMemory(CRYPTPROTECTMEMORY_SAME_PROCESS)` and
opened only for a scoped operation. The CNG key-object buffer and the encryption
input buffer are also locked. Failure to allocate, lock or protect these buffers
stops the operation. Buffers are cleared with `SecureZeroMemory` before release.

The main worker clears its firmware buffer, collected value buffers and JSON on
both success and exceptions. Discord request bodies are move-only and erased on
destruction; the exported AES key is appended directly into a reserved message
buffer, avoiding separate hexadecimal key strings and key-bearing reallocations.
Both release executables enable compiler stack checks, Control Flow Guard,
ASLR with high-entropy addressing, and DEP.

This protects selected sensitive data in memory, not the entire executable.
Code is not virtualized or packed, and debuggers are not blocked. A privileged
debugger, injected code or modified kernel can still inspect a running process.
Plaintext and keys must exist briefly while cryptography and HTTPS delivery use
them; the Discord message deliberately includes the decryption key. Standard
library, OS and TLS internals may have additional transient copies. These measures
reduce exposure and leftover buffers; they do not provide an unreadable-memory
guarantee or the protection of a separate hardware trust boundary.

## Animation

The square card grows from 0.1 to 1.0 around its center over 920 ms, then shrinks
back to 0.1 and fades on exit over 620 ms. Text, spinner and controls scale together.
GDI+ renders directly at the current scale into a persistent premultiplied surface,
without allocating or resampling a bitmap on every frame. The spinner settles into the
result icon at the same position, with eased text transitions and progress driven
by collection/encryption/delivery stages. Frames synchronize with the desktop compositor.
Windows' animation preference suppresses scaling, slide, spinning and icon stroke motion.
The window can be dragged by its upper area and closed with its close control or Escape.
Errors remain visible; use Try again or Enter to retry.

## Build and verification

`build.bat` requires Visual Studio 2022 Community with the C++ desktop workload.
`test.bat` checks the SHA-256 known-answer vector, firmware entry bounds, last
entry handling, padding independence, ordering, optional combinations and the
required NVRAM base, using synthetic data. It also checks an AES-256-GCM known-answer
vector, encrypted JSON roundtrip, Base64, fresh randomness, optional fields,
JSON escaping, and rejection of tampered salt, nonce, tag and ciphertext. Added
checks cover PCI normalization/order, C: mapping to a nonzero disk number,
multi-disk/truncated mappings, invalid storage offsets/strings, new fields in
the hash and JSON, protected key reuse, and cleanup/invalidation after exceptions.
`preview.bat` renders all three UI states and a scale timeline, and checks GDI
resource counts across 300 scaled frames.
The app never displays hardware identifiers; the decryption utility explicitly
prints the requested plaintext JSON. On this RTX 5070, NVML's physical serial is
the placeholder `0`; the app now uses the requested PCI ID and keeps the valid
GPU UUID. Live PCI and C: serial collection were compared with independent Windows
queries and preserved through encrypted JSON roundtrip. C: mapped to PhysicalDrive0
on the development machine, but this number is discovered at runtime.

`probe.bat` is a local NVIDIA diagnostic. It prints DLL/export/API status and
whether each serial is available, but never prints the serial value. It also
runs the exact collector used by `HWID.exe`, compares its UUIDs with direct driver
reads, and tests encrypted JSON roundtrip using synthetic NVRAM and the live GPU.
`probe_hardware.bat` validates live PCI IDs and C: storage without sending a report
or printing identifiers. Optional `HWID_EXPECTED_PCI` (newline-separated IDs),
`HWID_EXPECTED_C_DISK` and `HWID_EXPECTED_C_SERIAL` environment variables allow
comparison with independently collected values. These variables are used only by
the diagnostic executable, never by the production collector.

API references: [NVIDIA NVML serial query](https://docs.nvidia.com/deploy/nvml-api/group__nvmlDeviceQueries.html)
and [Microsoft Platform Crypto Provider sample](https://github.com/microsoft/TSS.MSR/blob/main/PCPTool.v11/exe/SDKSample.cpp).
Encryption uses [Windows CNG authenticated cipher APIs](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info).
Device queries use [SetupAPI instance IDs](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinstanceidw),
[volume disk extents](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extents),
and [storage device descriptors](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_device_descriptor).
Memory protection uses [CryptProtectMemory](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory)
and [VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock).
