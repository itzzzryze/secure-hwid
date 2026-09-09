<div align="center">

# secure-hwid

simple hwid profiler for security purposes

[![release](assets/badges/release.svg)](https://github.com/itzzzryze/secure-hwid/releases/latest)
[![platform](assets/badges/platform.svg)](#usage)
[![language](assets/badges/language.svg)](#building)
[![encryption](assets/badges/encryption.svg)](#report-format)

<img src="assets/ui-states.png" width="960" alt="secure-hwid gathering, completion and error states" />

<sub>UI states rendered with the application drawing code.</sub>

</div>

## method

secure-hwid collects hardware identifiers through Windows device and firmware interfaces. A deterministic SHA-256 digest identifies the collected configuration.

| Component | Collection method | Requirement |
| --- | --- | --- |
| NVRAM | `NtEnumerateSystemEnvironmentValuesEx`; selected firmware variables | Required |
| SMBIOS | `GetSystemFirmwareTable('RSMB')`; Type 1 system UUID and Type 2 baseboard serials | Valid values when present |
| GPU PCI ID | [SetupAPI](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinstanceidw); present PCI display devices | When available |
| NVIDIA UUID | [NVML](https://docs.nvidia.com/deploy/nvml-api/group__nvmlDeviceQueries.html); `nvmlDeviceGetUUID` | When available |
| TPM fingerprint | Platform Crypto Provider; SHA-256 of the endorsement public key | When available |
| C: storage serial | Volume disk extents, then [StorageDeviceProperty](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_device_descriptor) on the backing disk | Required |
| C: NVMe serial | Protocol-specific storage query; NVMe Identify Controller | When exposed by the storage stack |

The firmware input consists of `OfflineUniqueIDEKPub`, `OfflineUniqueIDEKPubCRC`, `OfflineUniqueIDRandomSeed`, `OfflineUniqueIDRandomSeedCRC`, and `UnlockIDCopy`. At least one nonempty value must exist. Vendor GUIDs and variable names identify each value; record padding is excluded.

Let `E_v` encode sorted fields as `HWID || version-byte`, followed by length-prefixed names and values. Lengths are unsigned 32-bit little-endian integers.

```text
N = SHA256(E_2(firmware values))
HWID = Base64(SHA256(E_3(N, GPU/TPM values, C: serial, SMBIOS values, C: NVMe serial)))
```

GPU values are sorted and deduplicated. The C: mapping and storage serial are read twice. Missing serials and C: volumes spanning distinct disks stop collection. Other drives are excluded.

SMBIOS UUID byte order follows the reported SMBIOS version. Zero/FF UUIDs and placeholder board serials are omitted; board serials are sorted and deduplicated. SMBIOS and NVMe reads must repeat consistently. Unsupported NVMe queries produce `null`, including storage stacks that hide the controller. No other disk is substituted. Malformed responses stop collection.

`hwid_version: 3` identifies this primary format. Its hashes differ from version 2, including when the added sources are unavailable. Available SMBIOS and NVMe values are primary hash inputs. Supporting identifiers and backend validation are not implemented.

## report format

The decrypted JSON contains `hwid_version`, `hwid`, `nvram`, `tpm_fingerprint`, `gpu_serial_source`, `gpu_serials`, `gpu_uuids`, `smbios.system_uuid`, `smbios.baseboard_serials`, `c_drive.storage_query_property_serial`, and `c_drive.nvme_identify_serial`. `gpu_serials` contains PCI device-instance IDs. Unavailable optional scalar values are `null`; unavailable array values are empty.

UTF-8 JSON is encrypted with AES-256-GCM. Key derivation uses PBKDF2-HMAC-SHA256 with 600,000 iterations and a random 16-byte salt. Each report has a random 12-byte nonce and a 16-byte authentication tag.

```text
Base64("HWEN" || 0x01 || salt[16] || nonce[12] || tag[16] || ciphertext)
```

The first 33 bytes are authenticated as AAD. Discord receives the ciphertext, raw AES key, nonce, tag in hex and Base64, and AAD in one message. Ciphertext over 1,000 characters uses numbered fields; concatenate them in order. Reports above 4,800 Base64 characters are rejected before delivery to fit [Discord's embed limits](https://docs.discord.com/developers/resources/message#embed-limits).

The client writes no report files and sends no attachments. Delivery uses HTTPS; `done` requires Discord confirmation. Anyone with access to the message can decrypt the report. AES derivation remains in the client for this version.

## usage

Download [HWID.exe](https://github.com/itzzzryze/secure-hwid/releases/latest/download/HWID.exe). Open PowerShell as administrator in that folder:

```powershell
$env:SECURE_HWID_WEBHOOK = Read-Host 'Discord webhook URL'
.\HWID.exe
```

Use a standard `https://discord.com/api/webhooks/` URL without query parameters. The destination is read at runtime. Missing configuration stops collection. The executable is unsigned.

The customer interface shows collection, delivery and completion. It has no report viewer, export or decryption controls. After a delivery timeout, check Discord before retrying; the message may already exist.

## limits

PCI IDs depend on device configuration. RAID controllers may report a logical disk serial. Hardware changes or unavailable sources can change the HWID. Hashing provides no proof of hardware authenticity.

AES key buffers use locked pages, scoped access and [CryptProtectMemory](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory). Sensitive buffers are erased after use. The build enables CFG, ASLR, DEP and stack checks. Privileged debuggers and modified kernels can still inspect the process.

## building

Requires Visual Studio 2022 Community with the C++ desktop workload, installed at the standard path.

```powershell
.\build.bat
.\test.bat
.\test_delivery.bat
```

`build.bat` produces only `HWID.exe`. Decryption helpers are isolated in `test_support.h` for in-memory verification. Tests cover parser bounds, disk selection, hash composition, AES-GCM vectors, tamper rejection, chunked messages and webhook configuration. Delivery tests run locally; `--send-test` sends a synthetic report. `probe.bat` and `probe_hardware.bat` check live GPU and C: reads without printing identifiers.

## API references

- [GetSystemFirmwareTable](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable): raw SMBIOS tables.
- [Windows NVMe protocol queries](https://learn.microsoft.com/en-us/windows/win32/fileio/working-with-nvme-devices): Identify Controller through `IOCTL_STORAGE_QUERY_PROPERTY`.
- [SetupDiGetDeviceInstanceIdW](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinstanceidw): PCI device-instance IDs.
- [NVIDIA NVML device queries](https://docs.nvidia.com/deploy/nvml-api/group__nvmlDeviceQueries.html): GPU UUIDs.
- [Microsoft Platform Crypto Provider sample](https://github.com/microsoft/TSS.MSR/blob/main/PCPTool.v11/exe/SDKSample.cpp): TPM endorsement public key access.
- [IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extents): C: volume-to-disk mapping.
- [IOCTL_STORAGE_QUERY_PROPERTY](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_storage_query_property) and [STORAGE_DEVICE_DESCRIPTOR](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_device_descriptor): storage serial queries.
- [CNG authenticated cipher parameters](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info): AES-GCM nonce, tag and AAD.
- [BCryptDeriveKeyPBKDF2](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekeypbkdf2): key derivation.
- [CryptProtectMemory](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory), [VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock) and [SecureZeroMemory](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-securezeromemory): sensitive memory handling.
- [Discord webhook execution](https://docs.discord.com/developers/resources/webhook#execute-webhook) and [embed limits](https://docs.discord.com/developers/resources/message#embed-limits): report delivery.
