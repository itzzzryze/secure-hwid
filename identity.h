#pragma once
#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <cctype>
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")

namespace identity {
using Bytes = std::vector<unsigned char>;
using Fields = std::map<std::string, Bytes>;
inline std::string Hex(const unsigned char* data, size_t size) {
    const char* digits = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < size; ++i) { out += digits[data[i] >> 4]; out += digits[data[i] & 15]; }
    return out;
}
inline Bytes Sha256(const Bytes& input) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))
        throw std::runtime_error("SHA-256 setup failed");
    Bytes digest(32);
    auto status = BCryptHash(alg, nullptr, 0, const_cast<PUCHAR>(input.data()),
        static_cast<ULONG>(input.size()), digest.data(), 32);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (status) throw std::runtime_error("SHA-256 failed");
    return digest;
}
inline void Length(Bytes& out, size_t size) {
    if (size > MAXDWORD) throw std::runtime_error("identity field too large");
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<unsigned char>(size >> (i * 8)));
}
inline Bytes Encode(const Fields& fields) {
    Bytes out = {'H','W','I','D',2};
    for (const auto& field : fields) {
        Length(out, field.first.size());
        out.insert(out.end(), field.first.begin(), field.first.end());
        Length(out, field.second.size());
        out.insert(out.end(), field.second.begin(), field.second.end());
    }
    return out;
}
inline DWORD Read32(const unsigned char* p) { DWORD value; memcpy(&value, p, 4); return value; }
// VARIABLE_NAME_AND_VALUE: next, value offset, value length, attributes, GUID, name.
inline Fields ParseNvram(const Bytes& buffer, size_t length) {
    if (length > buffer.size()) throw std::runtime_error("invalid NVRAM length");
    Fields fields;
    for (size_t offset = 0; offset < length;) {
        if (length - offset < 34) throw std::runtime_error("truncated NVRAM entry");
        const auto* p = buffer.data() + offset;
        DWORD next = Read32(p), dataOffset = Read32(p + 4), dataLength = Read32(p + 8);
        size_t entrySize = next ? next : length - offset;
        if (entrySize > length - offset || entrySize < 34 || dataOffset < 34 ||
            dataOffset > entrySize || dataLength > entrySize - dataOffset)
            throw std::runtime_error("invalid NVRAM entry bounds");
        std::wstring name;
        bool terminated = false;
        for (size_t pos = 32; pos + 1 < dataOffset; pos += 2) {
            wchar_t c; memcpy(&c, p + pos, 2);
            if (!c) { terminated = true; break; }
            name += c;
        }
        if (!terminated) throw std::runtime_error("unterminated NVRAM name");
        if (dataLength && (name == L"OfflineUniqueIDEKPub" || name == L"OfflineUniqueIDEKPubCRC" ||
            name == L"OfflineUniqueIDRandomSeed" || name == L"OfflineUniqueIDRandomSeedCRC" || name == L"UnlockIDCopy")) {
            std::string asciiName;
            for (wchar_t c : name) asciiName.push_back(static_cast<char>(c)); // Allowlisted ASCII names only.
            std::string key = "nvram/" + Hex(p + 16, 16) + "/" + asciiName;
            Bytes value(p + dataOffset, p + dataOffset + dataLength);
            auto existing = fields.find(key);
            if (existing != fields.end() && existing->second != value)
                throw std::runtime_error("conflicting NVRAM identity values");
            fields[key] = value;
        }
        if (!next) break;
        offset += next;
    }
    return fields;
}
inline std::string NormalizeGpuSerial(const char* value, size_t capacity);
inline void AddGpuSerials(Fields& fields, std::vector<std::string> serials) {
    for (auto& serial : serials) serial = NormalizeGpuSerial(serial.c_str(), serial.size() + 1);
    std::sort(serials.begin(), serials.end());
    serials.erase(std::unique(serials.begin(), serials.end()), serials.end());
    size_t index = 0;
    for (auto serial : serials) {
        if (serial.empty() || serial == "N/A" || serial == "Unknown" || serial == "Not Supported") continue;
        fields["gpu/nvidia/" + std::to_string(index++)] = Bytes(serial.begin(), serial.end());
    }
}
inline std::string NormalizeGpuSerial(const char* value, size_t capacity) {
    const char* end = static_cast<const char*>(memchr(value, 0, capacity));
    if (!end) throw std::runtime_error("NVIDIA returned an unterminated serial");
    std::string serial(value, end);
    while (!serial.empty() && std::isspace(static_cast<unsigned char>(serial.front()))) serial.erase(serial.begin());
    while (!serial.empty() && std::isspace(static_cast<unsigned char>(serial.back()))) serial.pop_back();
    std::string upper = serial;
    for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    if (serial.empty() || upper == "N/A" || upper == "UNKNOWN" || upper == "NOT SUPPORTED" ||
        upper == "[N/A]" || upper == "NONE" || upper == "NULL") return {};
    auto digits = upper.compare(0, 2, "0X") == 0 ? upper.substr(2) : upper;
    if (!digits.empty() && std::all_of(digits.begin(), digits.end(), [](char c) { return c == '0'; })) return {};
    if (serial.size() > 95) throw std::runtime_error("NVIDIA returned an invalid serial length");
    for (unsigned char c : serial)
        if (c < 0x21 || c > 0x7e) throw std::runtime_error("NVIDIA returned invalid serial characters");
    return serial;
}
inline bool IsGpuUuid(const std::string& value) {
    if (value.size() != 40 || value.compare(0, 4, "GPU-") != 0) return false;
    bool nonzero = false;
    for (size_t i = 4; i < value.size(); ++i) {
        if (i == 12 || i == 17 || i == 22 || i == 27) { if (value[i] != '-') return false; }
        else {
            if (!std::isxdigit(static_cast<unsigned char>(value[i]))) return false;
            nonzero |= value[i] != '0';
        }
    }
    return nonzero;
}
inline void ReadGpu(Fields& fields) {
    // NVML talks to NVIDIA's kernel-mode driver. Load it by absolute path so an
    // elevated process never searches its working directory for a replacement DLL.
    wchar_t systemDirectory[MAX_PATH]{};
    UINT systemLength = GetSystemDirectoryW(systemDirectory, MAX_PATH);
    HMODULE lib = nullptr;
    if (systemLength && systemLength < MAX_PATH) {
        std::wstring path(systemDirectory, systemLength);
        path += L"\\nvml.dll";
        lib = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    if (!lib) {
        PWSTR programFiles = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &programFiles))) {
            std::wstring path = std::wstring(programFiles) + L"\\NVIDIA Corporation\\NVSMI\\nvml.dll";
            CoTaskMemFree(programFiles);
            lib = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        }
    }
    if (!lib) return;
    using Init = int(__cdecl*)();
    using Count = int(__cdecl*)(unsigned int*);
    using Handle = int(__cdecl*)(unsigned int, void**);
    using Serial = int(__cdecl*)(void*, char*, unsigned int);
    auto init = reinterpret_cast<Init>(GetProcAddress(lib, "nvmlInit_v2"));
    if (!init) init = reinterpret_cast<Init>(GetProcAddress(lib, "nvmlInit"));
    auto shutdown = reinterpret_cast<Init>(GetProcAddress(lib, "nvmlShutdown"));
    auto count = reinterpret_cast<Count>(GetProcAddress(lib, "nvmlDeviceGetCount_v2"));
    if (!count) count = reinterpret_cast<Count>(GetProcAddress(lib, "nvmlDeviceGetCount"));
    auto handle = reinterpret_cast<Handle>(GetProcAddress(lib, "nvmlDeviceGetHandleByIndex_v2"));
    if (!handle) handle = reinterpret_cast<Handle>(GetProcAddress(lib, "nvmlDeviceGetHandleByIndex"));
    // NVML UUID, also exposed by nvidia-smi --query-gpu=uuid.
    auto uuid = reinterpret_cast<Serial>(GetProcAddress(lib, "nvmlDeviceGetUUID"));
    std::vector<std::string> uuids;
    try {
        if (!init || !shutdown || !count || !handle || !uuid)
            throw std::runtime_error("NVIDIA driver API is incomplete");
        int code = init();
        if (code != 0) throw std::runtime_error("NVIDIA driver initialization failed (NVML " + std::to_string(code) + ")");
        struct NvmlShutdown {
            Init fn;
            ~NvmlShutdown() { if (fn) fn(); }
        } cleanup{shutdown};
        unsigned int n = 0;
        code = count(&n);
        if (code != 0) throw std::runtime_error("NVIDIA device enumeration failed (NVML " + std::to_string(code) + ")");
        if (n > 64) throw std::runtime_error("NVIDIA returned an invalid device count");
        for (unsigned int i = 0; i < n; ++i) {
            void* device = nullptr;
            code = handle(i, &device);
            if (code != 0 || !device)
                throw std::runtime_error("NVIDIA device handle failed (NVML " + std::to_string(code) + ")");
            char uuidFirst[96]{}, uuidSecond[96]{};
            if (uuid(device, uuidFirst, sizeof(uuidFirst)) || uuid(device, uuidSecond, sizeof(uuidSecond)))
                throw std::runtime_error("NVIDIA UUID query failed");
            auto gpuUuid = NormalizeGpuSerial(uuidFirst, sizeof(uuidFirst));
            if (!IsGpuUuid(gpuUuid) || gpuUuid != NormalizeGpuSerial(uuidSecond, sizeof(uuidSecond)))
                throw std::runtime_error("NVIDIA returned an invalid or inconsistent UUID");
            for (auto& c : gpuUuid) if (c >= 'A' && c <= 'F') c += 'a' - 'A';
            uuids.push_back(gpuUuid);
            SecureZeroMemory(uuidFirst, sizeof(uuidFirst)); SecureZeroMemory(uuidSecond, sizeof(uuidSecond));
        }
        std::sort(uuids.begin(), uuids.end());
        uuids.erase(std::unique(uuids.begin(), uuids.end()), uuids.end());
        for (size_t i = 0; i < uuids.size(); ++i)
            fields["gpu/uuid/" + std::to_string(i)] = Bytes(uuids[i].begin(), uuids[i].end());
    } catch (...) {
        FreeLibrary(lib);
        throw;
    }
    FreeLibrary(lib);
}
inline void ReadTpm(Fields& fields) {
    NCRYPT_PROV_HANDLE provider = 0;
    if (NCryptOpenStorageProvider(&provider, MS_PLATFORM_CRYPTO_PROVIDER, 0)) return;
    // Read the existing public endorsement key; no private key export or persisted key creation.
    DWORD size = 0;
    Bytes key;
    if (!NCryptGetProperty(provider, NCRYPT_PCP_EKPUB_PROPERTY, nullptr, 0, &size, 0) && size && size <= 65536) {
        key.resize(size);
        if (NCryptGetProperty(provider, NCRYPT_PCP_EKPUB_PROPERTY, key.data(), size, &size, 0) || !size || size > key.size()) key.clear();
        else key.resize(size);
    }
    NCryptFreeObject(provider);
    if (!key.empty()) fields["tpm/ekpub-sha256"] = Sha256(key);
}
inline Bytes CombinedDigest(const Fields& nvram, const Fields& optional) {
    if (nvram.empty()) throw std::runtime_error("no NVRAM identity variables found");
    Fields parts = optional;
    parts["nvram/sha256"] = Sha256(Encode(nvram));
    auto encoded = Encode(parts);
    encoded[4] = 3; // Primary identity schema; firmware component encoding stays at version 2.
    return Sha256(encoded);
}
inline std::string Combine(const Fields& nvram, const Fields& optional) {
    auto hash = CombinedDigest(nvram, optional);
    return Hex(hash.data(), hash.size());
}
}
