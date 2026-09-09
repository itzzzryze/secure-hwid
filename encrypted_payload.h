#pragma once
#include "identity.h"
#include "secure_memory.h"
#include <wincrypt.h>
#include <array>
#pragma comment(lib, "crypt32.lib")

namespace payload {
using identity::Bytes;
constexpr size_t MaxPayload = 1024 * 1024;
constexpr ULONGLONG KdfIterations = 600000;
inline void Check(NTSTATUS status, const char* message) {
    if (status < 0) throw std::runtime_error(message);
}
struct Algorithm {
    BCRYPT_ALG_HANDLE handle = nullptr;
    Algorithm(LPCWSTR name, ULONG flags = 0) {
        Check(BCryptOpenAlgorithmProvider(&handle, name, nullptr, flags), "encryption setup failed");
    }
    ~Algorithm() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
    Algorithm(const Algorithm&) = delete;
    Algorithm& operator=(const Algorithm&) = delete;
};
struct Key {
    BCRYPT_KEY_HANDLE handle = nullptr;
    Key() = default;
    ~Key() { if (handle) BCryptDestroyKey(handle); }
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
};
using Secret = secure_memory::Secret;
inline std::string Base64(const Bytes& data) {
    DWORD size = 0;
    if (data.empty()) return "";
    if (data.size() > MaxPayload + 64 || !CryptBinaryToStringA(data.data(), (DWORD)data.size(),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &size)) throw std::runtime_error("Base64 encoding failed");
    std::string out(size, '\0');
    if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
        &out[0], &size)) throw std::runtime_error("Base64 encoding failed");
    out.resize(size); // Excludes the terminating NUL on the second call.
    return out;
}
inline Bytes Unbase64(const std::string& text) {
    if (text.size() > MaxPayload * 2) throw std::runtime_error("encrypted block too large");
    std::string clean;
    for (char c : text) if (c != '\r' && c != '\n' && c != ' ' && c != '\t') clean += c;
    DWORD size = 0;
    if (clean.empty() || !CryptStringToBinaryA(clean.data(), (DWORD)clean.size(), CRYPT_STRING_BASE64,
        nullptr, &size, nullptr, nullptr)) throw std::runtime_error("invalid Base64 block");
    Bytes out(size);
    if (!CryptStringToBinaryA(clean.data(), (DWORD)clean.size(), CRYPT_STRING_BASE64,
        out.data(), &size, nullptr, nullptr)) throw std::runtime_error("invalid Base64 block");
    out.resize(size);
    if (Base64(out) != clean) throw std::runtime_error("invalid Base64 block");
    return out;
}
inline std::string Quote(const std::string& value) {
    const char* digits = "0123456789abcdef";
    std::string out = "\"";
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c < 32 || c >= 127) { out += "\\u00"; out += digits[c >> 4]; out += digits[c & 15]; }
        else out += c;
    }
    return out + '"';
}
inline std::string Json(const identity::Fields& nvram, const identity::Fields& optional) {
    auto combined = identity::CombinedDigest(nvram, optional);
    auto nvramSerial = identity::Sha256(identity::Encode(nvram));
    std::string out = "{\n  \"hwid\": " + Quote(Base64(combined)) +
        ",\n  \"nvram\": " + Quote(identity::Hex(nvramSerial.data(), nvramSerial.size())) +
        ",\n  \"tpm_fingerprint\": ";
    auto tpm = optional.find("tpm/ekpub-sha256");
    out += tpm == optional.end() ? "null" : Quote(identity::Hex(tpm->second.data(), tpm->second.size()));
    out += ",\n  \"gpu_serial_source\": \"pci_device_instance_id\",\n  \"gpu_serials\": [";
    bool first = true;
    for (const auto& field : optional) if (field.first.find("gpu/pci/") == 0) {
        out += first ? "\n    " : ",\n    ";
        out += Quote(std::string(field.second.begin(), field.second.end()));
        first = false;
    }
    out += first ? "]" : "\n  ]";
    out += ",\n  \"gpu_uuids\": [";
    first = true;
    for (const auto& field : optional) if (field.first.find("gpu/uuid/") == 0) {
        out += first ? "\n    " : ",\n    ";
        out += Quote(std::string(field.second.begin(), field.second.end()));
        first = false;
    }
    out += first ? "]" : "\n  ]";
    out += ",\n  \"c_drive\": {\n    \"volume\": \"C:\",\n    \"storage_query_property_serial\": ";
    auto storage = optional.find("storage/c/serial");
    out += storage == optional.end() ? "null" : Quote(std::string(storage->second.begin(), storage->second.end()));
    out += "\n  }\n}\n";
    return out;
}
inline void Derive(const unsigned char* salt, Secret& output) {
    Algorithm sha(BCRYPT_SHA256_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    unsigned char material[] = {99, 97, 116, 104, 97, 99, 107, 115};
    struct ClearMaterial { unsigned char* data; size_t size; ~ClearMaterial() { SecureZeroMemory(data, size); } } wipe{material, sizeof(material)};
    output.Set([&](unsigned char* bytes) {
        Check(BCryptDeriveKeyPBKDF2(sha.handle, material, sizeof(material),
            const_cast<PUCHAR>(salt), 16, KdfIterations, bytes, 32, 0), "encryption derivation failed");
    });
}
// AES-256-GCM primitive, kept separate for independent standard test vectors.
inline Bytes GcmData(bool encrypt, const unsigned char* keyBytes, const unsigned char* input, size_t inputSize,
                 const Bytes& nonce, const Bytes& aad, Bytes& tag) {
    if (inputSize > MaxPayload || nonce.size() != 12 || tag.size() != 16 || aad.size() > MaxPayload)
        throw std::runtime_error("invalid AES-GCM parameters");
    Algorithm aes(BCRYPT_AES_ALGORITHM);
    Check(BCryptSetProperty(aes.handle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0), "AES-GCM setup failed");
    DWORD objectSize = 0, returned = 0;
    Check(BCryptGetProperty(aes.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
        sizeof(objectSize), &returned, 0), "AES key storage setup failed");
    if (!objectSize || objectSize > 65536) throw std::runtime_error("invalid AES key storage size");
    secure_memory::LockedBuffer keyObject(objectSize);
    Key key; // Destroy the CNG handle before erasing/releasing its locked backing buffer.
    Check(BCryptGenerateSymmetricKey(aes.handle, &key.handle, keyObject.data(), objectSize,
        const_cast<PUCHAR>(keyBytes), 32, 0), "AES key setup failed");
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(nonce.data()); info.cbNonce = (ULONG)nonce.size();
    info.pbAuthData = const_cast<PUCHAR>(aad.data()); info.cbAuthData = (ULONG)aad.size();
    info.pbTag = tag.data(); info.cbTag = (ULONG)tag.size();
    Bytes output(inputSize);
    ULONG written = 0;
    NTSTATUS status = encrypt
        ? BCryptEncrypt(key.handle, const_cast<PUCHAR>(input), (ULONG)inputSize, &info,
            nullptr, 0, output.data(), (ULONG)output.size(), &written, 0)
        : BCryptDecrypt(key.handle, const_cast<PUCHAR>(input), (ULONG)inputSize, &info,
            nullptr, 0, output.data(), (ULONG)output.size(), &written, 0);
    if (status < 0) {
        SecureZeroMemory(output.data(), output.size());
        throw std::runtime_error(encrypt ? "encryption failed" : "invalid or modified encrypted block");
    }
    output.resize(written);
    return output;
}
inline Bytes Gcm(bool encrypt, const unsigned char* keyBytes, const Bytes& input,
                 const Bytes& nonce, const Bytes& aad, Bytes& tag) {
    return GcmData(encrypt, keyBytes, input.data(), input.size(), nonce, aad, tag);
}
inline std::string Encrypt(const std::string& json) {
    if (json.empty() || json.size() > MaxPayload) throw std::runtime_error("invalid payload size");
    Bytes header = {'H','W','E','N',1};
    header.resize(33); // Version + 16-byte salt + 12-byte nonce.
    Check(BCryptGenRandom(nullptr, header.data() + 5, 28, BCRYPT_USE_SYSTEM_PREFERRED_RNG), "random generation failed");
    Secret key;
    Derive(header.data() + 5, key);
    Bytes tag(16);
    secure_memory::LockedBuffer plaintext(json.size());
    memcpy(plaintext.data(), json.data(), json.size());
    auto cipher = key.Use([&](unsigned char* bytes) {
        return GcmData(true, bytes, plaintext.data(), plaintext.size(),
            Bytes(header.begin() + 21, header.end()), header, tag);
    });
    header.insert(header.end(), tag.begin(), tag.end());
    header.insert(header.end(), cipher.begin(), cipher.end());
    return Base64(header);
}
}
