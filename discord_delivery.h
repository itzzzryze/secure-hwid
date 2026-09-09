#pragma once
#include "encrypted_payload.h"
#include "webhook_config.h"
#include <winhttp.h>
#include <atomic>
#pragma comment(lib, "winhttp.lib")

namespace delivery {
struct RequestBody {
    std::wstring contentType;
    std::string body;
    RequestBody() = default;
    RequestBody(const RequestBody&) = delete;
    RequestBody& operator=(const RequestBody&) = delete;
    RequestBody(RequestBody&& other) noexcept : contentType(std::move(other.contentType)), body(std::move(other.body)) {}
    ~RequestBody() { if (!body.empty()) SecureZeroMemory(&body[0], body.size()); }
};
inline std::string Field(const std::string& name, const std::string& value) {
    return "{\"name\":" + payload::Quote(name) + ",\"value\":" + payload::Quote(value) + ",\"inline\":false}";
}
inline RequestBody Compose(const std::string& encrypted, bool test = false) {
    auto block = payload::Unbase64(encrypted);
    const unsigned char magic[] = {'H','W','E','N',1};
    if (block.size() <= 49 || memcmp(block.data(), magic, 5)) throw std::runtime_error("invalid encrypted report");
    payload::Secret key;
    payload::Derive(block.data() + 5, key);
    std::string cipher = payload::Base64(identity::Bytes(block.begin() + 49, block.end()));
    std::string json = "{\"allowed_mentions\":{\"parse\":[]},\"embeds\":[{\"title\":" +
        payload::Quote(test ? "HWID delivery test - synthetic data" : "HWID report") +
        ",\"color\":13162723,\"description\":\"Encrypted UTF-8 JSON. All decryption parameters are below. The attached encrypted.txt is compatible with HWID-decrypt.exe.\",\"fields\":[";
    secure_memory::WipeOnExit<std::string> wipeJson(json);
    json.reserve(8192); // Reserve before adding secrets, avoiding stale key copies in reallocated buffers.
    json += Field("Encryption", "AES-256-GCM | UTF-8 JSON | Base64 ciphertext");
    json += "," + Field("Ciphertext (Base64)", cipher.size() <= 1000 ? "```\n" + cipher + "\n```" : "See ciphertext.txt attachment.");
    json += ",{\"name\":\"AES key (hex - use directly, do not hash)\",\"value\":\"```\\u000a";
    key.Use([&](unsigned char* bytes) {
        const char* digits = "0123456789abcdef";
        for (size_t i = 0; i < 32; ++i) { json += digits[bytes[i] >> 4]; json += digits[bytes[i] & 15]; }
        return true;
    });
    json += "\\u000a```\",\"inline\":false}";
    json += "," + Field("IV / nonce (hex)", "```\n" + identity::Hex(block.data() + 21, 12) + "\n```");
    json += "," + Field("Authentication tag (hex)", "```\n" + identity::Hex(block.data() + 33, 16) + "\n```");
    json += "," + Field("Authentication tag (Base64)", "```\n" +
        payload::Base64(identity::Bytes(block.begin() + 33, block.begin() + 49)) + "\n```");
    json += "," + Field("Additional authenticated data / AAD (hex)", "```\n" + identity::Hex(block.data(), 33) + "\n```");
    json += "]}]}";
    unsigned char random[16]{};
    payload::Check(BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG), "delivery setup failed");
    std::string boundary = "hwid-" + identity::Hex(random, sizeof(random));
    RequestBody result;
    result.contentType = L"Content-Type: multipart/form-data; boundary=" + std::wstring(boundary.begin(), boundary.end()) + L"\r\n";
    result.body.reserve(json.size() + encrypted.size() + cipher.size() + 2048);
    result.body += "--" + boundary + "\r\nContent-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json\r\n\r\n";
    result.body += json;
    result.body += "\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=\"files[0]\"; filename=\"encrypted.txt\"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + encrypted;
    if (cipher.size() > 1000) result.body += "\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=\"files[1]\"; filename=\"ciphertext.txt\"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + cipher;
    result.body += "\r\n--" + boundary + "--\r\n";
    return result;
}
struct InternetHandle {
    HINTERNET value;
    explicit InternetHandle(HINTERNET handle) : value(handle) {
        if (!value) throw std::runtime_error("Discord connection failed");
    }
    ~InternetHandle() { WinHttpCloseHandle(value); }
    InternetHandle(const InternetHandle&) = delete;
    InternetHandle& operator=(const InternetHandle&) = delete;
};
// A single confirmed POST: no automatic retries that could duplicate reports.
inline void Send(const std::string& encrypted, const std::atomic_bool& cancel, bool test = false) {
    if (cancel) throw std::runtime_error("delivery cancelled");
    auto webhookPath = webhook_config::Path();
    secure_memory::WipeOnExit<std::wstring> wipePath(webhookPath);
    auto message = Compose(encrypted, test);
    InternetHandle session(WinHttpOpen(L"HWID/3", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!WinHttpSetTimeouts(session.value, 5000, 5000, 10000, 10000)) throw std::runtime_error("Discord connection setup failed");
    InternetHandle connection(WinHttpConnect(session.value, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0));
    InternetHandle request(WinHttpOpenRequest(connection.value, L"POST", webhookPath.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
    DWORD disabled = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES;
    if (!WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)))
        throw std::runtime_error("Discord connection setup failed");
    if (cancel) throw std::runtime_error("delivery cancelled");
    if (!WinHttpSendRequest(request.value, message.contentType.c_str(), (DWORD)-1,
        &message.body[0], (DWORD)message.body.size(), (DWORD)message.body.size(), 0) ||
        !WinHttpReceiveResponse(request.value, nullptr)) throw std::runtime_error("Discord delivery not confirmed");
    DWORD status = 0, size = sizeof(status);
    if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)) throw std::runtime_error("Discord delivery not confirmed");
    if (status == 429) throw std::runtime_error("Discord rate limited - retry later");
    if (status == 401 || status == 403 || status == 404) throw std::runtime_error("Discord webhook unavailable");
    if (status != 200) throw std::runtime_error("Discord rejected the report");
    // wait=true returns HTTP 200 only after message creation. Never print the response:
    // Discord echoes the embed, including the decryption material.
}
}
