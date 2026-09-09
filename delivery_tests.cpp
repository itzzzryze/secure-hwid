#define WIN32_LEAN_AND_MEAN
#include "discord_delivery.h"
#include <cassert>
#include <iostream>
static std::string CodeField(const std::string& message, const std::string& name) {
    auto start = message.find("\"name\":\"" + name + "\"");
    assert(start != std::string::npos);
    start = message.find("\\u000a", start);
    assert(start != std::string::npos);
    start += 6;
    auto end = message.find("\\u000a", start);
    assert(end != std::string::npos);
    return message.substr(start, end - start);
}
static identity::Bytes Unhex(const std::string& text) {
    assert(text.size() % 2 == 0);
    identity::Bytes result;
    for (size_t i = 0; i < text.size(); i += 2)
        result.push_back(static_cast<unsigned char>(std::stoul(text.substr(i, 2), nullptr, 16)));
    return result;
}
static std::string PlainCodeField(const std::string& message, const std::string& name) {
    auto start = message.find("\"name\":\"" + name + "\"");
    assert(start != std::string::npos);
    start = message.find("\\u000a", start) + 6;
    auto end = message.find("\\u000a", start);
    assert(end != std::string::npos);
    return message.substr(start, end - start);
}
int main(int argc, char** argv) {
    try {
        const std::string json = "{\n  \"test\": true,\n  \"message\": \"Synthetic delivery test; no hardware identifiers\"\n}\n";
        auto encrypted = payload::Encrypt(json);
        auto message = delivery::Compose(encrypted, true);
        auto key = Unhex(CodeField(message.body, "AES key (hex - use directly, do not hash)"));
        auto nonce = Unhex(CodeField(message.body, "IV / nonce (hex)"));
        auto tag = Unhex(CodeField(message.body, "Authentication tag (hex)"));
        assert(PlainCodeField(message.body, "Authentication tag (Base64)") == payload::Base64(tag));
        auto aad = Unhex(CodeField(message.body, "Additional authenticated data / AAD (hex)"));
        auto cipher = payload::Unbase64(CodeField(message.body, "Ciphertext (Base64)"));
        assert(key.size() == 32 && nonce.size() == 12 && tag.size() == 16 && aad.size() == 33);
        auto plain = payload::Gcm(false, key.data(), cipher, nonce, aad, tag);
        assert(std::string(plain.begin(), plain.end()) == json);
        assert(message.body.find(encrypted) != std::string::npos);
        assert(message.body.find("\"allowed_mentions\":{\"parse\":[]}") != std::string::npos);
        auto large = delivery::Compose(payload::Encrypt(std::string(8000, 'x')), true);
        assert(large.body.find("filename=\"ciphertext.txt\"") != std::string::npos);
        std::atomic_bool cancelled{true};
        bool blocked = false;
        try { delivery::Send(encrypted, cancelled, true); } catch (...) { blocked = true; }
        assert(blocked);
        SecureZeroMemory(key.data(), key.size());
        std::cout << "PASS: message parameters decrypt correctly; attachments, oversized payload and cancellation verified\n";
        if (argc == 2 && std::string(argv[1]) == "--send-test") {
            std::atomic_bool cancel{false};
            delivery::Send(encrypted, cancel, true);
            std::cout << "PASS: Discord confirmed the synthetic test message (HTTP 200)\n";
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
