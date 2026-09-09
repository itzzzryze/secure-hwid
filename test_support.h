#pragma once
#include "encrypted_payload.h"

// In-memory decryption for tests and diagnostic roundtrips.
namespace payload {
inline std::string Decrypt(const std::string& encoded) {
    auto block = Unbase64(encoded);
    const unsigned char magic[] = {'H','W','E','N',1};
    if (block.size() <= 49 || block.size() > MaxPayload + 49 || memcmp(block.data(), magic, 5))
        throw std::runtime_error("unsupported or truncated encrypted block");
    Secret key;
    Derive(block.data() + 5, key);
    Bytes tag(block.begin() + 33, block.begin() + 49);
    auto plain = key.Use([&](unsigned char* bytes) {
        return Gcm(false, bytes, Bytes(block.begin() + 49, block.end()),
            Bytes(block.begin() + 21, block.begin() + 33), Bytes(block.begin(), block.begin() + 33), tag);
    });
    secure_memory::WipeOnExit<Bytes> wipe(plain);
    std::string result(plain.begin(), plain.end());
    return result;
}
}
