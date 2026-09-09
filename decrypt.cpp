#define WIN32_LEAN_AND_MEAN
#include "encrypted_payload.h"
#include <iostream>
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) { std::cerr << "Usage: HWID-decrypt.exe <encrypted-file>\nPrints the decrypted JSON.\n"; return 2; }
    HANDLE file = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) { std::cerr << "Cannot open input file.\n"; return 1; }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > payload::MaxPayload * 2) {
        CloseHandle(file); std::cerr << "Invalid input size.\n"; return 1;
    }
    std::string encoded((size_t)size.QuadPart, '\0');
    DWORD read = 0;
    bool ok = ReadFile(file, &encoded[0], (DWORD)encoded.size(), &read, nullptr) && read == encoded.size();
    CloseHandle(file);
    if (!ok) { std::cerr << "Cannot read input file.\n"; return 1; }
    try {
        auto json = payload::Decrypt(encoded);
        secure_memory::WipeOnExit<std::string> wipeJson(json);
        std::cout << json;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return std::cout.good() ? 0 : 1;
}
