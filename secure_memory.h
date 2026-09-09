#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <stdexcept>
#include <utility>
#pragma comment(lib, "crypt32.lib")

namespace secure_memory {
template<class Container> class WipeOnExit {
    Container& value;
public:
    explicit WipeOnExit(Container& container) : value(container) {}
    ~WipeOnExit() { if (!value.empty()) SecureZeroMemory(&value[0], value.size() * sizeof(value[0])); }
    WipeOnExit(const WipeOnExit&) = delete;
    WipeOnExit& operator=(const WipeOnExit&) = delete;
};
// Dedicated, non-executable pages. Locking prevents paging these bytes to disk;
// it is not a barrier to a privileged debugger or code running inside the process.
class LockedBuffer {
    unsigned char* memory = nullptr;
    size_t length;
public:
    explicit LockedBuffer(size_t size) : length(size) {
        memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!memory) throw std::runtime_error("secure allocation failed");
        if (!VirtualLock(memory, length)) {
            VirtualFree(memory, 0, MEM_RELEASE); memory = nullptr;
            throw std::runtime_error("secure memory lock failed");
        }
    }
    ~LockedBuffer() {
        if (memory) { SecureZeroMemory(memory, length); VirtualUnlock(memory, length); VirtualFree(memory, 0, MEM_RELEASE); }
    }
    LockedBuffer(const LockedBuffer&) = delete;
    LockedBuffer& operator=(const LockedBuffer&) = delete;
    unsigned char* data() { return memory; }
    const unsigned char* data() const { return memory; }
    size_t size() const { return length; }
};
class Secret {
    LockedBuffer bytes{32};
    bool sealed = false;
    void Seal() {
        if (!CryptProtectMemory(bytes.data(), 32, CRYPTPROTECTMEMORY_SAME_PROCESS)) {
            SecureZeroMemory(bytes.data(), 32);
            throw std::runtime_error("key memory protection failed");
        }
        sealed = true;
    }
public:
    template<class Initialize> void Set(Initialize initialize) {
        sealed = false;
        try { initialize(bytes.data()); Seal(); }
        catch (...) { SecureZeroMemory(bytes.data(), 32); throw; }
    }
    template<class Operation> auto Use(Operation operation) -> decltype(operation(static_cast<unsigned char*>(nullptr))) {
        if (!sealed || !CryptUnprotectMemory(bytes.data(), 32, CRYPTPROTECTMEMORY_SAME_PROCESS))
            throw std::runtime_error("key memory access failed");
        sealed = false;
        try {
            auto result = operation(bytes.data());
            Seal();
            return result;
        } catch (...) { SecureZeroMemory(bytes.data(), 32); throw; }
    }
};
}
