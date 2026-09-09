#define WIN32_LEAN_AND_MEAN
#include "identity.h"
#include "hardware_identity.h"
#include "encrypted_payload.h"
#include <iostream>
#include <cstring>

int main() {
    HMODULE lib = LoadLibraryExW(L"nvml.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    std::cout << "load=" << (lib ? "ok" : "failed") << " error=" << GetLastError() << '\n';
    if (!lib) return 1;
    using Init = int(__cdecl*)();
    using Count = int(__cdecl*)(unsigned int*);
    using Handle = int(__cdecl*)(unsigned int, void**);
    using Serial = int(__cdecl*)(void*, char*, unsigned int);
    auto init = reinterpret_cast<Init>(GetProcAddress(lib, "nvmlInit_v2"));
    auto shutdown = reinterpret_cast<Init>(GetProcAddress(lib, "nvmlShutdown"));
    auto count = reinterpret_cast<Count>(GetProcAddress(lib, "nvmlDeviceGetCount_v2"));
    auto handle = reinterpret_cast<Handle>(GetProcAddress(lib, "nvmlDeviceGetHandleByIndex_v2"));
    auto serial = reinterpret_cast<Serial>(GetProcAddress(lib, "nvmlDeviceGetSerial"));
    auto uuid = reinterpret_cast<Serial>(GetProcAddress(lib, "nvmlDeviceGetUUID"));
    std::cout << "exports=" << !!init << !!shutdown << !!count << !!handle << !!serial << '\n';
    if (!init || !shutdown || !count || !handle || !serial || !uuid) return 2;
    int initCode = init();
    std::cout << "init=" << initCode << '\n';
    if (initCode) return 3;
    unsigned int devices = 0;
    int countCode = count(&devices);
    std::cout << "count-code=" << countCode << " devices=" << devices << '\n';
    std::vector<std::string> expectedUuids;
    for (unsigned int i = 0; !countCode && i < devices; ++i) {
        void* device = nullptr;
        int handleCode = handle(i, &device);
        char value[96]{};
        int serialCode = handleCode ? -1 : serial(device, value, sizeof(value));
        bool valid = serialCode == 0 && !identity::NormalizeGpuSerial(value, sizeof(value)).empty();
        std::cout << "device=" << i << " handle-code=" << handleCode
                  << " serial-code=" << serialCode << " serial=" << (valid ? "available" : "unavailable") << '\n';
        SecureZeroMemory(value, sizeof(value));
        if (handleCode || uuid(device, value, sizeof(value))) return 4;
        auto gpuUuid = identity::NormalizeGpuSerial(value, sizeof(value));
        if (!identity::IsGpuUuid(gpuUuid)) return 4;
        for (auto& c : gpuUuid) if (c >= 'A' && c <= 'F') c += 'a' - 'A';
        expectedUuids.push_back(gpuUuid);
        SecureZeroMemory(value, sizeof(value));
    }
    shutdown();
    FreeLibrary(lib);
    identity::Fields fields;
    try {
        identity::ReadGpuPci(fields);
        identity::ReadGpu(fields);
        size_t collected = 0;
        std::vector<std::string> actualUuids;
        for (const auto& field : fields) if (field.first.find("gpu/pci/") == 0) ++collected;
        for (const auto& field : fields) if (field.first.find("gpu/uuid/") == 0)
            actualUuids.emplace_back(field.second.begin(), field.second.end());
        std::cout << "application-collector PCI device IDs=" << collected << '\n';
        std::sort(actualUuids.begin(), actualUuids.end());
        std::sort(expectedUuids.begin(), expectedUuids.end());
        expectedUuids.erase(std::unique(expectedUuids.begin(), expectedUuids.end()), expectedUuids.end());
        if (actualUuids != expectedUuids) return 4;
        auto json = payload::Json({{"synthetic-nvram", {1, 2, 3}}}, fields);
        if (payload::Decrypt(payload::Encrypt(json)) != json) return 6;
        std::cout << "PASS: " << actualUuids.size() << " GPU UUID(s) match driver; encrypted JSON roundtrip verified\n";
    } catch (const std::exception& error) {
        std::cout << "application-collector failed: " << error.what() << '\n';
        return 5;
    }
    return 0;
}
