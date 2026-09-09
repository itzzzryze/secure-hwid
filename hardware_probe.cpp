#define WIN32_LEAN_AND_MEAN
#include "hardware_identity.h"
#include "test_support.h"
#include <iostream>

static std::wstring Expected(const wchar_t* name) {
    DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size) return {};
    std::wstring value(size, 0);
    if (!GetEnvironmentVariableW(name, &value[0], size)) throw std::runtime_error("expected value unavailable");
    value.resize(size - 1);
    return value;
}
static std::string Ascii(const std::wstring& value) {
    std::string result;
    for (wchar_t c : value) {
        if (c > 127) throw std::runtime_error("expected identifier is not ASCII");
        result += static_cast<char>(c);
    }
    return result;
}
int main() {
    try {
        identity::Fields fields, again;
        identity::ReadGpuPci(fields);
        identity::ReadSmbios(fields);
        identity::ReadCDrive(fields);
        identity::ReadGpuPci(again);
        identity::ReadSmbios(again);
        identity::ReadCDrive(again);
        if (fields != again) throw std::runtime_error("hardware reads changed");
        auto expectedUuid = Ascii(Expected(L"HWID_EXPECTED_SMBIOS_UUID"));
        for (auto& c : expectedUuid) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (!expectedUuid.empty()) {
            const auto& actual = fields.at("smbios/system-uuid");
            if (std::string(actual.begin(), actual.end()) != expectedUuid) throw std::runtime_error("SMBIOS UUID comparison failed");
        }
        auto expectedBoard = Ascii(Expected(L"HWID_EXPECTED_BASEBOARD"));
        if (!expectedBoard.empty()) {
            const auto& actual = fields.at("smbios/baseboard/0");
            if (std::string(actual.begin(), actual.end()) != expectedBoard) throw std::runtime_error("SMBIOS baseboard comparison failed");
        }
        if (!expectedUuid.empty() && !expectedBoard.empty()) std::cout << "PASS: SMBIOS values match independent Windows queries\n";
        std::cout << "SMBIOS UUID=" << fields.count("smbios/system-uuid")
                  << " baseboard serial=" << fields.count("smbios/baseboard/0")
                  << " NVMe Identify=" << (fields.count("storage/c/nvme-identify-serial") ? "available" : "unavailable") << '\n';
        size_t gpuCount = 0;
        auto expectedGpu = Expected(L"HWID_EXPECTED_PCI");
        identity::Fields expectedPci;
        std::vector<std::string> expectedIds;
        size_t start = 0;
        while (start < expectedGpu.size()) {
            auto end = expectedGpu.find(L'\n', start);
            auto value = expectedGpu.substr(start, end == std::wstring::npos ? end : end - start);
            expectedIds.push_back(Ascii(value));
            if (end == std::wstring::npos) break;
            start = end + 1;
        }
        identity::AddGpuPciIds(expectedPci, expectedIds);
        identity::Fields actualPci;
        for (const auto& field : fields) if (field.first.find("gpu/pci/") == 0) { ++gpuCount; actualPci.insert(field); }
        if (!expectedGpu.empty() && actualPci != expectedPci) throw std::runtime_error("PCI IDs differ from independent WMI query");
        auto expectedSerial = Expected(L"HWID_EXPECTED_C_SERIAL");
        auto serial = fields.at("storage/c/serial");
        if (!expectedSerial.empty() && Ascii(expectedSerial) != std::string(serial.begin(), serial.end()))
            throw std::runtime_error("C: serial differs from independent storage query");
        identity::DeviceHandle volume(L"\\\\.\\C:");
        DWORD disk = identity::ReadMainDiskNumber(volume.value);
        auto expectedDisk = Expected(L"HWID_EXPECTED_C_DISK");
        if (!expectedDisk.empty() && std::stoul(expectedDisk) != disk) throw std::runtime_error("C: mapped to wrong disk");
        auto json = payload::Json({{"synthetic-nvram", {1,2,3}}}, fields);
        secure_memory::WipeOnExit<std::string> wipeJson(json);
        if (payload::Decrypt(payload::Encrypt(json)) != json) throw std::runtime_error("live hardware JSON roundtrip failed");
        std::cout << "PASS: " << gpuCount << " PCI GPU(s), C: maps to PhysicalDrive" << disk
                  << ", storage serial present, repeated reads and encrypted JSON verified\n";
        if (!expectedGpu.empty() && !expectedSerial.empty() && !expectedDisk.empty())
            std::cout << "PASS: independent PCI, C: disk mapping, and storage serial comparisons\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
