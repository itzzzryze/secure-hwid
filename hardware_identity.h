#pragma once
#include "identity.h"
#include <setupapi.h>
#include <winioctl.h>
#include <cstddef>
#pragma comment(lib, "setupapi.lib")

namespace identity {
struct DeviceHandle {
    HANDLE value;
    explicit DeviceHandle(const std::wstring& path) : value(CreateFileW(path.c_str(), 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr)) {
        if (value == INVALID_HANDLE_VALUE) throw std::runtime_error("C: storage device unavailable");
    }
    ~DeviceHandle() { CloseHandle(value); }
    DeviceHandle(const DeviceHandle&) = delete;
    DeviceHandle& operator=(const DeviceHandle&) = delete;
};
inline void AddGpuPciIds(Fields& fields, std::vector<std::string> values) {
    for (auto& value : values) {
        for (auto& c : value) {
            if (static_cast<unsigned char>(c) < 0x21 || static_cast<unsigned char>(c) > 0x7e)
                throw std::runtime_error("invalid GPU PCI device ID");
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        if (value.size() > 200 || value.compare(0, 8, "PCI\\VEN_") ||
            value.find("&DEV_") == std::string::npos || value.find('\\', 4) == std::string::npos)
            throw std::runtime_error("invalid GPU PCI device ID");
    }
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    for (size_t i = 0; i < values.size(); ++i)
        fields["gpu/pci/" + std::to_string(i)] = Bytes(values[i].begin(), values[i].end());
}
inline void ReadGpuPci(Fields& fields) {
    // Same PnP device-instance ID as spoofed's Win32_VideoController.PNPDeviceID.
    // Query the present display device set directly, including AMD/Intel PCI GPUs.
    const GUID displayClass = {0x4d36e968, 0xe325, 0x11ce, {0xbf,0xc1,0x08,0x00,0x2b,0xe1,0x03,0x18}};
    HDEVINFO set = SetupDiGetClassDevsW(&displayClass, nullptr, nullptr, DIGCF_PRESENT);
    if (set == INVALID_HANDLE_VALUE) throw std::runtime_error("GPU PCI enumeration failed");
    struct Cleanup { HDEVINFO set; ~Cleanup() { SetupDiDestroyDeviceInfoList(set); } } cleanup{set};
    std::vector<std::string> values;
    for (DWORD i = 0; ; ++i) {
        SP_DEVINFO_DATA device{}; device.cbSize = sizeof(device);
        if (!SetupDiEnumDeviceInfo(set, i, &device)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) break;
            throw std::runtime_error("GPU PCI enumeration failed");
        }
        wchar_t value[201]{};
        if (!SetupDiGetDeviceInstanceIdW(set, &device, value, 201, nullptr))
            throw std::runtime_error("GPU PCI device ID unavailable");
        if (_wcsnicmp(value, L"PCI\\", 4)) continue;
        std::string ascii;
        for (wchar_t c : std::wstring(value)) {
            if (c > 127) throw std::runtime_error("invalid GPU PCI device ID");
            ascii += static_cast<char>(c);
        }
        values.push_back(std::move(ascii));
    }
    AddGpuPciIds(fields, std::move(values));
}
inline DWORD MainDiskNumber(const Bytes& extents) {
    const size_t offset = offsetof(VOLUME_DISK_EXTENTS, Extents);
    if (extents.size() < offset) throw std::runtime_error("truncated C: disk mapping");
    DWORD count = Read32(extents.data());
    if (!count || count > 128 || count > (extents.size() - offset) / sizeof(DISK_EXTENT))
        throw std::runtime_error("invalid C: disk mapping");
    DWORD disk = Read32(extents.data() + offset + offsetof(DISK_EXTENT, DiskNumber));
    for (DWORD i = 1; i < count; ++i)
        if (Read32(extents.data() + offset + i * sizeof(DISK_EXTENT) + offsetof(DISK_EXTENT, DiskNumber)) != disk)
            throw std::runtime_error("C: spans multiple disks; no single main disk");
    return disk;
}
inline DWORD ReadMainDiskNumber(HANDLE volume) {
    Bytes extents(offsetof(VOLUME_DISK_EXTENTS, Extents) + 128 * sizeof(DISK_EXTENT));
    DWORD returned = 0;
    if (!DeviceIoControl(volume, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0,
        extents.data(), static_cast<DWORD>(extents.size()), &returned, nullptr) || returned > extents.size())
        throw std::runtime_error("C: disk mapping unavailable");
    extents.resize(returned);
    return MainDiskNumber(extents);
}
inline std::string StorageDescriptorSerial(const Bytes& descriptor) {
    const size_t minimum = offsetof(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties);
    if (descriptor.size() < minimum) throw std::runtime_error("truncated storage descriptor");
    DWORD size = Read32(descriptor.data() + offsetof(STORAGE_DEVICE_DESCRIPTOR, Size));
    DWORD offset = Read32(descriptor.data() + offsetof(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset));
    if (size < minimum || size > descriptor.size() || offset < minimum || offset >= size)
        throw std::runtime_error("C: storage serial unavailable");
    auto start = reinterpret_cast<const char*>(descriptor.data() + offset);
    auto end = static_cast<const char*>(memchr(start, 0, size - offset));
    if (!end) throw std::runtime_error("unterminated storage serial");
    std::string serial(start, end);
    while (!serial.empty() && std::isspace(static_cast<unsigned char>(serial.front()))) serial.erase(serial.begin());
    while (!serial.empty() && std::isspace(static_cast<unsigned char>(serial.back()))) serial.pop_back();
    if (serial.empty() || serial.size() > 1024) throw std::runtime_error("C: storage serial unavailable");
    std::string upper = serial;
    for (auto& c : upper) {
        if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) > 0x7e)
            throw std::runtime_error("invalid storage serial");
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    if (upper == "UNKNOWN" || upper == "N/A" || upper == "NONE" || upper == "NOT SUPPORTED" ||
        std::all_of(upper.begin(), upper.end(), [](char c) { return c == '0' || c == ' '; }))
        throw std::runtime_error("C: storage serial unavailable");
    return serial; // Preserve the driver-returned serial; no hex decoding or byte swapping.
}
inline std::string QueryStorageSerial(HANDLE disk) {
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    Bytes descriptor(4096);
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD returned = 0;
        BOOL ok = DeviceIoControl(disk, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
            descriptor.data(), static_cast<DWORD>(descriptor.size()), &returned, nullptr);
        DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        if (returned > descriptor.size() || (!ok && error != ERROR_MORE_DATA && error != ERROR_INSUFFICIENT_BUFFER))
            throw std::runtime_error("C: storage descriptor query failed");
        DWORD needed = returned >= 8 ? Read32(descriptor.data() + 4) : 0;
        if (needed > descriptor.size() && needed <= 1024 * 1024) { descriptor.resize(needed); continue; }
        if (!ok) throw std::runtime_error("C: storage descriptor query failed");
        descriptor.resize(returned);
        return StorageDescriptorSerial(descriptor);
    }
    throw std::runtime_error("C: storage descriptor too large");
}
inline void ReadCDrive(Fields& fields) {
    DeviceHandle volume(L"\\\\.\\C:");
    DWORD number = ReadMainDiskNumber(volume.value);
    // Never enumerate PhysicalDrive0..N, assume disk 0, or fall back to another disk.
    DeviceHandle disk(L"\\\\.\\PhysicalDrive" + std::to_wstring(number));
    auto serial = QueryStorageSerial(disk.value);
    if (QueryStorageSerial(disk.value) != serial || ReadMainDiskNumber(volume.value) != number)
        throw std::runtime_error("C: storage identity changed during collection");
    fields["storage/c/serial"] = Bytes(serial.begin(), serial.end());
}
}
