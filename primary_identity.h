#pragma once
#include "identity.h"
#include <winioctl.h>
#include <cstddef>

namespace identity {
inline std::string IdentitySerial(std::string value) {
    while (!value.empty() && value.front() == ' ') value.erase(value.begin());
    while (!value.empty() && value.back() == ' ') value.pop_back();
    std::string upper = value;
    for (auto& c : upper) {
        if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126)
            throw std::runtime_error("invalid identity serial characters");
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    if (upper.empty() || upper == "UNKNOWN" || upper == "NONE" || upper == "N/A" ||
        upper == "DEFAULT STRING" || upper == "SYSTEM SERIAL NUMBER" || upper == "BASE BOARD SERIAL NUMBER" ||
        upper == "TO BE FILLED BY O.E.M." || upper == "TO BE FILLED BY OEM" ||
        std::all_of(upper.begin(), upper.end(), [](char c) { return c == '0' || c == ' '; })) return {};
    return value;
}
inline Fields ParseSmbios(const Bytes& raw) {
    if (raw.size() < 8 || Read32(raw.data() + 4) != raw.size() - 8)
        throw std::runtime_error("invalid SMBIOS table size");
    Fields result;
    std::vector<std::string> boards;
    const bool littleEndianUuid = raw[1] > 2 || (raw[1] == 2 && raw[2] >= 6);
    for (size_t pos = 8; pos < raw.size();) {
        if (raw.size() - pos < 4) throw std::runtime_error("truncated SMBIOS structure");
        const auto* record = raw.data() + pos;
        size_t length = record[1];
        if (length < 4 || length > raw.size() - pos) throw std::runtime_error("invalid SMBIOS structure length");
        size_t end = pos + length;
        while (end + 1 < raw.size() && (raw[end] || raw[end + 1])) ++end;
        if (end + 1 >= raw.size()) throw std::runtime_error("unterminated SMBIOS strings");
        if (record[0] == 1 && length >= 24) {
            Bytes uuid(record + 8, record + 24);
            bool zero = std::all_of(uuid.begin(), uuid.end(), [](unsigned char c) { return c == 0; });
            bool missing = std::all_of(uuid.begin(), uuid.end(), [](unsigned char c) { return c == 255; });
            if (!zero && !missing) {
                if (littleEndianUuid) {
                    std::reverse(uuid.begin(), uuid.begin() + 4);
                    std::reverse(uuid.begin() + 4, uuid.begin() + 6);
                    std::reverse(uuid.begin() + 6, uuid.begin() + 8);
                }
                auto hex = Hex(uuid.data(), uuid.size());
                auto value = hex.substr(0,8) + "-" + hex.substr(8,4) + "-" + hex.substr(12,4) + "-" + hex.substr(16,4) + "-" + hex.substr(20);
                Bytes bytes(value.begin(), value.end());
                auto prior = result.find("smbios/system-uuid");
                if (prior != result.end() && prior->second != bytes) throw std::runtime_error("conflicting SMBIOS UUIDs");
                result["smbios/system-uuid"] = bytes;
            }
        }
        if (record[0] == 2 && length >= 8 && record[7]) {
            size_t start = pos + length;
            unsigned int index = 1;
            bool found = false;
            while (start < end) {
                size_t stop = start;
                while (stop < end && raw[stop]) ++stop;
                if (index == record[7]) {
                    auto serial = IdentitySerial(std::string(raw.begin() + start, raw.begin() + stop));
                    if (!serial.empty()) boards.push_back(serial);
                    found = true; break;
                }
                start = stop + 1; ++index;
            }
            if (!found) throw std::runtime_error("invalid SMBIOS serial string index");
        }
        if (record[0] == 127) break;
        pos = end + 2;
    }
    std::sort(boards.begin(), boards.end());
    boards.erase(std::unique(boards.begin(), boards.end()), boards.end());
    for (size_t i = 0; i < boards.size(); ++i)
        result["smbios/baseboard/" + std::to_string(i)] = Bytes(boards[i].begin(), boards[i].end());
    return result;
}
inline void ReadSmbios(Fields& fields) {
    constexpr DWORD provider = 0x52534d42; // RSMB
    UINT size = GetSystemFirmwareTable(provider, 0, nullptr, 0);
    if (!size) throw std::runtime_error("SMBIOS query unavailable");
    if (size > 16 * 1024 * 1024) throw std::runtime_error("SMBIOS table too large");
    Bytes raw(size);
    if (GetSystemFirmwareTable(provider, 0, raw.data(), size) != size)
        throw std::runtime_error("SMBIOS table changed during collection");
    auto first = ParseSmbios(raw);
    if (GetSystemFirmwareTable(provider, 0, raw.data(), size) != size || ParseSmbios(raw) != first)
        throw std::runtime_error("SMBIOS identity changed during collection");
    fields.insert(first.begin(), first.end());
}
inline std::string ParseNvmeIdentify(const Bytes& response) {
    if (response.size() < sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR)) throw std::runtime_error("truncated NVMe descriptor");
    STORAGE_PROTOCOL_DATA_DESCRIPTOR descriptor{};
    memcpy(&descriptor, response.data(), sizeof(descriptor));
    const auto& protocol = descriptor.ProtocolSpecificData;
    const size_t base = offsetof(STORAGE_PROTOCOL_DATA_DESCRIPTOR, ProtocolSpecificData);
    if (descriptor.Version != sizeof(descriptor) || descriptor.Size != sizeof(descriptor) ||
        protocol.ProtocolType != ProtocolTypeNvme || protocol.DataType != NVMeDataTypeIdentify ||
        protocol.ProtocolDataOffset < sizeof(protocol) || protocol.ProtocolDataOffset > response.size() - base ||
        protocol.ProtocolDataLength < 4096 || protocol.ProtocolDataLength > response.size() - base - protocol.ProtocolDataOffset)
        throw std::runtime_error("invalid NVMe Identify response");
    const auto* data = response.data() + base + protocol.ProtocolDataOffset;
    return IdentitySerial(std::string(reinterpret_cast<const char*>(data + 4), 20));
}
inline std::string QueryNvmeSerial(HANDLE disk) {
    const size_t base = offsetof(STORAGE_PROPERTY_QUERY, AdditionalParameters);
    Bytes buffer(base + sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) + 4096);
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageAdapterProtocolSpecificProperty;
    query.QueryType = PropertyStandardQuery;
    memcpy(buffer.data(), &query, base);
    STORAGE_PROTOCOL_SPECIFIC_DATA protocol{};
    protocol.ProtocolType = ProtocolTypeNvme;
    protocol.DataType = NVMeDataTypeIdentify;
    protocol.ProtocolDataRequestValue = 1; // Identify Controller (CNS).
    protocol.ProtocolDataOffset = sizeof(protocol);
    protocol.ProtocolDataLength = 4096;
    memcpy(buffer.data() + base, &protocol, sizeof(protocol));
    DWORD returned = 0;
    if (!DeviceIoControl(disk, IOCTL_STORAGE_QUERY_PROPERTY, buffer.data(), static_cast<DWORD>(buffer.size()),
        buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr)) {
        DWORD error = GetLastError();
        if (error == ERROR_INVALID_FUNCTION || error == ERROR_NOT_SUPPORTED || error == ERROR_INVALID_PARAMETER)
            return {}; // SATA and opaque RAID/bridge stacks may not expose NVMe Identify.
        throw std::runtime_error("NVMe Identify query failed");
    }
    if (returned > buffer.size()) throw std::runtime_error("invalid NVMe response size");
    buffer.resize(returned);
    return ParseNvmeIdentify(buffer);
}
}
