#define WIN32_LEAN_AND_MEAN
#include "primary_identity.h"
#include "test_support.h"
#include <cassert>
#include <iostream>
using namespace identity;
static Bytes Table(Bytes records, unsigned char minor = 6) {
    Bytes raw{0,2,minor,0,0,0,0,0};
    DWORD size = static_cast<DWORD>(records.size()); memcpy(raw.data() + 4, &size, 4);
    raw.insert(raw.end(), records.begin(), records.end()); return raw;
}
static Bytes Board(const std::string& serial) {
    Bytes record{2,8,0,0,0,0,0,1};
    record.insert(record.end(), serial.begin(), serial.end()); record.push_back(0); record.push_back(0); return record;
}
template<class Operation> static void Reject(Operation operation) {
    bool failed = false; try { operation(); } catch (const std::runtime_error&) { failed = true; } assert(failed);
}
int main() {
    Bytes system(26); system[0] = 1; system[1] = 24;
    for (int i = 0; i < 16; ++i) system[8 + i] = static_cast<unsigned char>(i);
    auto fields = ParseSmbios(Table(system));
    auto uuid = fields.at("smbios/system-uuid");
    assert(std::string(uuid.begin(), uuid.end()) == "03020100-0504-0706-0809-0a0b0c0d0e0f");
    uuid = ParseSmbios(Table(system, 5)).at("smbios/system-uuid");
    assert(std::string(uuid.begin(), uuid.end()) == "00010203-0405-0607-0809-0a0b0c0d0e0f");
    for (int fill : {0,255}) {
        auto missing = system; memset(missing.data() + 8, fill, 16);
        assert(ParseSmbios(Table(missing)).empty());
    }
    auto boardA = Board("  BOARD-A  "), boardB = Board("BOARD-B");
    auto records = system; records.insert(records.end(), boardB.begin(), boardB.end());
    records.insert(records.end(), boardA.begin(), boardA.end()); records.insert(records.end(), boardA.begin(), boardA.end());
    auto all = ParseSmbios(Table(records));
    assert(all.size() == 3 && all.at("smbios/baseboard/0") == Bytes({'B','O','A','R','D','-','A'}));
    auto otherOrder = system; otherOrder.insert(otherOrder.end(), boardA.begin(), boardA.end());
    otherOrder.insert(otherOrder.end(), boardB.begin(), boardB.end());
    assert(ParseSmbios(Table(otherOrder)) == all);
    for (const char* placeholder : {"Default string","To Be Filled By O.E.M.","0000","Unknown"})
        assert(ParseSmbios(Table(Board(placeholder))).empty());
    for (size_t n = 0; n < 8; ++n) Reject([&] { ParseSmbios(Bytes(n)); });
    auto broken = Table(system); broken[4]++; Reject([&] { ParseSmbios(broken); });
    broken = system; broken[1] = 3; Reject([&] { ParseSmbios(Table(broken)); });
    broken = system; broken.pop_back(); Reject([&] { ParseSmbios(Table(broken)); });
    broken = Board("BOARD"); broken[7] = 2; Reject([&] { ParseSmbios(Table(broken)); });

    STORAGE_PROTOCOL_DATA_DESCRIPTOR descriptor{};
    descriptor.Version = descriptor.Size = sizeof(descriptor);
    descriptor.ProtocolSpecificData.ProtocolType = ProtocolTypeNvme;
    descriptor.ProtocolSpecificData.DataType = NVMeDataTypeIdentify;
    descriptor.ProtocolSpecificData.ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
    descriptor.ProtocolSpecificData.ProtocolDataLength = 4096;
    Bytes response(sizeof(descriptor) + 4096);
    memcpy(response.data(), &descriptor, sizeof(descriptor));
    memset(response.data() + sizeof(descriptor) + 4, ' ', 20);
    memcpy(response.data() + sizeof(descriptor) + 4, "NVME-TEST", 9);
    assert(ParseNvmeIdentify(response) == "NVME-TEST");
    for (DWORD offset : {DWORD(0), DWORD(39), DWORD(MAXDWORD)}) {
        auto invalid = response; auto copy = descriptor; copy.ProtocolSpecificData.ProtocolDataOffset = offset;
        memcpy(invalid.data(), &copy, sizeof(copy)); Reject([&] { ParseNvmeIdentify(invalid); });
    }
    auto invalid = response; invalid.pop_back(); Reject([&] { ParseNvmeIdentify(invalid); });
    invalid = response; invalid[0] = 0; Reject([&] { ParseNvmeIdentify(invalid); });
    invalid = response; memset(invalid.data() + sizeof(descriptor) + 4, 0, 20); Reject([&] { ParseNvmeIdentify(invalid); });
    all["storage/c/nvme-identify-serial"] = Bytes{'N','V','M','E'};
    Fields nvram{{"synthetic", {1,2,3}}};
    auto hash = Combine(nvram, all);
    for (const char* key : {"smbios/system-uuid","smbios/baseboard/0","storage/c/nvme-identify-serial"}) {
        auto changed = all; changed.at(key).back() ^= 1;
        assert(Combine(nvram, changed) != hash);
        changed = all; changed.erase(key); assert(Combine(nvram, changed) != hash);
    }
    auto json = payload::Json(nvram, all);
    assert(json.find("\"hwid_version\": 3") != std::string::npos);
    assert(json.find("\"nvme_identify_serial\": \"NVME\"") != std::string::npos);
    assert(json.find("\"baseboard_serials\": [") != std::string::npos);
    assert(payload::Decrypt(payload::Encrypt(json)) == json);
    auto missing = payload::Json(nvram, {});
    assert(missing.find("\"nvme_identify_serial\": null") != std::string::npos);
    assert(missing.find("\"system_uuid\": null") != std::string::npos);
    Fields parts = all; parts["nvram/sha256"] = Sha256(Encode(nvram));
    assert(CombinedDigest(nvram, all) != Sha256(Encode(parts))); // Version 2 must not collide with version 3.
    std::cout << "PASS: SMBIOS byte order, missing values, strings and bounds; NVMe descriptor bounds; primary hash and JSON\n";
}
