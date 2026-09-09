#define WIN32_LEAN_AND_MEAN
#include "identity.h"
#include "encrypted_payload.h"
#include "hardware_identity.h"
#include <cassert>
#include <iostream>
#include <fstream>
using namespace identity;
static Bytes Entry(const std::wstring& name, Bytes value, bool last, unsigned char padding = 0) {
    size_t dataOffset = 32 + (name.size() + 1) * 2;
    Bytes entry(dataOffset + value.size() + 8, padding);
    DWORD header[] = {last ? 0 : (DWORD)entry.size(), (DWORD)dataOffset, (DWORD)value.size(), 7};
    memcpy(entry.data(), header, 16);
    memset(entry.data() + 16, 1, 16);
    memcpy(entry.data() + 32, name.c_str(), (name.size() + 1) * 2);
    memcpy(entry.data() + dataOffset, value.data(), value.size());
    return entry;
}
int main(int argc, char** argv) {
    auto sha = Sha256(Bytes{'a','b','c'});
    assert(Hex(sha.data(), sha.size()) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    auto a = Entry(L"OfflineUniqueIDRandomSeed", {1,2,3}, true, 0);
    auto b = Entry(L"OfflineUniqueIDRandomSeed", {1,2,3}, true, 255);
    auto nvram = ParseNvram(a, a.size());
    assert(nvram.size() == 1 && nvram.begin()->second == Bytes({1,2,3}));
    assert(nvram == ParseNvram(b, b.size())); // Padding must never affect the hash.
    auto first = Entry(L"UnlockIDCopy", {4,5}, false);
    first.insert(first.end(), a.begin(), a.end());
    assert(ParseNvram(first, first.size()).size() == 2); // Includes zero-next final entry.
    auto reverse = Entry(L"OfflineUniqueIDRandomSeed", {1,2,3}, false);
    auto end = Entry(L"UnlockIDCopy", {4,5}, true);
    reverse.insert(reverse.end(), end.begin(), end.end());
    assert(Combine(ParseNvram(first, first.size()), {}) == Combine(ParseNvram(reverse, reverse.size()), {}));
    for (size_t size = 1; size < 34; ++size) {
        bool rejected = false;
        try { ParseNvram(a, size); } catch (...) { rejected = true; }
        assert(rejected);
    }
    b = a; DWORD invalid = MAXDWORD; memcpy(b.data() + 4, &invalid, 4);
    bool rejected = false;
    try { ParseNvram(b, b.size()); } catch (...) { rejected = true; }
    assert(rejected);
    Fields gpuA, gpuB;
    AddGpuSerials(gpuA, {"B123", "A123", "A123", "N/A"});
    AddGpuSerials(gpuB, {"A123", "B123"});
    assert(gpuA == gpuB);
    Fields invalidGpu;
    AddGpuSerials(invalidGpu, {"0", "000000", "0x0000", " 0 ", "unknown", "[N/A]"});
    assert(invalidGpu.empty());
    assert(IsGpuUuid("GPU-12345678-1234-5678-9abc-123456789abc"));
    assert(!IsGpuUuid("GPU-00000000-0000-0000-0000-000000000000"));
    assert(!IsGpuUuid("GPU-Unknown") && !IsGpuUuid("0"));
    const auto base = Combine(nvram, {});
    const auto gpu = Combine(nvram, gpuA);
    Fields tpm{{"tpm/ekpub-sha256", Sha256(Bytes{8,9})}};
    const auto tpmOnly = Combine(nvram, tpm);
    auto both = gpuA; both.insert(tpm.begin(), tpm.end());
    assert(base.size() == 64 && gpu.size() == 64);
    assert(base != gpu && base != tpmOnly && gpu != tpmOnly && Combine(nvram, both) != gpu);
    assert(Encode({{"ab", {'c'}}}) != Encode({{"a", {'b','c'}}}));
    rejected = false;
    try { Combine({}, gpuA); } catch (...) { rejected = true; }
    assert(rejected);
    std::cout << "PASS: SHA-256, NVRAM bounds/final-entry/padding, ordering, optional combinations, required base\n";

    assert(payload::Base64(Bytes{'a','b','c'}) == "YWJj");
    assert(payload::Unbase64(" YWJj\r\n") == Bytes({'a','b','c'}));
    assert(payload::Base64(Bytes{'a'}) == "YQ==");
    // Standard AES-256-GCM vector: zero key, 96-bit zero IV, one zero block.
    unsigned char zeroKey[32]{};
    Bytes tag(16);
    auto cipher = payload::Gcm(true, zeroKey, Bytes(16), Bytes(12), {}, tag);
    assert(Hex(cipher.data(), cipher.size()) == "cea7403d4d606b6e074ec5d3baf39d18");
    assert(Hex(tag.data(), tag.size()) == "d0d1c8a799996bf0265b98b5d48ab919");
    assert(payload::Gcm(false, zeroKey, cipher, Bytes(12), {}, tag) == Bytes(16));
    auto json = payload::Json(nvram, both);
    auto encrypted = payload::Encrypt(json);
    assert(payload::Decrypt(encrypted) == json);
    assert(encrypted != payload::Encrypt(json)); // Fresh salt and nonce per save.
    assert(json.find("\"hwid\": \"" + payload::Base64(CombinedDigest(nvram, both))) != std::string::npos);
    Fields pciA, pciB;
    const std::string pci1 = "PCI\\VEN_10DE&DEV_1234&SUBSYS_12345678&REV_A1\\4&ABC&0&0019";
    const std::string pci2 = "PCI\\VEN_1002&DEV_5678&SUBSYS_87654321&REV_B1\\4&DEF&0&0020";
    AddGpuPciIds(pciA, {pci1, pci2, pci1});
    AddGpuPciIds(pciB, {pci2, pci1});
    assert(pciA == pciB && pciA.size() == 2);
    AddGpuPciIds(pciB = {}, {"pci\\ven_10de&dev_1234&subsys_12345678&rev_a1\\4&abc&0&0019"});
    assert(pciB.begin()->second == Bytes(pci1.begin(), pci1.end()));
    for (const auto& invalidId : {"GPU-1234", "PCI\\VEN_10DE&DEV_1234", "PCI\\VEN_10DE&DEV_1234\\bad\n"}) {
        rejected = false;
        try { Fields invalidFields; AddGpuPciIds(invalidFields, {invalidId}); } catch (...) { rejected = true; }
        assert(rejected);
    }
    auto pciJson = payload::Json(nvram, pciA);
    assert(pciJson.find(payload::Quote(pci1)) != std::string::npos);
    assert(pciJson.find("\"gpu_serial_source\": \"pci_device_instance_id\"") != std::string::npos);
    assert(Combine(nvram, pciA) != base);

    // The C: volume may have multiple extents on the same disk; unrelated disks
    // must never be chosen, and a volume spanning distinct disks is ambiguous.
    const size_t extentOffset = offsetof(VOLUME_DISK_EXTENTS, Extents);
    Bytes extents(extentOffset + 2 * sizeof(DISK_EXTENT));
    DWORD count = 2; memcpy(extents.data(), &count, 4);
    DISK_EXTENT extent{}; extent.DiskNumber = 7;
    memcpy(extents.data() + extentOffset, &extent, sizeof(extent));
    memcpy(extents.data() + extentOffset + sizeof(extent), &extent, sizeof(extent));
    assert(MainDiskNumber(extents) == 7); // Never assume PhysicalDrive0.
    extent.DiskNumber = 0;
    memcpy(extents.data() + extentOffset + sizeof(extent), &extent, sizeof(extent));
    rejected = false; try { MainDiskNumber(extents); } catch (...) { rejected = true; }
    assert(rejected);
    count = MAXDWORD; memcpy(extents.data(), &count, 4);
    rejected = false; try { MainDiskNumber(extents); } catch (...) { rejected = true; }
    assert(rejected);
    for (size_t size = 0; size < extentOffset + sizeof(DISK_EXTENT); ++size) {
        Bytes truncated(size); if (size >= 4) { count = 1; memcpy(truncated.data(), &count, 4); }
        rejected = false; try { MainDiskNumber(truncated); } catch (...) { rejected = true; }
        assert(rejected);
    }
    STORAGE_DEVICE_DESCRIPTOR descriptor{};
    descriptor.Version = sizeof(descriptor); descriptor.Size = 80; descriptor.SerialNumberOffset = 40;
    Bytes descriptorBytes(80); memcpy(descriptorBytes.data(), &descriptor, sizeof(descriptor));
    const char serialText[] = "  SYNTHETIC-C-SERIAL  ";
    memcpy(descriptorBytes.data() + 40, serialText, sizeof(serialText));
    assert(StorageDescriptorSerial(descriptorBytes) == "SYNTHETIC-C-SERIAL");
    for (DWORD offset : {DWORD(0), DWORD(4), DWORD(80), DWORD(MAXDWORD)}) {
        auto invalidDescriptor = descriptorBytes;
        memcpy(invalidDescriptor.data() + offsetof(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset), &offset, 4);
        rejected = false; try { StorageDescriptorSerial(invalidDescriptor); } catch (...) { rejected = true; }
        assert(rejected);
    }
    auto unterminated = descriptorBytes; memset(unterminated.data() + 40, 'X', 40);
    rejected = false; try { StorageDescriptorSerial(unterminated); } catch (...) { rejected = true; }
    assert(rejected);
    for (const char* placeholder : {"", "0", " 000 ", "UNKNOWN", "N/A"}) {
        auto invalidDescriptor = descriptorBytes;
        memcpy(invalidDescriptor.data() + 40, placeholder, strlen(placeholder) + 1);
        rejected = false; try { StorageDescriptorSerial(invalidDescriptor); } catch (...) { rejected = true; }
        assert(rejected);
    }
    auto allHardware = pciA;
    allHardware.insert(tpm.begin(), tpm.end());
    allHardware["gpu/uuid/0"] = Bytes{'G','P','U','-','t','e','s','t'};
    auto beforeStorage = Combine(nvram, allHardware);
    auto storageSerial = StorageDescriptorSerial(descriptorBytes);
    allHardware["storage/c/serial"] = Bytes(storageSerial.begin(), storageSerial.end());
    assert(Combine(nvram, allHardware) != beforeStorage);
    auto allJson = payload::Json(nvram, allHardware);
    assert(allJson.find("\"storage_query_property_serial\": \"SYNTHETIC-C-SERIAL\"") != std::string::npos);
    assert(payload::Decrypt(payload::Encrypt(allJson)) == allJson);
    allHardware["storage/c/serial"].back() ^= 1;
    assert(payload::Json(nvram, allHardware) != allJson);
    std::cout << "PASS: GPU PCI normalization/ordering, C: disk selection, storage descriptor bounds, JSON/hash integration\n";

    // Cleanup must also run on exception; protected secrets must support repeated
    // use and invalidate their contents if the consumer throws.
    Bytes wipeTest{1,2,3};
    try { secure_memory::WipeOnExit<Bytes> cleanup(wipeTest); throw 1; } catch (...) {}
    assert(wipeTest == Bytes(3));
    payload::Secret protectedKey;
    protectedKey.Set([](unsigned char* bytes) { memset(bytes, 0x5a, 32); });
    for (int i = 0; i < 2; ++i)
        assert(protectedKey.Use([](unsigned char* bytes) { return bytes[0] == 0x5a && bytes[31] == 0x5a; }));
    try { protectedKey.Use([](unsigned char*) -> bool { throw std::runtime_error("synthetic failure"); }); } catch (...) {}
    rejected = false;
    try { protectedKey.Use([](unsigned char*) { return true; }); } catch (...) { rejected = true; }
    assert(rejected);
    std::cout << "PASS: protected key reuse, failure invalidation, exception cleanup\n";
    const auto missing = payload::Json(nvram, {});
    assert(missing.find("\"tpm_fingerprint\": null") != std::string::npos);
    assert(missing.find("\"gpu_serials\": []") != std::string::npos);
    Fields uuidFields{{"gpu/uuid/0", Bytes{'G','P','U','-','t','e','s','t'}}};
    assert(payload::Json(nvram, uuidFields).find("\"gpu_uuids\": [\n    \"GPU-test\"") != std::string::npos);
    assert(Combine(nvram, uuidFields) != base);
    assert(payload::Quote("a\"b\\c\n") == "\"a\\\"b\\\\c\\u000a\"");
    for (size_t offset : {size_t(5), size_t(21), size_t(33), size_t(49)}) {
        auto modified = payload::Unbase64(encrypted);
        modified[offset] ^= 1;
        rejected = false;
        try { payload::Decrypt(payload::Base64(modified)); } catch (...) { rejected = true; }
        assert(rejected); // Salt, nonce, tag and ciphertext tampering all fail closed.
    }
    for (const auto& invalidText : {std::string("not base64!"), encrypted.substr(0, 12), std::string("YQ==junk")}) {
        rejected = false;
        try { payload::Decrypt(invalidText); } catch (...) { rejected = true; }
        assert(rejected);
    }
    std::cout << "PASS: Base64, AES-GCM known vector, JSON roundtrip, fresh randomness, optional fields, tamper rejection\n";
    if (argc == 2 && std::string(argv[1]) == "--fixtures") {
        std::ofstream("synthetic-payload.enc", std::ios::binary) << encrypted;
        std::ofstream("synthetic-payload.json", std::ios::binary) << json;
    }
}
