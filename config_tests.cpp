#define WIN32_LEAN_AND_MEAN
#include "webhook_config.h"
#include <cassert>
#include <iostream>

int main() {
    const wchar_t* name = L"SECURE_HWID_WEBHOOK";
    DWORD length = GetEnvironmentVariableW(name, nullptr, 0);
    std::wstring previous(length, L'\0');
    if (length) { GetEnvironmentVariableW(name, &previous[0], length); previous.resize(length - 1); }
    secure_memory::WipeOnExit<std::wstring> wipe(previous);
    struct Restore {
        const wchar_t* name; const std::wstring& value; bool existed;
        ~Restore() { SetEnvironmentVariableW(name, existed ? value.c_str() : nullptr); }
    } restore{name, previous, length != 0};
    const std::wstring origin = L"https://discord.com";
    const std::wstring route = L"/api/webhooks/123456789012345678/TEST_TOKEN_NOT_REAL";
    assert(SetEnvironmentVariableW(name, (origin + route).c_str()));
    assert(webhook_config::Path() == route + L"?wait=true");
    const std::wstring invalid[] = {
        L"", L"https://example.com" + route, L"http://discord.com" + route,
        L"https://discord.com.example.com" + route, origin + route + L"?wait=false",
        origin + route + L"#fragment", origin + route + L"\r\nX-Header: value",
        origin + L"/api/webhooks/not-a-number/token", origin + L"/api/webhooks/123/",
        origin + L"/api/webhooks/123/a/other", std::wstring(2049, L'x')
    };
    for (const auto& value : invalid) {
        assert(SetEnvironmentVariableW(name, value.empty() ? nullptr : value.c_str()));
        bool rejected = false;
        try { webhook_config::Path(); } catch (const std::runtime_error&) { rejected = true; }
        assert(rejected);
    }
    std::cout << "PASS: runtime webhook validation, missing configuration and destination restrictions\n";
}
