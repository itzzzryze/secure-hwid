#pragma once
#include "secure_memory.h"
#include <string>

namespace webhook_config {
// Runtime configuration only. No destination is built into distributed binaries.
inline std::wstring Path() {
    constexpr wchar_t variable[] = L"SECURE_HWID_WEBHOOK";
    DWORD size = GetEnvironmentVariableW(variable, nullptr, 0);
    if (!size || size > 2048) throw std::runtime_error("webhook configuration missing or invalid");
    std::wstring url(size, L'\0');
    secure_memory::WipeOnExit<std::wstring> wipeUrl(url);
    DWORD read = GetEnvironmentVariableW(variable, &url[0], size);
    if (!read || read >= size) throw std::runtime_error("webhook configuration missing or invalid");
    url.resize(read);
    const std::wstring prefix = L"https://discord.com/api/webhooks/";
    if (url.compare(0, prefix.size(), prefix)) throw std::runtime_error("webhook configuration missing or invalid");
    const size_t separator = url.find(L'/', prefix.size());
    if (separator == std::wstring::npos || separator == prefix.size() || separator + 1 == url.size())
        throw std::runtime_error("webhook configuration missing or invalid");
    for (size_t i = prefix.size(); i < separator; ++i)
        if (url[i] < L'0' || url[i] > L'9') throw std::runtime_error("webhook configuration missing or invalid");
    for (size_t i = separator + 1; i < url.size(); ++i)
        if (!(url[i] >= L'A' && url[i] <= L'Z') && !(url[i] >= L'a' && url[i] <= L'z') &&
            !(url[i] >= L'0' && url[i] <= L'9') && url[i] != L'_' && url[i] != L'-')
            throw std::runtime_error("webhook configuration missing or invalid");
    return url.substr(19) + L"?wait=true"; // Strip the exact validated HTTPS origin.
}
}
