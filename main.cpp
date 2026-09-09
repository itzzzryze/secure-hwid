// Win32/GDI+ interface and hardware collection worker.

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <objidl.h>
#include <shlobj.h>
#include <dwmapi.h>
#include <gdiplus.h>
#include <bcrypt.h>
#include <timeapi.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cmath>
#include "encrypted_payload.h"
#include "discord_delivery.h"
#include "hardware_identity.h"
#include <windowsx.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winmm.lib")

static constexpr float WIN_W = 420.0f;
static constexpr float WIN_H = 264.0f;

static const Gdiplus::Color COL_BG      (255, 23, 24, 27);
static const Gdiplus::Color COL_TEXT    (255, 240, 240, 243);
static const Gdiplus::Color COL_TRACK   (255, 45, 48, 53);
static const Gdiplus::Color COL_ACCENT  (255, 200, 216, 227);

// timing (ms)
static constexpr float T_APPEAR      = 920.0f;
static constexpr float T_BAR_TO_FULL = 350.0f;
static constexpr float T_LOADOUT    = 480.0f;   // loading UI fades out fully before done appears
static constexpr float T_DONE_HOLD   = 2600.0f;
static constexpr float T_EXIT        = 620.0f;
static constexpr float MIN_WORK_MS   = 1800.0f;

static float EaseOutCubic(float t)  { t = t < 0 ? 0 : t > 1 ? 1 : t; float u = 1 - t; return 1 - u * u * u; }
static float EaseInOutCubic(float t){ t = t < 0 ? 0 : t > 1 ? 1 : t; return t < .5f ? 4*t*t*t : 1 - powf(-2*t + 2, 3) / 2; }
static float EaseOutQuint(float t)  { t = t < 0 ? 0 : t > 1 ? 1 : t; float u = 1 - t; return 1 - u * u * u * u * u; }
static float Clamp01(float v)       { return v < 0 ? 0 : v > 1 ? 1 : v; }

typedef LONG (NTAPI *PFN_NtEnum)(int, void*, unsigned long*);

struct HwidResult {
    std::atomic_bool done{false};
    std::atomic_bool ok{false};
    std::atomic_int stage{0};
    std::atomic_bool cancel{false};
    std::wstring errorTitle;
};
static HwidResult g_hwid;
static std::thread g_worker;

static bool EnableFirmwarePrivilege() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return false;
    TOKEN_PRIVILEGES tp{};
    if (!LookupPrivilegeValueW(nullptr, SE_SYSTEM_ENVIRONMENT_NAME, &tp.Privileges[0].Luid)) { CloseHandle(tok); return false; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, 0, nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(tok);
    return ok && err == ERROR_SUCCESS;
}

static void HwidWorker() {
    HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    try {
        g_hwid.stage = -1;
        {
            auto path = webhook_config::Path();
            secure_memory::WipeOnExit<std::wstring> wipePath(path);
        }
        g_hwid.stage = 0;
        if (!EnableFirmwarePrivilege()) throw std::runtime_error("firmware privilege not held; run as administrator");
        auto enumerate = (PFN_NtEnum)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtEnumerateSystemEnvironmentValuesEx");
        if (!enumerate) throw std::runtime_error("NVRAM enumeration unavailable");
        identity::Bytes buffer(1 << 20);
        secure_memory::WipeOnExit<identity::Bytes> wipeBuffer(buffer);
        unsigned long length = 0;
        LONG status = 0;
        for (int attempt = 0; attempt < 4; ++attempt) {
            length = (unsigned long)buffer.size();
            status = enumerate(2, buffer.data(), &length);
            if (status != (LONG)0xC0000023 && status != (LONG)0x80000005) break;
            size_t required = (std::max)(size_t(length), buffer.size() * 2);
            if (required > 64 * 1024 * 1024) break;
            SecureZeroMemory(buffer.data(), buffer.size());
            buffer.resize(required);
        }
        if (status != 0) throw std::runtime_error("NVRAM enumeration failed");
        auto nvram = identity::ParseNvram(buffer, length);
        SecureZeroMemory(buffer.data(), buffer.size());
        struct ClearFields {
            identity::Fields& fields;
            ~ClearFields() { for (auto& field : fields) SecureZeroMemory(field.second.data(), field.second.size()); }
        } wipeNvram{nvram};
        identity::Fields optional;
        ClearFields wipeOptional{optional};
        if (nvram.empty()) throw std::runtime_error("firmware identity unavailable");
        identity::ReadSmbios(optional);
        g_hwid.stage = 1;
        identity::ReadGpuPci(optional);
        identity::ReadGpu(optional);
        g_hwid.stage = 2;
        identity::ReadTpm(optional);
        g_hwid.stage = 3;
        identity::ReadCDrive(optional);
        g_hwid.stage = 4;
        auto json = payload::Json(nvram, optional);
        secure_memory::WipeOnExit<std::string> wipeJson(json);
        auto encrypted = payload::Encrypt(json);
        SecureZeroMemory(&json[0], json.size());
        g_hwid.stage = 5;
        delivery::Send(encrypted, g_hwid.cancel);
        g_hwid.ok = !g_hwid.cancel;
    } catch (const std::exception& error) {
        g_hwid.ok = false;
        g_hwid.errorTitle = g_hwid.stage == -1 ? L"Set SECURE_HWID_WEBHOOK" :
            g_hwid.stage == 0 ? L"Firmware unavailable" :
            g_hwid.stage == 1 ? L"GPU identity unavailable" :
            g_hwid.stage == 2 ? L"TPM unavailable" :
            g_hwid.stage == 3 ? L"C: drive identity unavailable" :
            g_hwid.stage == 5 ? L"Discord delivery failed" : L"Couldn't create identity";
        if (g_hwid.stage == 5) {
            std::string message(error.what());
            if (message == "Discord rate limited - retry later") g_hwid.errorTitle = L"Retry Discord later";
            else if (message == "report exceeds Discord message limit") g_hwid.errorTitle = L"Report exceeds Discord limit";
            else if (message == "Discord webhook unavailable") g_hwid.errorTitle = L"Webhook unavailable";
        }
    }
    if (SUCCEEDED(com)) CoUninitialize();
    g_hwid.done = true;
}

enum Phase { PH_APPEAR, PH_LOADING, PH_TOFULL, PH_LOADOUT, PH_DONE, PH_EXIT, PH_QUIT };
static Phase g_phase = PH_APPEAR;
static std::chrono::steady_clock::time_point g_phaseStart;
static std::chrono::steady_clock::time_point g_t0;

static HWND g_hwnd = nullptr;
static ULONG_PTR g_gdiToken = 0;
static Gdiplus::Bitmap* g_backing = nullptr;
static Gdiplus::Graphics* g_gfx = nullptr;

static float WinW = WIN_W, WinH = WIN_H;
static float S = 1.0f;

// Shared animation clock.
static float NowMs()  { return std::chrono::duration<float, std::milli>(std::chrono::steady_clock::now() - g_t0).count(); }
static float PhaseMs(){ return std::chrono::duration<float, std::milli>(std::chrono::steady_clock::now() - g_phaseStart).count(); }
static void  SetPhase(Phase p) { g_phase = p; g_phaseStart = std::chrono::steady_clock::now(); }

// captured once, when the crossfade begins
static float g_doneStartMs = 0.0f;
static float g_fillAtCompletion = 0.0f;
static bool g_reduceMotion = false;
static float g_progress = 0, g_lastFrame = 0, g_hoverClose = 0, g_hoverRetry = 0;
static bool g_closeHot = false, g_retryHot = false;
static BYTE g_alpha = 0;
static float g_lift = 0;
static POINT g_origin{};
static HDC g_memDC = nullptr;
static HBITMAP g_dib = nullptr, g_oldDib = nullptr;
static float g_spinnerEnd = 0, g_sweepEnd = 0;
static bool g_exitShowsResult = false;
static BYTE g_exitAlpha = 255;
static float g_exitLift = 0;
static float g_scale = .1f, g_exitScale = 1;

static void FillRounded(Gdiplus::Graphics& g, float x, float y, float w, float h, float r, const Gdiplus::Color& c) {
    (void)r; // Square edges throughout the card and controls.
    if (w <= 0 || h <= 0) return;
    Gdiplus::SolidBrush b(c);
    g.FillRectangle(&b, x, y, w, h);
}

static void StrokeArc(Gdiplus::Graphics& g, float cx, float cy, float r, float startDeg, float sweepDeg, float width, const Gdiplus::Color& c) {
    Gdiplus::Pen pen(c, width);
    pen.SetStartCap(Gdiplus::LineCapRound);
    pen.SetEndCap(Gdiplus::LineCapRound);
    g.DrawArc(&pen, cx - r, cy - r, r * 2, r * 2, startDeg, sweepDeg);
}

struct Fonts {
    Gdiplus::FontFamily* fam = nullptr;
    Gdiplus::Font* title = nullptr;
    Gdiplus::Font* smallFont = nullptr;
    void Init() {
        fam = new Gdiplus::FontFamily(L"Segoe UI Variable Text");
        if (fam->GetLastStatus() != Gdiplus::Ok) { delete fam; fam = new Gdiplus::FontFamily(L"Segoe UI"); }
        title = new Gdiplus::Font(fam, 18.0f * S, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
        smallFont = new Gdiplus::Font(fam, 12.0f * S, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
    }
};
static Fonts g_fonts;

static void DrawCenteredText(Gdiplus::Graphics& g, const std::wstring& s, Gdiplus::Font* f, float cx, float y, const Gdiplus::Color& c) {
    Gdiplus::SolidBrush b(c);
    Gdiplus::StringFormat sf(Gdiplus::StringFormat::GenericDefault());
    sf.SetAlignment(Gdiplus::StringAlignmentCenter);
    Gdiplus::RectF layout(cx - WinW / 2, y, WinW, 1000);
    g.DrawString(s.c_str(), -1, f, layout, &sf, &b);
}

static void DrawGathering(Gdiplus::Graphics& g, float cx, float y, float now, BYTE alpha) {
    const wchar_t* label = g_hwid.stage == 5 ? L"sending to Discord" : L"gathering";
    Gdiplus::StringFormat format(Gdiplus::StringFormat::GenericTypographic());
    Gdiplus::RectF bounds;
    g.MeasureString(label, -1, g_fonts.title, Gdiplus::PointF(0, 0), &format, &bounds);
    // Reserve all three dots so the label stays centered throughout the cycle.
    float x = cx - (bounds.Width + 22 * S) / 2;
    Gdiplus::SolidBrush text(Gdiplus::Color(alpha, 235, 238, 241));
    g.DrawString(label, -1, g_fonts.title, Gdiplus::PointF(x, y), &format, &text);
    for (int i = 0; i < 3; ++i) {
        float wave = g_reduceMotion ? 1 : .5f + .5f * cosf(now / 1400 * 6.2831853f - i * .9f);
        float pulse = wave * wave;
        float lift = g_reduceMotion ? 0 : 1.2f * S * pulse;
        Gdiplus::SolidBrush dot(Gdiplus::Color((BYTE)(alpha * (.22f + .78f * pulse)), 235, 238, 241));
        g.DrawString(L".", -1, g_fonts.title,
            Gdiplus::PointF(x + bounds.Width + (6 + i * 6) * S, y - lift), &format, &dot);
    }
}

static void Render() {
    if (!g_gfx) return;
    auto& g = *g_gfx;
    g.ResetTransform();
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.SetTextRenderingHint(Gdiplus::TextRenderingHintAntiAliasGridFit);
    g.Clear(Gdiplus::Color(0, 0, 0, 0));
    g.ScaleTransform(g_scale, g_scale);
    FillRounded(g, 0, 0, WinW, WinH, 22 * S, COL_BG);
    const float cx = WinW / 2, cy = 102 * S, now = NowMs();
    const bool result = g_phase == PH_LOADOUT || g_phase == PH_DONE || (g_phase == PH_EXIT && g_exitShowsResult);
    const float dt = result ? now - g_doneStartMs : 0;
    float transition = g_phase == PH_LOADOUT ? Clamp01(dt / T_LOADOUT) : result ? 1.0f : 0.0f;
    float loadingAlpha = 1 - EaseInOutCubic(Clamp01(transition * 2.4f));
    float resultAlpha = EaseOutCubic(Clamp01((transition - 0.35f) / 0.65f));
    float entrance = g_reduceMotion ? 1 : EaseOutQuint(Clamp01((now - 100) / 700));
    loadingAlpha *= g_reduceMotion ? 1 : EaseOutCubic(Clamp01((now - 80) / 470));
    float contentY = g_reduceMotion ? 0 : (1 - entrance) * 11 * S;

    FillRounded(g, WinW - 47 * S, 13 * S, 32 * S, 32 * S, 10 * S,
        Gdiplus::Color((BYTE)(g_hoverClose * 18), 255, 255, 255));
    Gdiplus::Pen closePen(Gdiplus::Color(255, (BYTE)(106 + g_hoverClose * 100),
        (BYTE)(112 + g_hoverClose * 100), (BYTE)(120 + g_hoverClose * 100)), 1.3f * S);
    float closeX = WinW - 31 * S, closeY = 29 * S;
    g.DrawLine(&closePen, closeX - 4 * S, closeY - 4 * S, closeX + 4 * S, closeY + 4 * S);
    g.DrawLine(&closePen, closeX + 4 * S, closeY - 4 * S, closeX - 4 * S, closeY + 4 * S);

    // The spinner and result share an anchor, so completion has no layout jump.
    if (loadingAlpha > .001f) {
        BYTE alpha = (BYTE)(loadingAlpha * 255);
        float phase = now / 1800.0f * 6.2831853f;
        float sweep = g_reduceMotion ? 260 : 190 + 115 * sinf(phase);
        float rotation = g_reduceMotion ? -90 : now * .20f - sweep * .5f;
        if (g_phase == PH_TOFULL || g_phase == PH_LOADOUT) {
            float t = g_phase == PH_LOADOUT ? 1 : EaseInOutCubic(PhaseMs() / T_BAR_TO_FULL);
            sweep = g_sweepEnd + (360 - g_sweepEnd) * t;
            rotation = g_spinnerEnd + (g_reduceMotion ? 0 : 50 * t);
        }
        StrokeArc(g, cx, cy + contentY, 23 * S, -90, 360, 2.2f * S,
            Gdiplus::Color(alpha, COL_TRACK.GetR(), COL_TRACK.GetG(), COL_TRACK.GetB()));
        StrokeArc(g, cx, cy + contentY, 23 * S, rotation, sweep, 2.2f * S,
            Gdiplus::Color(alpha, COL_ACCENT.GetR(), COL_ACCENT.GetG(), COL_ACCENT.GetB()));
        DrawGathering(g, cx, 153 * S + contentY, now, alpha);
        float width = 146 * S, height = 2 * S;
        FillRounded(g, cx - width / 2, 199 * S, width, height, height / 2,
            Gdiplus::Color(alpha, 45, 48, 53));
        FillRounded(g, cx - width / 2, 199 * S, width * g_progress, height, height / 2,
            Gdiplus::Color(alpha, 150, 169, 184));
    }
    if (resultAlpha > .001f) {
        BYTE alpha = (BYTE)(resultAlpha * 255);
        float rise = g_reduceMotion ? 0 : (1 - EaseOutQuint(Clamp01(dt / 650))) * 5 * S;
        Gdiplus::Color accent(alpha, 200, 216, 227);
        StrokeArc(g, cx, cy, 23 * S, -90, 360, 2.2f * S,
            g_hwid.ok ? accent : Gdiplus::Color(alpha, 215, 145, 140));
        float reveal = g_reduceMotion ? 1 : EaseOutCubic(Clamp01((dt - 160) / 450));
        Gdiplus::Pen pen(g_hwid.ok ? accent : Gdiplus::Color(alpha, 215, 145, 140), 2.2f * S);
        pen.SetStartCap(Gdiplus::LineCapRound); pen.SetEndCap(Gdiplus::LineCapRound);
        if (g_hwid.ok) {
            Gdiplus::PointF a(cx - 10 * S, cy), b(cx - 3 * S, cy + 7 * S), c(cx + 11 * S, cy - 8 * S);
            float first = Clamp01(reveal * 3), second = Clamp01((reveal - 1.0f / 3) * 1.5f);
            if (first > 0) g.DrawLine(&pen, a.X, a.Y, a.X + (b.X - a.X) * first, a.Y + (b.Y - a.Y) * first);
            if (second > 0) g.DrawLine(&pen, b.X, b.Y, b.X + (c.X - b.X) * second, b.Y + (c.Y - b.Y) * second);
        } else {
            float r = 7 * S * reveal;
            g.DrawLine(&pen, cx - r, cy - r, cx + r, cy + r);
            g.DrawLine(&pen, cx + r, cy - r, cx - r, cy + r);
        }
        DrawCenteredText(g, g_hwid.ok ? L"done" : g_hwid.errorTitle,
            g_fonts.title, cx, 153 * S + rise, Gdiplus::Color(alpha, 235, 238, 241));
        if (!g_hwid.ok) {
            FillRounded(g, cx - 48 * S, 194 * S, 96 * S, 30 * S, 9 * S,
                Gdiplus::Color((BYTE)(resultAlpha * (16 + 12 * g_hoverRetry)), 255, 255, 255));
            DrawCenteredText(g, L"Try again", g_fonts.smallFont, cx, 201 * S, Gdiplus::Color(alpha, 202, 208, 214));
        }
    }
}

// Reuse the premultiplied DIB for GDI+ rendering and the layered window.
static void DestroyBacking() {
    delete g_gfx; g_gfx = nullptr;
    delete g_backing; g_backing = nullptr;
    if (g_memDC && g_oldDib) SelectObject(g_memDC, g_oldDib);
    if (g_dib) DeleteObject(g_dib);
    if (g_memDC) DeleteDC(g_memDC);
    g_memDC = nullptr; g_dib = nullptr; g_oldDib = nullptr;
}
static void RecreateBacking() {
    DestroyBacking();
    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = (int)WinW; info.bmiHeader.biHeight = -(int)WinH;
    info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    g_memDC = CreateCompatibleDC(nullptr);
    g_dib = CreateDIBSection(g_memDC, &info, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!g_memDC || !g_dib || !bits) throw std::runtime_error("render surface unavailable");
    g_oldDib = (HBITMAP)SelectObject(g_memDC, g_dib);
    g_backing = new Gdiplus::Bitmap((int)WinW, (int)WinH, (int)WinW * 4, PixelFormat32bppPARGB, (BYTE*)bits);
    g_gfx = new Gdiplus::Graphics(g_backing);
}
static void PresentFrame() {
    g_gfx->Flush(Gdiplus::FlushIntentionSync);
    SIZE size{(LONG)lroundf(WinW * g_scale), (LONG)lroundf(WinH * g_scale)};
    POINT src{}, dst{g_origin.x + ((LONG)WinW - size.cx) / 2,
        g_origin.y + ((LONG)WinH - size.cy) / 2};
    BLENDFUNCTION blend{AC_SRC_OVER, 0, g_alpha, AC_SRC_ALPHA};
    UpdateLayeredWindow(g_hwnd, nullptr, &dst, &size, g_memDC, &src, 0, &blend, ULW_ALPHA);
}
static void StartWork() {
    if (g_worker.joinable()) g_worker.join();
    g_hwid.done = false; g_hwid.ok = false; g_hwid.cancel = false; g_hwid.stage = 0;
    g_hwid.errorTitle.clear();
    g_progress = 0; g_lastFrame = 0;
    g_t0 = std::chrono::steady_clock::now();
    g_worker = std::thread(HwidWorker);
}
static void RequestClose() {
    if (g_phase == PH_EXIT || g_phase == PH_QUIT) return;
    g_hwid.cancel = true;
    g_exitShowsResult = g_phase == PH_LOADOUT || g_phase == PH_DONE;
    g_exitAlpha = g_alpha; g_exitLift = g_lift;
    g_exitScale = g_scale;
    SetPhase(PH_EXIT);
}
static void Tick() {
    float pm = PhaseMs(), now = NowMs();
    float elapsed = (std::min)(64.0f, (std::max)(0.0f, now - g_lastFrame));
    g_lastFrame = now;
    float easeHover = 1 - expf(-elapsed / 85);
    g_hoverClose += ((g_closeHot ? 1.0f : 0.0f) - g_hoverClose) * easeHover;
    g_hoverRetry += ((g_retryHot ? 1.0f : 0.0f) - g_hoverRetry) * easeHover;
    const float targets[] = {.12f, .30f, .46f, .62f, .76f, .90f};
    if (g_phase == PH_APPEAR || g_phase == PH_LOADING)
        g_progress += (targets[(std::max)(0, (std::min)(5, g_hwid.stage.load()))] - g_progress) * (1 - expf(-elapsed / 250));
    switch (g_phase) {
    case PH_APPEAR: {
        float t = EaseOutQuint(Clamp01(pm / T_APPEAR));
        g_scale = g_reduceMotion ? 1 : .1f + .9f * t;
        g_alpha = (BYTE)(255 * EaseOutCubic(Clamp01(pm / 460)));
        if (pm >= T_APPEAR) { g_alpha = 255; g_scale = 1; SetPhase(PH_LOADING); }
        break;
    }
    case PH_LOADING:
        if (now >= MIN_WORK_MS && g_hwid.done) {
            g_fillAtCompletion = g_progress;
            g_sweepEnd = g_reduceMotion ? 260 : 190 + 115 * sinf(now / 1800 * 6.2831853f);
            g_spinnerEnd = g_reduceMotion ? -90 : now * .20f - g_sweepEnd * .5f;
            SetPhase(PH_TOFULL);
        }
        break;
    case PH_TOFULL:
        g_progress = g_fillAtCompletion + (1 - g_fillAtCompletion) * EaseInOutCubic(pm / T_BAR_TO_FULL);
        if (pm >= T_BAR_TO_FULL) { g_doneStartMs = now; SetPhase(PH_LOADOUT); }
        break;
    case PH_LOADOUT:
        if (pm >= T_LOADOUT) SetPhase(PH_DONE);
        break;
    case PH_DONE:
        if (g_hwid.ok && pm >= T_DONE_HOLD) RequestClose();
        break;
    case PH_EXIT: {
        float t = EaseInOutCubic(Clamp01(pm / T_EXIT));
        g_scale = g_reduceMotion ? 1 : g_exitScale + (.1f - g_exitScale) * t;
        g_alpha = (BYTE)(g_exitAlpha * (1 - t));
        g_lift = g_reduceMotion ? 0 : g_exitLift - 6 * S * t;
        if (pm >= T_EXIT) { g_phase = PH_QUIT; PostQuitMessage(0); }
        break;
    }
    case PH_QUIT: break;
    }
}
static bool HitClose(POINT p) { float x = p.x / g_scale, y = p.y / g_scale; return x >= WinW - 49 * S && x <= WinW - 13 * S && y >= 11 * S && y <= 47 * S; }
static bool HitRetry(POINT p) { return g_phase == PH_DONE && !g_hwid.ok && p.x >= WinW / 2 - 48 * S && p.x <= WinW / 2 + 48 * S && p.y >= 194 * S && p.y <= 224 * S; }
static void Retry() { if (g_phase == PH_DONE && !g_hwid.ok) { StartWork(); SetPhase(PH_LOADING); } }
static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_PAINT: { PAINTSTRUCT ps; BeginPaint(h, &ps); EndPaint(h, &ps); return 0; }
    case WM_ERASEBKGND: return 1;
    case WM_CLOSE: RequestClose(); return 0;
    case WM_KEYDOWN:
        if (w == VK_ESCAPE) RequestClose();
        if (w == VK_RETURN || w == VK_SPACE) Retry();
        return 0;
    case WM_MOUSEMOVE: {
        POINT p{GET_X_LPARAM(l), GET_Y_LPARAM(l)};
        g_closeHot = HitClose(p); g_retryHot = HitRetry(p);
        TRACKMOUSEEVENT track{sizeof(track), TME_LEAVE, h, 0}; TrackMouseEvent(&track);
        return 0;
    }
    case WM_MOUSELEAVE: g_closeHot = g_retryHot = false; return 0;
    case WM_LBUTTONUP: {
        POINT p{GET_X_LPARAM(l), GET_Y_LPARAM(l)};
        if (HitClose(p)) RequestClose(); else if (HitRetry(p)) Retry();
        return 0;
    }
    case WM_NCHITTEST: {
        POINT p{GET_X_LPARAM(l), GET_Y_LPARAM(l)}; ScreenToClient(h, &p);
        return HitClose(p) || HitRetry(p) ? HTCLIENT : g_phase != PH_APPEAR && g_phase != PH_EXIT && p.y < 55 * S ? HTCAPTION : HTCLIENT;
    }
    case WM_EXITSIZEMOVE: { RECT r; GetWindowRect(h, &r); g_origin = {r.left, r.top}; return 0; }
    case WM_SETTINGCHANGE: {
        BOOL enabled = TRUE; SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &enabled, 0);
        g_reduceMotion = !enabled; return 0;
    }
    case WM_DESTROY: g_hwid.cancel = true; PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, m, w, l);
}
int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int show) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    BOOL animation = TRUE;
    SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &animation, 0);
    g_reduceMotion = !animation;
    Gdiplus::GdiplusStartupInput startup;
    if (Gdiplus::GdiplusStartup(&g_gdiToken, &startup, nullptr) != Gdiplus::Ok) return 1;
    HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    timeBeginPeriod(1);
    S = GetDpiForSystem() / 96.0f;
    WinW = roundf(WIN_W * S); WinH = roundf(WIN_H * S);
    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc; wc.hInstance = inst; wc.lpszClassName = L"HwidLoader";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassW(&wc);
    RECT work{}; SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    g_origin = {(LONG)(work.left + (work.right - work.left - WinW) / 2),
                (LONG)(work.top + (work.bottom - work.top - WinH) / 2)};
    g_hwnd = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        L"HwidLoader", L"HWID", WS_POPUP, g_origin.x, g_origin.y, (int)WinW, (int)WinH,
        nullptr, nullptr, inst, nullptr);
    if (!g_hwnd) return 1;
    DWM_WINDOW_CORNER_PREFERENCE pref = DWMWCP_DONOTROUND;
    DwmSetWindowAttribute(g_hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &pref, sizeof(pref));
    int result = 0;
    try {
        RecreateBacking(); g_fonts.Init();
        StartWork(); SetPhase(PH_APPEAR); g_scale = g_reduceMotion ? 1 : .1f;
        Render(); PresentFrame(); // First visible frame is already initialized.
        ShowWindow(g_hwnd, show);
        MSG msg{}; bool running = true;
        while (running) {
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT) running = false;
                TranslateMessage(&msg); DispatchMessageW(&msg);
            }
            if (!running || g_phase == PH_QUIT) break;
            Tick(); Render(); PresentFrame();
            if (FAILED(DwmFlush())) Sleep(16);
        }
    } catch (...) { result = 1; }
    g_hwid.cancel = true;
    ShowWindow(g_hwnd, SW_HIDE);
    if (g_worker.joinable()) g_worker.join();
    DestroyWindow(g_hwnd);
    DestroyBacking();
    delete g_fonts.title; delete g_fonts.smallFont; delete g_fonts.fam;
    timeEndPeriod(1);
    Gdiplus::GdiplusShutdown(g_gdiToken);
    if (SUCCEEDED(com)) CoUninitialize();
    return result;
}
