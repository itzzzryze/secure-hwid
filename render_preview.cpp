// Render the actual UI offscreen with synthetic state; does not query hardware.
#include "main.cpp"
#include <iostream>
int main() {
    Gdiplus::GdiplusStartupInput startup;
    if (Gdiplus::GdiplusStartup(&g_gdiToken, &startup, nullptr) != Gdiplus::Ok) return 1;
    int result = 0;
    {
        UINT count = 0, size = 0;
        Gdiplus::GetImageEncodersSize(&count, &size);
        std::vector<unsigned char> storage(size);
        auto* encoders = reinterpret_cast<Gdiplus::ImageCodecInfo*>(storage.data());
        Gdiplus::GetImageEncoders(count, size, encoders);
        CLSID png{};
        for (UINT i = 0; i < count; ++i) if (!wcscmp(encoders[i].MimeType, L"image/png")) png = encoders[i].Clsid;
        RecreateBacking();
        g_fonts.Init();
        Gdiplus::Bitmap sheet((int)WIN_W * 3, (int)WIN_H, PixelFormat32bppPARGB);
        Gdiplus::Graphics canvas(&sheet);
        canvas.Clear(Gdiplus::Color(255, 16, 16, 19));
        g_t0 = std::chrono::steady_clock::now() - std::chrono::milliseconds(2200);
        g_phaseStart = std::chrono::steady_clock::now();
        g_phase = PH_LOADING;
        g_scale = 1;
        g_progress = .65f;
        Render(); canvas.DrawImage(g_backing, 0, 0);
        g_phase = PH_DONE; g_doneStartMs = NowMs() - 1000; g_hwid.ok = true;
        Render(); canvas.DrawImage(g_backing, (int)WIN_W, 0);
        g_hwid.ok = false;
        g_hwid.errorTitle = L"Firmware unavailable";
        Render(); canvas.DrawImage(g_backing, (int)WIN_W * 2, 0);
        if (sheet.Save(L"ui-preview.png", &png) != Gdiplus::Ok) result = 1;
        // Exercise opening and closing at 60Hz, including exact scale endpoints.
        Gdiplus::Bitmap motion((int)WIN_W * 4, (int)WIN_H * 2, PixelFormat32bppPARGB);
        Gdiplus::Graphics timeline(&motion);
        timeline.Clear(Gdiplus::Color(255, 40, 42, 46));
        for (int sample = 0; sample < 8; ++sample) {
            float t = (sample % 4) / 3.0f;
            g_scale = sample < 4 ? .1f + .9f * EaseOutQuint(t) : 1 - .9f * EaseInOutCubic(t);
            g_phase = sample < 4 ? PH_LOADING : PH_DONE;
            g_hwid.ok = true; g_doneStartMs = NowMs() - 1000;
            Render();
            int w = (int)lroundf(WinW * g_scale), h = (int)lroundf(WinH * g_scale);
            timeline.DrawImage(g_backing, Gdiplus::Rect(sample % 4 * (int)WIN_W + ((int)WinW - w) / 2,
                sample / 4 * (int)WIN_H + ((int)WinH - h) / 2, w, h), 0, 0, w, h, Gdiplus::UnitPixel);
        }
        if (motion.Save(L"motion-preview.png", &png) != Gdiplus::Ok) result = 1;
        DWORD objects = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
        auto start = std::chrono::steady_clock::now();
        for (int frame = 0; frame < 300; ++frame) {
            g_phase = PH_LOADING;
            float t = (frame % 60) / 59.0f;
            g_scale = frame % 120 < 60 ? .1f + .9f * EaseOutQuint(t) : 1 - .9f * EaseInOutCubic(t);
            g_t0 = std::chrono::steady_clock::now() - std::chrono::milliseconds(frame * 16);
            Render();
            g_gfx->Flush(Gdiplus::FlushIntentionSync);
        }
        if (GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS) != objects) result = 1;
        float elapsed = std::chrono::duration<float, std::milli>(std::chrono::steady_clock::now() - start).count();
        std::cout << "300 offscreen frames: " << elapsed / 300 << " ms/frame; GDI object count stable\n";
        DestroyBacking();
        delete g_fonts.title; delete g_fonts.smallFont; delete g_fonts.fam;
    }
    Gdiplus::GdiplusShutdown(g_gdiToken);
    if (!result) std::cout << "Rendered loading, success and error states to ui-preview.png\n";
    return result;
}
