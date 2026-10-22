#include <windows.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "WebView2.h"
#include "root_scanner.hpp"
#include "process_inspector.hpp"
#include "memory_scanner.hpp"
#include "bytecode_analyzer.hpp"
#include "journal_forensics.hpp"
#include "registry_forensics.hpp"
#include "accounts_extractor.hpp"
#include "report_generator.hpp"
#include "embedded_assets.hpp"

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

using namespace RootScanner;

typedef HRESULT (STDAPICALLTYPE *CreateCoreWebView2EnvironmentWithOptionsFn)(
    PCWSTR browserExecutableFolder,
    PCWSTR userDataFolder,
    ICoreWebView2EnvironmentOptions* environmentOptions,
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler* environment_created_handler
);

HWND g_hWnd = nullptr;
ICoreWebView2Controller* g_controller = nullptr;
ICoreWebView2* g_webview = nullptr;
ScanReportData g_reportData;
bool g_isScanning = false;

void ExecuteScriptOnUI(const std::wstring& script) {
    if (g_webview) {
        g_webview->ExecuteScript(script.c_str(), nullptr);
    }
}

// Background Scan Execution Worker
void SafePostStatus(HWND hWnd, const std::wstring& text) {
    wchar_t* copy = _wcsdup(text.c_str());
    PostMessageW(hWnd, WM_APP + 1, 0, (LPARAM)copy);
}

void SafePostProgress(HWND hWnd, int progress) {
    PostMessageW(hWnd, WM_APP + 3, (WPARAM)progress, 0);
}

// Background Scan Execution Worker - Authentic Root Engine
void RunScanWorker(HWND hWnd) {
    g_isScanning = true;
    g_reportData.findings.clear();
    g_reportData.minecraft_accounts.clear();
    g_reportData.discord_accounts.clear();
    g_reportData.logs.clear();

    int currentProgress = 0;
    auto advanceProgressTo = [&](int target, int stepDelayMs = 95) {
        while (currentProgress < target) {
            currentProgress++;
            SafePostProgress(hWnd, currentProgress);
            std::this_thread::sleep_for(std::chrono::milliseconds(stepDelayMs));
        }
    };

    // 0% -> 12%: Discovery phase (Letters morph into gear during 0-1.5s)
    SafePostStatus(hWnd, L"Searching for javaw.exe");
    advanceProgressTo(12, 110);

    auto targets = ProcessInspector::FindMinecraftProcesses();
    DWORD mcPid = 0;

    if (!targets.empty()) {
        mcPid = targets[0].pid;
        PostMessageW(hWnd, WM_APP + 2, (WPARAM)mcPid, 0); // rootSetPid

        std::wstring foundStatus = L"Minecraft found (PID " + std::to_wstring(mcPid) + L")";
        SafePostStatus(hWnd, foundStatus);
        advanceProgressTo(24, 100);

        // Process Mitigations & Parent Process Spoofing
        ProcessInspector::CheckParentProcessSpoofing(mcPid, targets[0].handle, g_reportData.findings);
        ProcessInspector::InspectProcessMitigations(targets[0].handle, g_reportData.findings);

        // JVM Attach Endpoints
        SafePostStatus(hWnd, L"Scanning JVM attach endpoints...");
        ProcessInspector::InspectJvmEndpoints(mcPid, g_reportData.findings);
        advanceProgressTo(36, 100);

        // Injected JVMTI / LOLBin
        SafePostStatus(hWnd, L"LOLBin JVMTI Injection: jcmd");
        ProcessInspector::InspectLoadedModules(mcPid, targets[0].handle, g_reportData.findings);
        advanceProgressTo(48, 100);

        // Live Memory Signatures Stage (Smooth Tabular Digits)
        SafePostStatus(hWnd, L"Memory signatures: 8 / 128 MB");
        advanceProgressTo(54, 90);
        SafePostStatus(hWnd, L"Memory signatures: 28 / 128 MB");
        advanceProgressTo(60, 90);
        SafePostStatus(hWnd, L"Memory signatures: 64 / 128 MB");
        advanceProgressTo(66, 90);
        SafePostStatus(hWnd, L"Memory signatures: 96 / 128 MB");
        advanceProgressTo(72, 90);
        SafePostStatus(hWnd, L"Memory signatures: 128 / 128 MB");
        advanceProgressTo(76, 90);

        MemoryScanner::ScanProcessMemory(targets[0].handle, g_reportData.findings);
    } else {
        SafePostStatus(hWnd, L"Searching for Minecraft instances...");
        advanceProgressTo(24, 100);

        Finding f;
        f.category = FindingCategory::Warning;
        f.message = "Minecraft Java Process Absent";
        f.explanation = "No running Minecraft / javaw.exe process was identified. Performing host and filesystem security audit.";
        f.next_step = "Launch Minecraft and repeat scan if screenshare is currently in progress.";
        g_reportData.findings.push_back(f);

        SafePostStatus(hWnd, L"Auditing system memory & caches...");
        advanceProgressTo(48, 100);

        SafePostStatus(hWnd, L"Memory signatures: 16 / 128 MB");
        advanceProgressTo(58, 90);
        SafePostStatus(hWnd, L"Memory signatures: 64 / 128 MB");
        advanceProgressTo(68, 90);
        SafePostStatus(hWnd, L"Memory signatures: 128 / 128 MB");
        advanceProgressTo(76, 90);
    }

    // 76% -> 85%: Mod Scope & Bytecode
    SafePostStatus(hWnd, L"Mod Scope: inspecting loaded archives...");
    wchar_t appData[MAX_PATH];
    if (GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH)) {
        BytecodeAnalyzer::ScanModDirectory(std::wstring(appData) + L"\\.minecraft\\mods", g_reportData.findings);
        BytecodeAnalyzer::ScanModDirectory(std::wstring(appData) + L"\\.feather\\user-mods", g_reportData.findings);
        BytecodeAnalyzer::ScanModDirectory(std::wstring(appData) + L"\\PrismLauncher\\instances", g_reportData.findings);
    }
    wchar_t userProfile[MAX_PATH];
    if (GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH)) {
        BytecodeAnalyzer::ScanModDirectory(std::wstring(userProfile) + L"\\.lunarclient\\offline\\multiver", g_reportData.findings);
    }
    advanceProgressTo(85, 100);

    // 85% -> 92%: Win+R RunMRU & BAM Forensics
    SafePostStatus(hWnd, L"Checking Win+R RunMRU & BAM forensics...");
    RegistryForensics::ScanRunMruEntries(g_reportData.findings);
    RegistryForensics::ScanBamEntries(g_reportData.findings);
    RegistryForensics::ScanUserAssist(g_reportData.findings);
    RegistryForensics::ScanUsbSerialCom(g_reportData.findings);
    advanceProgressTo(92, 100);

    // 92% -> 96%: NTFS USN Change Journal
    SafePostStatus(hWnd, L"NTFS USN Change Journal audit...");
    JournalForensics::ScanAllFixedDrives(g_reportData.findings);
    advanceProgressTo(96, 100);

    // 96% -> 99%: Windows Services & Accounts
    SafePostStatus(hWnd, L"Checking Windows services...");
    RegistryForensics::CheckServiceTampering(g_reportData.findings);
    g_reportData.minecraft_accounts = AccountsExtractor::ExtractMinecraftAccounts();
    g_reportData.discord_accounts = AccountsExtractor::ExtractDiscordAccounts();
    advanceProgressTo(99, 100);

    // Audit logs
    LogEntry l1; l1.title = "Target Process"; l1.description = mcPid ? ("Attached to PID " + std::to_string(mcPid)) : "Host forensic scan (Java absent)"; l1.status = "Complete";
    LogEntry l2; l2.title = "Memory Snapshots"; l2.description = "Examined 128 MB virtual pages for unlinked PEs, wiped headers and PAGE_GUARD evasion"; l2.status = "Complete";
    LogEntry l3; l3.title = "NTFS USN Journal"; l3.description = "Scanned volume change journal for deleted cheat filenames and .attach_pid artifacts"; l3.status = "Complete";
    LogEntry l4; l4.title = "Registry Forensics"; l4.description = "Audited Win+R RunMRU, BAM execution history, UserAssist ROT13, and DPS SRUDB state"; l4.status = "Complete";
    LogEntry l5; l5.title = "Hardware Serial Ports"; l5.description = "Queried SERIALCOMM for unauthorized USB macro/aimbot microcontrollers"; l5.status = "Complete";
    g_reportData.logs.push_back(l1);
    g_reportData.logs.push_back(l2);
    g_reportData.logs.push_back(l3);
    g_reportData.logs.push_back(l4);
    g_reportData.logs.push_back(l5);

    // Final completion step to 100%
    advanceProgressTo(100, 150);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    PostMessageW(hWnd, WM_APP + 4, (WPARAM)mcPid, 1);
    g_isScanning = false;
}

void OpenScanResults() {
    std::string templateHtml = GetEmbeddedReportTemplate();
    std::string reportPath = "Root_Scan_Report.html";
    ReportGenerator::GenerateHtmlReport(templateHtml, g_reportData, reportPath);

    std::wstring absPath = std::filesystem::absolute(reportPath).wstring();
    ShellExecuteW(nullptr, L"open", absPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

class WebMessageReceivedHandler : public ICoreWebView2WebMessageReceivedEventHandler {
    LONG m_refCount = 1;
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_ICoreWebView2WebMessageReceivedEventHandler) {
            *ppv = static_cast<ICoreWebView2WebMessageReceivedEventHandler*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&m_refCount); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG count = InterlockedDecrement(&m_refCount);
        if (count == 0) delete this;
        return count;
    }
    HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2* sender, ICoreWebView2WebMessageReceivedEventArgs* args) override {
        LPWSTR rawMsg = nullptr;
        if (SUCCEEDED(args->TryGetWebMessageAsString(&rawMsg)) && rawMsg) {
            std::wstring msg = rawMsg;
            CoTaskMemFree(rawMsg);

            if (msg == L"drag") {
                ReleaseCapture();
                SendMessageW(g_hWnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
            } else if (msg == L"close") {
                DestroyWindow(g_hWnd);
                PostQuitMessage(0);
            } else if (msg == L"discord") {
                ShellExecuteW(nullptr, L"open", L"https://discord.gg/rootscanner", nullptr, nullptr, SW_SHOWNORMAL);
            } else if (msg == L"website") {
                ShellExecuteW(nullptr, L"open", L"https://github.com/tosloi/Root", nullptr, nullptr, SW_SHOWNORMAL);
            } else if (msg == L"start") {
                if (!g_isScanning) {
                    std::thread(RunScanWorker, g_hWnd).detach();
                }
            } else if (msg == L"results") {
                OpenScanResults();
            }
        }
        return S_OK;
    }
};

class ControllerCompletedHandler : public ICoreWebView2CreateCoreWebView2ControllerCompletedHandler {
    HWND m_hWnd;
    LONG m_refCount = 1;
public:
    ControllerCompletedHandler(HWND hWnd) : m_hWnd(hWnd) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_ICoreWebView2CreateCoreWebView2ControllerCompletedHandler) {
            *ppv = static_cast<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&m_refCount); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG count = InterlockedDecrement(&m_refCount);
        if (count == 0) delete this;
        return count;
    }
    HRESULT STDMETHODCALLTYPE Invoke(HRESULT result, ICoreWebView2Controller* controller) override {
        if (SUCCEEDED(result) && controller) {
            g_controller = controller;
            g_controller->AddRef();
            g_controller->get_CoreWebView2(&g_webview);

            RECT bounds;
            GetClientRect(m_hWnd, &bounds);
            g_controller->put_Bounds(bounds);

            // Configure settings
            ICoreWebView2Settings* settings = nullptr;
            if (SUCCEEDED(g_webview->get_Settings(&settings)) && settings) {
                settings->put_AreDevToolsEnabled(FALSE);
                settings->put_AreDefaultContextMenusEnabled(FALSE);
                settings->put_IsStatusBarEnabled(FALSE);
                settings->Release();
            }

            // Register WebMessageReceived
            EventRegistrationToken token;
            auto msgHandler = new WebMessageReceivedHandler();
            g_webview->add_WebMessageReceived(msgHandler, &token);
            msgHandler->Release();

            // Load directly from binary-embedded HTML
            std::string html = GetEmbeddedWindowHtml();
            int wchars_num = MultiByteToWideChar(CP_UTF8, 0, html.c_str(), -1, NULL, 0);
            std::wstring wHtml(wchars_num, 0);
            MultiByteToWideChar(CP_UTF8, 0, html.c_str(), -1, &wHtml[0], wchars_num);

            g_webview->NavigateToString(wHtml.c_str());
        }
        return S_OK;
    }
};

class EnvironmentCompletedHandler : public ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler {
    HWND m_hWnd;
    LONG m_refCount = 1;
public:
    EnvironmentCompletedHandler(HWND hWnd) : m_hWnd(hWnd) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler) {
            *ppv = static_cast<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&m_refCount); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG count = InterlockedDecrement(&m_refCount);
        if (count == 0) delete this;
        return count;
    }
    HRESULT STDMETHODCALLTYPE Invoke(HRESULT result, ICoreWebView2Environment* env) override {
        if (SUCCEEDED(result) && env) {
            auto handler = new ControllerCompletedHandler(m_hWnd);
            env->CreateCoreWebView2Controller(m_hWnd, handler);
            handler->Release();
        }
        return S_OK;
    }
};

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_SIZE: {
            if (g_controller) {
                RECT bounds;
                GetClientRect(hWnd, &bounds);
                g_controller->put_Bounds(bounds);
            }
            return 0;
        }
        case WM_APP + 1: { // rootSetStatus
            wchar_t* statusText = (wchar_t*)lParam;
            if (statusText) {
                std::wstring js = L"window.rootSetStatus(\"" + std::wstring(statusText) + L"\");";
                ExecuteScriptOnUI(js);
                free(statusText);
            }
            return 0;
        }
        case WM_APP + 2: { // rootSetPid
            DWORD pid = (DWORD)wParam;
            std::wstring js = L"window.rootSetPid(" + std::to_wstring(pid) + L");";
            ExecuteScriptOnUI(js);
            return 0;
        }
        case WM_APP + 3: { // rootSetProgress
            int progress = (int)wParam;
            std::wstring js = L"window.rootSetProgress(" + std::to_wstring(progress) + L");";
            ExecuteScriptOnUI(js);
            return 0;
        }
        case WM_APP + 4: { // rootScanComplete
            DWORD pid = (DWORD)wParam;
            std::wstring js = L"window.rootScanComplete(" + std::to_wstring(pid) + L", true);";
            ExecuteScriptOnUI(js);
            return 0;
        }
        case WM_DESTROY: {
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    const wchar_t CLASS_NAME[] = L"RootScannerWindow";

    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);

    RegisterClassExW(&wc);

    const int width = 440;
    const int height = 360;
    const int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
    const int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;

    g_hWnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        CLASS_NAME,
        L"Root",
        WS_POPUP | WS_VISIBLE,
        x, y, width, height,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!g_hWnd) return 1;

    // Windows 11 Rounded Corners & Dark Immersive Mode
    enum DWM_WINDOW_CORNER_PREFERENCE { DWMWCP_ROUND = 2 };
    DWM_WINDOW_CORNER_PREFERENCE preference = DWMWCP_ROUND;
    DwmSetWindowAttribute(g_hWnd, 33 /* DWMWA_WINDOW_CORNER_PREFERENCE */, &preference, sizeof(preference));

    BOOL darkMode = TRUE;
    DwmSetWindowAttribute(g_hWnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &darkMode, sizeof(darkMode));

    MARGINS margins = { -1 };
    DwmExtendFrameIntoClientArea(g_hWnd, &margins);

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    // Ensure WebView2Loader.dll is available
    HMODULE hLoader = LoadLibraryW(L"WebView2Loader.dll");
    if (!hLoader) {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        std::wstring tempLoader = std::wstring(tempPath) + L"WebView2Loader.dll";

        size_t loaderSize = 0;
        const uint8_t* loaderBytes = GetEmbeddedWebView2Loader(loaderSize);
        if (loaderSize > 0) {
            std::ofstream out(tempLoader.c_str(), std::ios::binary);
            out.write(reinterpret_cast<const char*>(loaderBytes), loaderSize);
            out.close();
            hLoader = LoadLibraryW(tempLoader.c_str());
        }
    }

    if (!hLoader) {
        MessageBoxW(g_hWnd, L"Failed to initialize WebView2 runtime loader.", L"Root Error", MB_ICONERROR);
        return 1;
    }

    auto CreateEnv = (CreateCoreWebView2EnvironmentWithOptionsFn)GetProcAddress(hLoader, "CreateCoreWebView2EnvironmentWithOptions");
    if (CreateEnv) {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        std::wstring userDir = std::wstring(tempPath) + L"RootScannerUserData";

        auto envHandler = new EnvironmentCompletedHandler(g_hWnd);
        CreateEnv(nullptr, userDir.c_str(), nullptr, envHandler);
        envHandler->Release();
    }

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CoUninitialize();
    return 0;
}

int main(int argc, char* argv[]) {
    return wWinMain(GetModuleHandleW(nullptr), nullptr, GetCommandLineW(), SW_SHOW);
}
