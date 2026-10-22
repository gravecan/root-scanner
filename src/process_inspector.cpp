#include "process_inspector.hpp"
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <filesystem>

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

namespace RootScanner {

void EnableDebugPrivilege() {
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) {
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        }
        CloseHandle(hToken);
    }
}

std::vector<ProcessTarget> ProcessInspector::FindMinecraftProcesses() {
    EnableDebugPrivilege();
    std::vector<ProcessTarget> targets;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return targets;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(hSnap, &pe32)) {
        do {
            std::wstring name = pe32.szExeFile;
            std::wstring lowerName = name;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

            bool isCandidate = (lowerName == L"javaw.exe" || lowerName == L"java.exe" ||
                                lowerName == L"minecraft.exe" || lowerName == L"minecraftlauncher.exe" ||
                                lowerName.find(L"lunar") != std::wstring::npos ||
                                lowerName.find(L"badlion") != std::wstring::npos ||
                                lowerName.find(L"feather") != std::wstring::npos);

            if (isCandidate) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProc) {
                    ProcessTarget t;
                    t.pid = pe32.th32ProcessID;
                    t.process_name = name;
                    t.handle = hProc;
                    BOOL isWow64 = FALSE;
                    IsWow64Process(hProc, &isWow64);
                    t.is_64bit = !isWow64;
                    targets.push_back(t);
                }
            }
        } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return targets;
}

bool ProcessInspector::CheckParentProcessSpoofing(DWORD pid, HANDLE hProcess, std::vector<Finding>& outFindings) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    auto NtQueryInfoProc = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInfoProc) return false;

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG retLen = 0;
    NTSTATUS status = NtQueryInfoProc(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
    if (status != 0) return false;

    DWORD parentPid = (DWORD)(ULONG_PTR)pbi.InheritedFromUniqueProcessId;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    std::wstring parentName = L"unknown";

    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (pe32.th32ProcessID == parentPid) {
                parentName = pe32.szExeFile;
                break;
            }
        } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);

    std::wstring lowerParent = parentName;
    std::transform(lowerParent.begin(), lowerParent.end(), lowerParent.begin(), ::towlower);

    if (lowerParent == L"services.exe" || lowerParent == L"svchost.exe" || lowerParent == L"lsass.exe") {
        Finding f;
        f.category = FindingCategory::Bypass;
        f.message = "Parent Process Spoofing Detected (services.exe)";
        f.explanation = "Minecraft process reports parent as services.exe / svchost.exe. Minecraft is never spawned by system service hosts; indicates PROC_THREAD_ATTRIBUTE_PARENT_PROCESS spoofing to evade detection.";
        f.next_step = "Check process creation audit logs (Event 4688) and inspect launcher shortcut.";
        outFindings.push_back(f);
        return true;
    }

    return false;
}

bool ProcessInspector::InspectProcessMitigations(HANDLE hProcess, std::vector<Finding>& outFindings) {
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = { 0 };
    if (GetProcessMitigationPolicy(hProcess, ProcessSignaturePolicy, &policy, sizeof(policy))) {
        if (policy.MicrosoftSignedOnly) {
            Finding f;
            f.category = FindingCategory::Warning;
            f.message = "MicrosoftSignedOnly Mitigation Enabled";
            f.explanation = "Selected Java process has MicrosoftSignedOnly binary-signature mitigation enabled. This can restrict future DLL loading; policy alone does not establish tampering, parent spoofing, injection or cheating.";
            f.next_step = "Verify launcher configuration and JVM launch arguments.";
            outFindings.push_back(f);
            return true;
        }
    }
    return false;
}

void ProcessInspector::InspectLoadedModules(DWORD pid, HANDLE hProcess, std::vector<Finding>& outFindings) {
    // 1. Check for attached debuggers
    BOOL isDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(hProcess, &isDebuggerPresent) && isDebuggerPresent) {
        Finding f;
        f.category = FindingCategory::Detect;
        f.message = "Active Remote Debugger Attached (CheckRemoteDebuggerPresent)";
        f.explanation = "CheckRemoteDebuggerPresent reports an external debugger is actively attached to the game process. External injector/debugger attached via DebugActiveProcess or NtDebugActiveProcess to redirect execution.";
        f.next_step = "Identify debugging process and review hooked execution threads.";
        outFindings.push_back(f);
    }

    // 2. Snapshot loaded modules
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me32;
    me32.dwSize = sizeof(me32);

    if (Module32FirstW(hSnap, &me32)) {
        do {
            std::wstring modName = me32.szModule;
            std::string lowerMod;
            for (wchar_t wc : modName) lowerMod.push_back(static_cast<char>(::towlower(wc)));

            // Check if .NET CLR is loaded inside javaw.exe
            if (lowerMod == "clr.dll" || lowerMod == "mscoree.dll") {
                Finding f;
                f.category = FindingCategory::Detect;
                f.message = "In-Process CLR Runtime Hosting: " + lowerMod;
                f.explanation = "Microsoft .NET Common Language Runtime module '" + lowerMod + "' detected inside javaw.exe process space. Legitimate Minecraft runs on JVM; hosting the CLR indicates in-memory C# assembly execution (Assembly.Load).";
                f.next_step = "Inspect loaded managed assemblies and C# native injector payloads.";
                outFindings.push_back(f);
            }

            // Check exports of modules
            HMODULE hLocalMod = LoadLibraryExW(me32.szExePath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
            if (hLocalMod) {
                FARPROC pAgentAttach = GetProcAddress(hLocalMod, "Agent_OnAttach");
                FARPROC pAgentLoad = GetProcAddress(hLocalMod, "Agent_OnLoad");
                if (pAgentAttach || pAgentLoad) {
                    Finding f;
                    f.category = FindingCategory::Detect;
                    f.message = "Injected JVMTI Agent (Agent_OnAttach): " + lowerMod;
                    f.explanation = "Module '" + lowerMod + "' exports JVMTI attach entrypoints (Agent_OnAttach / Agent_OnLoad) to hook JVM internals. Injected dynamic Java instrumentation agent detected in javaw.exe.";
                    f.next_step = "Check DLL provenance, digital signature, and file creation timestamp.";
                    outFindings.push_back(f);
                }

                FARPROC pJniGetVms = GetProcAddress(hLocalMod, "JNI_GetCreatedJavaVMs");
                if (pJniGetVms && lowerMod != "jvm.dll") {
                    Finding f;
                    f.category = FindingCategory::Detect;
                    f.message = "JNI Proxy / Imposter DLL (JNI_GetCreatedJavaVMs): " + lowerMod;
                    f.explanation = "Module '" + lowerMod + "' exports JNI_GetCreatedJavaVMs but is not jvm.dll. Imposter/proxy DLL hijacking JVM functions.";
                    f.next_step = "Quarantine suspicious proxy library.";
                    outFindings.push_back(f);
                }

                FreeLibrary(hLocalMod);
            }
        } while (Module32NextW(hSnap, &me32));
    }
    CloseHandle(hSnap);
}

void ProcessInspector::InspectJvmEndpoints(DWORD pid, std::vector<Finding>& outFindings) {
    // Check for \\.\pipe\javatool* attach pipe
    std::wstring pipeName = L"\\\\.\\pipe\\javatool" + std::to_wstring(pid);
    HANDLE hPipe = CreateFileW(pipeName.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        Finding f;
        f.category = FindingCategory::Warning;
        f.message = "JVM attach endpoint exists: javatool" + std::to_string(pid);
        f.explanation = "JVM Dynamic Attach API endpoint is active. Allows dynamic Java agent injection and diagnostic bytecode manipulation.";
        f.next_step = "Verify JVM startup flag -XX:+DisableAttachMechanism.";
        outFindings.push_back(f);
    }

    // Check %TEMP%\.attach_pid*
    wchar_t tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath)) {
        std::wstring attachFile = std::wstring(tempPath) + L".attach_pid" + std::to_wstring(pid);
        if (std::filesystem::exists(attachFile)) {
            Finding f;
            f.category = FindingCategory::Detect;
            f.message = "USN attach-request filename reference: .attach_pid" + std::to_string(pid);
            f.explanation = "Active .attach_pid file discovered in temp directory. Confirms recent or active dynamic JVM agent attachment request.";
            f.next_step = "Inspect process that created the attach trigger file.";
            outFindings.push_back(f);
        }
    }
}

std::vector<std::wstring> ProcessInspector::ExtractJvmArguments(HANDLE hProcess, const std::wstring& cmdLine) {
    std::vector<std::wstring> args;
    std::wistringstream ss(cmdLine);
    std::wstring token;
    while (ss >> token) {
        args.push_back(token);
    }
    return args;
}

void ProcessInspector::InspectArgumentFiles(const std::vector<std::wstring>& args, std::vector<Finding>& outFindings) {
    for (const auto& arg : args) {
        if (!arg.empty() && arg[0] == L'@') {
            Finding fd;
            fd.category = FindingCategory::Warning;
            fd.message = "Java Argument-File Reference";
            fd.explanation = "Java launcher specified external @argfile parameter. Ordered Java launcher inspection incomplete; unreadable argument file or token limit reached.";
            fd.next_step = "Check launcher profile arguments for hidden injected libraries.";
            outFindings.push_back(fd);
        }
    }
}

} // namespace RootScanner

