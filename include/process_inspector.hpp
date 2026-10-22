#pragma once

#include "root_scanner.hpp"
#include <vector>

namespace RootScanner {

class ProcessInspector {
public:
    static std::vector<ProcessTarget> FindMinecraftProcesses();
    static bool CheckParentProcessSpoofing(DWORD pid, HANDLE hProcess, std::vector<Finding>& outFindings);
    static bool InspectProcessMitigations(HANDLE hProcess, std::vector<Finding>& outFindings);
    static void InspectLoadedModules(DWORD pid, HANDLE hProcess, std::vector<Finding>& outFindings);
    static void InspectJvmEndpoints(DWORD pid, std::vector<Finding>& outFindings);
    static std::vector<std::wstring> ExtractJvmArguments(HANDLE hProcess, const std::wstring& cmdLine);
    static void InspectArgumentFiles(const std::vector<std::wstring>& args, std::vector<Finding>& outFindings);
};

} // namespace RootScanner
