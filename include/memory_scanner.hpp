#pragma once

#include "root_scanner.hpp"
#include <vector>
#include <functional>

namespace RootScanner {

using MemoryProgressCallback = std::function<void(int currentMb, int totalMb)>;

class MemoryScanner {
public:
    static void ScanProcessMemory(HANDLE hProcess, std::vector<Finding>& outFindings, MemoryProgressCallback onProgress = nullptr);

private:
    static void CheckUnmappedExecutableMemory(HANDLE hProcess, const MEMORY_BASIC_INFORMATION& mbi, const std::vector<uint8_t>& buffer, std::vector<Finding>& outFindings);
    static void CheckPngSteganography(HANDLE hProcess, const MEMORY_BASIC_INFORMATION& mbi, const std::vector<uint8_t>& buffer, std::vector<Finding>& outFindings);
    static void CheckKnownCheatPatterns(const std::vector<uint8_t>& buffer, uint64_t baseAddress, std::vector<Finding>& outFindings);
    static void CheckDoomsdaySignature(const std::vector<uint8_t>& buffer, uint64_t baseAddress, std::vector<Finding>& outFindings);
};

} // namespace RootScanner
