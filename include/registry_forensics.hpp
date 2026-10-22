#pragma once

#include "root_scanner.hpp"
#include <vector>
#include <string>

namespace RootScanner {

class RegistryForensics {
public:
    static void ScanBamEntries(std::vector<Finding>& outFindings);
    static void ScanUserAssist(std::vector<Finding>& outFindings);
    static void ScanRunMruEntries(std::vector<Finding>& outFindings);
    static void ScanUsbSerialCom(std::vector<Finding>& outFindings);
    static void CheckServiceTampering(std::vector<Finding>& outFindings);
    static std::string DecodeRot13(const std::string& input);
};

} // namespace RootScanner
