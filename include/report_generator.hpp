#pragma once

#include "root_scanner.hpp"
#include <string>

namespace RootScanner {

class ReportGenerator {
public:
    static std::string SerializeToJson(const ScanReportData& data);
    static bool GenerateHtmlReport(const std::string& templateHtml, const ScanReportData& data, const std::string& outputPath);

private:
    static std::string CategoryToString(FindingCategory cat);
    static std::string EscapeJson(const std::string& str);
};

} // namespace RootScanner
